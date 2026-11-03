package filesystem

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

type ApplyOptions struct {
	// The caller must stop the registered application targets, hold all resource
	// locks and persist a recovery point before authorizing active file writes.
	ApplicationsStopped bool
	PreserveOwnership   bool
	Exclusions          []string
}

// Apply replaces individual managed files durably. It is not a transaction over
// the tree: a crash/error may leave partial application and requires executor
// recovery. No unmanaged path, excluded entry or persistent data is deleted.
func Apply(ctx context.Context, contentRoot, activeRoot string, previous, next domain.Manifest, managed []domain.ManagedPath, options ApplyOptions) error {
	if !options.ApplicationsStopped {
		return fmt.Errorf("application targets must be stopped before materialization")
	}
	p, err := makePolicy(managed, options.Exclusions)
	if err != nil {
		return err
	}
	for _, manifest := range []domain.Manifest{previous, next} {
		if _, err = domain.NewManifest(manifest.Entries()); err != nil {
			return err
		}
		for _, entry := range manifest.Entries() {
			if !p.allows(entry) {
				return fmt.Errorf("manifest path outside managed policy: %q", entry.Path)
			}
		}
	}
	previousTypes := map[string]domain.EntryType{}
	for _, entry := range previous.Entries() {
		previousTypes[entry.Path] = entry.Type
	}
	for _, entry := range next.Entries() {
		if before, exists := previousTypes[entry.Path]; exists && before != entry.Type {
			return fmt.Errorf("file/directory transitions require an expanded materialization profile: %q", entry.Path)
		}
	}
	if err = Verify(ctx, contentRoot, next); err != nil {
		return err
	}
	if err = disjoint(contentRoot, activeRoot); err != nil {
		return err
	}
	active, err := openDirectory(activeRoot)
	if err != nil {
		return err
	}
	defer active.close()
	source, err := openDirectory(contentRoot)
	if err != nil {
		return err
	}
	defer source.close()
	actual, observed, err := scan(ctx, active, p, nil)
	if err != nil {
		return err
	}
	if actual.Digest() != previous.Digest() {
		return ErrDrift
	}
	return materialize(ctx, source, active, previous, next, p, observed, options.PreserveOwnership)
}

// MaterializeBuild makes a disposable context with recorded modes, including
// executable bits, while retaining executor ownership. The root remains 0700.
// The complete artifact is verified even when exact files are excluded.
// It never writes to an existing nonempty directory.
func MaterializeBuild(ctx context.Context, contentRoot, destinationRoot string, manifest domain.Manifest, excludeFiles ...string) error {
	if err := Verify(ctx, contentRoot, manifest); err != nil {
		return err
	}
	if len(excludeFiles) > 0 {
		excluded := make(map[string]bool, len(excludeFiles))
		for _, name := range excludeFiles {
			excluded[name] = true
		}
		entries := manifest.Entries()
		kept := entries[:0]
		for _, entry := range entries {
			if !excluded[entry.Path] {
				kept = append(kept, entry)
				continue
			}
			if entry.Type != domain.EntryFile {
				return fmt.Errorf("build exclusion is not a regular file: %q", entry.Path)
			}
			delete(excluded, entry.Path)
		}
		if len(excluded) != 0 {
			return fmt.Errorf("build exclusion is missing from the verified manifest")
		}
		filtered, err := domain.NewManifest(kept)
		if err != nil {
			return err
		}
		manifest = filtered
	}
	target, err := protectedDestination(destinationRoot)
	if err != nil {
		return err
	}
	defer target.close()
	if err = disjoint(contentRoot, destinationRoot); err != nil {
		return err
	}
	source, err := openDirectory(contentRoot)
	if err != nil {
		return err
	}
	defer source.close()
	var managed []domain.ManagedPath
	for _, entry := range manifest.Entries() {
		contained := false
		for _, existing := range managed {
			if entry.Path == existing.Path || strings.HasPrefix(entry.Path, existing.Path+"/") {
				contained = true
				break
			}
		}
		if !contained {
			managed = append(managed, domain.ManagedPath{Path: entry.Path, Kind: domain.ManagedCode})
		}
	}
	// Empty manifests legitimately produce empty build contexts.
	p := policy{managed: managed}
	empty, _ := domain.NewManifest(nil)
	return materialize(ctx, source, target, empty, manifest, p, map[string]identity{}, false)
}

func ensureDirectory(target *directory, name string) error {
	parent, leaf, err := target.parent(name)
	if err != nil {
		return err
	}
	defer parent.Close()
	err = parent.Mkdir(leaf, 0700)
	if err != nil && !os.IsExist(err) {
		return err
	}
	file, id, err := target.open(name)
	if err != nil {
		return err
	}
	file.Close()
	if !id.mode.IsDir() {
		return fmt.Errorf("%w: expected directory %q", ErrUnsafePath, name)
	}
	return syncParent(parent)
}

func syncParent(parent *os.Root) error {
	file, err := parent.Open(".")
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func checkExpected(parent *os.Root, leaf, name string, observed map[string]identity) error {
	info, err := parent.Lstat(leaf)
	expected, exists := observed[name]
	if !exists {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("%w: new path appeared %q", ErrDrift, name)
	}
	if err != nil {
		return fmt.Errorf("%w: path disappeared %q", ErrDrift, name)
	}
	actual, err := identify(info)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("%w: path changed %q", ErrDrift, name)
	}
	return nil
}

func materialize(ctx context.Context, source, target *directory, previous, next domain.Manifest, p policy, observed map[string]identity, preserveOwnership bool) error {
	entries := next.Entries()
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Type == domain.EntryDirectory {
			if err := ensureDirectory(target, entry.Path); err != nil {
				return err
			}
		}
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Type != domain.EntryFile {
			continue
		}
		parent, leaf, err := target.parent(entry.Path)
		if err != nil {
			return err
		}
		err = replaceFile(ctx, source, parent, leaf, entry, observed, preserveOwnership)
		parent.Close()
		if err != nil {
			return err
		}
	}
	keep := map[string]bool{}
	for _, entry := range entries {
		keep[entry.Path] = true
	}
	old := previous.Entries()
	sort.Slice(old, func(i, j int) bool {
		return strings.Count(old[i].Path, "/") > strings.Count(old[j].Path, "/") || strings.Count(old[i].Path, "/") == strings.Count(old[j].Path, "/") && old[i].Path > old[j].Path
	})
	for _, entry := range old {
		if keep[entry.Path] || !p.manages(entry.Path) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		parent, leaf, err := target.parent(entry.Path)
		if err != nil {
			return err
		}
		if entry.Type != domain.EntryDirectory {
			err = checkExpected(parent, leaf, entry.Path, observed)
		} else {
			info, statErr := parent.Lstat(leaf)
			if statErr != nil {
				err = statErr
			} else {
				id, identifyErr := identify(info)
				expected := observed[entry.Path]
				if identifyErr != nil || !id.mode.IsDir() || id.device != expected.device || id.inode != expected.inode {
					err = fmt.Errorf("%w: directory replaced %q", ErrDrift, entry.Path)
				}
			}
		}
		if err == nil {
			err = parent.Remove(leaf)
		}
		// Excluded/unmanaged children are always preserved, even if this leaves a
		// directory whose managed contents have been removed.
		if entry.Type == domain.EntryDirectory && (os.IsExist(err) || errors.Is(err, syscall.ENOTEMPTY)) {
			err = nil
		}
		if err == nil {
			err = syncParent(parent)
		}
		parent.Close()
		if err != nil {
			return err
		}
	}
	// Children are populated while directory permissions are still 0700. Apply
	// original modes deepest-first, using opened descriptors for chmod/chown.
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if entry.Type != domain.EntryDirectory {
			continue
		}
		if !p.manages(entry.Path) {
			continue
		} // Do not chmod structural ancestors.
		file, _, err := target.open(entry.Path)
		if err != nil {
			return err
		}
		if preserveOwnership {
			err = file.Chown(int(entry.UID), int(entry.GID))
		}
		if err == nil {
			err = file.Chmod(os.FileMode(entry.Mode))
		}
		if err == nil {
			err = file.Sync()
		}
		file.Close()
		if err != nil {
			return err
		}
	}
	return syncTree(target)
}

func replaceFile(ctx context.Context, source *directory, parent *os.Root, leaf string, entry domain.ManifestEntry, observed map[string]identity, preserveOwnership bool) error {
	input, _, err := source.open(entry.Path)
	if err != nil {
		return err
	}
	defer input.Close()
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return err
	}
	temporary := ".ctfm-" + hex.EncodeToString(random[:])
	output, err := parent.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollowFlags, 0600)
	if err != nil {
		return err
	}
	defer func() { output.Close(); _ = parent.Remove(temporary) }()
	hasher := sha256.New()
	count, err := io.Copy(io.MultiWriter(output, hasher), contextReader{ctx, io.LimitReader(input, entry.Size+1)})
	if err != nil {
		return err
	}
	if count != entry.Size || domain.Digest("sha256:"+hex.EncodeToString(hasher.Sum(nil))) != entry.Digest {
		return fmt.Errorf("artifact changed during materialization")
	}
	if preserveOwnership {
		if err = output.Chown(int(entry.UID), int(entry.GID)); err != nil {
			return err
		}
	}
	if err = output.Chmod(os.FileMode(entry.Mode)); err != nil {
		return err
	}
	if err = output.Sync(); err != nil {
		return err
	}
	if err = output.Close(); err != nil {
		return err
	}
	if err = checkExpected(parent, leaf, entry.Path, observed); err != nil {
		return err
	}
	if err = parent.Rename(temporary, leaf); err != nil {
		return err
	}
	return syncParent(parent)
}
