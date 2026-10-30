package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

const maxFileBytes int64 = 1 << 30
const maxTotalBytes int64 = 4 << 30
const maxEntries = 100000

type contextReader struct {
	context context.Context
	reader  io.Reader
}

func (r contextReader) Read(buffer []byte) (int, error) {
	if err := r.context.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

func disjoint(left, right string) error {
	l, err := filepath.EvalSymlinks(left)
	if err != nil {
		return err
	}
	r, err := filepath.EvalSymlinks(right)
	if err != nil {
		return err
	}
	if domain.PathsOverlap(filepath.ToSlash(l), filepath.ToSlash(r)) {
		return fmt.Errorf("source and destination overlap")
	}
	return nil
}

func protectedDestination(name string) (*directory, error) {
	if err := domain.ValidateAbsolutePath(filepath.ToSlash(name)); err != nil {
		return nil, err
	}
	if err := os.Mkdir(name, 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	d, err := openDirectory(name)
	if err != nil {
		return nil, err
	}
	f, err := d.root.Open(".")
	if err != nil {
		d.close()
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		d.close()
		return nil, err
	}
	id, err := identify(info)
	if err != nil {
		d.close()
		return nil, err
	}
	if id.uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0700 {
		d.close()
		return nil, fmt.Errorf("destination must be executor-owned mode 0700")
	}
	entries, err := f.ReadDir(1)
	if err != nil && err != io.EOF {
		d.close()
		return nil, err
	}
	if len(entries) != 0 {
		d.close()
		return nil, fmt.Errorf("destination must be empty")
	}
	return d, nil
}

// Capture publishes no metadata itself. On failure destination is partial and
// must not be referenced as a complete snapshot. File contents are copied, never
// hard-linked; original ownership/mode exist only in the immutable manifest.
func Capture(ctx context.Context, sourceRoot, destinationRoot string, managed []domain.ManagedPath, exclusions []string) (domain.Manifest, error) {
	return capture(ctx, sourceRoot, destinationRoot, managed, exclusions, nil)
}

// afterCopy is an internal deterministic fault-injection seam for copy races.
// It is never exposed through configuration or the executor protocol.
func capture(ctx context.Context, sourceRoot, destinationRoot string, managed []domain.ManagedPath, exclusions []string, afterCopy func()) (domain.Manifest, error) {
	if err := ctx.Err(); err != nil {
		return domain.Manifest{}, err
	}
	p, err := makePolicy(managed, exclusions)
	if err != nil {
		return domain.Manifest{}, err
	}
	destination, err := protectedDestination(destinationRoot)
	if err != nil {
		return domain.Manifest{}, err
	}
	defer destination.close()
	if err = disjoint(sourceRoot, destinationRoot); err != nil {
		return domain.Manifest{}, err
	}
	source, err := openDirectory(sourceRoot)
	if err != nil {
		return domain.Manifest{}, err
	}
	defer source.close()
	manifest, observed, err := scan(ctx, source, p, destination)
	if err != nil {
		return domain.Manifest{}, err
	}
	if afterCopy != nil {
		afterCopy()
	}
	// A second full observation catches additions/deletions, inode replacement and
	// edits after an individual file's first read. This is coordinated copying,
	// never a claim of an atomic snapshot of a live filesystem.
	check, after, err := scan(ctx, source, p, nil)
	if err != nil {
		return domain.Manifest{}, err
	}
	if manifest.Digest() != check.Digest() || !sameObservations(observed, after) {
		return domain.Manifest{}, ErrSourceChanged
	}
	if err = syncTree(destination); err != nil {
		return domain.Manifest{}, err
	}
	return manifest, nil
}

func sameObservations(a, b map[string]identity) bool {
	if len(a) != len(b) {
		return false
	}
	for name, id := range a {
		if b[name] != id {
			return false
		}
	}
	return true
}

func scan(ctx context.Context, source *directory, p policy, destination *directory) (domain.Manifest, map[string]identity, error) {
	entries := map[string]domain.ManifestEntry{}
	observed := map[string]identity{}
	var total int64
	var visit func(string, bool) error
	visit = func(name string, recurse bool) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if p.excludes(name) {
			return nil
		}
		if _, ok := entries[name]; ok {
			return nil
		}
		file, id, err := source.open(name)
		if err != nil {
			return err
		}
		defer file.Close()
		if len(entries) >= maxEntries {
			return fmt.Errorf("managed tree entry limit exceeded")
		}
		entry := domain.ManifestEntry{Path: name, Mode: uint32(id.mode.Perm()), UID: id.uid, GID: id.gid}
		if id.mode.IsDir() {
			entry.Type = domain.EntryDirectory
			entries[name] = entry
			observed[name] = id
			if destination != nil {
				if err := destination.root.MkdirAll(name, 0700); err != nil {
					return err
				}
			}
			if recurse {
				for {
					children, readErr := file.ReadDir(256)
					for _, child := range children {
						if err = visit(path.Join(name, child.Name()), true); err != nil {
							return err
						}
					}
					if readErr == io.EOF {
						break
					}
					if readErr != nil {
						return readErr
					}
				}
			}
		} else {
			if id.size > maxFileBytes || id.size > maxTotalBytes-total {
				return fmt.Errorf("managed tree byte limit exceeded")
			}
			total += id.size
			entry.Type = domain.EntryFile
			entry.Size = id.size
			var writer io.Writer = io.Discard
			var output *os.File
			if destination != nil {
				if err = destination.root.MkdirAll(path.Dir(name), 0700); err != nil {
					return err
				}
				output, err = destination.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollowFlags, 0600)
				if err != nil {
					return err
				}
				defer output.Close()
				writer = output
			}
			hasher := sha256.New()
			count, err := io.Copy(io.MultiWriter(writer, hasher), contextReader{ctx, io.LimitReader(file, id.size+1)})
			if err != nil {
				return err
			}
			if count != id.size {
				return ErrSourceChanged
			}
			entry.Digest = domain.Digest("sha256:" + hex.EncodeToString(hasher.Sum(nil)))
			if output != nil {
				if err = output.Chmod(0400); err != nil {
					return err
				}
				if err = output.Sync(); err != nil {
					return err
				}
				if err = output.Close(); err != nil {
					return err
				}
			}
			entries[name] = entry
			observed[name] = id
		}
		after, err := file.Stat()
		if err != nil {
			return err
		}
		afterID, err := identify(after)
		if err != nil {
			return err
		}
		if afterID != id {
			return ErrSourceChanged
		}
		return nil
	}
	for _, managed := range p.managed {
		if p.excludes(managed.Path) {
			continue
		}
		// A missing path represents deletion in a candidate; it is not created by
		// copying. Ancestors are structural metadata, not authorization to mutate
		// unmanaged siblings.
		file, _, err := source.open(managed.Path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return domain.Manifest{}, nil, err
		}
		file.Close()
		var ancestors []string
		for parent := path.Dir(managed.Path); parent != "."; parent = path.Dir(parent) {
			ancestors = append(ancestors, parent)
		}
		for i := len(ancestors) - 1; i >= 0; i-- {
			if err = visit(ancestors[i], false); err != nil {
				return domain.Manifest{}, nil, err
			}
		}
		if err = visit(managed.Path, true); err != nil {
			return domain.Manifest{}, nil, err
		}
	}
	result := make([]domain.ManifestEntry, 0, len(entries))
	for _, entry := range entries {
		result = append(result, entry)
	}
	manifest, err := domain.NewManifest(result)
	return manifest, observed, err
}

func syncTree(directory *directory) error {
	var names []string
	err := fs.WalkDir(directory.root.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			names = append(names, name)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(names, func(i, j int) bool { return strings.Count(names[i], "/") > strings.Count(names[j], "/") })
	for _, name := range names {
		file, err := directory.root.Open(name)
		if err != nil {
			return err
		}
		err = file.Sync()
		file.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// Verify checks protected physical contents against their original manifest.
// It deliberately does not compare physical 0400/0700 permissions with the
// recorded source permissions used later for builds and active materialization.
func Verify(ctx context.Context, contentRoot string, manifest domain.Manifest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	validated, err := domain.NewManifest(manifest.Entries())
	if err != nil {
		return err
	}
	if validated.Digest() != manifest.Digest() {
		return fmt.Errorf("invalid manifest")
	}
	root, err := openDirectory(contentRoot)
	if err != nil {
		return err
	}
	defer root.close()
	rootFile, err := root.root.Open(".")
	if err != nil {
		return err
	}
	rootInfo, err := rootFile.Stat()
	rootFile.Close()
	if err != nil {
		return err
	}
	rootID, err := identify(rootInfo)
	if err != nil {
		return err
	}
	if rootID.uid != uint32(os.Geteuid()) || rootID.mode.Perm() != 0700 {
		return fmt.Errorf("artifact root must be executor-owned mode 0700")
	}
	expected := map[string]domain.ManifestEntry{}
	for _, entry := range manifest.Entries() {
		if entry.Type == domain.EntrySymlink {
			return fmt.Errorf("%w: symlinks are not in the initial profile", ErrUnsafePath)
		}
		expected[entry.Path] = entry
	}
	seen := map[string]bool{}
	err = fs.WalkDir(root.root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		expect, exists := expected[name]
		if !exists {
			return fmt.Errorf("unexpected artifact path %q", name)
		}
		file, id, err := root.open(name)
		if err != nil {
			return err
		}
		defer file.Close()
		if id.uid != uint32(os.Geteuid()) {
			return fmt.Errorf("artifact is not executor-owned")
		}
		if id.mode.IsDir() {
			if expect.Type != domain.EntryDirectory || id.mode.Perm() != 0700 {
				return fmt.Errorf("artifact directory mismatch %q", name)
			}
		} else {
			if expect.Type != domain.EntryFile || id.mode.Perm() != 0400 || id.size != expect.Size {
				return fmt.Errorf("artifact file mismatch %q", name)
			}
			hasher := sha256.New()
			_, err = io.Copy(hasher, contextReader{ctx, file})
			if err != nil {
				return err
			}
			if domain.Digest("sha256:"+hex.EncodeToString(hasher.Sum(nil))) != expect.Digest {
				return fmt.Errorf("artifact digest mismatch %q", name)
			}
		}
		seen[name] = true
		return nil
	})
	if err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("artifact paths missing")
	}
	return nil
}
