package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/filesystem"
)

// preserveGitComposeInputs changes only the private export owned by the current
// Fetch. The executor still builds and deploys against the approved policy.
func (m *Manager) preserveGitComposeInputs(ctx context.Context, s domain.Service, st runtimeState, source string) ([]string, error) {
	remote, err := filesystem.Observe(ctx, source, s.ManagedPaths, nil)
	if err != nil {
		return nil, err
	}
	frozen := make(map[string]domain.ManifestEntry, len(s.ComposeFiles))
	for _, name := range s.ComposeFiles {
		frozen[name] = domain.ManifestEntry{}
	}
	hasManagedFiles := false
	for _, entry := range remote.Entries() {
		if _, protected := frozen[entry.Path]; protected {
			frozen[entry.Path] = entry
		}
		if !hasManagedFiles && entry.Type == domain.EntryFile && !gitComposePath(frozen, entry.Path) {
			hasManagedFiles = true
		}
	}
	baseline, err := m.approvedComposeSnapshot(ctx, s, st)
	if err != nil {
		return nil, err
	}
	entries := make(map[string]domain.ManifestEntry)
	for _, entry := range baseline.Manifest.Entries() {
		entries[entry.Path] = entry
	}
	if !hasManagedFiles {
		// Keep existing image-only projects working when their managed
		// Compose inputs already match the approved snapshot.
		hasMatchingCompose := false
		for _, name := range s.ComposeFiles {
			remoteEntry, baselineEntry := frozen[name], entries[name]
			if remoteEntry.Path == "" && baselineEntry.Path == "" {
				continue
			}
			if !sameGitComposeBytes(remoteEntry, baselineEntry) {
				hasMatchingCompose = false
				break
			}
			hasMatchingCompose = true
		}
		if !hasMatchingCompose {
			return nil, errors.New("Git tree contains none of the approved managed paths outside frozen Compose inputs; verify repository subdirectory")
		}
	}
	content, err := m.Snapshots.ContentPath(baseline.ID)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(source)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	var hostOnly []string
	for _, name := range s.ComposeFiles {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		remoteEntry := frozen[name]
		entry, exists := entries[name]
		if !exists {
			// An unmanaged or excluded Compose file was never captured. Keep
			// it absent even when a remote file appears at the same path.
			if remoteEntry.Path != "" {
				if err := root.RemoveAll(name); err != nil {
					return nil, fmt.Errorf("omit Compose input %q missing from baseline: %w", name, err)
				}
			}
			continue
		}
		if entry.Type != domain.EntryFile {
			return nil, fmt.Errorf("frozen Compose input %q is not a regular baseline file", name)
		}
		if !sameGitComposeBytes(remoteEntry, entry) {
			hostOnly = append(hostOnly, name)
		}
		if remoteEntry == entry {
			continue
		}
		if err := restoreGitComposeFile(ctx, root, content, entry, entries); err != nil {
			return nil, fmt.Errorf("preserve frozen Compose input %q: %w", name, err)
		}
	}
	return hostOnly, nil
}

func sameGitComposeBytes(remote, baseline domain.ManifestEntry) bool {
	return remote.Type == domain.EntryFile && baseline.Type == domain.EntryFile && remote.Digest == baseline.Digest
}

func gitComposePath(frozen map[string]domain.ManifestEntry, name string) bool {
	for current := name; current != "."; current = path.Dir(current) {
		if _, protected := frozen[current]; protected {
			return true
		}
	}
	return false
}

func restoreGitComposeFile(ctx context.Context, root *os.Root, content string, entry domain.ManifestEntry, entries map[string]domain.ManifestEntry) error {
	if err := ensureGitComposeParent(root, path.Dir(entry.Path), entries); err != nil {
		return err
	}
	// An upstream file or directory at the frozen path is irrelevant to the
	// release. Remove that exact path inside the isolated export.
	if err := root.RemoveAll(entry.Path); err != nil {
		return err
	}
	file, err := root.OpenFile(entry.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := filesystem.CopyVerifiedFile(ctx, content, entry, file); err != nil {
		return err
	}
	if err := preserveGitComposeMetadata(file, entry); err != nil {
		return err
	}
	return file.Close()
}

func ensureGitComposeParent(root *os.Root, parent string, entries map[string]domain.ManifestEntry) error {
	if parent == "." {
		return nil
	}
	info, err := root.Lstat(parent)
	if err == nil {
		if info.IsDir() {
			return nil
		}
		return fmt.Errorf("Git path %q conflicts with a frozen Compose directory", parent)
	}
	if !os.IsNotExist(err) {
		return err
	}
	if err := ensureGitComposeParent(root, path.Dir(parent), entries); err != nil {
		return err
	}
	if err := root.Mkdir(parent, 0700); err != nil {
		return err
	}
	entry, exists := entries[parent]
	if !exists {
		return nil
	}
	if entry.Type != domain.EntryDirectory {
		return fmt.Errorf("invalid baseline directory %q for frozen Compose input", parent)
	}
	directory, err := root.Open(parent)
	if err != nil {
		return err
	}
	defer directory.Close()
	return preserveGitComposeMetadata(directory, entry)
}

func preserveGitComposeMetadata(file *os.File, entry domain.ManifestEntry) error {
	if err := file.Chown(int(entry.UID), int(entry.GID)); err != nil {
		return err
	}
	return file.Chmod(os.FileMode(entry.Mode))
}
