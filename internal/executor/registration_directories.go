package executor

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

const (
	registrationDirectoryMaxEntries = 4096
	registrationDirectoryMaxResults = 256
	registrationDirectoryMaxPath    = 4096
	registrationDirectoryMaxDepth   = 256
	registrationDirectoryMaxName    = 255
	registrationDirectoryMaxOutput  = 64 * 1024
)

// BrowseRegistrationDirectories lists directory names only. It neither reads
// service contents nor queries Docker, and does not change the configured roots.
func (m *Manager) BrowseRegistrationDirectories(ctx context.Context, input transport.RegistrationBrowseRequest) (transport.RegistrationDirectoryListing, error) {
	result := transport.RegistrationDirectoryListing{
		Directories:  []transport.RegistrationDirectoryEntry{},
		ComposeFiles: []string{},
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if input.Directory == "" {
		seen := map[string]bool{}
		outputBytes := 0
		for _, root := range m.Config.DiscoveryRoots {
			if !registrationDirectoryPath(root) || root == "/" || seen[root] {
				continue
			}
			seen[root] = true
			name := filepath.Base(root)
			if len(result.Directories) >= registrationDirectoryMaxResults || outputBytes+len(root)+len(name) > registrationDirectoryMaxOutput {
				result.Truncated = true
				break
			}
			result.Directories = append(result.Directories, transport.RegistrationDirectoryEntry{Name: name, Path: root})
			outputBytes += len(root) + len(name)
		}
		sortRegistrationDirectories(result.Directories)
		return result, nil
	}
	if !registrationDirectoryPath(input.Directory) {
		return result, registrationInvalid("Choose a canonical absolute service directory without control characters")
	}
	approved := ""
	for _, root := range m.Config.DiscoveryRoots {
		if !registrationDirectoryPath(root) || root == "/" {
			continue
		}
		relative, err := filepath.Rel(root, input.Directory)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && len(root) > len(approved) {
			approved = root
		}
	}
	if approved == "" {
		return result, registrationInvalid("Choose a directory inside an approved service root")
	}
	selected, before, err := openRegistrationDirectory(ctx, input.Directory)
	if err != nil {
		return result, registrationDirectoryError(ctx)
	}
	defer selected.Close()
	listing, err := selected.Open(".")
	if err != nil {
		return result, registrationDirectoryError(ctx)
	}
	defer listing.Close()
	entries, err := listing.ReadDir(registrationDirectoryMaxEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return result, registrationDirectoryError(ctx)
	}
	if len(entries) > registrationDirectoryMaxEntries {
		entries = entries[:registrationDirectoryMaxEntries]
		result.Truncated = true
	}
	outputBytes := 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return transport.RegistrationDirectoryListing{}, err
		}
		name := entry.Name()
		if !registrationDirectoryName(name) {
			continue
		}
		path := filepath.Join(input.Directory, name)
		if len(path) > registrationDirectoryMaxPath {
			continue
		}
		info, err := selected.Lstat(name)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if len(result.Directories) >= registrationDirectoryMaxResults || outputBytes+len(path)+len(name) > registrationDirectoryMaxOutput {
			result.Truncated = true
			continue
		}
		result.Directories = append(result.Directories, transport.RegistrationDirectoryEntry{Name: name, Path: path})
		outputBytes += len(path) + len(name)
	}
	for _, name := range []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"} {
		info, err := selected.Lstat(name)
		if err == nil && info.Mode().IsRegular() {
			result.ComposeFiles = append(result.ComposeFiles, name)
		}
	}
	// If the selected absolute path was replaced during listing, do not return
	// names from a directory that no longer has the approved path identity.
	afterRoot, after, err := openRegistrationDirectory(ctx, input.Directory)
	if err != nil {
		return transport.RegistrationDirectoryListing{}, registrationDirectoryError(ctx)
	}
	afterRoot.Close()
	if !os.SameFile(before, after) {
		return transport.RegistrationDirectoryListing{}, registrationInvalid("Service directory changed while browsing; reopen the folder")
	}
	result.Directory = input.Directory
	if input.Directory != approved {
		result.Parent = filepath.Dir(input.Directory)
	}
	sortRegistrationDirectories(result.Directories)
	return result, nil
}

func sortRegistrationDirectories(entries []transport.RegistrationDirectoryEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
}

func registrationDirectoryError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return registrationInvalid("Service directory is unavailable; check its executor mount and avoid symbolic links")
}

func registrationDirectoryPath(name string) bool {
	if !utf8.ValidString(name) || len(name) > registrationDirectoryMaxPath || !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return false
	}
	for _, character := range name {
		if unicode.IsControl(character) {
			return false
		}
	}
	parts := strings.Split(strings.TrimPrefix(name, string(filepath.Separator)), string(filepath.Separator))
	if len(parts) > registrationDirectoryMaxDepth {
		return false
	}
	for _, part := range parts {
		if !registrationDirectoryName(part) {
			return false
		}
	}
	return true
}

func registrationDirectoryName(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > registrationDirectoryMaxName || !utf8.ValidString(name) || strings.TrimSpace(name) != name || strings.ContainsAny(name, `/\`) {
		return false
	}
	for _, character := range name {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

// openRegistrationDirectory pins each component before moving to the next.
// os.Root confines an attempted symlink traversal to its current parent, while
// before/open/after inode checks reject aliases before any names are read.
func openRegistrationDirectory(ctx context.Context, name string) (*os.Root, os.FileInfo, error) {
	current, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, nil, err
	}
	var opened os.FileInfo
	for _, part := range strings.Split(strings.TrimPrefix(name, string(filepath.Separator)), string(filepath.Separator)) {
		if err := ctx.Err(); err != nil {
			current.Close()
			return nil, nil, err
		}
		before, err := current.Lstat(part)
		if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			current.Close()
			return nil, nil, errors.New("unavailable real directory")
		}
		child, err := current.OpenRoot(part)
		if err != nil {
			current.Close()
			return nil, nil, err
		}
		file, err := child.Open(".")
		if err == nil {
			opened, err = file.Stat()
			file.Close()
		}
		if err == nil && !os.SameFile(before, opened) {
			err = errors.New("directory changed during open")
		}
		if err == nil {
			after, statErr := current.Lstat(part)
			if statErr != nil || !after.IsDir() || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, after) {
				err = errors.New("directory changed during open")
			}
		}
		current.Close()
		if err != nil {
			child.Close()
			return nil, nil, err
		}
		current = child
	}
	return current, opened, nil
}
