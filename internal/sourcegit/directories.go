package sourcegit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path"
	"strings"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

const (
	maxDirectoryEntries       = 256
	maxDirectoryResponseBytes = 128 << 10
)

type DirectoryEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type DirectoryListing struct {
	Directory   string           `json:"directory"`
	Parent      *string          `json:"parent,omitempty"`
	Directories []DirectoryEntry `json:"directories"`
	Truncated   bool             `json:"truncated"`
}

// ValidateBrowseDirectory accepts the empty string for the repository root and
// canonical paths that can be saved as source subdirectories.
func ValidateBrowseDirectory(directory string) error {
	if directory == "" {
		return nil
	}
	if err := domain.ValidateRelativePath(directory); err != nil {
		return probeFailure("git_invalid", "Git directory must be a canonical relative path below the repository root")
	}
	for _, part := range strings.Split(directory, "/") {
		if strings.EqualFold(part, ".git") || strings.EqualFold(part, ".gitmodules") {
			return probeFailure("git_invalid", "Git metadata cannot be browsed as a source directory")
		}
	}
	return nil
}

// BrowseDirectories reads direct child trees of one path without exporting any
// repository files. A shallow, blobless fetch is requested when supported.
func BrowseDirectories(ctx context.Context, c Config, token []byte, directory string) (DirectoryListing, error) {
	c.Subdirectory = ""
	if err := c.Validate(); err != nil {
		return DirectoryListing{}, probeFailure("git_invalid", "Git connection settings are invalid; verify HTTPS URL, ref and credentials")
	}
	return browseDirectories(ctx, c, token, directory, false)
}

func browseDirectories(parent context.Context, c Config, token []byte, directory string, local bool) (DirectoryListing, error) {
	if err := ValidateBrowseDirectory(directory); err != nil {
		return DirectoryListing{}, err
	}
	if err := validateGitToken(token); err != nil {
		return DirectoryListing{}, probeFailure("git_invalid", "Git credentials have an invalid format")
	}
	ctx, cancel := context.WithTimeout(parent, ProbeTimeout)
	defer cancel()
	var listing DirectoryListing
	root, err := withFetchedRepository(ctx, c, token, local, true, func(ctx context.Context, r runner, commit string) error {
		var readErr error
		listing, readErr = listDirectories(ctx, r, commit, directory)
		return readErr
	})
	if err != nil {
		if ctx.Err() != nil {
			return DirectoryListing{}, probeContextError(ctx)
		}
		var safe *ProbeError
		if errors.As(err, &safe) {
			return DirectoryListing{}, safe
		}
		return DirectoryListing{}, probeFailure("git_access_failed", "Git directories could not be read; verify HTTPS URL, ref, credentials and repository limits")
	}
	_ = os.RemoveAll(root)
	return listing, nil
}

func listDirectories(ctx context.Context, r runner, commit, directory string) (DirectoryListing, error) {
	object := commit
	if directory != "" {
		object += ":" + directory
		objectType, err := r.objectCommand(ctx, "cat-file", "-t", "--", object).Output()
		if ctx.Err() != nil {
			return DirectoryListing{}, ctx.Err()
		}
		// A gitlink can resolve to a commit already present in this repository.
		// ls-tree accepts commits as tree-ish, so verify that this path is a tree.
		if err != nil || string(objectType) != "tree\n" {
			return DirectoryListing{}, probeFailure("git_directory_missing", "Git directory was not found in the selected ref")
		}
	}
	output := &limitedBuffer{limit: 4 << 20}
	cmd := r.objectCommand(ctx, "ls-tree", "-dz", "--full-tree", object)
	cmd.Stdout = output
	if err := cmd.Run(); err != nil {
		if output.overflow {
			return DirectoryListing{}, probeFailure("git_limits", "Git directory exceeds listing limits")
		}
		return DirectoryListing{}, err
	}
	return parseDirectories(output.Bytes(), directory)
}

func parseDirectories(data []byte, directory string) (DirectoryListing, error) {
	listing := DirectoryListing{Directory: directory, Directories: []DirectoryEntry{}}
	prefix := ""
	if directory != "" {
		parent := CleanSubdirectory(path.Dir(directory))
		listing.Parent = &parent
		prefix = directory + "/"
	}
	responseBytes := 0
	for len(data) > 0 {
		record, remaining, terminated := bytes.Cut(data, []byte{0})
		data = remaining
		header, name, hasPath := strings.Cut(string(record), "\t")
		object, tree := strings.CutPrefix(header, "040000 tree ")
		if !terminated || !hasPath {
			return DirectoryListing{}, probeFailure("git_invalid", "Git returned invalid directory listing data")
		}
		if linkedCommit, gitlink := strings.CutPrefix(header, "160000 commit "); gitlink && objectPattern.MatchString(linkedCommit) {
			continue
		}
		if !tree || !objectPattern.MatchString(object) {
			return DirectoryListing{}, probeFailure("git_invalid", "Git returned invalid directory listing data")
		}
		fullPath := prefix + name
		if strings.Contains(name, "/") || domain.ValidateRelativePath(name) != nil || ValidateBrowseDirectory(fullPath) != nil {
			continue
		}
		entry := DirectoryEntry{Name: name, Path: fullPath}
		encoded, _ := json.Marshal(entry) // Both fields are strings.
		responseBytes += len(encoded) + 1
		if len(listing.Directories) == maxDirectoryEntries || responseBytes > maxDirectoryResponseBytes {
			listing.Truncated = true
			break
		}
		listing.Directories = append(listing.Directories, entry)
	}
	return listing, nil
}
