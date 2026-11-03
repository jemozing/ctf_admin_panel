package sourcegit

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBrowseDirectoriesListsOnlyChildTreesOfSelectedRef(t *testing.T) {
	repo, commit := fixtureRepository(t, map[string]string{
		"README.md":                 "fixture\n",
		"service/app/main.txt":      "fixture\n",
		"service/dir with spaces/x": "fixture\n",
		"service/file.txt":          "fixture\n",
		"tools/run.sh":              "fixture\n",
	})
	fixtureGit(t, repo, "branch", "service-branch", commit)
	fixtureGit(t, repo, "config", "uploadpack.allowFilter", "true")
	if err := os.Symlink("service", filepath.Join(repo, "shortcut")); err != nil {
		t.Fatal(err)
	}
	fixtureGit(t, repo, "add", "shortcut")
	fixtureGit(t, repo, "rm", "-r", "tools")
	fixtureGit(t, repo, "update-index", "--add", "--cacheinfo", "160000,"+commit+",linked-module")
	fixtureGit(t, repo, "commit", "-m", "different HEAD")

	cfg := Config{URL: "file://" + repo, Ref: "refs/heads/service-branch"}
	check := func(directory string, parent *string, expected []DirectoryEntry) {
		t.Helper()
		listing, err := browseDirectories(t.Context(), cfg, nil, directory, true)
		if err != nil {
			t.Fatal(err)
		}
		if listing.Directory != directory || !reflect.DeepEqual(listing.Parent, parent) || listing.Truncated || !reflect.DeepEqual(listing.Directories, expected) {
			t.Fatalf("unexpected directory listing: %+v", listing)
		}
	}
	root := ""
	service := "service"
	check("", nil, []DirectoryEntry{{"service", "service"}, {"tools", "tools"}})
	check("service", &root, []DirectoryEntry{{"app", "service/app"}, {"dir with spaces", "service/dir with spaces"}})
	check("service/app", &service, []DirectoryEntry{})
	cfg.Ref = "HEAD"
	check("", nil, []DirectoryEntry{{"service", "service"}})

	for path, want := range map[string]string{"../service": "git_invalid", "service/.GIT": "git_invalid", "service/file.txt": "git_directory_missing", "shortcut": "git_directory_missing", "linked-module": "git_directory_missing"} {
		_, err := browseDirectories(t.Context(), cfg, nil, path, true)
		var safe *ProbeError
		if !errors.As(err, &safe) || safe.Code != want {
			t.Fatalf("%q: got %v, want %q", path, err, want)
		}
	}

	// The original commit referenced by the gitlink still exists in this
	// fixture's object store. It must not be browsable through the gitlink.
	binary, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	r := runner{binary: binary, repo: repo, env: gitEnvironment(repo, cfg, nil)}
	head := fixtureGit(t, repo, "rev-parse", "HEAD")
	_, err = listDirectories(t.Context(), r, head, "linked-module")
	var safe *ProbeError
	if !errors.As(err, &safe) || safe.Code != "git_directory_missing" {
		t.Fatalf("browsing a gitlink with an available commit returned %v", err)
	}
}

func TestParseDirectoriesBoundsResponseAndOmitsUnusableNames(t *testing.T) {
	var data bytes.Buffer
	write := func(name string) { fmt.Fprintf(&data, "040000 tree %s\t%s\x00", strings.Repeat("a", 40), name) }
	for _, name := range []string{".GIT", ".gitmodules", " invalid", "unsafe/name", "valid"} {
		write(name)
	}
	for i := 0; i < maxDirectoryEntries; i++ {
		write(fmt.Sprintf("dir-%04d", i))
	}
	listing, err := parseDirectories(data.Bytes(), "")
	if err != nil || !listing.Truncated || len(listing.Directories) != maxDirectoryEntries || listing.Directories[0].Name != "valid" {
		t.Fatalf("unexpected directory listing: %+v, %v", listing, err)
	}
}
