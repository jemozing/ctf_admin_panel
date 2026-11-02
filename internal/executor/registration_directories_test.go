package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func registrationBrowserFixture(t *testing.T) (*Manager, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &Manager{Config: config.Config{DiscoveryRoots: []string{root}}}, root
}

func browserMkdir(t *testing.T, name string) {
	t.Helper()
	if err := os.MkdirAll(name, 0700); err != nil {
		t.Fatal(err)
	}
}

func browserWrite(t *testing.T, name string) {
	t.Helper()
	if err := os.WriteFile(name, []byte("private-content-that-must-not-be-returned"), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestRegistrationDirectoryBrowserRootsAndNavigation(t *testing.T) {
	m, root := registrationBrowserFixture(t)
	browserMkdir(t, filepath.Join(root, "game", "app"))
	browserMkdir(t, filepath.Join(root, "alpha"))
	browserWrite(t, filepath.Join(root, "readme.md"))
	browserWrite(t, filepath.Join(root, "game", "compose.yaml"))
	browserWrite(t, filepath.Join(root, "game", "docker-compose.yml"))
	browserWrite(t, filepath.Join(root, "game", "secret.env"))
	if err := os.Symlink(filepath.Join(root, "game"), filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "game", "compose.yaml"), filepath.Join(root, "compose.yml")); err != nil {
		t.Fatal(err)
	}
	// Hints inspect regular-file metadata only; a FIFO with a Compose filename
	// must not be opened or block the browser waiting for a writer.
	if err := syscall.Mkfifo(filepath.Join(root, "docker-compose.yaml"), 0600); err != nil {
		t.Fatal(err)
	}
	missing := root + "-not-mounted"
	m.Config.DiscoveryRoots = []string{root, missing, root}
	roots, err := m.BrowseRegistrationDirectories(t.Context(), transport.RegistrationBrowseRequest{})
	if err != nil || roots.Directory != "" || roots.Parent != "" || roots.Truncated || len(roots.Directories) != 2 || roots.Directories[0].Path != root || roots.Directories[1].Path != missing {
		t.Fatalf("configured roots, including unmounted root: %#v %v", roots, err)
	}
	listing, err := m.BrowseRegistrationDirectories(t.Context(), transport.RegistrationBrowseRequest{Directory: root})
	want := []transport.RegistrationDirectoryEntry{{Name: "alpha", Path: filepath.Join(root, "alpha")}, {Name: "game", Path: filepath.Join(root, "game")}}
	if err != nil || listing.Directory != root || listing.Parent != "" || listing.Truncated || !reflect.DeepEqual(listing.Directories, want) || len(listing.ComposeFiles) != 0 {
		t.Fatalf("root listing includes aliases/files or escapes parent: %#v %v", listing, err)
	}
	game, err := m.BrowseRegistrationDirectories(t.Context(), transport.RegistrationBrowseRequest{Directory: filepath.Join(root, "game")})
	if err != nil || game.Parent != root || !reflect.DeepEqual(game.ComposeFiles, []string{"compose.yaml", "docker-compose.yml"}) || len(game.Directories) != 1 || game.Directories[0].Name != "app" {
		t.Fatalf("game directory: %#v %v", game, err)
	}
	encoded, err := json.Marshal(game)
	if err != nil || strings.Contains(string(encoded), "private-content") || strings.Contains(string(encoded), "secret.env") {
		t.Fatalf("file contents or unrelated filenames escaped: %s %v", encoded, err)
	}
	for _, value := range []transport.RegistrationDirectoryListing{roots, listing, game} {
		if value.Directories == nil || value.ComposeFiles == nil {
			t.Fatal("browser arrays must encode as arrays, not null")
		}
	}
}

func TestRegistrationDirectoryBrowserRejectsUnapprovedAndUnsafePaths(t *testing.T) {
	m, root := registrationBrowserFixture(t)
	outside := root + "-outside"
	browserMkdir(t, outside)
	t.Cleanup(func() { os.RemoveAll(outside) })
	browserMkdir(t, filepath.Join(root, "safe", "nested"))
	if err := os.Symlink(outside, filepath.Join(root, "external")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "safe"), filepath.Join(root, "internal")); err != nil {
		t.Fatal(err)
	}
	browserWrite(t, filepath.Join(root, "regular-file"))
	paths := []string{"relative", "/", root + "/", root + "/./safe", root + "/safe/../safe", root + "\n", root + "\x00", root + string([]byte{0xff}), outside, filepath.Join(root, "missing"), filepath.Join(root, "external"), filepath.Join(root, "external", "nested"), filepath.Join(root, "internal"), filepath.Join(root, "internal", "nested"), filepath.Join(root, "regular-file")}
	for _, path := range paths {
		t.Run(fmt.Sprintf("%q", path), func(t *testing.T) {
			_, err := m.BrowseRegistrationDirectories(t.Context(), transport.RegistrationBrowseRequest{Directory: path})
			var invalid *transport.RegistrationInputError
			if !errors.As(err, &invalid) || strings.Contains(err.Error(), root) || strings.Contains(err.Error(), outside) {
				t.Fatalf("unsafe path accepted or filesystem detail disclosed: %v", err)
			}
		})
	}
	// A configured discovery root cannot hide a symlink in its own ancestry.
	m.Config.DiscoveryRoots = []string{filepath.Join(root, "internal")}
	if _, err := m.BrowseRegistrationDirectories(t.Context(), transport.RegistrationBrowseRequest{Directory: filepath.Join(root, "internal", "nested")}); err == nil {
		t.Fatal("configured root alias accepted")
	}
}

func TestRegistrationDirectoryBrowserLongestRootBoundsParent(t *testing.T) {
	m, root := registrationBrowserFixture(t)
	nested := filepath.Join(root, "nested")
	browserMkdir(t, filepath.Join(nested, "game"))
	m.Config.DiscoveryRoots = []string{root, nested}
	listing, err := m.BrowseRegistrationDirectories(t.Context(), transport.RegistrationBrowseRequest{Directory: nested})
	if err != nil || listing.Parent != "" {
		t.Fatalf("nested approved root exposes its parent: %#v %v", listing, err)
	}
	listing, err = m.BrowseRegistrationDirectories(t.Context(), transport.RegistrationBrowseRequest{Directory: filepath.Join(nested, "game")})
	if err != nil || listing.Parent != nested {
		t.Fatalf("wrong nested parent boundary: %#v %v", listing, err)
	}
}

func TestRegistrationDirectoryBrowserNoRootsAndCancelled(t *testing.T) {
	m := &Manager{}
	listing, err := m.BrowseRegistrationDirectories(t.Context(), transport.RegistrationBrowseRequest{})
	if err != nil || listing.Directory != "" || len(listing.Directories) != 0 || listing.Truncated {
		t.Fatalf("empty roots: %#v %v", listing, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := m.BrowseRegistrationDirectories(ctx, transport.RegistrationBrowseRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled browse continued: %v", err)
	}
}

func TestRegistrationDirectoryBrowserBoundsEntriesAndResponse(t *testing.T) {
	m, root := registrationBrowserFixture(t)
	for i := range registrationDirectoryMaxResults + 1 {
		browserMkdir(t, filepath.Join(root, fmt.Sprintf("game-%03d", i)))
	}
	listing, err := m.BrowseRegistrationDirectories(t.Context(), transport.RegistrationBrowseRequest{Directory: root})
	if err != nil || !listing.Truncated || len(listing.Directories) != registrationDirectoryMaxResults {
		t.Fatalf("large directory is unbounded or completeness overstated: %d truncated=%t %v", len(listing.Directories), listing.Truncated, err)
	}
	files := filepath.Join(root, "many-files")
	browserMkdir(t, files)
	for i := range registrationDirectoryMaxEntries + 1 {
		if err := os.WriteFile(filepath.Join(files, fmt.Sprintf("file-%04d", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	listing, err = m.BrowseRegistrationDirectories(t.Context(), transport.RegistrationBrowseRequest{Directory: files})
	if err != nil || !listing.Truncated || len(listing.Directories) != 0 {
		t.Fatalf("scan limit not signalled: %#v %v", listing, err)
	}
	longRoot := filepath.Join(root, "long")
	for range 5 {
		longRoot = filepath.Join(longRoot, strings.Repeat("d", 100))
	}
	browserMkdir(t, longRoot)
	for i := range registrationDirectoryMaxResults {
		browserMkdir(t, filepath.Join(longRoot, fmt.Sprintf("game-%03d", i)))
	}
	listing, err = m.BrowseRegistrationDirectories(t.Context(), transport.RegistrationBrowseRequest{Directory: longRoot})
	if err != nil || !listing.Truncated || len(listing.Directories) >= registrationDirectoryMaxResults {
		t.Fatalf("output byte budget not bounded: %d %#v %v", len(listing.Directories), listing, err)
	}
}

func TestRegistrationDirectoryBrowserBoundsConfiguredRootListing(t *testing.T) {
	m := &Manager{}
	for i := range registrationDirectoryMaxResults + 1 {
		m.Config.DiscoveryRoots = append(m.Config.DiscoveryRoots, fmt.Sprintf("/srv/services-%03d", i))
	}
	listing, err := m.BrowseRegistrationDirectories(t.Context(), transport.RegistrationBrowseRequest{})
	if err != nil || !listing.Truncated || len(listing.Directories) != registrationDirectoryMaxResults {
		t.Fatalf("configured roots response is unbounded: %d truncated=%t %v", len(listing.Directories), listing.Truncated, err)
	}
}

func TestRegistrationDirectoryBrowserHidesControlNames(t *testing.T) {
	m, root := registrationBrowserFixture(t)
	for _, name := range []string{"safe space", "unicode-игра", "bad\nname", "bad\x7fname", `back\slash`, "trailing-space "} {
		browserMkdir(t, filepath.Join(root, name))
	}
	listing, err := m.BrowseRegistrationDirectories(t.Context(), transport.RegistrationBrowseRequest{Directory: root})
	if err != nil || len(listing.Directories) != 2 || listing.Directories[0].Name != "safe space" || listing.Directories[1].Name != "unicode-игра" {
		t.Fatalf("unsafe names displayed or legitimate spaces/Unicode rejected: %#v %v", listing, err)
	}
}

func TestRegistrationDirectoryBrowserNeverListsSwappedOutsideDirectory(t *testing.T) {
	m, root := registrationBrowserFixture(t)
	selected := filepath.Join(root, "selected")
	parked := filepath.Join(root, "parked")
	outside := root + "-outside"
	browserMkdir(t, filepath.Join(selected, "approved-marker"))
	browserMkdir(t, filepath.Join(outside, "outside-marker"))
	t.Cleanup(func() { os.RemoveAll(outside) })
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			if os.Rename(selected, parked) != nil {
				continue
			}
			if os.Symlink(outside, selected) == nil {
				runtime.Gosched()
				os.Remove(selected)
			}
			os.Rename(parked, selected)
		}
	}()
	defer func() { close(done); wg.Wait() }()
	for range 200 {
		listing, err := m.BrowseRegistrationDirectories(t.Context(), transport.RegistrationBrowseRequest{Directory: selected})
		if err != nil {
			continue
		}
		for _, entry := range listing.Directories {
			if entry.Name != "approved-marker" {
				t.Fatalf("external directory traversed during swap: %#v", listing)
			}
		}
	}
}
