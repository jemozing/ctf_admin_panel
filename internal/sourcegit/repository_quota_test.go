package sourcegit

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestRepositoryQuotaAllowsLockRemovedAfterDirectoryListing(t *testing.T) {
	repo := t.TempDir()
	lock := filepath.Join(repo, "maintenance.lock")
	data := []byte("temporary Git maintenance lock\n")
	if err := os.WriteFile(lock, data, 0600); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(repo)
	if err != nil || len(entries) != 1 {
		t.Fatalf("read directory: %v, %d entries", err, len(entries))
	}
	if size, err := repositoryEntrySize(entries[0]); err != nil || size != int64(len(data)) {
		t.Fatalf("existing entry: size %d, error %v", size, err)
	}
	// This is the observed Git race, reproduced without relying on scheduling:
	// ReadDir returns an entry, then Git removes it before DirEntry.Info's lstat.
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if _, err := entries[0].Info(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("fixture did not produce a vanished entry: %v", err)
	}
	if size, err := repositoryEntrySize(entries[0]); err != nil || size != 0 {
		t.Fatalf("vanished lock cancelled a valid quota scan: size %d, error %v", size, err)
	}
	if err := checkRepository(repo); err != nil {
		t.Fatalf("remaining repository was rejected: %v", err)
	}
}

type repositoryInfoErrorEntry struct {
	fs.DirEntry
	err error
}

func (e repositoryInfoErrorEntry) Info() (fs.FileInfo, error) { return nil, e.err }

func TestRepositoryQuotaKeepsUnsafeInfoErrors(t *testing.T) {
	for _, failure := range []error{fs.ErrPermission, syscall.ENOTDIR, syscall.ELOOP, syscall.EIO} {
		t.Run(failure.Error(), func(t *testing.T) {
			original := &fs.PathError{Op: "lstat", Path: "maintenance.lock", Err: failure}
			_, err := repositoryEntrySize(repositoryInfoErrorEntry{err: original})
			if err != original || !errors.Is(err, failure) {
				t.Fatalf("unsafe filesystem error was hidden: %v", err)
			}
		})
	}
}

func TestRepositoryQuotaStillRejectsMissingRootAndByteLimit(t *testing.T) {
	repo := t.TempDir()
	file, err := os.Create(filepath.Join(repo, "oversized-pack"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(MaxRepositoryBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := checkRepository(repo); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("repository byte limit changed: %v", err)
	}
	if err := os.RemoveAll(repo); err != nil {
		t.Fatal(err)
	}
	if err := checkRepository(repo); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing repository root was accepted: %v", err)
	}
}
