//go:build linux || darwin

package maintenance

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLifetimeLocksExcludeMaintenance(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	first, err := Acquire(root, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Acquire(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(root, true); !errors.Is(err, ErrActive) {
		t.Fatalf("exclusive lock while applications open: %v", err)
	}
	first.Close()
	if _, err := Acquire(root, true); !errors.Is(err, ErrActive) {
		t.Fatalf("second application must still hold state: %v", err)
	}
	second.Close()
	exclusive, err := Acquire(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(root, false); !errors.Is(err, ErrActive) {
		t.Fatalf("application opened during maintenance: %v", err)
	}
	if err := exclusive.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLockRefusesSymlinkAndHardlink(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			os.Chmod(root, 0700)
			target := filepath.Join(t.TempDir(), "victim")
			if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
				t.Fatal(err)
			}
			lock := filepath.Join(root, ".maintenance.lock")
			var err error
			if kind == "symlink" {
				err = os.Symlink(target, lock)
			} else {
				err = os.Link(target, lock)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Acquire(root, true); err == nil {
				t.Fatal("unsafe lock accepted")
			}
			data, err := os.ReadFile(target)
			if err != nil || string(data) != "unchanged" {
				t.Fatal("maintenance changed unrelated file")
			}
		})
	}
}
