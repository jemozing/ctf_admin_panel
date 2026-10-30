package filesystem

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

func TestNestedMountBoundary(t *testing.T) {
	root := os.Getenv("CTFM_TEST_NESTED_MOUNT_ROOT")
	managed := "code"
	if root == "" {
		root = "/dev"
		managed = "shm"
		if _, err := os.Stat("/dev/shm"); err != nil {
			t.Skip("no nested mount available")
		}
		base, err := openDirectory(root)
		if err != nil {
			t.Fatal(err)
		}
		file, err := base.root.Open(managed)
		if err != nil {
			base.close()
			t.Fatal(err)
		}
		mount, err := mountIdentity(file)
		file.Close()
		if err != nil {
			base.close()
			t.Fatal(err)
		}
		if mount == base.mount {
			base.close()
			t.Skip("/dev/shm is not a separate mount")
		}
		base.close()
	} else if os.Getenv("CTFM_TEST_REQUIRE_SAME_DEVICE") == "1" {
		base, err := os.Stat(root)
		if err != nil {
			t.Fatal(err)
		}
		nested, err := os.Stat(filepath.Join(root, managed))
		if err != nil {
			t.Fatal(err)
		}
		if base.Sys().(*syscall.Stat_t).Dev != nested.Sys().(*syscall.Stat_t).Dev {
			t.Fatal("test requires a same-device bind mount")
		}
	}
	_, err := Capture(context.Background(), root, filepath.Join(t.TempDir(), "content"), []domain.ManagedPath{{Path: managed, Kind: domain.ManagedCode}}, nil)
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("nested mount was traversed: %v", err)
	}
}

func TestMountBoundaryDoesNotAssumeUniformDeviceIDs(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "code"), []byte("version=1"), 0600); err != nil {
		t.Fatal(err)
	}
	d, err := openDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	// OverlayFS can give the parent directory a different device ID from a
	// regular child. Exercise that condition without requiring a privileged
	// overlay mount in the test runner.
	d.device++
	file, _, err := d.open("code")
	if err != nil {
		t.Fatalf("same mount with nonuniform device IDs rejected: %v", err)
	}
	file.Close()
	// The mount ID remains mandatory even when device IDs cannot identify the
	// boundary. A same-device bind mount must still be rejected.
	d.mount++
	if file, _, err = d.open("code"); !errors.Is(err, ErrUnsafePath) {
		if file != nil {
			file.Close()
		}
		t.Fatalf("different mount identity accepted: %v", err)
	}
}
