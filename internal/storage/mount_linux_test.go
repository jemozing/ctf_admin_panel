package storage

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMeasureRejectsNestedMount(t *testing.T) {
	// /dev/shm is normally a separate tmpfs. Invoke the descriptor walker with
	// /dev's identity so this check cannot pass merely by finding a device node.
	parent, err := os.Open("/dev")
	if err != nil {
		t.Skip("no /dev mount")
	}
	defer parent.Close()
	base, err := parent.Stat()
	if err != nil {
		t.Fatal(err)
	}
	baseMount, err := mountIdentity(parent)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot("/dev/shm")
	if err != nil {
		t.Skip("no /dev/shm mount")
	}
	defer root.Close()
	file, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	nestedMount, err := mountIdentity(file)
	if err != nil {
		t.Fatal(err)
	}
	if nestedMount == baseMount {
		t.Skip("/dev/shm is not a separate mount")
	}
	_, err = measure(context.Background(), root, before, treeIdentity{device: uint64(base.Sys().(*syscall.Stat_t).Dev), mount: baseMount})
	if !errors.Is(err, ErrUnsafeTree) {
		t.Fatalf("nested mount accepted: %v", err)
	}
}

func TestOverlayDeviceIdentityUsesMountID(t *testing.T) {
	if !sameFilesystem(20, 21, 42, 42) {
		t.Fatal("OverlayFS entries on the same mount were rejected")
	}
	if sameFilesystem(20, 20, 42, 43) {
		t.Fatal("same-device nested bind mount was accepted")
	}
}

func TestMeasureRejectsRegularFileMountBoundary(t *testing.T) {
	// Docker normally binds /etc/hosts as a regular file on its own mount.
	// Exercise the exact metadata-only branch, without walking unrelated /etc.
	directory, name := "/etc", "hosts"
	if fixture := os.Getenv("CTFM_TEST_REGULAR_FILE_MOUNT_ROOT"); fixture != "" {
		directory, name = fixture, "bound"
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Skip("no /etc directory")
	}
	defer root.Close()
	parent, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	parentInfo, err := parent.Stat()
	if err != nil {
		t.Fatal(err)
	}
	parentMount, err := mountIdentity(parent)
	if err != nil {
		t.Fatal(err)
	}
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() {
		t.Skip("no regular /etc/hosts")
	}
	// Supplying the parent's mount identity must reject a regular-file bind,
	// even when its filesystem device happens to match the parent device.
	identity := treeIdentity{device: uint64(parentInfo.Sys().(*syscall.Stat_t).Dev), mount: parentMount}
	metadata, err := root.OpenFile(name, unix.O_PATH|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	entryMount, mountErr := mountIdentity(metadata)
	metadata.Close()
	if mountErr != nil {
		t.Fatal(mountErr)
	}
	if entryMount == parentMount {
		if directory != "/etc" {
			t.Fatal("explicit regular-file fixture has no separate mount")
		}
		t.Skip("/etc/hosts is not a separate regular-file mount")
	}
	if directory != "/etc" && before.Sys().(*syscall.Stat_t).Dev != parentInfo.Sys().(*syscall.Stat_t).Dev {
		t.Fatal("explicit regular-file fixture does not exercise a same-device mount")
	}
	if _, err := inspectRegularMetadata(root, name, before, &identity); !errors.Is(err, ErrUnsafeTree) {
		t.Fatalf("regular-file nested mount accepted: %v", err)
	}
}
