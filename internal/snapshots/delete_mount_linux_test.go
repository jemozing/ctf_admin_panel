package snapshots

import (
	"context"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestRemovalRejectsNestedMountBeforeTraversal(t *testing.T) {
	parent, err := os.Open("/dev")
	if err != nil {
		t.Skip("no /dev mount")
	}
	defer parent.Close()
	base, err := parent.Stat()
	if err != nil {
		t.Fatal(err)
	}
	baseMount, err := deletionMount(parent)
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
	nestedMount, err := deletionMount(file)
	if err != nil {
		t.Fatal(err)
	}
	if nestedMount == baseMount {
		t.Skip("/dev/shm is not a separate mount")
	}
	// The boundary must fail before entry traversal and before the delete pass.
	err = walkRemoval(context.Background(), root, before, deletionIdentity{device: uint64(base.Sys().(*syscall.Stat_t).Dev), mount: baseMount}, false)
	if err == nil || !strings.Contains(err.Error(), "boundary") {
		t.Fatalf("nested mount accepted or not checked: %v", err)
	}
}

func TestRemovalOverlayDeviceIdentityUsesMountID(t *testing.T) {
	if !sameDeletionFilesystem(20, 21, 42, 42) {
		t.Fatal("OverlayFS entries on the same mount were rejected")
	}
	if sameDeletionFilesystem(20, 20, 42, 43) {
		t.Fatal("same-device nested bind mount was accepted")
	}
}
