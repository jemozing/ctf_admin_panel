package storage

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestCheckQuotaBoundaries(t *testing.T) {
	space := Space{AvailableBytes: 500, AvailableInodes: 20, InodesKnown: true}
	tests := []struct {
		name                                          string
		used, additional, max, reserve, inodes, files uint64
		space                                         Space
		kind                                          string
	}{
		{name: "exact quota and reserve", used: 700, additional: 100, max: 800, reserve: 400, inodes: 15, files: 5, space: space},
		{name: "quota exceeded", used: 701, additional: 100, max: 800, space: space, kind: "quota"},
		{name: "already over quota", used: 900, max: 800, space: space, kind: "quota"},
		{name: "capacity reserve", additional: 101, reserve: 400, space: space, kind: "capacity"},
		{name: "inode reserve", inodes: 16, files: 5, space: space, kind: "inodes"},
		{name: "unknown inodes", inodes: math.MaxUint64, files: 1, space: Space{AvailableBytes: 500}},
		{name: "quota disabled", used: 100000, additional: 500, max: 0, space: space},
		{name: "usage overflow", used: math.MaxUint64, additional: 1, space: space, kind: "overflow"},
		{name: "reserve overflow", additional: 1, reserve: math.MaxUint64, space: space, kind: "overflow"},
		{name: "inode overflow", files: 1, inodes: math.MaxUint64, space: space, kind: "overflow"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := CheckQuota(test.used, test.additional, test.max, test.space, test.reserve, test.inodes, test.files)
			if test.kind == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var limit *QuotaError
			if !errors.As(err, &limit) || limit.Kind != test.kind {
				t.Fatalf("got %v, want %s QuotaError", err, test.kind)
			}
		})
	}
}

func TestMeasureLogicalBytesAndEntries(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "code"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "code/small"), []byte("hello"), 0400); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(filepath.Join(root, "sparse"))
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Truncate(1 << 20); err != nil {
		t.Fatal(err)
	}
	file.Close()
	usage, err := Measure(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if usage.Bytes != 1<<20+5 || usage.Files != 4 {
		t.Fatalf("incorrect usage: %+v", usage)
	}
	space, err := Capacity(root)
	if err != nil {
		t.Fatal(err)
	}
	if space.AvailableBytes == 0 {
		t.Fatal("capacity was not measured")
	}
}

func TestMeasureRejectsLinksAndCancellation(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "root-symlink"} {
		t.Run(kind, func(t *testing.T) {
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte("do not read"), 0600); err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			switch kind {
			case "symlink":
				if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(outside, filepath.Join(root, "link")); err != nil {
					t.Fatal(err)
				}
			case "root-symlink":
				link := filepath.Join(t.TempDir(), "root-link")
				if err := os.Symlink(root, link); err != nil {
					t.Fatal(err)
				}
				root = link
			}
			if _, err := Measure(context.Background(), root); !errors.Is(err, ErrUnsafeTree) {
				t.Fatalf("unsafe tree accepted: %v", err)
			}
			content, err := os.ReadFile(outside)
			if err != nil || string(content) != "do not read" {
				t.Fatal("outside file modified")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Measure(ctx, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, path := range []string{".", "/", "/tmp/../tmp"} {
		if _, err := Measure(context.Background(), path); err == nil {
			t.Fatalf("unsafe root %q accepted", path)
		}
	}
}

func TestRegularMetadataRejectsSymlinkReplacement(t *testing.T) {
	directory := t.TempDir()
	filename := filepath.Join(directory, "entry")
	if err := os.WriteFile(filename, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	before, err := root.Lstat("entry")
	if err != nil {
		t.Fatal(err)
	}
	parent, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	mount, err := mountIdentity(parent)
	if err != nil {
		t.Fatal(err)
	}
	parentInfo, err := parent.Stat()
	if err != nil {
		t.Fatal(err)
	}
	identity := treeIdentity{device: uint64(parentInfo.Sys().(*syscall.Stat_t).Dev), mount: mount}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filename); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filename); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectRegularMetadata(root, "entry", before, &identity); err == nil {
		t.Fatal("regular entry replaced with an outside symlink was accepted")
	}
	content, err := os.ReadFile(outside)
	if err != nil || string(content) != "outside" {
		t.Fatal("metadata measurement changed the outside file", err)
	}
}
