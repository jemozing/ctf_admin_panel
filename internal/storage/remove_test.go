package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func privateAllocation(t *testing.T) (string, string) {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(parent, "allocation")
	if err := os.MkdirAll(filepath.Join(child, "content/code"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(child, "content/code/partial"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(child, ".metadata-partial"), []byte("{"), 0400); err != nil {
		t.Fatal(err)
	}
	return parent, child
}

func TestRemovePrivateTreeInterruptedAllocationAndResume(t *testing.T) {
	for _, resume := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "partial-trash"}[resume], func(t *testing.T) {
			parent, child := privateAllocation(t)
			if resume {
				if err := os.Rename(child, filepath.Join(parent, ".trash-allocation")); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(parent, ".trash-allocation/.metadata-partial")); err != nil {
					t.Fatal(err)
				}
			}
			for range 2 {
				if err := RemovePrivateTree(context.Background(), parent, "allocation"); err != nil {
					t.Fatal(err)
				}
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatalf("cleanup left entries: %v %v", entries, err)
			}
		})
	}
}

func TestRemovePrivateTreeRejectsUnsafeEntriesBeforeQuarantine(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "public-mode", "public-directory", "root-symlink", "trash-symlink"} {
		t.Run(kind, func(t *testing.T) {
			parent, child := privateAllocation(t)
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
				t.Fatal(err)
			}
			inspect := child
			switch kind {
			case "symlink":
				if err := os.Symlink(outside, filepath.Join(child, "z-link")); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(outside, filepath.Join(child, "z-link")); err != nil {
					t.Fatal(err)
				}
			case "public-mode":
				if err := os.Chmod(filepath.Join(child, "content/code/partial"), 0644); err != nil {
					t.Fatal(err)
				}
			case "public-directory":
				if err := os.Chmod(filepath.Join(child, "content/code"), 0755); err != nil {
					t.Fatal(err)
				}
			case "root-symlink":
				if err := os.Rename(child, child+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Dir(outside), child); err != nil {
					t.Fatal(err)
				}
				inspect = child + "-original"
			case "trash-symlink":
				inspect = filepath.Join(parent, ".trash-allocation")
				if err := os.Rename(child, inspect); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(inspect, "z-link")); err != nil {
					t.Fatal(err)
				}
			}
			if err := RemovePrivateTree(context.Background(), parent, "allocation"); !errors.Is(err, ErrUnsafeTree) {
				t.Fatalf("unsafe tree accepted: %v", err)
			}
			if _, err := os.Stat(filepath.Join(inspect, "content/code/partial")); err != nil {
				t.Fatal("preflight partially deleted allocation", err)
			}
			if data, err := os.ReadFile(outside); err != nil || string(data) != "outside" {
				t.Fatal("outside modified", err)
			}
		})
	}
}

func TestRemovePrivateTreeValidatesParentNameAndContext(t *testing.T) {
	parent, child := privateAllocation(t)
	for _, name := range []string{"../allocation", ".", "/allocation", ".trash-allocation", "allocation/child"} {
		if err := RemovePrivateTree(context.Background(), parent, name); err == nil {
			t.Fatalf("invalid child name accepted: %s", name)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := RemovePrivateTree(ctx, parent, "allocation"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0755); err != nil {
		t.Fatal(err)
	}
	if err := RemovePrivateTree(context.Background(), parent, "allocation"); !errors.Is(err, ErrUnsafeTree) {
		t.Fatal("public parent accepted", err)
	}
	if _, err := os.Stat(filepath.Join(child, "content/code/partial")); err != nil {
		t.Fatal("invalid request modified allocation", err)
	}
}

func TestRemoveStagingTreePreservesPrivateBoundaryAndAllowsExecutableModes(t *testing.T) {
	parent, child := privateAllocation(t)
	if err := os.Chmod(filepath.Join(child, "content/code"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(child, "content/code/partial"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := RemovePrivateTree(context.Background(), parent, "allocation"); !errors.Is(err, ErrUnsafeTree) {
		t.Fatal("unpublished snapshot policy widened", err)
	}
	if err := RemoveStagingTree(context.Background(), parent, "allocation"); err != nil {
		t.Fatal("ordinary build modes rejected", err)
	}
	if _, err := os.Stat(child); !os.IsNotExist(err) {
		t.Fatal("staging left behind", err)
	}
	parent, child = privateAllocation(t)
	if err := os.Chmod(child, 0755); err != nil {
		t.Fatal(err)
	}
	if err := RemoveStagingTree(context.Background(), parent, "allocation"); !errors.Is(err, ErrUnsafeTree) {
		t.Fatal("public allocation root accepted", err)
	}
	if err := os.Chmod(child, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(child, "content/code/partial"), os.ModeSetuid|0755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(child, "content/code/partial"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetuid == 0 {
		t.Skip("filesystem did not preserve the requested setuid bit")
	}
	if err := RemoveStagingTree(context.Background(), parent, "allocation"); !errors.Is(err, ErrUnsafeTree) {
		t.Fatal("setuid build output accepted", err)
	}
}
