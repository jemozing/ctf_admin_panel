package snapshots

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func deletionStore(t *testing.T) (*Store, string) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "snapshots")
	store, err := NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if _, err = store.Create(context.Background(), snapshotRequest("to-remove"), sourceTree(t), managed, []string{"code/.env"}); err != nil {
		t.Fatal(err)
	}
	return store, directory
}

func TestRemoveVerifiedArtifactIsIdempotent(t *testing.T) {
	store, directory := deletionStore(t)
	for range 2 {
		if err := store.Remove(context.Background(), "to-remove"); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"to-remove", ".trash-to-remove"} {
		if _, err := os.Lstat(filepath.Join(directory, name)); !os.IsNotExist(err) {
			t.Fatalf("deletion left %s: %v", name, err)
		}
	}
	if _, err := store.Load(context.Background(), "to-remove"); !os.IsNotExist(err) {
		t.Fatalf("removed artifact still loads: %v", err)
	}
}

func TestRemoveResumesPartiallyDeletedTrash(t *testing.T) {
	store, directory := deletionStore(t)
	// Simulate a process crash after quarantine and partial unlinking. Metadata
	// need not survive; the durable database tombstone remains the authorization.
	trash := filepath.Join(directory, ".trash-to-remove")
	if err := os.Rename(filepath.Join(directory, "to-remove"), trash); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(trash, "snapshot.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(trash, "content/code/run.sh")); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(context.Background(), "to-remove"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(trash); !os.IsNotExist(err) {
		t.Fatal("partial trash was not removed", err)
	}
}

func TestRemoveUnsafeLiveArtifactKeepsAllFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "wrong-mode", "corrupt-content", "missing-metadata", "root-symlink"} {
		t.Run(kind, func(t *testing.T) {
			store, directory := deletionStore(t)
			artifact := filepath.Join(directory, "to-remove")
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte("outside remains"), 0400); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				if err := os.Symlink(outside, filepath.Join(artifact, "link")); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(outside, filepath.Join(artifact, "link")); err != nil {
					t.Fatal(err)
				}
			case "wrong-mode":
				if err := os.Chmod(filepath.Join(artifact, "content/code/run.sh"), 0600); err != nil {
					t.Fatal(err)
				}
			case "corrupt-content":
				path := filepath.Join(artifact, "content/code/run.sh")
				if err := os.Chmod(path, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("corrupted"), 0400); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0400); err != nil {
					t.Fatal(err)
				}
			case "missing-metadata":
				if err := os.Remove(filepath.Join(artifact, "snapshot.json")); err != nil {
					t.Fatal(err)
				}
			case "root-symlink":
				if err := os.Rename(artifact, artifact+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Dir(outside), artifact); err != nil {
					t.Fatal(err)
				}
			}
			if err := store.Remove(context.Background(), "to-remove"); err == nil {
				t.Fatal("unsafe artifact deleted")
			}
			if _, err := os.Lstat(artifact); err != nil {
				t.Fatal("unsafe artifact was moved/deleted", err)
			}
			if _, err := os.Lstat(filepath.Join(directory, ".trash-to-remove")); !os.IsNotExist(err) {
				t.Fatal("unsafe artifact was quarantined", err)
			}
			if data, err := os.ReadFile(outside); err != nil || string(data) != "outside remains" {
				t.Fatal("outside data modified", err)
			}
			if kind != "root-symlink" {
				if _, err := os.Stat(filepath.Join(artifact, "content/code/run.sh")); err != nil {
					t.Fatal("artifact was partially deleted", err)
				}
			}
		})
	}
}

func TestRemoveUnsafeTrashPreservesItBeforeAnyUnlink(t *testing.T) {
	store, directory := deletionStore(t)
	trash := filepath.Join(directory, ".trash-to-remove")
	if err := os.Rename(filepath.Join(directory, "to-remove"), trash); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("safe"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(trash, "z-link")); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(context.Background(), "to-remove"); err == nil {
		t.Fatal("unsafe trash accepted")
	}
	for _, name := range []string{"snapshot.json", "content/code/run.sh", "z-link"} {
		if _, err := os.Lstat(filepath.Join(trash, name)); err != nil {
			t.Fatalf("preflight partially deleted %s: %v", name, err)
		}
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "safe" {
		t.Fatal("followed trash symlink", err)
	}
}

func TestRemoveRefusesIDCollisionAndInvalidID(t *testing.T) {
	store, directory := deletionStore(t)
	if err := os.Mkdir(filepath.Join(directory, ".trash-to-remove"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(context.Background(), "to-remove"); err == nil {
		t.Fatal("ambiguous live/trash entries accepted")
	}
	if err := store.Remove(context.Background(), "../escape"); err == nil {
		t.Fatal("invalid ID accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.Remove(ctx, "to-remove"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background(), "to-remove"); err != nil {
		t.Fatal("cancelled removal modified artifact", err)
	}
}
