package snapshots

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveUnpublishedFailedCaptureAndTemporaryMetadata(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "snapshots")
	store, err := NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	source := sourceTree(t)
	outside := filepath.Join(t.TempDir(), "outside")
	if err = os.WriteFile(outside, []byte("outside remains"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, filepath.Join(source, "code/z-link")); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Create(context.Background(), snapshotRequest("failed-capture"), source, managed, []string{"code/.env"}); err == nil {
		t.Fatal("unsafe source captured")
	}
	artifact := filepath.Join(directory, "failed-capture")
	if err = os.WriteFile(filepath.Join(artifact, ".metadata-interrupted"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = store.Remove(context.Background(), "failed-capture"); err == nil {
		t.Fatal("complete-only cleanup accepted incomplete capture")
	}
	for range 2 {
		if err = store.RemoveUnpublished(context.Background(), "failed-capture"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = os.Stat(artifact); !os.IsNotExist(err) {
		t.Fatal("unpublished allocation not removed", err)
	}
	if content, err := os.ReadFile(outside); err != nil || string(content) != "outside remains" {
		t.Fatal("source symlink target changed", err)
	}
}
