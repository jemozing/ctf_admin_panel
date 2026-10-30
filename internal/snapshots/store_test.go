package snapshots

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

func sourceTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "code"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "code/run.sh"), []byte("#!/bin/sh\necho fixture\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "code/.env"), []byte("SECRET_TEST"), 0600); err != nil {
		t.Fatal(err)
	}
	return root
}

func snapshotRequest(id domain.ID) domain.Snapshot {
	return domain.Snapshot{ID: id, ServiceID: "fixture", CreatedAt: time.Now().UTC(), Author: "admin", Purpose: domain.SnapshotBaseline, FileMapRevision: 1, Consistency: domain.ConsistencyCoordinated}
}

var managed = []domain.ManagedPath{{Path: "code", Kind: domain.ManagedCode}}

func TestCreateLoadImmutableAndDuplicateID(t *testing.T) {
	root := filepath.Join(t.TempDir(), "snapshots")
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	source := sourceTree(t)
	created, err := store.Create(context.Background(), snapshotRequest("snapshot-1"), source, managed, []string{"code/.env"})
	if err != nil {
		t.Fatal(err)
	}
	if created.State != domain.SnapshotComplete || created.ManifestDigest == "" {
		t.Fatal("snapshot incomplete")
	}
	if err = os.WriteFile(filepath.Join(source, "code/run.sh"), []byte("changed later"), 0755); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ManifestDigest != created.ManifestDigest {
		t.Fatal("loaded different manifest")
	}
	content, _ := store.ContentPath(created.ID)
	if _, err = os.Stat(filepath.Join(content, "code/.env")); !os.IsNotExist(err) {
		t.Fatal("secret copied")
	}
	data, err := os.ReadFile(filepath.Join(content, "code/run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == "changed later" {
		t.Fatal("snapshot changed with source")
	}
	if _, err = store.Create(context.Background(), snapshotRequest(created.ID), source, managed, nil); !os.IsExist(err) {
		t.Fatalf("duplicate ID overwritten: %v", err)
	}
	if _, err = store.Load(context.Background(), created.ID); err != nil {
		t.Fatal("duplicate attempt corrupted original", err)
	}
	info, err := os.Stat(filepath.Join(root, string(created.ID), "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0400 {
		t.Fatalf("metadata not protected: %o", info.Mode().Perm())
	}
}

func TestLoadRejectsMissingMetadataAndTamperedContent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "snapshots")
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = os.Mkdir(filepath.Join(root, "incomplete"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Load(context.Background(), "incomplete"); err == nil {
		t.Fatal("incomplete snapshot accepted")
	}
	created, err := store.Create(context.Background(), snapshotRequest("valid"), sourceTree(t), managed, []string{"code/.env"})
	if err != nil {
		t.Fatal(err)
	}
	content, _ := store.ContentPath(created.ID)
	name := filepath.Join(content, "code/run.sh")
	if err = os.Chmod(name, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(name, []byte("CORRUPT"), 0400); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(name, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Load(context.Background(), created.ID); err == nil {
		t.Fatal("tampered snapshot accepted")
	}
}

func TestStoreRejectsUnsafeRootAndSourceOverlap(t *testing.T) {
	root := filepath.Join(t.TempDir(), "unsafe")
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(root); err == nil {
		t.Fatal("unprotected snapshot root accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(link); err == nil {
		t.Fatal("symlink store root accepted")
	}
	source := sourceTree(t)
	store, err := NewStore(filepath.Join(source, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err = store.Create(context.Background(), snapshotRequest("overlap"), source, managed, nil); err == nil {
		t.Fatal("store inside source accepted")
	}
	if _, err = os.Stat(filepath.Join(source, "snapshots/overlap")); !os.IsNotExist(err) {
		t.Fatal("overlap created an artifact")
	}
	if _, err = store.ContentPath("../escape"); err == nil {
		t.Fatal("invalid snapshot ID accepted")
	}
}
