package snapshots

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/storage"
)

// Opt in only on an explicitly provisioned tiny filesystem. The test creates no
// mounts and requires neither SYS_ADMIN nor Docker access inside its process.
func TestSnapshotRealENOSPCKeepsSourceAndCleansUnpublishedAllocation(t *testing.T) {
	limited := os.Getenv("CTFM_TEST_ENOSPC_ROOT")
	if limited == "" {
		t.Skip("set CTFM_TEST_ENOSPC_ROOT to an isolated <=1MiB filesystem")
	}
	directory := filepath.Join(limited, "snapshot-store")
	store, err := NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	before, err := storage.Capacity(directory)
	if err != nil {
		t.Fatal(err)
	}
	if before.AvailableBytes == 0 || before.AvailableBytes > 1<<20 {
		t.Fatalf("expected isolated <=1MiB filesystem, got %+v", before)
	}
	source := t.TempDir()
	if err = os.Mkdir(filepath.Join(source, "code"), 0700); err != nil {
		t.Fatal(err)
	}
	// Allocate actual non-sparse source bytes on the separate /tmp filesystem.
	data := bytes.Repeat([]byte("CTFM_ENOSPC_SOURCE_UNCHANGED\n"), 100000)
	path := filepath.Join(source, "code/large")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	digest := domain.Hash(data)
	id := domain.ID("enospc-allocation")
	created, err := store.Create(context.Background(), snapshotRequest(id), source, managed, nil)
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("expected real filesystem ENOSPC, got %v", err)
	}
	if created.State == domain.SnapshotComplete {
		t.Fatal("full filesystem published a complete snapshot")
	}
	if _, err = store.Load(context.Background(), id); err == nil {
		t.Fatal("partial snapshot became loadable")
	}
	if _, err = os.Lstat(filepath.Join(directory, string(id), "snapshot.json")); !os.IsNotExist(err) {
		t.Fatal("failed capture published metadata", err)
	}
	content, err := os.ReadFile(path)
	if err != nil || domain.Hash(content) != digest {
		t.Fatal("ENOSPC changed source bytes", err)
	}
	// The executor's durable receipt and terminal owner operation authorize this
	// cleanup; the store itself intentionally has no database authorization API.
	if err = store.RemoveUnpublished(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	after, err := storage.Capacity(directory)
	if err != nil {
		t.Fatal(err)
	}
	if after.AvailableBytes < before.AvailableBytes {
		t.Fatalf("partial allocation leaked disk space: before=%+v after=%+v", before, after)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("cleanup left partial artifacts: %v %v", entries, err)
	}
	t.Logf("real ENOSPC: source=%d bytes, capacity before=%d after=%d", len(data), before.AvailableBytes, after.AvailableBytes)
}

func TestRealInodeReserveRefusesAllocationBeforeCapture(t *testing.T) {
	limited := os.Getenv("CTFM_TEST_INODE_ROOT")
	if limited == "" {
		t.Skip("set CTFM_TEST_INODE_ROOT to an isolated nr_inodes=32 filesystem")
	}
	directory := filepath.Join(limited, "snapshot-store")
	store, err := NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	space, err := storage.Capacity(directory)
	if err != nil {
		t.Fatal(err)
	}
	if !space.InodesKnown || space.AvailableInodes >= 32 {
		t.Fatalf("expected actual tmpfs inode limit below reserve, got %+v", space)
	}
	err = storage.CheckQuota(0, 0, 0, space, 0, 32, 1)
	var quota *storage.QuotaError
	if !errors.As(err, &quota) || quota.Kind != "inodes" {
		t.Fatalf("inode pressure not refused: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("inode preflight created snapshot artifacts: %v %v", entries, err)
	}
	t.Logf("real tmpfs inode reserve: available=%d required=%d", space.AvailableInodes, 33)
}
