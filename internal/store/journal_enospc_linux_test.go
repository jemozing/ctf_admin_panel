package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

// This opt-in test needs a private small tmpfs provisioned by the caller. It
// mounts nothing, needs no Docker socket/capabilities, and fills only that tmpfs.
func TestJournalRealENOSPCRetainsMutationIntentAndLocks(t *testing.T) {
	root := os.Getenv("CTFM_TEST_JOURNAL_ENOSPC_ROOT")
	if root == "" {
		t.Skip("set CTFM_TEST_JOURNAL_ENOSPC_ROOT to a private <=4MiB tmpfs")
	}
	var space syscall.Statfs_t
	if err := syscall.Statfs(root, &space); err != nil {
		t.Fatal(err)
	}
	if space.Type != 0x01021994 || space.Blocks*uint64(space.Bsize) > 4<<20 {
		t.Fatal("refusing to fill anything except an explicitly provisioned <=4MiB tmpfs")
	}
	directory, err := os.MkdirTemp(root, "journal-enospc-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	filename := filepath.Join(directory, "executor.db")
	s, err := Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	op := makeOperation(t, "enospc-operation", "enospc-service", "enospc-key")
	if _, _, err = s.BeginOperation(ctx, op, domain.Hash([]byte("enospc-input"))); err != nil {
		t.Fatal(err)
	}
	op = runOperation(t, s, op)
	previous := op.UpdatedAt
	if err = op.BeginMutation("enospc-recovery-point", previous.Add(time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if err = s.UpdateOperation(ctx, op, previous); err != nil {
		t.Fatal(err)
	}
	beforeEvents, err := s.Events(ctx, op.Spec.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Truncate reusable WAL space before exhausting the actual filesystem. No
	// SQLite max_page_count, mocked VFS or fabricated ENOSPC error is used.
	if _, err = s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	fillerPath := filepath.Join(directory, "filler")
	filler, err := os.OpenFile(fillerPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	block := bytes.Repeat([]byte{0x5a}, 4096)
	for err == nil {
		_, err = filler.Write(block)
	}
	_ = filler.Close()
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("expected real tmpfs ENOSPC, got %v", err)
	}
	terminal := op
	if err = terminal.Transition(domain.OperationSucceeded, domain.OutcomeEvidence{ActualStateKnown: true, ResultRecorded: true}, op.UpdatedAt.Add(time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	err = s.UpdateOperation(ctx, terminal, op.UpdatedAt)
	if err == nil {
		t.Fatal("journal update reported success on an exhausted filesystem")
	}
	var sqliteError interface{ Code() int }
	if !errors.As(err, &sqliteError) || sqliteError.Code()&255 != 13 {
		t.Fatalf("expected SQLite FULL from real ENOSPC, got %v", err)
	}
	t.Logf("real full-filesystem journal failure: %v", err)
	if err = os.Remove(fillerPath); err != nil {
		t.Fatal(err)
	}
	// Reopen as after a process restart, checking WAL recovery and integrity.
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := s.GetOperation(ctx, op.Spec.ID)
	if err != nil || !reflect.DeepEqual(actual, op) {
		t.Fatalf("failed terminal commit changed durable mutation intent: %+v, %v", actual, err)
	}
	afterEvents, err := s.Events(ctx, op.Spec.ID)
	if err != nil || !reflect.DeepEqual(beforeEvents, afterEvents) {
		t.Fatal("failed commit changed the append-only event journal", err)
	}
	var locks int
	if err = s.db.QueryRow("SELECT count(*) FROM locks WHERE operation_id=?", op.Spec.ID).Scan(&locks); err != nil || locks != len(op.Spec.Resources) {
		t.Fatalf("full journal released mutation resource locks: %d, %v", locks, err)
	}
	var integrity string
	if err = s.db.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("database integrity after disk exhaustion: %q, %v", integrity, err)
	}
	interrupted, err := s.MarkInterrupted(ctx, time.Now().UTC().Add(time.Second))
	if err != nil || len(interrupted) != 1 || !interrupted[0].MutationStarted || interrupted[0].RecoveryPointID != op.RecoveryPointID {
		t.Fatalf("restart lost reconciliation/recovery evidence: %+v, %v", interrupted, err)
	}
	if err = s.db.QueryRow("SELECT count(*) FROM locks WHERE operation_id=?", op.Spec.ID).Scan(&locks); err != nil || locks != len(op.Spec.Resources) {
		t.Fatal("interrupted mutation lost resource locks", err)
	}
}
