package executor

import (
	"errors"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/storage"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSnapshotQuotaRefusesBeforeCreatingArtifact(t *testing.T) {
	f := newPlanningFixture(t)
	before, err := os.ReadDir(filepath.Join(f.m.Config.StateDirectory, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	f.m.Config.Storage.SnapshotMaxBytes = 1
	_, err = f.m.capture(t.Context(), f.s, "local-admin", domain.SnapshotManual, f.s.ProjectDirectory)
	var quota *storage.QuotaError
	if !errors.As(err, &quota) {
		t.Fatalf("wanted quota rejection: %v", err)
	}
	after, _ := os.ReadDir(filepath.Join(f.m.Config.StateDirectory, "snapshots"))
	if len(after) != len(before) {
		t.Fatal("quota refusal allocated an artifact")
	}
	if _, err := f.m.loadSnapshot(t.Context(), f.baseline.ID); err != nil {
		t.Fatal("baseline lost", err)
	}
	if _, err := f.m.loadRelease(t.Context(), f.s, f.release.Spec().ID); err != nil {
		t.Fatal("imported release lost", err)
	}
}
func TestQuotaPressureCanDiscardManualButNotProtectedTree(t *testing.T) {
	f := newPlanningFixture(t)
	manual := retentionSnapshot(t, f, "manual-pressure", domain.SnapshotManual, time.Now().UTC())
	all, err := storage.Measure(t.Context(), filepath.Join(f.m.Config.StateDirectory, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	additional := uint64(128)
	f.m.Config.Storage.SnapshotMaxBytes = all.Bytes + additional - 1
	if err := f.m.preflightAllocation(t.Context(), filepath.Join(f.m.Config.StateDirectory, "snapshots"), additional, 1, f.m.Config.Storage.Effective().SnapshotMaxBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.loadSnapshot(t.Context(), manual.ID); err == nil {
		t.Fatal("unprotected manual snapshot not retired under pressure")
	}
	if _, err := f.m.loadSnapshot(t.Context(), f.baseline.ID); err != nil {
		t.Fatal("protected baseline removed", err)
	}
}
func TestStateQuotaChargesNonSnapshotStorage(t *testing.T) {
	f := newPlanningFixture(t)
	f.m.Config.Storage.StateMaxBytes = 1
	if _, err := f.m.preflightSnapshot(t.Context(), f.s, f.s.SourceDirectory); err == nil {
		t.Fatal("state quota ignored")
	}
}
