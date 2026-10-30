package executor

import (
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/filesystem"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"testing"
)

func TestReviewedDriftRecoveryPointCapturesExactTreeWithoutMutation(t *testing.T) {
	f := newPlanningFixture(t)
	writePlanningFile(t, f.activeFile, "manual repair = 2\n")
	st, err := f.m.state(t.Context(), f.s)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := filesystem.Observe(t.Context(), f.s.ProjectDirectory, f.s.ManagedPaths, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.createRecoveryPoint(t.Context(), f.s, st, "admin", nil); err == nil {
		t.Fatal("implicit drift acceptance")
	}
	if _, err := f.m.createRecoveryPoint(t.Context(), f.s, st, "admin", nil, domain.Hash([]byte("old review"))); err == nil {
		t.Fatal("stale reviewed tree accepted")
	}
	id, err := f.m.createRecoveryPoint(t.Context(), f.s, st, "admin", nil, observed.Digest())
	if err != nil {
		t.Fatal(err)
	}
	var point recoveryPoint
	if err := f.m.Store.Get(t.Context(), "recovery_point", id, &point); err != nil {
		t.Fatal(err)
	}
	snap, err := f.m.loadSnapshot(t.Context(), point.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	if snap.ManifestDigest != observed.Digest() || snap.Purpose != domain.SnapshotRecovery || point.ReleaseID != f.release.Spec().ID {
		t.Fatal("drift recovery evidence mismatch")
	}
	after, err := f.m.state(t.Context(), f.s)
	if err != nil || after.ActiveSnapshotID != st.ActiveSnapshotID || after.CurrentReleaseID != st.CurrentReleaseID {
		t.Fatal("acceptance changed active state")
	}
	st.ActiveSnapshotID = point.SnapshotID
	if matched, err := f.m.activeReleaseTreeMatches(t.Context(), f.s, st); err != nil || matched {
		t.Fatal("unverified recovery tree claimed as immutable release")
	}
	if rid, err := f.m.healthReleaseID(t.Context(), f.s, st); err != nil || rid != "" {
		t.Fatal("health evidence assigned to old immutable release")
	}
}
func TestDriftAcceptanceRequiresNewBoundPlanAndNeverQueuesImplicitly(t *testing.T) {
	f := newPlanningFixture(t)
	writePlanningFile(t, f.activeFile, "manual repair = 2\n")
	req := transport.SubmitRequest{ServiceID: f.s.ID, Action: domain.OperationRollback, ReleaseID: f.release.Spec().ID, IdempotencyKey: "drift-review", ConfirmDataCompatibility: true, Initiator: "admin"}
	first, err := f.m.Preview(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !first.ActiveFileDrift || first.AcceptedFileDrift || len(first.DriftChangedFiles) != 1 {
		t.Fatalf("drift hidden: %+v", first)
	}
	req.PlanDigest = first.PlanDigest
	if _, err := f.m.Submit(t.Context(), transport.Principal{}, req); err == nil {
		t.Fatal("unreviewed drift queued")
	}
	req.AcceptFileDrift = true
	if _, err := f.m.Submit(t.Context(), transport.Principal{}, req); err == nil {
		t.Fatal("old plan reused for drift acceptance")
	}
	accepted, err := f.m.Preview(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.PlanDigest == first.PlanDigest || !accepted.AcceptedFileDrift {
		t.Fatal("acceptance not bound to new plan")
	}
	writePlanningFile(t, f.activeFile, "manual repair = 3\n")
	req.PlanDigest = accepted.PlanDigest
	if _, err := f.m.Submit(t.Context(), transport.Principal{}, req); err == nil {
		t.Fatal("later edits silently accepted")
	}
	ops, err := f.m.Store.ListOperations(t.Context())
	if err != nil || len(ops) != 0 {
		t.Fatalf("invalid plan queued: %v %v", ops, err)
	}
}
