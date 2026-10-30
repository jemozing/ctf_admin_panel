package executor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/jobs"
	"github.com/ctf-service-manager/ctf-service-manager/internal/storage"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func retentionSnapshot(t *testing.T, f *planningFixture, id domain.ID, purpose domain.SnapshotPurpose, at time.Time, pins ...string) domain.Snapshot {
	t.Helper()
	s, err := f.m.Snapshots.Create(t.Context(), domain.Snapshot{ID: id, ServiceID: f.s.ID, CreatedAt: at, Author: "local-admin", Purpose: purpose, FileMapRevision: 1, Consistency: domain.ConsistencyCoordinated, PinReasons: pins}, f.s.ProjectDirectory, f.s.ManagedPaths, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.m.Store.PutImmutable(t.Context(), "snapshot", id, f.s.ID, s); err != nil {
		t.Fatal(err)
	}
	return s
}

func retentionRelease(t *testing.T, f *planningFixture, snapshot domain.Snapshot, id domain.ID, at time.Time) domain.Release {
	t.Helper()
	spec := f.release.Spec()
	spec.ID, spec.Source, spec.CreatedAt = id, domain.ReleaseWorkspace, at
	spec.SnapshotID, spec.TreeDigest = snapshot.ID, snapshot.ManifestDigest
	for i := range spec.Images {
		spec.Images[i].RetentionTag = retentionTag(f.s, id, spec.Images[i].Component)
	}
	r, err := domain.NewRelease(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.m.Store.PutImmutable(t.Context(), "release", id, f.s.ID, r); err != nil {
		t.Fatal(err)
	}
	return r
}

func retentionOperation(t *testing.T, f *planningFixture, id domain.ID, kind domain.OperationKind, releaseID, candidateID domain.ID) domain.Operation {
	t.Helper()
	spec := domain.OperationSpec{ID: id, Kind: kind, Initiator: "local-admin", IdempotencyKey: string(id), ServiceID: f.s.ID, ReleaseID: releaseID, ExpectedPolicyRevision: 1, ExpectedTreeDigest: f.baseline.ManifestDigest, Resources: []string{"service:" + string(f.s.ID)}, TimeoutSeconds: 600}
	input := operationInput{Request: transport.SubmitRequest{ServiceID: f.s.ID, Action: kind, ReleaseID: releaseID, CandidateID: candidateID, IdempotencyKey: string(id)}, Plan: transport.PreviewResult{ServiceID: f.s.ID, CandidateID: candidateID}}
	if err := f.m.Store.PutImmutable(t.Context(), "operation_input", id, f.s.ID, input); err != nil {
		t.Fatal(err)
	}
	op, _, err := jobs.New(f.m.Store).Submit(t.Context(), spec, domain.Hash([]byte(id)))
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func containsID(ids []domain.ID, id domain.ID) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

func TestRetentionRotatesManualSnapshotsAndProtectsReferenceGraph(t *testing.T) {
	f := newPlanningFixture(t)
	f.m.Config.Storage.ManualSnapshots = 3
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)
	manuals := make([]domain.Snapshot, 6)
	for i := range manuals {
		manuals[i] = retentionSnapshot(t, f, domain.ID(fmt.Sprintf("manual-%d", i)), domain.SnapshotManual, old.Add(time.Duration(i)*time.Minute))
	}
	active := retentionSnapshot(t, f, "active-tree", domain.SnapshotCandidate, old)
	activeRelease := retentionRelease(t, f, active, "active-release", old)
	latestCandidate := retentionSnapshot(t, f, "latest-candidate", domain.SnapshotCandidate, old)
	queuedCandidate := retentionSnapshot(t, f, "queued-build-candidate", domain.SnapshotCandidate, old)
	queuedReleaseTree := retentionSnapshot(t, f, "queued-release-tree", domain.SnapshotCandidate, old)
	queuedRelease := retentionRelease(t, f, queuedReleaseTree, "queued-release", old)
	recoveryTree := retentionSnapshot(t, f, "recovery-tree", domain.SnapshotRecovery, old)
	recoveryReleaseTree := retentionSnapshot(t, f, "recovery-release-tree", domain.SnapshotCandidate, old)
	recoveryRelease := retentionRelease(t, f, recoveryReleaseTree, "recovery-release", old)
	explicit := retentionSnapshot(t, f, "explicit-pin", domain.SnapshotManual, old, "operator")
	orphan := retentionSnapshot(t, f, "orphan-candidate", domain.SnapshotCandidate, old)
	orphanRelease := retentionRelease(t, f, orphan, "orphan-release", old)
	finishedRecovery := retentionSnapshot(t, f, "finished-recovery", domain.SnapshotRecovery, old)
	st, err := f.m.state(t.Context(), f.s)
	if err != nil {
		t.Fatal(err)
	}
	st.CurrentReleaseID, st.ActiveSnapshotID, st.CandidateID = activeRelease.Spec().ID, active.ID, latestCandidate.ID
	if err = f.m.saveState(t.Context(), &st); err != nil {
		t.Fatal(err)
	}
	retentionOperation(t, f, "queued-build", domain.OperationBuild, "", queuedCandidate.ID)
	retentionOperation(t, f, "queued-deploy", domain.OperationDeploy, queuedRelease.Spec().ID, "")
	recovering := retentionOperation(t, f, "recovering-deploy", domain.OperationDeploy, queuedRelease.Spec().ID, "")
	manager := jobs.New(f.m.Store)
	if _, err = manager.Start(t.Context(), recovering.Spec.ID); err != nil {
		t.Fatal(err)
	}
	point := recoveryPoint{SnapshotID: recoveryTree.ID, ReleaseID: recoveryRelease.Spec().ID, State: st}
	if err = f.m.Store.PutImmutable(t.Context(), "recovery_point", recoveryTree.ID, f.s.ID, point); err != nil {
		t.Fatal(err)
	}
	if _, err = manager.BeginMutation(t.Context(), recovering.Spec.ID, recoveryTree.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Transition(t.Context(), recovering.Spec.ID, domain.OperationRequiresRecovery, domain.OutcomeEvidence{Reason: "injected failure after mutation"}); err != nil {
		t.Fatal(err)
	}
	plan, err := f.m.Rotate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, snapshot := range []domain.Snapshot{f.baseline, active, latestCandidate, queuedCandidate, queuedReleaseTree, recoveryTree, recoveryReleaseTree, explicit, manuals[3], manuals[4], manuals[5]} {
		if containsID(plan.DeleteSnapshots, snapshot.ID) {
			t.Fatalf("protected snapshot selected: %s", snapshot.ID)
		}
		if _, err = f.m.Snapshots.Load(t.Context(), snapshot.ID); err != nil {
			t.Fatalf("protected snapshot removed: %s: %v", snapshot.ID, err)
		}
	}
	for _, snapshot := range []domain.Snapshot{manuals[0], manuals[1], manuals[2], orphan, finishedRecovery} {
		if !containsID(plan.DeleteSnapshots, snapshot.ID) {
			t.Fatalf("expired unreferenced snapshot retained: %s", snapshot.ID)
		}
		retired, err := f.m.isRetired(t.Context(), "deleted_snapshot", snapshot.ID)
		if err != nil || !retired {
			t.Fatalf("missing durable deletion tombstone %s: %v", snapshot.ID, err)
		}
		if _, err = os.Stat(filepath.Join(f.m.Config.StateDirectory, "snapshots", string(snapshot.ID))); !os.IsNotExist(err) {
			t.Fatalf("deleted snapshot artifact retained: %s: %v", snapshot.ID, err)
		}
	}
	if !containsID(plan.RetireReleases, orphanRelease.Spec().ID) {
		t.Fatal("unreferenced expired release not retired")
	}
	for _, release := range []domain.Release{f.release, activeRelease, queuedRelease, recoveryRelease} {
		if containsID(plan.RetireReleases, release.Spec().ID) {
			t.Fatalf("referenced release retired: %s", release.Spec().ID)
		}
	}
	if _, err = f.m.Rotate(t.Context()); err != nil {
		t.Fatal("repeat rotation failed", err)
	}
}

func TestRetentionPressureKeepsCurrentCandidateAndQueuedInputs(t *testing.T) {
	f := newPlanningFixture(t)
	old := time.Now().UTC().Add(-48 * time.Hour)
	unreferenced := retentionSnapshot(t, f, "manual-pressure", domain.SnapshotManual, old)
	queued := retentionSnapshot(t, f, "queued-pressure", domain.SnapshotCandidate, old)
	retentionOperation(t, f, "pressure-build", domain.OperationBuild, "", queued.ID)
	plan, err := f.m.retentionPlan(t.Context(), time.Now().UTC(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !containsID(plan.DeleteSnapshots, unreferenced.ID) {
		t.Fatal("pressure retained unreferenced manual snapshot")
	}
	for _, id := range []domain.ID{f.baseline.ID, queued.ID} {
		if containsID(plan.DeleteSnapshots, id) || len(plan.ProtectedSnapshots[id]) == 0 {
			t.Fatalf("pressure discarded reference %s", id)
		}
	}
}

func TestRetentionTombstonesPreventReuseBeforePhysicalCleanup(t *testing.T) {
	f := newPlanningFixture(t)
	old := time.Now().UTC().Add(-48 * time.Hour)
	candidate := retentionSnapshot(t, f, "tombstoned-candidate", domain.SnapshotCandidate, old)
	releaseTree := retentionSnapshot(t, f, "retired-release-tree", domain.SnapshotCandidate, old)
	release := retentionRelease(t, f, releaseTree, "retired-target", old)
	for _, item := range []struct {
		kind string
		id   domain.ID
	}{{"deleted_snapshot", candidate.ID}, {"retired_release", release.Spec().ID}} {
		if err := f.m.Store.PutImmutable(t.Context(), item.kind, item.id, f.s.ID, retirement{ID: item.id, At: time.Now().UTC(), Reason: "crash after durable retirement"}); err != nil {
			t.Fatal(err)
		}
	}
	// A crash may leave fully valid content. The immutable tombstone, rather
	// than physical nonexistence, must reject acquisition of a new reference.
	if _, err := f.m.Snapshots.Load(t.Context(), candidate.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Preview(t.Context(), transport.SubmitRequest{ServiceID: f.s.ID, Action: domain.OperationBuild, CandidateID: candidate.ID, IdempotencyKey: "no-resurrection"}); err == nil {
		t.Fatal("build preview resurrected a tombstoned candidate")
	}
	if _, err := f.m.loadRelease(t.Context(), f.s, release.Spec().ID); err == nil {
		t.Fatal("retired release can be loaded for a new operation")
	}
	if _, err := f.m.Rotate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.m.Config.StateDirectory, "snapshots", string(candidate.ID))); !os.IsNotExist(err) {
		t.Fatal("crash-leftover artifact not removed on rotation retry", err)
	}
}

func TestSnapshotQuotaRefusesAllocationWithoutDiscardingBaseline(t *testing.T) {
	for _, kind := range []string{"snapshot", "whole-state"} {
		t.Run(kind, func(t *testing.T) {
			f := newPlanningFixture(t)
			if kind == "snapshot" {
				f.m.Config.Storage.SnapshotMaxBytes = 1
			} else {
				f.m.Config.Storage.StateMaxBytes = 1
			}
			before, err := os.ReadFile(f.activeFile)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.m.capture(t.Context(), f.s, "local-admin", domain.SnapshotManual, f.s.ProjectDirectory)
			var quota *storage.QuotaError
			if !errors.As(err, &quota) || quota.Kind != "quota" {
				t.Fatalf("allocation was not refused by quota: %v", err)
			}
			if _, err = f.m.loadSnapshot(t.Context(), f.baseline.ID); err != nil {
				t.Fatal("quota pressure removed baseline", err)
			}
			entries, err := os.ReadDir(filepath.Join(f.m.Config.StateDirectory, "snapshots"))
			if err != nil || len(entries) != 1 {
				t.Fatalf("refused allocation left partial artifact: %d %v", len(entries), err)
			}
			after, err := os.ReadFile(f.activeFile)
			if err != nil || string(after) != string(before) {
				t.Fatal("quota refusal modified active files", err)
			}
		})
	}
}
