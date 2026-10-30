package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/jobs"
)

func restoreCandidateOperation(t *testing.T, f *planningFixture, source domain.ID) domain.Operation {
	t.Helper()
	op, err := domain.NewOperation(domain.OperationSpec{ID: "restore-op", Kind: domain.OperationRestoreSnapshot, SnapshotID: source, Initiator: "local-admin", IdempotencyKey: "restore-baseline", ServiceID: f.s.ID, ExpectedPolicyRevision: f.s.PolicyRevision, ExpectedTreeDigest: f.baseline.ManifestDigest, Resources: []string{"service:" + string(f.s.ID)}, TimeoutSeconds: 60}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.m.Store.BeginOperation(t.Context(), op, domain.Hash([]byte("restore"))); err != nil {
		t.Fatal(err)
	}
	op, err = jobs.New(f.m.Store).Start(t.Context(), op.Spec.ID)
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func TestRestoreSnapshotCreatesNewCandidatePreservingActiveAndWorkspace(t *testing.T) {
	f := newPlanningFixture(t)
	writePlanningFile(t, f.workspaceFile, "unpublished workspace edits\n")
	activeBefore, err := os.ReadFile(f.activeFile)
	if err != nil {
		t.Fatal(err)
	}
	workspaceBefore, err := os.ReadFile(f.workspaceFile)
	if err != nil {
		t.Fatal(err)
	}
	st, err := f.m.state(t.Context(), f.s)
	if err != nil {
		t.Fatal(err)
	}
	op := restoreCandidateOperation(t, f, f.baseline.ID)
	if err := f.m.restoreSnapshotCandidate(t.Context(), f.s, &st, op, f.baseline.ID); err != nil {
		t.Fatal(err)
	}
	if st.CandidateID == "" || st.CandidateID == f.baseline.ID || st.CurrentReleaseID != f.release.Spec().ID || st.ActiveSnapshotID != f.baseline.ID {
		t.Fatalf("restore mutated active state: %#v", st)
	}
	candidate, err := f.m.loadSnapshot(t.Context(), st.CandidateID)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Purpose != domain.SnapshotCandidate || candidate.ManifestDigest != f.baseline.ManifestDigest {
		t.Fatal("wrong restored candidate")
	}
	for file, want := range map[string][]byte{f.activeFile: activeBefore, f.workspaceFile: workspaceBefore} {
		got, err := os.ReadFile(file)
		if err != nil || string(got) != string(want) {
			t.Fatalf("restore wrote external tree %s: %v", file, err)
		}
	}
	content, _ := f.m.Snapshots.ContentPath(candidate.ID)
	got, err := os.ReadFile(filepath.Join(content, "app/main.py"))
	if err != nil || !strings.Contains(string(got), "version = 1") {
		t.Fatal("baseline bytes lost", err)
	}
	updated, err := f.m.Store.GetOperation(t.Context(), op.Spec.ID)
	if err != nil || updated.MutationStarted {
		t.Fatal("candidate restore crossed active mutation boundary", err)
	}
}

func TestRestoreSnapshotRejectsStaleFileMapAndQuotaBeforePublication(t *testing.T) {
	f := newPlanningFixture(t)
	st, err := f.m.state(t.Context(), f.s)
	if err != nil {
		t.Fatal(err)
	}
	op := restoreCandidateOperation(t, f, f.baseline.ID)
	stale := f.s
	stale.FileMapRevision++
	if _, err := f.m.snapshotCandidateSource(t.Context(), stale, f.baseline.ID); err == nil {
		t.Fatal("stale snapshot map accepted")
	}
	f.m.Config.Storage.SnapshotMaxBytes = 1
	if err := f.m.restoreSnapshotCandidate(t.Context(), f.s, &st, op, f.baseline.ID); err == nil {
		t.Fatal("quota ignored")
	}
	if st.CandidateID != "" {
		t.Fatal("failed clone published candidate")
	}
}
