package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/jobs"
	"github.com/ctf-service-manager/ctf-service-manager/internal/snapshots"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

type planningFixture struct {
	m             *Manager
	s             domain.Service
	baseline      domain.Snapshot
	release       domain.Release
	workspaceFile string
	activeFile    string
}

func newPlanningFixture(t *testing.T) *planningFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(root, "active")
	workspace := filepath.Join(root, "workspace")
	state := filepath.Join(root, "state")
	for _, dir := range []string{filepath.Join(active, "app"), filepath.Join(workspace, "app"), state} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	activeFile := filepath.Join(active, "app", "main.py")
	workspaceFile := filepath.Join(workspace, "app", "main.py")
	for _, file := range []string{activeFile, workspaceFile} {
		if err := os.WriteFile(file, []byte("version = 1\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	db, err := store.Open(filepath.Join(state, "executor.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	artifacts, err := snapshots.NewStore(filepath.Join(state, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { artifacts.Close() })
	s := domain.Service{SchemaVersion: domain.SchemaVersion, ID: "flags", Name: "Planning fixture", ProjectDirectory: active, SourceDirectory: workspace, ComposeProject: "flags", ComposeFiles: []string{"compose.yaml"}, ManagedPaths: []domain.ManagedPath{{Path: "app", Kind: domain.ManagedCode}}, Targets: []string{"app"}, Containers: []domain.ContainerRef{{Component: "app", ID: strings.Repeat("a", 64), ImageID: domain.Hash([]byte("initial-image")), Role: domain.RoleApplication}}, DataPaths: []domain.DataPath{{Name: "game-data", Component: "app", Kind: domain.StorageNamedVolume, Source: "flags_game-data", Target: "/data", Significant: true}}, PolicyRevision: 1, FileMapRevision: 1}
	digest := domain.Hash([]byte("approved-configuration"))
	now := time.Now().UTC()
	proposal, err := db.CreateProposal(t.Context(), "planning-policy", s, digest, "local-admin", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ApproveProposal(t.Context(), proposal.ID, proposal.Digest, "local-admin", now); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Config: config.Config{StateDirectory: state, Development: true}, Store: db, Snapshots: artifacts}
	baseline, err := m.capture(t.Context(), s, "local-admin", domain.SnapshotBaseline, active)
	if err != nil {
		t.Fatal(err)
	}
	release := planningRelease(t, m, s, baseline, "release-baseline")
	st := runtimeState{ServiceID: s.ID, CurrentReleaseID: release.Spec().ID, ActiveSnapshotID: baseline.ID, BaselineID: baseline.ID, Containers: s.Containers}
	if err := m.saveState(t.Context(), &st); err != nil {
		t.Fatal(err)
	}
	return &planningFixture{m: m, s: s, baseline: baseline, release: release, activeFile: activeFile, workspaceFile: workspaceFile}
}
func planningRelease(t *testing.T, m *Manager, s domain.Service, snapshot domain.Snapshot, id domain.ID) domain.Release {
	t.Helper()
	r, err := domain.NewRelease(domain.ReleaseSpec{SchemaVersion: domain.SchemaVersion, ID: id, ServiceID: s.ID, CreatedAt: time.Now().UTC(), Author: "local-admin", Source: domain.ReleaseImported, SnapshotID: snapshot.ID, TreeDigest: snapshot.ManifestDigest, ConfigurationDigest: domain.Hash([]byte("approved-configuration")), PolicyRevision: s.PolicyRevision, FileMapRevision: s.FileMapRevision, Images: []domain.ImageRef{{Component: "app", ImageID: s.Containers[0].ImageID, RetentionTag: retentionTag(s, id, "app")}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Store.PutImmutable(t.Context(), "release", id, s.ID, r); err != nil {
		t.Fatal(err)
	}
	return r
}
func writePlanningFile(t *testing.T, name, value string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
}
func TestPreviewBindsActiveAndSourceTreesAndStateSequence(t *testing.T) {
	f := newPlanningFixture(t)
	req := transport.SubmitRequest{ServiceID: f.s.ID, Action: domain.OperationPrepare, IdempotencyKey: "prepare"}
	first, err := f.m.Preview(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	repeat, err := f.m.Preview(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if repeat.PlanDigest != first.PlanDigest {
		t.Fatal("unchanged preview is unstable")
	}
	writePlanningFile(t, f.workspaceFile, "version = 2\n")
	changed, err := f.m.Preview(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if changed.PlanDigest == first.PlanDigest || changed.CurrentTreeDigest != first.CurrentTreeDigest || len(changed.ChangedFiles) != 1 || changed.ChangedFiles[0].Path != "app/main.py" {
		t.Fatalf("source edits not bound to preview: %#v", changed)
	}
	st, err := f.m.state(t.Context(), f.s)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.m.saveState(t.Context(), &st); err != nil {
		t.Fatal(err)
	}
	advanced, err := f.m.Preview(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if advanced.PlanDigest == changed.PlanDigest {
		t.Fatal("runtime state sequence not bound to preview")
	}
	writePlanningFile(t, f.activeFile, "external edit\n")
	active, err := f.m.Preview(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if active.PlanDigest == advanced.PlanDigest || active.CurrentTreeDigest == advanced.CurrentTreeDigest {
		t.Fatal("active edits not bound to preview")
	}
}
func TestBuildPreviewUsesImmutableCandidateRatherThanLaterWorkspace(t *testing.T) {
	f := newPlanningFixture(t)
	writePlanningFile(t, f.workspaceFile, "version = 2\n")
	candidate, err := f.m.capture(t.Context(), f.s, "defender", domain.SnapshotCandidate, f.s.SourceDirectory)
	if err != nil {
		t.Fatal(err)
	}
	req := transport.SubmitRequest{ServiceID: f.s.ID, Action: domain.OperationBuild, CandidateID: candidate.ID, IdempotencyKey: "build"}
	first, err := f.m.Preview(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	writePlanningFile(t, f.workspaceFile, "version = 3\n")
	second, err := f.m.Preview(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if first.PlanDigest != second.PlanDigest || second.CandidateID != candidate.ID {
		t.Fatal("later workspace edits changed immutable candidate plan")
	}
	foreign := f.s
	foreign.ID = "another-service"
	bad, err := f.m.capture(t.Context(), foreign, "defender", domain.SnapshotCandidate, foreign.SourceDirectory)
	if err != nil {
		t.Fatal(err)
	}
	req.CandidateID = bad.ID
	if _, err := f.m.Preview(t.Context(), req); err == nil {
		t.Fatal("another service candidate accepted")
	}
}
func TestSubmitRejectsUnreviewedAndStalePlansWithoutQueueing(t *testing.T) {
	f := newPlanningFixture(t)
	req := transport.SubmitRequest{ServiceID: f.s.ID, Action: domain.OperationSnapshot, IdempotencyKey: "snapshot"}
	p := transport.Principal{UID: 12000}
	if _, err := f.m.Submit(t.Context(), p, req); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("unreviewed plan accepted: %v", err)
	}
	preview, err := f.m.Preview(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	req.PlanDigest = preview.PlanDigest
	writePlanningFile(t, f.activeFile, "external edit\n")
	if _, err := f.m.Submit(t.Context(), p, req); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale plan accepted: %v", err)
	}
	operations, err := f.m.Store.ListOperations(t.Context())
	if err != nil || len(operations) != 0 {
		t.Fatalf("invalid request queued effects: %#v %v", operations, err)
	}
}
func TestSubmitIdempotencyPrecedesStalePreviewAndScopesActor(t *testing.T) {
	f := newPlanningFixture(t)
	req := transport.SubmitRequest{ServiceID: f.s.ID, Action: domain.OperationSnapshot, IdempotencyKey: "snapshot"}
	principal := transport.Principal{UID: 12000}
	preview, err := f.m.Preview(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	req.PlanDigest = preview.PlanDigest
	first, err := f.m.Submit(t.Context(), principal, req)
	if err != nil {
		t.Fatal(err)
	}
	writePlanningFile(t, f.activeFile, "external edit after accepted request\n")
	second, err := f.m.Submit(t.Context(), principal, req)
	if err != nil || second.Spec.ID != first.Spec.ID {
		t.Fatalf("safe idempotent replay rejected after state changed: %#v %v", second, err)
	}
	changed := req
	changed.Action = domain.OperationRestart
	if _, err := f.m.Submit(t.Context(), principal, changed); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed request reused key: %v", err)
	}
	preview, err = f.m.Preview(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	req.PlanDigest = preview.PlanDigest
	other, err := f.m.Submit(t.Context(), transport.Principal{UID: 12001}, req)
	if err != nil || other.Spec.ID == first.Spec.ID || other.Spec.Initiator == first.Spec.Initiator {
		t.Fatalf("actor-scoped keys collided: %#v %v", other, err)
	}
}
func TestConcurrentSubmitProducesOneJob(t *testing.T) {
	f := newPlanningFixture(t)
	req := transport.SubmitRequest{ServiceID: f.s.ID, Action: domain.OperationSnapshot, IdempotencyKey: "concurrent"}
	preview, err := f.m.Preview(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	req.PlanDigest = preview.PlanDigest
	var wait sync.WaitGroup
	ids := make(chan domain.ID, 12)
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			op, err := f.m.Submit(context.Background(), transport.Principal{UID: 12000}, req)
			if err != nil {
				errs <- err
			} else {
				ids <- op.Spec.ID
			}
		}()
	}
	wait.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	var first domain.ID
	for id := range ids {
		if first == "" {
			first = id
		}
		if id != first {
			t.Fatal("one idempotency key produced multiple operations")
		}
	}
	operations, err := f.m.Store.ListOperations(t.Context())
	if err != nil || len(operations) != 1 {
		t.Fatalf("concurrent queue duplicated jobs: %d %v", len(operations), err)
	}
}
func TestDeployRequiresDataConfirmationAndReleasePolicyOwnership(t *testing.T) {
	f := newPlanningFixture(t)
	req := transport.SubmitRequest{ServiceID: f.s.ID, Action: domain.OperationDeploy, ReleaseID: f.release.Spec().ID, IdempotencyKey: "deploy"}
	preview, err := f.m.Preview(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !preview.DataCompatibilityRequired {
		t.Fatal("significant persistent data did not require compatibility review")
	}
	req.PlanDigest = preview.PlanDigest
	if _, err := f.m.Submit(t.Context(), transport.Principal{UID: 12000}, req); err == nil {
		t.Fatal("data compatibility confirmation omitted")
	}
	req.ConfirmDataCompatibility = true
	if _, err := f.m.Submit(t.Context(), transport.Principal{UID: 12000}, req); err != nil {
		t.Fatalf("confirmed plan rejected: %v", err)
	}
	foreign := f.s
	foreign.ID = "another-service"
	r := planningRelease(t, f.m, foreign, f.baseline, "release-other")
	req.ReleaseID = r.Spec().ID
	if _, err := f.m.Preview(t.Context(), req); err == nil {
		t.Fatal("foreign release accepted")
	}
	stale := f.s
	stale.PolicyRevision = 2
	r = planningRelease(t, f.m, stale, f.baseline, "release-stale-policy")
	req.ReleaseID = r.Spec().ID
	if _, err := f.m.Preview(t.Context(), req); err == nil {
		t.Fatal("release from another policy revision accepted")
	}
}

func TestRecoveryIdempotencyConflictsWithOtherActionsAndServices(t *testing.T) {
	f := newPlanningFixture(t)
	principal := transport.Principal{UID: 12000}
	initial := transport.SubmitRequest{ServiceID: f.s.ID, Action: domain.OperationSnapshot, IdempotencyKey: "original-job"}
	preview, err := f.m.Preview(t.Context(), initial)
	if err != nil {
		t.Fatal(err)
	}
	initial.PlanDigest = preview.PlanDigest
	op, err := f.m.Submit(t.Context(), principal, initial)
	if err != nil {
		t.Fatal(err)
	}
	worker := jobs.New(f.m.Store)
	if _, err := worker.Start(t.Context(), op.Spec.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := worker.ReconcileOnStart(t.Context()); err != nil {
		t.Fatal(err)
	}
	recovery := transport.SubmitRequest{ServiceID: f.s.ID, Action: domain.OperationRecover, RecoveryOperationID: op.Spec.ID, IdempotencyKey: "recovery-key"}
	preview, err = f.m.Preview(t.Context(), recovery)
	if err != nil {
		t.Fatal(err)
	}
	recovery.PlanDigest = preview.PlanDigest
	recovered, err := f.m.Submit(t.Context(), principal, recovery)
	if err != nil || recovered.Spec.ID != op.Spec.ID {
		t.Fatalf("recovery request rejected: %#v %v", recovered, err)
	}
	repeat, err := f.m.Submit(t.Context(), principal, recovery)
	if err != nil || repeat.Spec.ID != op.Spec.ID {
		t.Fatalf("recovery idempotency failed: %#v %v", repeat, err)
	}
	records, err := f.m.Store.List(t.Context(), "recovery_request", f.s.ID)
	if err != nil || len(records) != 1 {
		t.Fatalf("recovery intent duplicated: %d %v", len(records), err)
	}
	changed := recovery
	changed.Action = domain.OperationSnapshot
	changed.RecoveryOperationID = ""
	if _, err := f.m.Submit(t.Context(), principal, changed); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("recovery key reused by ordinary operation: %v", err)
	}
	changed = recovery
	changed.ServiceID = "another-service"
	if _, err := f.m.Submit(t.Context(), principal, changed); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("recovery key reused across services: %v", err)
	}
}
