package executor

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/jobs"
	"github.com/ctf-service-manager/ctf-service-manager/internal/snapshots"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"github.com/moby/moby/client"
)

func metadataManager(t *testing.T, source *planningFixture) *Manager {
	t.Helper()
	state, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	if err := source.m.Store.ExportMetadata(t.Context(), filepath.Join(state, "executor.db")); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(state, "executor.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.PrepareRestoredState(t.Context(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	artifacts, err := snapshots.NewStore(filepath.Join(state, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { artifacts.Close() })
	return &Manager{Config: config.Config{StateDirectory: state, Development: true}, Store: db, Snapshots: artifacts}
}

func TestMetadataRestoreBlocksEveryFreshOperationBeforeReadingActiveState(t *testing.T) {
	f := newPlanningFixture(t)
	old := time.Now().Add(-72 * time.Hour)
	candidate := retentionSnapshot(t, f, "restore-candidate", domain.SnapshotCandidate, old)
	release := retentionRelease(t, f, candidate, "restore-release", old)
	m := metadataManager(t, f)
	before, err := os.ReadFile(f.activeFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []domain.OperationKind{domain.OperationSnapshot, domain.OperationPrepare, domain.OperationBuild, domain.OperationDeploy, domain.OperationRollback, domain.OperationStart, domain.OperationStop, domain.OperationRestart, domain.OperationRecover} {
		req := transport.SubmitRequest{ServiceID: f.s.ID, Action: action, Initiator: "restore-user", IdempotencyKey: "review-required-" + string(action), PlanDigest: domain.Hash(nil)}
		if action == domain.OperationBuild {
			req.CandidateID = candidate.ID
		}
		if action == domain.OperationDeploy || action == domain.OperationRollback {
			req.ReleaseID = release.Spec().ID
		}
		if action == domain.OperationRecover {
			req.RecoveryOperationID = "old-operation"
		}
		if _, err := m.Submit(t.Context(), transport.Principal{UID: uint32(os.Geteuid())}, req); err == nil || !strings.Contains(err.Error(), "metadata-only restore requires local policy review") {
			t.Fatalf("%s bypassed metadata restore gate: %v", action, err)
		}
	}
	ops, err := m.Store.ListOperations(t.Context())
	if err != nil || len(ops) != 0 {
		t.Fatalf("rejected metadata requests created queued work: %d %v", len(ops), err)
	}
	after, err := os.ReadFile(f.activeFile)
	if err != nil || string(after) != string(before) {
		t.Fatal("metadata restore rejection modified active files")
	}
}

func TestMetadataRestorePinsEntireLiveCatalogDespiteMissingRecoveryInputs(t *testing.T) {
	f := newPlanningFixture(t)
	old := time.Now().Add(-72 * time.Hour)
	allSnapshots := []domain.Snapshot{f.baseline}
	for _, item := range []struct {
		id      domain.ID
		purpose domain.SnapshotPurpose
	}{{"restore-manual", domain.SnapshotManual}, {"restore-candidate", domain.SnapshotCandidate}, {"restore-recovery", domain.SnapshotRecovery}} {
		allSnapshots = append(allSnapshots, retentionSnapshot(t, f, item.id, item.purpose, old))
	}
	release := retentionRelease(t, f, allSnapshots[2], "restore-workspace-release", old)
	op := retentionOperation(t, f, "restore-interrupted", domain.OperationDeploy, release.Spec().ID, "")
	manager := jobs.New(f.m.Store)
	if _, err := manager.Start(t.Context(), op.Spec.ID); err != nil {
		t.Fatal(err)
	}
	state, err := f.m.state(t.Context(), f.s)
	if err != nil {
		t.Fatal(err)
	}
	point := recoveryPoint{SnapshotID: allSnapshots[3].ID, ReleaseID: f.release.Spec().ID, State: state}
	if err := f.m.Store.PutImmutable(t.Context(), "recovery_point", point.SnapshotID, f.s.ID, point); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.BeginMutation(t.Context(), op.Spec.ID, point.SnapshotID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Transition(t.Context(), op.Spec.ID, domain.OperationRequiresRecovery, domain.OutcomeEvidence{Reason: "test requires manual recovery"}); err != nil {
		t.Fatal(err)
	}
	m := metadataManager(t, f)
	var input operationInput
	if err := m.Store.Get(t.Context(), "operation_input", op.Spec.ID, &input); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("test metadata unexpectedly retained private operation input")
	}
	var missingPoint recoveryPoint
	if err := m.Store.Get(t.Context(), "recovery_point", point.SnapshotID, &missingPoint); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("test metadata unexpectedly retained private recovery input")
	}
	for _, pressure := range []bool{false, true} {
		plan, err := m.retentionPlan(t.Context(), time.Now().UTC(), pressure)
		if err != nil {
			t.Fatalf("metadata catalog cannot be inspected without excluded inputs: %v", err)
		}
		if len(plan.DeleteSnapshots) != 0 || len(plan.RetireReleases) != 0 {
			t.Fatalf("unreviewed metadata selected for reclamation: %#v", plan)
		}
		for _, snapshot := range allSnapshots {
			if !hasRestoreReason(plan.ProtectedSnapshots[snapshot.ID], "metadata_restore_review") {
				t.Fatalf("snapshot %s lacks review pin", snapshot.ID)
			}
		}
		for _, release := range []domain.Release{f.release, release} {
			if !hasRestoreReason(plan.ProtectedReleases[release.Spec().ID], "metadata_restore_review") {
				t.Fatalf("release %s lacks review pin", release.Spec().ID)
			}
		}
	}
	if _, err := m.Rotate(t.Context()); err != nil {
		t.Fatalf("metadata rotation should safely preserve its missing-artifact catalog: %v", err)
	}
	ops, err := m.Store.ListOperations(t.Context())
	if err != nil || len(ops) != 1 || ops[0].State != domain.OperationRequiresRecovery {
		t.Fatal("metadata cleanup changed unresolved recovery state", err)
	}
}

func hasRestoreReason(reasons []string, want string) bool {
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}

func TestMetadataRestoreDefersTombstoneCleanupUntilPolicyReview(t *testing.T) {
	f := newPlanningFixture(t)
	old := time.Now().Add(-72 * time.Hour)
	retiredSnapshot := retentionSnapshot(t, f, "restore-retired-tree", domain.SnapshotCandidate, old)
	retiredRelease := retentionRelease(t, f, retiredSnapshot, "restore-retired-release", old)
	for _, item := range []struct {
		kind string
		id   domain.ID
	}{{"deleted_snapshot", retiredSnapshot.ID}, {"retired_release", retiredRelease.Spec().ID}} {
		if err := f.m.Store.PutImmutable(t.Context(), item.kind, item.id, f.s.ID, retirement{item.id, time.Now().UTC(), "retention"}); err != nil {
			t.Fatal(err)
		}
	}
	m := metadataManager(t, f)
	// An administrator may first recover some missing artifacts, before the
	// inspection/approval step. An old tombstone must not resume cleanup yet.
	if _, err := m.Snapshots.Create(t.Context(), retiredSnapshot, f.s.ProjectDirectory, f.s.ManagedPaths, nil); err != nil {
		t.Fatal(err)
	}
	requests := 0
	tag := retiredRelease.Spec().Images[0].RetentionTag
	image := string(retiredRelease.Spec().Images[0].ImageID)
	api, err := client.New(client.WithHost("http://daemon.test"), client.WithAPIVersion("1.56"), client.WithHTTPClient(&http.Client{Transport: retentionRoundTrip(func(req *http.Request) (*http.Response, error) {
		requests++
		body := ""
		switch req.Method {
		case http.MethodGet:
			if !strings.HasSuffix(req.URL.Path, "/images/"+tag+"/json") {
				t.Fatalf("unexpected image inspect %s", req.URL.Path)
			}
			body = `{"Id":"` + image + `"}`
		case http.MethodDelete:
			if !strings.HasSuffix(req.URL.Path, "/images/"+tag) || req.URL.Query().Get("force") != "" || req.URL.Query().Get("noprune") != "1" {
				t.Fatalf("unsafe image deletion %s", req.URL)
			}
			body = `[{"Untagged":"` + tag + `"}]`
		default:
			t.Fatalf("unexpected daemon request %s %s", req.Method, req.URL)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	m.Engine = &docker.Engine{Client: api}
	if _, err := m.Rotate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatal("unreviewed metadata restore resumed Docker image cleanup")
	}
	if _, err := m.Snapshots.Load(t.Context(), retiredSnapshot.ID); err != nil {
		t.Fatalf("unreviewed metadata restore resumed snapshot cleanup: %v", err)
	}
	policy, err := m.Store.GetService(t.Context(), f.s.ID)
	if err != nil {
		t.Fatal(err)
	}
	policy.PolicyRevision++
	proposal, err := m.Store.CreateProposal(t.Context(), "restore-reviewed", policy, domain.Hash([]byte("new-configuration")), "local-admin", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Store.ApproveProposal(t.Context(), proposal.ID, proposal.Digest, "local-admin", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	pending, err := m.Store.MetadataRestoreNeedsReview(t.Context(), f.s.ID)
	if err != nil || pending {
		t.Fatal("new approved revision did not satisfy metadata review", err)
	}
	if _, err := m.Rotate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("reviewed retirement did not resume exact tag cleanup: %d requests", requests)
	}
	if _, err := os.Stat(filepath.Join(m.Config.StateDirectory, "snapshots", string(retiredSnapshot.ID))); !os.IsNotExist(err) {
		t.Fatal("reviewed retirement did not resume snapshot cleanup", err)
	}
}

func TestMetadataRestorePreservesRecordedUnpublishedAllocations(t *testing.T) {
	f := newPlanningFixture(t)
	m := metadataManager(t, f)
	if err := ensureStaging(m.Config.StateDirectory); err != nil {
		t.Fatal(err)
	}
	buildID, snapshotID := domain.ID("build-restored-unreviewed"), domain.ID("snap-restored-unreviewed")
	build := filepath.Join(stagingPath(m.Config.StateDirectory), string(buildID))
	partial := filepath.Join(m.Config.StateDirectory, "snapshots", string(snapshotID))
	for _, directory := range []string{build, filepath.Join(partial, "content")} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, filename := range []string{filepath.Join(build, "input"), filepath.Join(partial, "content", "input")} {
		if err := os.WriteFile(filename, []byte("restored partial source"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		kind      string
		id        domain.ID
		directory string
	}{{"build_allocation", buildID, string(buildID)}, {"snapshot_allocation", snapshotID, ""}} {
		if err := m.Store.PutImmutable(t.Context(), item.kind, item.id, f.s.ID, allocation{ID: item.id, Directory: item.directory, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.cleanupAllocations(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{build, partial} {
		if _, err := os.Stat(directory); err != nil {
			t.Fatalf("unreviewed recorded allocation removed: %s: %v", directory, err)
		}
	}
}

func TestRestoredCompletedBuildReceiptAllowsAbsentStagingDirectory(t *testing.T) {
	f := newPlanningFixture(t)
	op := retentionOperation(t, f, "completed-before-backup", domain.OperationBuild, "", f.baseline.ID)
	if _, err := jobs.New(f.m.Store).Transition(t.Context(), op.Spec.ID, domain.OperationFailed, domain.OutcomeEvidence{ActualStateKnown: true, ResultRecorded: true, Reason: "test completed before backup"}); err != nil {
		t.Fatal(err)
	}
	id := domain.ID("build-completed-before-backup")
	if err := f.m.Store.PutImmutable(t.Context(), "build_allocation", id, f.s.ID, allocation{ID: id, OperationID: op.Spec.ID, Directory: string(id), CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stagingPath(f.m.Config.StateDirectory)); !os.IsNotExist(err) {
		t.Fatal("test requires staging omitted from restored backup")
	}
	if err := f.m.cleanupAllocations(t.Context()); err != nil {
		t.Fatalf("completed receipt for omitted staging blocks post-restore jobs: %v", err)
	}
}
