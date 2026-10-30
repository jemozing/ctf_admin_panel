package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

var ctx = context.Background()

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "executor.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func makeOperation(t *testing.T, id, service, key string, extra ...string) domain.Operation {
	t.Helper()
	resources := append([]string{"service:" + service}, extra...)
	op, err := domain.NewOperation(domain.OperationSpec{ID: domain.ID(id), Kind: domain.OperationDeploy, Initiator: "defender", IdempotencyKey: key, ServiceID: domain.ID(service), ReleaseID: "release-1", ExpectedPolicyRevision: 1, ExpectedTreeDigest: domain.Hash([]byte("active")), Resources: resources, TimeoutSeconds: 300}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func runOperation(t *testing.T, s *Store, op domain.Operation) domain.Operation {
	t.Helper()
	if err := s.Acquire(ctx, op.Spec.ID, op.Spec.Resources); err != nil {
		t.Fatal(err)
	}
	previous := op.UpdatedAt
	if err := op.Transition(domain.OperationRunning, domain.OutcomeEvidence{}, previous.Add(time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateOperation(ctx, op, previous); err != nil {
		t.Fatal(err)
	}
	return op
}

func TestWALFullAndImmutableRecord(t *testing.T) {
	s := openTestStore(t)
	journal, syncMode, err := s.Durability(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if journal != "wal" || syncMode != 2 {
		t.Fatalf("insufficient durability: %s %d", journal, syncMode)
	}
	value := map[string]string{"config": "original"}
	if err := s.PutImmutable(ctx, "configuration", "config-1", "flags", value); err != nil {
		t.Fatal(err)
	}
	if err := s.PutImmutable(ctx, "configuration", "config-1", "flags", value); err != nil {
		t.Fatal(err)
	}
	value["config"] = "replaced"
	if err := s.PutImmutable(ctx, "configuration", "config-1", "flags", value); !errors.Is(err, ErrImmutable) {
		t.Fatalf("replacement accepted: %v", err)
	}
	if _, err := s.db.Exec("UPDATE records SET payload='{}'"); err == nil {
		t.Fatal("SQL can mutate immutable records")
	}
	var actual map[string]string
	if err := s.Get(ctx, "configuration", "config-1", &actual); err != nil {
		t.Fatal(err)
	}
	if actual["config"] != "original" {
		t.Fatal("stored object changed")
	}
}

func TestConcurrentRetriesCreateExactlyOneOperation(t *testing.T) {
	s := openTestStore(t)
	const workers = 12
	var wg sync.WaitGroup
	results := make(chan domain.Operation, workers)
	created := make(chan bool, workers)
	errs := make(chan error, workers)
	ops := make([]domain.Operation, workers)
	for i := range ops {
		ops[i] = makeOperation(t, fmt.Sprintf("op-%d", i), "flags", "same-key")
	}
	for _, op := range ops {
		wg.Add(1)
		go func(op domain.Operation) {
			defer wg.Done()
			result, isNew, err := s.BeginOperation(ctx, op, domain.Hash([]byte("same input")))
			if err != nil {
				errs <- err
				return
			}
			results <- result
			created <- isNew
		}(op)
	}
	wg.Wait()
	close(results)
	close(created)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var first domain.ID
	for op := range results {
		if first == "" {
			first = op.Spec.ID
		}
		if op.Spec.ID != first {
			t.Fatal("retry created another operation")
		}
	}
	count := 0
	for value := range created {
		if value {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("created=%d", count)
	}
	conflicting := makeOperation(t, "op-conflict", "flags", "same-key")
	if _, _, err := s.BeginOperation(ctx, conflicting, domain.Hash([]byte("different input"))); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed request accepted: %v", err)
	}
	events, err := s.Events(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != "accepted" {
		t.Fatalf("duplicate accepted events: %#v", events)
	}
}

func TestLocksCoverIntersectingPathsAndRetainUnknownState(t *testing.T) {
	s := openTestStore(t)
	a := makeOperation(t, "op-a", "alpha", "key-a", "path:/srv/game/app")
	b := makeOperation(t, "op-b", "beta", "key-b", "path:/srv/game/app/nested")
	for _, op := range []domain.Operation{a, b} {
		if _, _, err := s.BeginOperation(ctx, op, domain.Hash([]byte(op.Spec.ID))); err != nil {
			t.Fatal(err)
		}
	}
	a = runOperation(t, s, a)
	if err := s.Acquire(ctx, b.Spec.ID, b.Spec.Resources); !errors.Is(err, ErrBusy) {
		t.Fatalf("overlapping path lock accepted: %v", err)
	}
	if err := s.Release(ctx, a.Spec.ID); err == nil {
		t.Fatal("running operation released resources")
	}
	previous := a.UpdatedAt
	if err := a.Transition(domain.OperationRequiresRecovery, domain.OutcomeEvidence{Reason: "unknown Docker response"}, previous.Add(time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateOperation(ctx, a, previous); err != nil {
		t.Fatal(err)
	}
	if err := s.Release(ctx, a.Spec.ID); err == nil {
		t.Fatal("unresolved operation released resources")
	}
	if err := s.Acquire(ctx, b.Spec.ID, b.Spec.Resources); !errors.Is(err, ErrBusy) {
		t.Fatal("recovery operation lost lock")
	}
	if err := s.Acquire(ctx, b.Spec.ID, []string{"service:beta"}); err == nil {
		t.Fatal("partial resource set accepted")
	}
}

func TestRestartMarksInterruptedWithoutReplayAndPreservesRecovery(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "executor.db")
	s, err := Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	op := makeOperation(t, "op-a", "flags", "deploy-a", "compose:round_one")
	if _, _, err := s.BeginOperation(ctx, op, domain.Hash([]byte("input"))); err != nil {
		t.Fatal(err)
	}
	op = runOperation(t, s, op)
	previous := op.UpdatedAt
	if err := op.BeginMutation("recovery-1", previous.Add(time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateOperation(ctx, op, previous); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	interrupted, err := s.MarkInterrupted(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(interrupted) != 1 || interrupted[0].State != domain.OperationInterrupted || interrupted[0].RecoveryPointID != "recovery-1" {
		t.Fatalf("bad recovery state: %#v", interrupted)
	}
	op, err = s.GetOperation(ctx, "op-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Release(ctx, op.Spec.ID); err == nil {
		t.Fatal("startup reconciliation released locks")
	}
	events, err := s.Events(ctx, op.Spec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 4 {
		t.Fatalf("missing durable event history: %d", len(events))
	}
	if _, err := s.db.Exec("UPDATE events SET message='forged'"); err == nil {
		t.Fatal("journal is mutable")
	}
	if _, err := s.db.Exec("DELETE FROM events"); err == nil {
		t.Fatal("journal can be deleted")
	}
	previous = op.UpdatedAt
	if err := op.Transition(domain.OperationSucceeded, domain.OutcomeEvidence{ActualStateKnown: true, ResultRecorded: true}, previous.Add(time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateOperation(ctx, op, previous); err != nil {
		t.Fatal(err)
	}
	if err := s.Release(ctx, op.Spec.ID); err != nil {
		t.Fatal(err)
	}
}

func TestOptimisticUpdatesRejectStaleAndFalseSuccess(t *testing.T) {
	s := openTestStore(t)
	op := makeOperation(t, "op-a", "flags", "key-a")
	if _, _, err := s.BeginOperation(ctx, op, domain.Hash(nil)); err != nil {
		t.Fatal(err)
	}
	previous := op.UpdatedAt
	forged := op
	forged.State = domain.OperationRunning
	forged.UpdatedAt = previous.Add(time.Nanosecond)
	if err := s.UpdateOperation(ctx, forged, previous); err == nil {
		t.Fatal("running without locks accepted")
	}
	op = runOperation(t, s, op)
	stale := op
	previous = op.UpdatedAt
	op.Stage = domain.StageCopying
	op.UpdatedAt = previous.Add(time.Nanosecond)
	if err := s.UpdateOperation(ctx, op, previous); err != nil {
		t.Fatal(err)
	}
	stale.UpdatedAt = op.UpdatedAt.Add(time.Nanosecond)
	if err := s.UpdateOperation(ctx, stale, previous); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale overwrite accepted: %v", err)
	}
	previous = op.UpdatedAt
	op.State = domain.OperationSucceeded
	op.UpdatedAt = previous.Add(time.Nanosecond)
	if err := s.UpdateOperation(ctx, op, previous); err == nil {
		t.Fatal("forged success without evidence persisted")
	}
}

func policyFixture() domain.Service {
	return domain.Service{SchemaVersion: 1, ID: "flags", Name: "Flags", ProjectDirectory: "/srv/ctf/flags", SourceDirectory: "/srv/work/flags", ComposeProject: "flags", ComposeFiles: []string{"compose.yaml"}, ManagedPaths: []domain.ManagedPath{{Path: "app", Kind: domain.ManagedCode}}, Targets: []string{"app"}, Containers: []domain.ContainerRef{{Component: "app", ID: strings.Repeat("a", 64), ImageID: domain.Hash([]byte("app")), Role: domain.RoleApplication}}, PolicyRevision: 1, FileMapRevision: 1}
}

func TestApprovalBindsPayloadAndCurrentPolicyRevision(t *testing.T) {
	s := openTestStore(t)
	policy := policyFixture()
	at := time.Now().UTC()
	p, err := s.CreateProposal(ctx, "proposal-1", policy, domain.Hash([]byte("normalized config")), "admin", at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveProposal(ctx, p.ID, domain.Hash([]byte("wrong digest")), "local-admin", at); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong digest approved: %v", err)
	}
	changed := policy
	changed.Name = "Changed"
	if _, err := s.CreateProposal(ctx, p.ID, changed, p.ConfigurationDigest, "admin", at); !errors.Is(err, ErrImmutable) {
		t.Fatalf("proposal replaced after review: %v", err)
	}
	if _, err := s.ApproveProposal(ctx, p.ID, p.Digest, "local-admin", at); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveProposal(ctx, p.ID, p.Digest, "local-admin", at); err != nil {
		t.Fatal(err)
	}
	actual, err := s.GetService(ctx, "flags")
	if err != nil {
		t.Fatal(err)
	}
	if actual.Name != "Flags" {
		t.Fatal("wrong policy approved")
	}
	policy.PolicyRevision = 2
	policy.Name = "Flags updated"
	next, err := s.CreateProposal(ctx, "proposal-2", policy, p.ConfigurationDigest, "admin", at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveProposal(ctx, next.ID, next.Digest, "local-admin", at); err != nil {
		t.Fatal(err)
	}
	// Reapproving an old proposal is idempotent and must not revert current policy.
	if _, err := s.ApproveProposal(ctx, p.ID, p.Digest, "local-admin", at); err != nil {
		t.Fatal(err)
	}
	actual, err = s.GetService(ctx, "flags")
	if err != nil {
		t.Fatal(err)
	}
	if actual.PolicyRevision != 2 {
		t.Fatal("old approval reverted policy")
	}
	other := policyFixture()
	other.ID = "other"
	other.ProjectDirectory = "/srv/ctf/other"
	other.SourceDirectory = "/srv/work/other"
	conflict, err := s.CreateProposal(ctx, "proposal-other", other, p.ConfigurationDigest, "admin", at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveProposal(ctx, conflict.ID, conflict.Digest, "local-admin", at); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate Compose project registered: %v", err)
	}
}
