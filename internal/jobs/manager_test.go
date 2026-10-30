package jobs

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
)

func TestConflictWaitsForConfirmedOutcome(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(filepath.Join(t.TempDir(), "executor.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m := New(s)
	spec := domain.OperationSpec{ID: "op-a", Kind: domain.OperationDeploy, Initiator: "defender", IdempotencyKey: "deploy-a", ServiceID: "flags", ReleaseID: "release-a", ExpectedPolicyRevision: 1, ExpectedTreeDigest: domain.Hash(nil), Resources: []string{"service:flags", "compose:flags"}, TimeoutSeconds: 60}
	a, created, err := m.Submit(ctx, spec, domain.Hash([]byte("first")))
	if err != nil || !created {
		t.Fatalf("submit: %v", err)
	}
	if _, err := m.Start(ctx, a.Spec.ID); err != nil {
		t.Fatal(err)
	}
	spec.ID = "op-b"
	spec.IdempotencyKey = "deploy-b"
	b, _, err := m.Submit(ctx, spec, domain.Hash([]byte("second")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(ctx, b.Spec.ID); !errors.Is(err, store.ErrBusy) {
		t.Fatalf("conflicting operation started: %v", err)
	}
	if _, err := m.BeginMutation(ctx, a.Spec.ID, "recovery-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Transition(ctx, a.Spec.ID, domain.OperationCancelled, domain.OutcomeEvidence{ActualStateKnown: true, ResultRecorded: true}); err == nil {
		t.Fatal("cancellation after switching released locks without return")
	}
	if _, err := m.Start(ctx, b.Spec.ID); !errors.Is(err, store.ErrBusy) {
		t.Fatal("failed cancellation lost locks")
	}
	if _, err := m.Transition(ctx, a.Spec.ID, domain.OperationCancelled, domain.OutcomeEvidence{ActualStateKnown: true, ResultRecorded: true, ReturnedToPrevious: true}); err != nil {
		t.Fatal(err)
	}
	if op, err := m.Start(ctx, b.Spec.ID); err != nil || op.State != domain.OperationRunning {
		t.Fatalf("queued operation did not resume: %v", err)
	}
}
