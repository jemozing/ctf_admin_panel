package jobs

import (
	"context"
	"errors"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"path/filepath"
	"testing"
)

func TestSafeCancellationAndRecoveryLocks(t *testing.T) {
	for _, phase := range []string{"queued", "pre_mutation", "post_mutation"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			s, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			m := New(s)
			spec := domain.OperationSpec{ID: "op-a", Kind: domain.OperationDeploy, Initiator: "admin", IdempotencyKey: "a", ServiceID: "svc", ReleaseID: "r-a", ExpectedPolicyRevision: 1, ExpectedTreeDigest: domain.Hash(nil), Resources: []string{"service:svc"}, TimeoutSeconds: 60}
			if _, _, err := m.Submit(ctx, spec, domain.Hash(nil)); err != nil {
				t.Fatal(err)
			}
			if phase != "queued" {
				if _, err := m.Start(ctx, spec.ID); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "post_mutation" {
				if _, err := m.BeginMutation(ctx, spec.ID, "point-a"); err != nil {
					t.Fatal(err)
				}
			}
			op, err := m.RequestCancel(ctx, spec.ID, "admin")
			if err != nil {
				t.Fatal(err)
			}
			if !op.CancelRequested {
				t.Fatal("request not durable")
			}
			if phase == "queued" {
				if op.State != domain.OperationCancelled {
					t.Fatal(op.State)
				}
			} else {
				if phase == "pre_mutation" {
					if _, err := m.BeginMutation(ctx, spec.ID, "point-a"); !errors.Is(err, ErrCancelRequested) {
						t.Fatalf("mutation after cancellation: %v", err)
					}
				}
				op, err = m.Transition(ctx, spec.ID, domain.OperationSucceeded, domain.OutcomeEvidence{ActualStateKnown: true, ResultRecorded: true})
				if err != nil {
					t.Fatal(err)
				}
			}
			spec.ID = "op-b"
			spec.IdempotencyKey = "b"
			if _, _, err := m.Submit(ctx, spec, domain.Hash(nil)); err != nil {
				t.Fatal(err)
			}
			_, err = m.Start(ctx, spec.ID)
			if phase == "post_mutation" {
				if op.State != domain.OperationRequiresRecovery || !errors.Is(err, store.ErrBusy) {
					t.Fatalf("unsafe cancellation: state=%s error=%v", op.State, err)
				}
				if _, err := m.Transition(ctx, "op-a", domain.OperationInterrupted, domain.OutcomeEvidence{Reason: "reviewed"}); err != nil {
					t.Fatal(err)
				}
				if _, err := m.Transition(ctx, "op-a", domain.OperationRunning, domain.OutcomeEvidence{ActualStateKnown: true}); err != nil {
					t.Fatal(err)
				}
				op, err = m.Transition(ctx, "op-a", domain.OperationFailed, domain.OutcomeEvidence{ActualStateKnown: true, ResultRecorded: true, ReturnedToPrevious: true, Reason: "recovered"})
				if err != nil || op.State != domain.OperationCancelled {
					t.Fatalf("confirmed recovery: %s %v", op.State, err)
				}
				if _, err := m.Start(ctx, "op-b"); err != nil {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatalf("safe cancellation retained lock: %v", err)
			}
		})
	}
}
