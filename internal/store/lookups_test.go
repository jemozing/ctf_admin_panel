package store

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

func TestConfigurationLookupUsesApprovedExactRevision(t *testing.T) {
	s := openTestStore(t)
	service := policyFixture()
	first := domain.Hash([]byte("first configuration"))
	second := domain.Hash([]byte("second configuration"))
	at := time.Now().UTC()
	p, err := s.CreateProposal(ctx, "proposal-first", service, first, "admin", at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetServiceConfiguration(ctx, service.ID, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pending proposal exposed: %v", err)
	}
	if _, err := s.ApproveProposal(ctx, p.ID, p.Digest, "admin", at); err != nil {
		t.Fatal(err)
	}
	service.PolicyRevision = 2
	p2, err := s.CreateProposal(ctx, "proposal-next", service, second, "admin", at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	found, err := s.GetServiceConfiguration(ctx, service.ID, 1)
	if err != nil || found != first {
		t.Fatalf("pending proposal replaced current binding: %s %v", found, err)
	}
	if _, err := s.GetServiceConfiguration(ctx, service.ID, 2); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pending second revision exposed: %v", err)
	}
	if _, err := s.ApproveProposal(ctx, p2.ID, p2.Digest, "admin", at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for revision, want := range map[uint64]domain.Digest{1: first, 2: second} {
		found, err := s.GetServiceConfiguration(ctx, service.ID, revision)
		if err != nil || found != want {
			t.Fatalf("wrong revision binding: %s %v", found, err)
		}
	}
	if _, err := s.GetServiceConfiguration(ctx, "missing-service", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing service: %v", err)
	}
	if _, err := s.GetServiceConfiguration(ctx, service.ID, 0); err == nil {
		t.Fatal("zero revision accepted")
	}
}
func TestOperationLookupScopesActorAndValidatesStoredIdentity(t *testing.T) {
	s := openTestStore(t)
	op := makeOperation(t, "lookup-one", "flags", "lookup-key")
	digest := domain.Hash([]byte("first input"))
	if _, _, err := s.FindOperation(ctx, op.Spec.Initiator, op.Spec.IdempotencyKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing operation: %v", err)
	}
	if _, _, err := s.BeginOperation(ctx, op, digest); err != nil {
		t.Fatal(err)
	}
	found, hash, err := s.FindOperation(ctx, op.Spec.Initiator, op.Spec.IdempotencyKey)
	if err != nil || found.Spec.ID != op.Spec.ID || hash != digest {
		t.Fatalf("wrong operation lookup: %#v %s %v", found, hash, err)
	}
	if _, _, err := s.FindOperation(ctx, "another-actor", op.Spec.IdempotencyKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("idempotency leaked across actors: %v", err)
	}
	forged := op
	forged.Spec.Initiator = "forged-actor"
	raw, _ := json.Marshal(forged)
	if _, err := s.db.Exec("UPDATE operations SET payload=? WHERE id=?", raw, op.Spec.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.FindOperation(ctx, op.Spec.Initiator, op.Spec.IdempotencyKey); err == nil {
		t.Fatal("payload/query identity mismatch accepted")
	}
}

func TestApprovalCannotReplacePolicyUnderRunningOperation(t *testing.T) {
	s := openTestStore(t)
	service := policyFixture()
	at := time.Now().UTC()
	p, err := s.CreateProposal(ctx, "proposal-lock-1", service, domain.Hash([]byte("config")), "admin", at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveProposal(ctx, p.ID, p.Digest, "admin", at); err != nil {
		t.Fatal(err)
	}
	spec := domain.OperationSpec{ID: "operation-lock", Kind: domain.OperationSnapshot, ServiceID: service.ID, Initiator: "admin", IdempotencyKey: "lock", ExpectedPolicyRevision: 1, ExpectedTreeDigest: domain.Hash([]byte("tree")), Resources: []string{"service:" + string(service.ID)}, TimeoutSeconds: 60}
	op, err := domain.NewOperation(spec, at)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.BeginOperation(ctx, op, domain.Hash([]byte("request"))); err != nil {
		t.Fatal(err)
	}
	if err := s.Acquire(ctx, op.Spec.ID, op.Spec.Resources); err != nil {
		t.Fatal(err)
	}
	service.PolicyRevision = 2
	p, err = s.CreateProposal(ctx, "proposal-lock-2", service, domain.Hash([]byte("config-2")), "admin", at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveProposal(ctx, p.ID, p.Digest, "admin", at); !errors.Is(err, ErrBusy) {
		t.Fatalf("policy replaced while resource locked: %v", err)
	}
}
