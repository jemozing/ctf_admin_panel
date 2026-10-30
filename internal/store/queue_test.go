package store

import (
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

func TestQueueObservationUsesHeldPathOwnerAndDoesNotWriteJournal(t *testing.T) {
	s := openTestStore(t)
	owner := makeOperation(t, "owner", "service-a", "owner", "path:/srv/shared/code")
	owner.Spec.Initiator = "local-admin"
	waiter := makeOperation(t, "waiter", "service-b", "waiter", "path:/srv/shared/code/subtree")
	independent := makeOperation(t, "independent", "service-c", "independent", "path:/srv/shared/code-other")
	for _, op := range []domain.Operation{owner, waiter, independent} {
		if _, _, err := s.BeginOperation(t.Context(), op, domain.Hash([]byte(op.Spec.ID))); err != nil {
			t.Fatal(err)
		}
	}
	owner = runOperation(t, s, owner)
	before, err := s.Events(t.Context(), waiter.Spec.ID)
	if err != nil {
		t.Fatal(err)
	}
	waits, err := s.OperationQueueWaits(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := waits[owner.Spec.ID]; ok {
		t.Fatal("running operation shown as waiting")
	}
	if len(waits[waiter.Spec.ID]) != 1 {
		t.Fatalf("missing overlapping path blocker: %#v", waits)
	}
	blocker := waits[waiter.Spec.ID][0]
	if blocker.Resource != "path:/srv/shared/code" || blocker.OperationID != owner.Spec.ID || blocker.Actor != "local-admin" {
		t.Fatalf("wrong owner observation: %#v", blocker)
	}
	if len(waits[independent.Spec.ID]) != 0 {
		t.Fatal("non-overlapping sibling blocked")
	}
	after, err := s.Events(t.Context(), waiter.Spec.ID)
	if err != nil || len(after) != len(before) {
		t.Fatal("queue observation wrote journal", err)
	}
	previous := owner.UpdatedAt
	if err := owner.Transition(domain.OperationSucceeded, domain.OutcomeEvidence{ActualStateKnown: true, ResultRecorded: true}, previous.Add(time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateOperation(t.Context(), owner, previous); err != nil {
		t.Fatal(err)
	}
	waits, err = s.OperationQueueWaits(t.Context())
	if err != nil || len(waits[waiter.Spec.ID]) != 0 {
		t.Fatal("released owner still blocks", waits, err)
	}
}

func TestQueueObservationCannotBePersisted(t *testing.T) {
	s := openTestStore(t)
	op := makeOperation(t, "view", "service", "view")
	op.QueueWait = &domain.QueueWait{Reason: "scheduler", Lane: "switch", Limit: 1}
	if _, _, err := s.BeginOperation(t.Context(), op, domain.Hash(nil)); err == nil {
		t.Fatal("derived queue view persisted in new operation")
	}
	op.QueueWait = nil
	if _, _, err := s.BeginOperation(t.Context(), op, domain.Hash(nil)); err != nil {
		t.Fatal(err)
	}
	previous := op.UpdatedAt
	op.UpdatedAt = previous.Add(time.Nanosecond)
	op.QueueWait = &domain.QueueWait{Reason: "resource_locked"}
	if err := s.UpdateOperation(t.Context(), op, previous); err == nil {
		t.Fatal("derived queue view persisted in journal update")
	}
	raw, err := s.GetOperation(t.Context(), op.Spec.ID)
	if err != nil || raw.QueueWait != nil {
		t.Fatal("raw operation has queue view", raw, err)
	}
}
