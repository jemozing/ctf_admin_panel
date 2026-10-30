// Package jobs coordinates durable operations and executor-wide resource locks.
// It never decides that an interrupted Docker/filesystem step is safe to repeat.
package jobs

import (
	"context"
	"errors"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
)

type Manager struct {
	store *store.Store
	now   func() time.Time
}

func New(s *store.Store) *Manager { return &Manager{store: s, now: time.Now} }

func (m *Manager) Submit(ctx context.Context, spec domain.OperationSpec, inputHash domain.Digest) (domain.Operation, bool, error) {
	op, err := domain.NewOperation(spec, m.now())
	if err != nil {
		return domain.Operation{}, false, err
	}
	return m.store.BeginOperation(ctx, op, inputHash)
}

// Start leaves conflicting operations queued. The caller can retry Start after a
// resource release; Submit itself never creates another operation on retry.
func (m *Manager) Start(ctx context.Context, id domain.ID) (domain.Operation, error) {
	op, err := m.store.GetOperation(ctx, id)
	if err != nil {
		return op, err
	}
	if op.State != domain.OperationQueued {
		return op, store.ErrConflict
	}
	if err := m.store.Acquire(ctx, id, op.Spec.Resources); err != nil {
		return op, err
	}
	previous := op.UpdatedAt
	at := m.nextTime(previous)
	if err := op.Transition(domain.OperationRunning, domain.OutcomeEvidence{}, at); err != nil {
		return op, err
	}
	if err := m.store.UpdateOperation(ctx, op, previous); err != nil {
		_ = m.store.Release(ctx, id)
		return op, err
	}
	return op, nil
}

func (m *Manager) Transition(ctx context.Context, id domain.ID, next domain.OperationState, evidence domain.OutcomeEvidence) (domain.Operation, error) {
	for attempt := 0; attempt < 8; attempt++ {
		op, err := m.transition(ctx, id, next, evidence)
		if !errors.Is(err, store.ErrConflict) {
			return op, err
		}
	}
	return domain.Operation{}, store.ErrConflict
}

func (m *Manager) transition(ctx context.Context, id domain.ID, next domain.OperationState, evidence domain.OutcomeEvidence) (domain.Operation, error) {
	op, err := m.store.GetOperation(ctx, id)
	if err != nil {
		return op, err
	}
	if op.State == domain.OperationRunning && op.CancelRequested && next.Terminal() {
		evidence.Reason = ErrCancelRequested.Error()
		next = domain.OperationCancelled
		if op.MutationStarted && !evidence.ReturnedToPrevious {
			next = domain.OperationRequiresRecovery
			evidence.ActualStateKnown = false
		}
	}
	previous := op.UpdatedAt
	if err := op.Transition(next, evidence, m.nextTime(previous)); err != nil {
		return op, err
	}
	if err := m.store.UpdateOperation(ctx, op, previous); err != nil {
		return op, err
	}
	if next.Terminal() {
		if err := m.store.Release(ctx, id); err != nil {
			return op, err
		}
	}
	return op, nil
}

func (m *Manager) BeginMutation(ctx context.Context, id, recoveryPoint domain.ID) (domain.Operation, error) {
	op, err := m.store.GetOperation(ctx, id)
	if err != nil {
		return op, err
	}
	if op.CancelRequested {
		return op, ErrCancelRequested
	}
	previous := op.UpdatedAt
	if err := op.BeginMutation(recoveryPoint, m.nextTime(previous)); err != nil {
		return op, err
	}
	if err := m.store.UpdateOperation(ctx, op, previous); err != nil {
		return op, err
	}
	return op, nil
}

func (m *Manager) ReconcileOnStart(ctx context.Context) ([]domain.Operation, error) {
	return m.store.MarkInterrupted(ctx, m.now())
}

func (m *Manager) nextTime(previous time.Time) time.Time {
	at := m.now().UTC()
	if !at.After(previous) {
		return previous.Add(time.Nanosecond)
	}
	return at
}
