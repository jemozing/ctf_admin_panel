package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
)

// ErrCancelRequested is a safe checkpoint, never a signal to kill a mutating
// child process. Once mutation began the executor retains locks for Recover.
var ErrCancelRequested = errors.New("cancellation requested at a safe checkpoint")

func (m *Manager) RequestCancel(ctx context.Context, id, actor domain.ID) (domain.Operation, error) {
	if err := actor.Validate(); err != nil {
		return domain.Operation{}, err
	}
	for attempt := 0; attempt < 8; attempt++ {
		op, err := m.store.GetOperation(ctx, id)
		if err != nil {
			return op, err
		}
		if op.CancelRequested {
			return op, nil
		}
		if op.State != domain.OperationQueued && op.State != domain.OperationRunning {
			return op, fmt.Errorf("%w: only queued or running operations can be cancelled", store.ErrConflict)
		}
		previous := op.UpdatedAt
		at := m.nextTime(previous)
		if err := op.RequestCancel(at); err != nil {
			return op, err
		}
		if op.State == domain.OperationQueued {
			if err := op.Transition(domain.OperationCancelled, domain.OutcomeEvidence{ActualStateKnown: true, ResultRecorded: true, Reason: "cancelled before execution"}, at); err != nil {
				return op, err
			}
		}
		if err := m.store.UpdateOperation(ctx, op, previous); errors.Is(err, store.ErrConflict) {
			continue
		} else if err != nil {
			return op, err
		}
		if err := m.store.AppendEvent(ctx, store.Event{OperationID: id, At: time.Now().UTC(), Kind: "cancel_requested", Message: "Safe cancellation requested by " + string(actor)}); err != nil {
			return op, err
		}
		if op.State.Terminal() {
			if err := m.store.Release(ctx, id); err != nil {
				return op, err
			}
		}
		return op, nil
	}
	return domain.Operation{}, store.ErrConflict
}
