package executor

import (
	"context"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/jobs"
)

type recoveryExecutionKey struct{}

func (m *Manager) CancelOperation(ctx context.Context, id, actor domain.ID) (domain.Operation, error) {
	return jobs.New(m.Store).RequestCancel(ctx, id, actor)
}

func (m *Manager) cancellationCheckpoint(ctx context.Context, id domain.ID) error {
	op, err := m.Store.GetOperation(ctx, id)
	if err != nil {
		return err
	}
	if op.CancelRequested {
		return jobs.ErrCancelRequested
	}
	return nil
}
