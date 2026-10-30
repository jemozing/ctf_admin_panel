package executor

import (
	"context"
	"errors"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/jobs"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
)

func (m *Manager) stage(ctx context.Context, id domain.ID, next domain.OperationStage) error {
	for attempt := 0; attempt < 8; attempt++ {
		err := m.updateStage(ctx, id, next)
		if !errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	return store.ErrConflict
}
func (m *Manager) updateStage(ctx context.Context, id domain.ID, next domain.OperationStage) error {
	op, err := m.Store.GetOperation(ctx, id)
	if err != nil {
		return err
	}
	if op.CancelRequested && next != domain.StageRecording && ctx.Value(recoveryExecutionKey{}) != true {
		return jobs.ErrCancelRequested
	}
	previous := op.UpdatedAt
	op.Stage = next
	op.UpdatedAt = time.Now().UTC()
	if !op.UpdatedAt.After(previous) {
		op.UpdatedAt = previous.Add(time.Nanosecond)
	}
	return m.Store.UpdateOperation(ctx, op, previous)
}
func healthSignals(items []struct{ state, health string }) []domain.HealthSignal {
	now := time.Now().UTC()
	container := domain.HealthHealthy
	docker := domain.HealthNotConfigured
	if len(items) == 0 {
		container = domain.HealthUnknown
	}
	for _, item := range items {
		if item.state != "running" {
			container = domain.HealthUnhealthy
		}
		switch item.health {
		case "healthy":
			if docker == domain.HealthNotConfigured {
				docker = domain.HealthHealthy
			}
		case "unhealthy":
			docker = domain.HealthUnhealthy
		case "starting":
			if docker != domain.HealthUnhealthy {
				docker = domain.HealthUnknown
			}
		}
	}
	return []domain.HealthSignal{{Source: domain.HealthContainer, State: container, ObservedAt: now, ValidUntil: now.Add(15 * time.Second)}, {Source: domain.HealthDocker, State: docker, ObservedAt: now, ValidUntil: now.Add(15 * time.Second)}, {Source: domain.HealthReadiness, State: domain.HealthNotConfigured}, {Source: domain.HealthFunctional, State: domain.HealthNotConfigured}, {Source: domain.HealthExternal, State: domain.HealthUnknown}}
}
