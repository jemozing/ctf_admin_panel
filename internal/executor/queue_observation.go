package executor

import (
	"context"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

func (m *Manager) observeOperationQueue(ctx context.Context, operations []domain.Operation) error {
	waits, err := m.Store.OperationQueueWaits(ctx)
	if err != nil {
		return err
	}
	policy := m.Config.Scheduler.Effective()
	limits := map[workLane]uint32{laneBuild: policy.Builds, laneCopy: policy.Copies, laneSwitch: policy.Switches}
	running := map[workLane][]domain.Operation{}
	for _, op := range operations {
		if op.State == domain.OperationRunning {
			lane := operationLane(op.Spec.Kind)
			running[lane] = append(running[lane], op)
		}
	}
	for i := range operations {
		op := &operations[i]
		op.QueueWait = nil
		if op.State != domain.OperationQueued {
			continue
		}
		lane := operationLane(op.Spec.Kind)
		view := &domain.QueueWait{Reason: "scheduler", Blockers: []domain.QueueBlocker{}, Lane: string(lane), Limit: limits[lane]}
		if blockers := waits[op.Spec.ID]; len(blockers) > 0 {
			view.Reason = "resource_locked"
			view.Blockers = blockers
		} else if uint32(len(running[lane])) >= limits[lane] {
			view.Reason = "lane_limit"
			for _, owner := range running[lane] {
				view.Blockers = append(view.Blockers, domain.QueueBlocker{Resource: "lane:" + string(lane), OperationID: owner.Spec.ID, Actor: owner.Spec.Initiator})
			}
		}
		op.QueueWait = view
	}
	return nil
}
