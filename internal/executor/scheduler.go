package executor

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/jobs"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
)

type workLane string

const (
	laneBuild  workLane = "build"
	laneCopy   workLane = "copy"
	laneSwitch workLane = "switch"
)

func operationLane(kind domain.OperationKind) workLane {
	switch kind {
	case domain.OperationBuild:
		return laneBuild
	case domain.OperationPrepare, domain.OperationSnapshot, domain.OperationRestoreSnapshot, domain.OperationFetchSource:
		return laneCopy
	default:
		return laneSwitch
	}
}
func operationPriority(kind domain.OperationKind) int {
	switch kind {
	case domain.OperationRecover:
		return 0
	case domain.OperationRollback:
		return 1
	case domain.OperationStop:
		return 2
	default:
		return 3
	}
}
func prioritizeOperations(ops []domain.Operation) []domain.Operation {
	out := append([]domain.Operation{}, ops...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := operationPriority(out[i].Spec.Kind), operationPriority(out[j].Spec.Kind)
		if a != b {
			return a < b
		}
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].Spec.ID < out[j].Spec.ID
	})
	return out
}

type artifactGateKey struct{}

// withArtifactReleased is valid only from worker/recovery contexts that own the
// gate. Durable locks/pins and published reservations survive the unlocked work.
func (m *Manager) withArtifactReleased(ctx context.Context, work func(context.Context) error) error {
	owned, _ := ctx.Value(artifactGateKey{}).(bool)
	if !owned {
		return work(ctx)
	}
	m.artifactMu.Unlock()
	defer m.artifactMu.Lock()
	return work(context.WithValue(ctx, artifactGateKey{}, false))
}
func (m *Manager) warmup(ctx context.Context, s domain.Service) error {
	return m.withArtifactReleased(ctx, func(ctx context.Context) error { return m.warmupObserved(ctx, s) })
}
func (m *Manager) runChecks(ctx context.Context, s domain.Service, id domain.ID) error {
	return m.withArtifactReleased(ctx, func(ctx context.Context) error { return m.runChecksObserved(ctx, s, id) })
}

// Run gives Rollback/Recover precedence without interrupting a critical step.
// Lane limits bound long Docker/network/warmup jobs; the artifact gate preserves
// atomic quota checks, immutable publication and all filesystem mutations.
func (m *Manager) Run(ctx context.Context) error {
	owner, err := m.privateExecutorLock(".worker-owner")
	if err != nil {
		return err
	}
	defer owner.Close()
	m.proxyMu.Lock()
	err = m.reconcileCutoversOnStart(ctx)
	if err == nil {
		m.cutoverReady = true
	}
	m.proxyMu.Unlock()
	if err != nil {
		return err
	}
	defer func() {
		if m.cutoverCancel != nil {
			m.cutoverCancel()
		}
		m.proxyMu.Lock()
		m.cutoverReady = false
		m.cutoverClosing = true
		m.proxyMu.Unlock()
		m.cutoverWG.Wait()
	}()
	stopCapture := m.runCapturePublisher(ctx)
	defer stopCapture()
	return m.runScheduler(ctx, m.execute)
}
func (m *Manager) runScheduler(ctx context.Context, execute func(context.Context, domain.Operation) error) error {
	manager := jobs.New(m.Store)
	if _, err := manager.ReconcileOnStart(ctx); err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	policy := m.Config.Scheduler.Effective()
	limits := map[workLane]uint32{laneBuild: policy.Builds, laneCopy: policy.Copies, laneSwitch: policy.Switches}
	counts := map[workLane]uint32{}
	active := map[domain.ID]workLane{}
	type completion struct {
		id  domain.ID
		err error
	}
	completed := make(chan completion, 12)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case result := <-completed:
			counts[active[result.id]]--
			delete(active, result.id)
			if result.err != nil {
				return result.err
			}
		case <-ticker.C:
		}
		if ctx.Err() != nil {
			return nil
		}
		// Recovery is a fresh human approval of an unresolved operation. Serialize it
		// with switching jobs, while already running builds/fetches can finish safely.
		if counts[laneSwitch] == 0 {
			if worked, err := m.runRequestedRecovery(runCtx); err != nil {
				return err
			} else if worked {
				continue
			}
		}
		operations, err := m.Store.ListOperations(runCtx)
		if err != nil {
			return err
		}
		for _, op := range prioritizeOperations(operations) {
			lane := operationLane(op.Spec.Kind)
			if op.State != domain.OperationQueued || active[op.Spec.ID] != "" || counts[lane] >= limits[lane] {
				continue
			}
			// Do not mark a job running, hold durable resource locks or start its timeout
			// while waiting on the artifact gate. The next tick reconsiders priority.
			if !m.artifactMu.TryLock() {
				break
			}
			started, err := manager.Start(runCtx, op.Spec.ID)
			if errors.Is(err, store.ErrBusy) || errors.Is(err, store.ErrConflict) {
				m.artifactMu.Unlock()
				continue
			}
			if err != nil {
				m.artifactMu.Unlock()
				return err
			}
			active[op.Spec.ID] = lane
			counts[lane]++
			wg.Add(1)
			go func(started domain.Operation) {
				defer wg.Done()
				err := m.runScheduledOperation(runCtx, started, execute)
				completed <- completion{started.Spec.ID, err}
			}(started)
		}
	}
}

// Called with artifactMu already owned; it always releases ownership on return.
func (m *Manager) runScheduledOperation(ctx context.Context, op domain.Operation, execute func(context.Context, domain.Operation) error) error {
	defer m.artifactMu.Unlock()
	task, stop := context.WithTimeout(ctx, time.Duration(op.Spec.TimeoutSeconds)*time.Second)
	task = context.WithValue(context.WithValue(task, operationContextKey{}, op.Spec.ID), artifactGateKey{}, true)
	err := m.reclaim(task, false)
	if err == nil {
		err = execute(task, op)
	}
	stop()
	record, done := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer done()
	latest, getErr := m.Store.GetOperation(record, op.Spec.ID)
	if getErr != nil {
		return getErr
	}
	state := domain.OperationSucceeded
	evidence := domain.OutcomeEvidence{ActualStateKnown: true, ResultRecorded: true}
	if latest.CancelRequested {
		err = jobs.ErrCancelRequested
	}
	if err != nil {
		evidence.Reason = err.Error()
		state = domain.OperationFailed
		if errors.Is(err, jobs.ErrCancelRequested) {
			state = domain.OperationCancelled
		}
		if latest.MutationStarted {
			state = domain.OperationRequiresRecovery
			evidence.ActualStateKnown = false
		}
	}
	if err == nil {
		if stageErr := m.stage(record, op.Spec.ID, domain.StageRecording); stageErr != nil && !errors.Is(stageErr, store.ErrConflict) {
			return stageErr
		}
	}
	_, saveErr := jobs.New(m.Store).Transition(record, op.Spec.ID, state, evidence)
	if saveErr == nil {
		if maintenanceErr := m.reclaim(record, false); maintenanceErr != nil {
			_ = m.event(record, op.Spec.ID, "maintenance_warning", "retention cleanup deferred; protected artifacts retained")
		}
	}
	return saveErr
}
