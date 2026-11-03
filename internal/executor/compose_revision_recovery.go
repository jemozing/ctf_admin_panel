package executor

import (
	"context"
	"errors"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/filesystem"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func (m *Manager) recoverFailedComposeSwitch(ctx context.Context, op domain.Operation) (bool, error) {
	if op.Spec.Kind != domain.OperationDeploy && op.Spec.Kind != domain.OperationRollback {
		return false, nil
	}
	task, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	task = context.WithValue(context.WithValue(context.WithValue(task, operationContextKey{}, op.Spec.ID), recoveryExecutionKey{}, true), artifactGateKey{}, true)
	var input operationInput
	if err := m.Store.Get(task, "operation_input", op.Spec.ID, &input); err != nil {
		return false, nil
	}
	if !input.Plan.ComposeChange || !input.Request.ConfirmComposeChange {
		return false, nil
	}
	if err := m.event(task, op.Spec.ID, "compose_recovery_started", "restoring the previous Compose release after a failed switch"); err != nil {
		return true, err
	}
	s, err := m.Store.GetService(task, op.Spec.ServiceID)
	if err != nil {
		return true, err
	}
	var point recoveryPoint
	if err := m.Store.Get(task, "recovery_point", op.RecoveryPointID, &point); err != nil {
		return true, err
	}
	before, err := m.loadSnapshot(task, point.SnapshotID)
	if err != nil {
		return true, err
	}
	target, err := m.loadRelease(task, s, op.Spec.ReleaseID)
	if err != nil {
		return true, err
	}
	after, err := m.loadSnapshot(task, target.Spec().SnapshotID)
	if err != nil {
		return true, err
	}
	current, err := filesystem.Observe(task, s.ProjectDirectory, s.ManagedPaths, nil)
	if err != nil {
		return true, err
	}
	if !knownComposeRecoveryTree(before.Manifest, after.Manifest, current) {
		return true, errors.New("active files differ from both approved trees; review a recovery plan")
	}
	return true, m.compensate(task, op, input.Request, transport.PreviewResult{CurrentTreeDigest: current.Digest()})
}

func knownComposeRecoveryTree(before, after, actual domain.Manifest) bool {
	type fileState struct {
		before domain.ManifestEntry
		after  domain.ManifestEntry
		actual domain.ManifestEntry
	}
	states := map[string]fileState{}
	for _, entry := range before.Entries() {
		states[entry.Path] = fileState{before: entry}
	}
	for _, entry := range after.Entries() {
		state := states[entry.Path]
		state.after = entry
		states[entry.Path] = state
	}
	for _, entry := range actual.Entries() {
		state := states[entry.Path]
		state.actual = entry
		states[entry.Path] = state
	}
	for _, state := range states {
		if state.actual != state.before && state.actual != state.after {
			return false
		}
	}
	return true
}
