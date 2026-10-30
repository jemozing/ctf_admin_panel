package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/filesystem"
	"github.com/ctf-service-manager/ctf-service-manager/internal/jobs"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

type recoveryPoint struct {
	SnapshotID  domain.ID         `json:"snapshot_id"`
	ReleaseID   domain.ID         `json:"release_id"`
	State       runtimeState      `json:"state"`
	PriorStates map[string]string `json:"prior_states,omitempty"`
}
type recoveryRequest struct {
	OperationID domain.ID               `json:"operation_id"`
	Request     transport.SubmitRequest `json:"request"`
	InputHash   domain.Digest           `json:"input_hash"`
}

func (m *Manager) previewRecovery(ctx context.Context, s domain.Service, st runtimeState, req transport.SubmitRequest, current domain.Manifest) (transport.PreviewResult, error) {
	result := transport.PreviewResult{ServiceID: s.ID, Action: domain.OperationRecover, RecoveryOperationID: req.RecoveryOperationID, Targets: s.Targets, PolicyRevision: s.PolicyRevision, CurrentTreeDigest: current.Digest(), ChangedFiles: []transport.FileChange{}}
	op, err := m.Store.GetOperation(ctx, req.RecoveryOperationID)
	if err != nil {
		return result, err
	}
	if op.Spec.ServiceID != s.ID || op.Spec.ExpectedPolicyRevision != s.PolicyRevision || (op.State != domain.OperationInterrupted && op.State != domain.OperationRequiresRecovery) {
		return result, errors.New("recovery requires an unresolved operation under the same service policy")
	}
	if !op.MutationStarted {
		data, _ := json.Marshal(struct {
			Plan      transport.PreviewResult
			Operation domain.Operation
		}{result, op})
		result.PlanDigest = domain.Hash(data)
		return result, nil
	}
	if op.RecoveryPointID == "" {
		return result, errors.New("this operation has no file recovery point; local administrator reconciliation is required")
	}
	var point recoveryPoint
	if err := m.Store.Get(ctx, "recovery_point", op.RecoveryPointID, &point); err != nil {
		return result, err
	}
	release, err := m.loadRelease(ctx, s, point.ReleaseID)
	if err != nil {
		return result, err
	}
	snapshot, err := m.loadSnapshot(ctx, point.SnapshotID)
	if err != nil {
		return result, err
	}
	result.ActiveReleaseID = st.CurrentReleaseID
	result.TargetReleaseID = point.ReleaseID
	result.Images = release.Spec().Images
	result.ChangedFiles = manifestDiff(current, snapshot.Manifest)
	result.HasRollback = true
	for _, d := range s.DataPaths {
		result.DataCompatibilityRequired = result.DataCompatibilityRequired || d.Significant
	}
	data, _ := json.Marshal(struct {
		Plan      transport.PreviewResult
		Operation domain.Operation
		Sequence  uint64
	}{result, op, st.Sequence})
	result.PlanDigest = domain.Hash(data)
	return result, nil
}
func (m *Manager) requestRecovery(ctx context.Context, req transport.SubmitRequest, hash domain.Digest) (domain.Operation, error) {
	// Idempotency covers a separate, append-only recovery intent while preserving
	// the original operation's locks and mutation evidence until compensation ends.
	records, err := m.Store.List(ctx, "recovery_request", req.ServiceID)
	if err != nil {
		return domain.Operation{}, err
	}
	for _, record := range records {
		var v recoveryRequest
		if err := json.Unmarshal(record.Payload, &v); err != nil {
			return domain.Operation{}, err
		}
		if v.Request.Initiator == req.Initiator && v.Request.IdempotencyKey == req.IdempotencyKey {
			if v.InputHash != hash {
				return domain.Operation{}, store.ErrIdempotencyConflict
			}
			return m.Store.GetOperation(ctx, v.OperationID)
		}
	}
	plan, err := m.Preview(ctx, req)
	if err != nil {
		return domain.Operation{}, err
	}
	if req.PlanDigest != plan.PlanDigest {
		return domain.Operation{}, fmt.Errorf("%w: review a fresh recovery preview", store.ErrConflict)
	}
	if plan.DataCompatibilityRequired && !req.ConfirmDataCompatibility {
		return domain.Operation{}, errors.New("confirm persistent data compatibility before recovery")
	}
	op, err := m.Store.GetOperation(ctx, req.RecoveryOperationID)
	if err != nil {
		return op, err
	}
	if err := m.Store.PutImmutable(ctx, "recovery_request", NewID("recover-"), req.ServiceID, recoveryRequest{op.Spec.ID, req, hash}); err != nil {
		return op, err
	}
	if err := m.event(ctx, op.Spec.ID, "recovery_requested", "explicit recovery requested by "+string(req.Initiator)); err != nil {
		return op, err
	}
	return op, nil
}
func (m *Manager) runRequestedRecovery(ctx context.Context) (bool, error) {
	records, err := m.Store.List(ctx, "recovery_request", "")
	if err != nil {
		return false, err
	}
	for _, record := range records {
		var req recoveryRequest
		if err := json.Unmarshal(record.Payload, &req); err != nil {
			return false, err
		}
		var done bool
		err = m.Store.Get(ctx, "recovery_consumed", record.ID, &done)
		if err == nil {
			continue
		}
		if !errors.Is(err, store.ErrNotFound) {
			return false, err
		}
		op, err := m.Store.GetOperation(ctx, req.OperationID)
		if err != nil {
			return false, err
		}
		// Persist consumption before any effect. A second crash never replays the same
		// human approval; the operator must inspect a fresh preview and approve again.
		if err := m.Store.PutImmutable(ctx, "recovery_consumed", record.ID, op.Spec.ServiceID, true); err != nil {
			return false, err
		}
		if op.State.Terminal() {
			continue
		}
		plan, err := m.Preview(ctx, req.Request)
		if err != nil || plan.PlanDigest != req.Request.PlanDigest {
			if err := m.event(ctx, op.Spec.ID, "recovery_rejected", "recovery plan changed; request a fresh preview"); err != nil {
				return false, err
			}
			return true, nil
		}
		manager := jobs.New(m.Store)
		if op.State == domain.OperationRequiresRecovery {
			op, err = manager.Transition(ctx, op.Spec.ID, domain.OperationInterrupted, domain.OutcomeEvidence{Reason: "explicit recovery reconciliation"})
			if err != nil {
				return false, err
			}
		}
		// Acquiring the identical lock set is idempotent for its existing owner.
		if err := m.Store.Acquire(ctx, op.Spec.ID, op.Spec.Resources); err != nil {
			return false, err
		}
		op, err = manager.Transition(ctx, op.Spec.ID, domain.OperationRunning, domain.OutcomeEvidence{ActualStateKnown: true, Reason: "explicit recovery plan validated"})
		if err != nil {
			return false, err
		}
		task, cancel := context.WithTimeout(ctx, 10*time.Minute)
		m.artifactMu.Lock()
		recoveryContext := context.WithValue(context.WithValue(context.WithValue(task, operationContextKey{}, op.Spec.ID), recoveryExecutionKey{}, true), artifactGateKey{}, true)
		err = m.compensate(recoveryContext, op, req.Request, plan)
		cancel()
		recording, stop := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		state := domain.OperationFailed
		evidence := domain.OutcomeEvidence{ActualStateKnown: true, ResultRecorded: true, ReturnedToPrevious: true, Reason: "explicit recovery returned to the previous release; original operation did not complete"}
		if err != nil {
			state = domain.OperationRequiresRecovery
			evidence = domain.OutcomeEvidence{Reason: err.Error()}
		}
		_, saveErr := manager.Transition(recording, op.Spec.ID, state, evidence)
		if saveErr == nil {
			if maintenanceErr := m.reclaim(recording, false); maintenanceErr != nil {
				_ = m.event(recording, op.Spec.ID, "maintenance_warning", "retention cleanup deferred; protected artifacts retained")
			}
		}
		m.artifactMu.Unlock()
		stop()
		return true, saveErr
	}
	return false, nil
}
func (m *Manager) compensate(ctx context.Context, op domain.Operation, req transport.SubmitRequest, plan transport.PreviewResult) error {
	if !op.MutationStarted {
		return m.event(ctx, op.Spec.ID, "reconciled", "interrupted before active mutation; no Docker or file step replayed")
	}
	m.pauseCapture(ctx)
	s, err := m.Store.GetService(ctx, op.Spec.ServiceID)
	if err != nil {
		return err
	}
	var point recoveryPoint
	if err := m.Store.Get(ctx, "recovery_point", op.RecoveryPointID, &point); err != nil {
		return err
	}
	release, err := m.loadRelease(ctx, s, point.ReleaseID)
	if err != nil {
		return err
	}
	snapshot, err := m.loadSnapshot(ctx, point.SnapshotID)
	if err != nil {
		return err
	}
	configuration, err := m.LoadConfiguration(ctx, release.Spec().ConfigurationDigest)
	if err != nil {
		return err
	}
	model, err := m.runtimeConfiguration(ctx, s, configuration)
	if err != nil {
		return err
	}
	pinModelImages(model, release.Spec().Images)
	for _, image := range release.Spec().Images {
		inspected, err := m.Engine.Client.ImageInspect(ctx, string(image.ImageID))
		if err != nil || inspected.ID != string(image.ImageID) {
			return errors.New("exact recovery image unavailable")
		}
	}
	allowedImages := map[string]map[string]bool{}
	for _, image := range release.Spec().Images {
		allowedImages[image.Component] = map[string]bool{string(image.ImageID): true}
	}
	if op.Spec.ReleaseID != "" {
		target, err := m.loadRelease(ctx, s, op.Spec.ReleaseID)
		if err != nil {
			return err
		}
		for _, image := range target.Spec().Images {
			if allowedImages[image.Component] == nil {
				return errors.New("target image component outside recovery point")
			}
			allowedImages[image.Component][string(image.ImageID)] = true
		}
	}
	actual, err := m.Engine.Inventory(ctx, s.ComposeProject)
	if err != nil {
		return err
	}
	if len(actual) != len(point.State.Containers) {
		return errors.New("runtime component count changed; administrator reconciliation required")
	}
	// Replacement IDs are possible after a partial Compose up. Each component must
	// still have a registered role, unchanged persistent mounts and the frozen
	// effective settings. Unmanaged dependency identities remain exact.
	seen := map[string]bool{}
	for _, c := range actual {
		if seen[c.Component] || !allowedImages[c.Component][c.ImageID] {
			return errors.New("unapproved image or duplicate component prevents recovery")
		}
		seen[c.Component] = true
		var ref *domain.ContainerRef
		for i := range point.State.Containers {
			if point.State.Containers[i].Component == c.Component {
				ref = &point.State.Containers[i]
			}
		}
		if ref == nil {
			return errors.New("unknown recovery component")
		}
		if !hasTarget(s, c.Component) && c.ID != ref.ID {
			return errors.New("dependency identity changed")
		}
		component := model["services"].(map[string]any)[c.Component].(map[string]any)
		old := component["image"]
		component["image"] = c.ImageID
		issues := c.RuntimeIssues(model, s.ComposeProject)
		component["image"] = old
		if len(issues) > 0 {
			return errors.New("runtime configuration drift prevents automatic recovery")
		}
	}
	current, err := filesystem.Observe(ctx, s.ProjectDirectory, s.ManagedPaths, nil)
	if err != nil {
		return err
	}
	if current.Digest() != plan.CurrentTreeDigest {
		return errors.New("active files changed after recovery approval")
	}
	for _, c := range actual {
		if hasTarget(s, c.Component) {
			if err := m.Engine.Stop(ctx, c.ID); err != nil {
				return err
			}
		}
	}
	stopped, err := m.Engine.Inventory(ctx, s.ComposeProject)
	if err != nil {
		return err
	}
	if err := confirmStopped(s, actual, stopped, model); err != nil {
		return err
	}

	content, _ := m.Snapshots.ContentPath(snapshot.ID)
	if err := filesystem.Apply(ctx, content, s.ProjectDirectory, current, snapshot.Manifest, s.ManagedPaths, filesystem.ApplyOptions{ApplicationsStopped: true, PreserveOwnership: !m.Config.Development}); err != nil {
		return err
	}
	composeErr := m.composeActionWithDiagnostics(ctx, s, op.Spec.ID, configuration, model, "up", s.Targets, nil)
	observationErr := m.recordRuntimeSwitchObservation(ctx, s, op.Spec.ID, point.ReleaseID, composeErr == nil)
	if composeErr != nil || observationErr != nil {
		return errors.Join(composeErr, observationErr)
	}
	items, err := m.Engine.Inventory(ctx, s.ComposeProject)
	if err != nil {
		return err
	}
	if len(items) != len(point.State.Containers) {
		return errors.New("recovery component count mismatch")
	}
	st, err := m.state(ctx, s)
	if err != nil {
		return err
	}
	refs := []domain.ContainerRef{}
	for _, old := range point.State.Containers {
		found := false
		for _, c := range items {
			if old.Component == c.Component {
				if c.ImageID != string(old.ImageID) {
					return errors.New("recovery image observation mismatch")
				}
				if issues := c.RuntimeIssues(model, s.ComposeProject); len(issues) > 0 {
					return errors.New("recovery runtime settings mismatch")
				}
				refs = append(refs, domain.ContainerRef{Component: old.Component, ID: c.ID, ImageID: old.ImageID, Role: old.Role})
				found = true
			}
		}
		if !found {
			return errors.New("recovery component missing")
		}
	}
	st.CurrentReleaseID = point.ReleaseID
	st.ActiveSnapshotID = point.SnapshotID
	st.Containers = refs
	if err := m.saveState(ctx, &st); err != nil {
		return err
	}
	allRunning := true
	for _, target := range s.Targets {
		if state, ok := point.PriorStates[target]; ok && state != "running" {
			allRunning = false
			for _, c := range items {
				if c.Component == target {
					if err := m.Engine.Stop(ctx, c.ID); err != nil {
						return err
					}
				}
			}
		}
	}
	if !allRunning {
		return m.event(ctx, op.Spec.ID, "recovered", "previous release and stopped application state restored; persistent data was not restored")
	}
	if err := m.warmup(ctx, s); err != nil {
		return err
	}
	if err := m.runChecks(ctx, s, op.Spec.ID); err != nil {
		return err
	}
	return m.event(ctx, op.Spec.ID, "recovered", "previous release observed; persistent data was not restored")
}

func (m *Manager) createRecoveryPoint(ctx context.Context, s domain.Service, st runtimeState, author domain.ID, actual []docker.Container, reviewedDrift ...domain.Digest) (domain.ID, error) {
	previous, err := m.loadSnapshot(ctx, st.ActiveSnapshotID)
	if err != nil {
		return "", err
	}
	observed, err := filesystem.Observe(ctx, s.ProjectDirectory, s.ManagedPaths, nil)
	if err != nil {
		return "", err
	}
	accepted := len(reviewedDrift) == 1 && reviewedDrift[0] != "" && reviewedDrift[0] == observed.Digest()
	if observed.Digest() != previous.ManifestDigest && !accepted {
		return "", errors.New("active files differ from current release; reconcile external edits first")
	}
	snapshot, err := m.capture(ctx, s, author, domain.SnapshotRecovery, s.ProjectDirectory)
	if err != nil {
		return "", err
	}
	if snapshot.ManifestDigest != observed.Digest() {
		return "", errors.New("active files changed while recording recovery point")
	}
	point := recoveryPoint{SnapshotID: snapshot.ID, ReleaseID: st.CurrentReleaseID, State: st, PriorStates: map[string]string{}}
	for _, c := range actual {
		if hasTarget(s, c.Component) {
			point.PriorStates[c.Component] = c.State
		}
	}
	return snapshot.ID, m.Store.PutImmutable(ctx, "recovery_point", snapshot.ID, s.ID, point)
}
func exactTargets(s domain.Service, items []docker.Container) error {
	seen := map[string]int{}
	for _, c := range items {
		seen[c.Component]++
	}
	for _, name := range s.Targets {
		if seen[name] != 1 {
			return errors.New("application target is missing or duplicated")
		}
	}
	return nil
}

func confirmStopped(s domain.Service, before, after []docker.Container, model map[string]any) error {
	if len(before) != len(after) {
		return errors.New("component count changed during stop")
	}
	if err := exactTargets(s, after); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, current := range after {
		if seen[current.Component] {
			return errors.New("duplicate component during stop")
		}
		seen[current.Component] = true
		found := false
		for _, old := range before {
			if old.Component == current.Component {
				if old.ID != current.ID || old.ImageID != current.ImageID {
					return errors.New("runtime identity changed during stop")
				}
				found = true
			}
		}
		if !found {
			return errors.New("unexpected component during stop")
		}
		if hasTarget(s, current.Component) && current.State != "exited" {
			return errors.New("target is not confirmed stopped")
		}
		services, _ := model["services"].(map[string]any)
		component, ok := services[current.Component].(map[string]any)
		if !ok {
			return errors.New("component outside frozen configuration")
		}
		original := component["image"]
		component["image"] = current.ImageID
		issues := current.RuntimeIssues(model, s.ComposeProject)
		component["image"] = original
		if len(issues) > 0 {
			return errors.New("runtime configuration changed during stop")
		}
	}
	return nil
}
