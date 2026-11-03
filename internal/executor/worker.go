package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/jobs"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

type operationInput struct {
	Request transport.SubmitRequest `json:"request"`
	Plan    transport.PreviewResult `json:"plan"`
}

func (m *Manager) Submit(ctx context.Context, principal transport.Principal, req transport.SubmitRequest) (domain.Operation, error) {
	m.submitMu.Lock()
	defer m.submitMu.Unlock()
	unlockAdmission, err := m.lockCutoverAdmission()
	if err != nil {
		return domain.Operation{}, err
	}
	defer unlockAdmission()
	if err := req.Validate(); err != nil {
		return domain.Operation{}, err
	}
	if req.Initiator == "" {
		req.Initiator = domain.ID(fmt.Sprintf("uid-%d", principal.UID))
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return domain.Operation{}, err
	}
	hash := domain.Hash(raw)
	recoveries, err := m.Store.List(ctx, "recovery_request", "")
	if err != nil {
		return domain.Operation{}, err
	}
	for _, record := range recoveries {
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
	existing, inputHash, err := m.Store.FindOperation(ctx, req.Initiator, req.IdempotencyKey)
	if err == nil {
		if inputHash != hash {
			return existing, store.ErrIdempotencyConflict
		}
		return existing, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return domain.Operation{}, err
	}
	if err := m.requireNoPendingCutover(ctx); err != nil {
		return domain.Operation{}, err
	}
	needs, err := m.Store.MetadataRestoreNeedsReview(ctx, req.ServiceID)
	if err != nil {
		return domain.Operation{}, err
	}
	if needs {
		return domain.Operation{}, errors.New("metadata-only restore requires local policy review and missing artifacts before operations")
	}
	if req.Action == domain.OperationRecover {
		return m.requestRecovery(ctx, req, hash)
	}
	plan, err := m.Preview(ctx, req)
	if err != nil {
		return domain.Operation{}, err
	}
	if req.PlanDigest == "" || req.PlanDigest != plan.PlanDigest {
		return domain.Operation{}, fmt.Errorf("%w: review a fresh operation preview before submitting", store.ErrConflict)
	}
	if plan.ComposeChange && !req.ConfirmComposeChange {
		return domain.Operation{}, fmt.Errorf("%w: confirm the reviewed Compose configuration change before switching", store.ErrConflict)
	}
	if plan.DataCompatibilityRequired && !req.ConfirmDataCompatibility {
		return domain.Operation{}, errors.New("confirm persistent data compatibility with the selected release")
	}
	if plan.ActiveFileDrift && !plan.AcceptedFileDrift {
		return domain.Operation{}, errors.New("review active file changes and explicitly accept an unverified recovery point before switching")
	}
	s, err := m.Store.GetService(ctx, req.ServiceID)
	if err != nil {
		return domain.Operation{}, err
	}
	id := NewID("op-")
	resources := operationResources(s, req.Action)
	spec := domain.OperationSpec{ID: id, Kind: req.Action, Initiator: req.Initiator, IdempotencyKey: req.IdempotencyKey, ServiceID: s.ID, ReleaseID: req.ReleaseID, SnapshotID: req.SnapshotID, ExpectedPolicyRevision: s.PolicyRevision, ExpectedTreeDigest: plan.CurrentTreeDigest, Resources: uniqueStrings(resources), TimeoutSeconds: 600}
	if err := m.Store.PutImmutable(ctx, "operation_input", id, s.ID, operationInput{req, plan}); err != nil {
		return domain.Operation{}, err
	}
	op, _, err := jobs.New(m.Store).Submit(ctx, spec, hash)
	return op, err
}

// Source-only jobs neither mount nor modify significant runtime data. A shared
// volume therefore conflicts only between jobs that can affect its consumers.
func operationResources(s domain.Service, kind domain.OperationKind) []string {
	resources := []string{"service:" + string(s.ID), "project:" + s.ComposeProject, "path:" + s.ProjectDirectory, "path:" + s.SourceDirectory}
	switch kind {
	case domain.OperationStart, domain.OperationStop, domain.OperationRestart, domain.OperationDeploy, domain.OperationRollback, domain.OperationRecover:
		for _, data := range s.DataPaths {
			if data.SharedResource != "" {
				resources = append(resources, "shared:"+string(data.SharedResource))
			}
		}
	}
	return uniqueStrings(resources)
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func (m *Manager) execute(ctx context.Context, op domain.Operation) error {
	switch op.Spec.Kind {
	case domain.OperationStart, domain.OperationStop, domain.OperationRestart, domain.OperationDeploy, domain.OperationRollback, domain.OperationRecover:
		m.pauseCapture(ctx)
	}
	if err := m.requireNoPendingCutover(ctx); err != nil {
		return err
	}
	if err := m.cancellationCheckpoint(ctx, op.Spec.ID); err != nil {
		return err
	}
	var input operationInput
	if err := m.Store.Get(ctx, "operation_input", op.Spec.ID, &input); err != nil {
		return err
	}
	s, err := m.Store.GetService(ctx, op.Spec.ServiceID)
	if err != nil {
		return err
	}
	if s.PolicyRevision != op.Spec.ExpectedPolicyRevision {
		return errors.New("approved policy changed while queued")
	}
	fresh, err := m.Preview(ctx, input.Request)
	if err != nil {
		return err
	}
	if fresh.PlanDigest != input.Plan.PlanDigest {
		return errors.New("operation plan changed while queued; request a new preview")
	}
	st, err := m.state(ctx, s)
	if err != nil {
		return err
	}
	if op.Spec.Kind == domain.OperationFetchSource {
		return m.fetchGitSource(ctx, s, st, op)
	}
	configDigest, err := m.activeConfigurationDigest(ctx, s, st)
	if err != nil {
		return err
	}
	configuration, err := m.LoadConfiguration(ctx, configDigest)
	if err != nil {
		return err
	}
	model, err := m.runtimeConfiguration(ctx, s, configuration)
	if err != nil {
		return err
	}
	if st.CurrentReleaseID != "" {
		r, err := m.loadRelease(ctx, s, st.CurrentReleaseID)
		if err != nil {
			return err
		}
		pinModelImages(model, r.Spec().Images)
	}
	actual, err := m.verifyRuntime(ctx, s, st, model)
	if err != nil {
		return err
	}
	switch op.Spec.Kind {
	case domain.OperationPrepareCompose:
		return m.prepareComposeRelease(ctx, s, st, op, input, configuration, configDigest)
	case domain.OperationRestoreSnapshot:
		return m.restoreSnapshotCandidate(ctx, s, &st, op, input.Plan.SnapshotID)
	case domain.OperationSnapshot:
		if err := m.stage(ctx, op.Spec.ID, domain.StageCopying); err != nil {
			return err
		}
		purpose := domain.SnapshotManual
		if st.BaselineID == "" {
			purpose = domain.SnapshotBaseline
		}
		snap, err := m.capture(ctx, s, op.Spec.Initiator, purpose, s.ProjectDirectory)
		if err != nil {
			return err
		}
		if purpose == domain.SnapshotBaseline {
			release, err := m.importRelease(ctx, s, op.Spec.Initiator, configDigest, snap, actual)
			if err != nil {
				return err
			}
			st.CurrentReleaseID = release.Spec().ID
			st.BaselineID = snap.ID
			st.ActiveSnapshotID = snap.ID
			if err := m.saveState(ctx, &st); err != nil {
				return err
			}
			if err := m.seedRegistrationWorkspace(ctx, s, snap); err != nil {
				return err
			}
		} else {
			initialized, err := m.registrationInitialized(ctx, s, st.BaselineID)
			if err != nil {
				return err
			}
			if !initialized {
				baseline, err := m.loadSnapshot(ctx, st.BaselineID)
				if err != nil {
					return err
				}
				if err := m.seedRegistrationWorkspace(ctx, s, baseline); err != nil {
					return err
				}
			}
		}
		return m.event(ctx, op.Spec.ID, "snapshot_created", string(snap.ID))
	case domain.OperationPrepare:
		if err := m.stage(ctx, op.Spec.ID, domain.StageCopying); err != nil {
			return err
		}
		snap, err := m.capture(ctx, s, op.Spec.Initiator, domain.SnapshotCandidate, s.SourceDirectory)
		if err != nil {
			return err
		}
		st.CandidateID = snap.ID
		if err := m.saveState(ctx, &st); err != nil {
			return err
		}
		return m.event(ctx, op.Spec.ID, "candidate_created", string(snap.ID))
	case domain.OperationBuild:
		if err := m.stage(ctx, op.Spec.ID, domain.StageBuilding); err != nil {
			return err
		}
		return m.buildRelease(ctx, s, st, op, input, configuration, configDigest)
	case domain.OperationStart, domain.OperationStop, domain.OperationRestart:
		point, err := m.createRecoveryPoint(ctx, s, st, op.Spec.Initiator, actual)
		if err != nil {
			return err
		}
		if _, err := jobs.New(m.Store).BeginMutation(ctx, op.Spec.ID, point); err != nil {
			return err
		}
		for _, c := range actual {
			if !hasTarget(s, c.Component) {
				continue
			}
			switch op.Spec.Kind {
			case domain.OperationStart:
				err = m.Engine.Start(ctx, c.ID)
			case domain.OperationStop:
				err = m.Engine.Stop(ctx, c.ID)
			case domain.OperationRestart:
				err = m.Engine.Restart(ctx, c.ID)
			}
			if err != nil {
				return errors.New("container action failed; reconcile actual state before proceeding")
			}
		}
		observed, err := m.verifyRuntime(ctx, s, st, model)
		if err != nil {
			return err
		}
		for _, c := range observed {
			if hasTarget(s, c.Component) {
				if op.Spec.Kind == domain.OperationStop && c.State != "exited" {
					return errors.New("target is not confirmed stopped")
				}
				if op.Spec.Kind != domain.OperationStop && c.State != "running" {
					return errors.New("target is not confirmed running")
				}
			}
		}
		if op.Spec.Kind != domain.OperationStop {
			if err := m.warmup(ctx, s); err != nil {
				return err
			}
			if err := m.runChecks(ctx, s, op.Spec.ID); err != nil {
				return err
			}
		}
		return m.event(ctx, op.Spec.ID, "observed", "target container states confirmed; game checker is independent")
	case domain.OperationDeploy, domain.OperationRollback:
		return m.switchRelease(ctx, s, &st, op, input, configDigest, model, actual)
	}
	return errors.New("operation is not implemented")
}
func (m *Manager) capture(ctx context.Context, s domain.Service, author domain.ID, purpose domain.SnapshotPurpose, source string, gitSource ...*domain.GitProvenance) (domain.Snapshot, error) {
	observed, err := m.preflightSnapshot(ctx, s, source)
	if err != nil {
		return domain.Snapshot{}, err
	}
	id := NewID("snap-")
	if err := m.Store.PutImmutable(ctx, "snapshot_allocation", id, s.ID, allocation{ID: id, OperationID: allocationOperation(ctx), CreatedAt: time.Now().UTC()}); err != nil {
		return domain.Snapshot{}, err
	}
	metadata := domain.Snapshot{ID: id, ServiceID: s.ID, CreatedAt: time.Now().UTC(), Author: author, Purpose: purpose, FileMapRevision: s.FileMapRevision, Consistency: domain.ConsistencyCoordinated}
	if len(gitSource) > 0 {
		metadata.GitSource = gitSource[0]
	}
	snap, err := m.Snapshots.Create(ctx, metadata, source, s.ManagedPaths, nil)
	if err != nil {
		return snap, err
	}
	if snap.ManifestDigest != observed.Digest() {
		_ = m.Snapshots.Remove(context.WithoutCancel(ctx), snap.ID)
		return domain.Snapshot{}, errors.New("source changed after quota preflight")
	}
	if err := m.verifyCapturedQuota(ctx, snap.ID); err != nil {
		return domain.Snapshot{}, err
	}
	if err := m.Store.PutImmutable(ctx, "snapshot", snap.ID, s.ID, snap); err != nil {
		return snap, err
	}
	return snap, nil
}
