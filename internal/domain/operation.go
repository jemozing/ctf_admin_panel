package domain

import (
	"fmt"
	"sort"
	"time"
)

type OperationKind string
type OperationState string
type OperationStage string

const (
	OperationStart            OperationKind  = "start"
	OperationStop             OperationKind  = "stop"
	OperationRestart          OperationKind  = "restart"
	OperationPrepare          OperationKind  = "prepare"
	OperationPrepareCompose   OperationKind  = "prepare_compose"
	OperationFetchSource      OperationKind  = "fetch_source"
	OperationBuild            OperationKind  = "build"
	OperationDeploy           OperationKind  = "deploy"
	OperationSnapshot         OperationKind  = "snapshot"
	OperationRestoreSnapshot  OperationKind  = "restore_snapshot"
	OperationRollback         OperationKind  = "rollback"
	OperationRecover          OperationKind  = "recover"
	OperationQueued           OperationState = "queued"
	OperationRunning          OperationState = "running"
	OperationSucceeded        OperationState = "succeeded"
	OperationFailed           OperationState = "failed"
	OperationCancelled        OperationState = "cancelled"
	OperationInterrupted      OperationState = "interrupted"
	OperationRequiresRecovery OperationState = "requires_recovery"
	StageValidation           OperationStage = "validation"
	StageCopying              OperationStage = "copying"
	StageBuilding             OperationStage = "building"
	StageRecoveryPoint        OperationStage = "recovery_point"
	StageSwitching            OperationStage = "switching"
	StageWarmup               OperationStage = "warmup"
	StageFunctionalCheck      OperationStage = "functional_check"
	StageRecording            OperationStage = "recording"
	StageReconciliation       OperationStage = "reconciliation"
)

type OperationSpec struct {
	ID                     ID            `json:"id"`
	Kind                   OperationKind `json:"kind"`
	Initiator              ID            `json:"initiator"`
	IdempotencyKey         string        `json:"idempotency_key"`
	ServiceID              ID            `json:"service_id"`
	ReleaseID              ID            `json:"release_id,omitempty"`
	SnapshotID             ID            `json:"snapshot_id,omitempty"`
	ExpectedPolicyRevision uint64        `json:"expected_policy_revision"`
	ExpectedTreeDigest     Digest        `json:"expected_tree_digest"`
	Resources              []string      `json:"resources"`
	TimeoutSeconds         uint32        `json:"timeout_seconds"`
}

func (s OperationSpec) Validate() error {
	for _, id := range []ID{s.ID, s.Initiator, s.ServiceID} {
		if err := id.Validate(); err != nil {
			return err
		}
	}
	switch s.Kind {
	case OperationStart, OperationStop, OperationRestart, OperationPrepare, OperationPrepareCompose, OperationFetchSource, OperationBuild, OperationDeploy, OperationSnapshot, OperationRestoreSnapshot, OperationRollback, OperationRecover:
	default:
		return fmt.Errorf("unknown operation kind")
	}
	if err := validateText(s.IdempotencyKey, "idempotency key", 128); err != nil {
		return err
	}
	if s.ExpectedPolicyRevision == 0 || s.TimeoutSeconds == 0 {
		return fmt.Errorf("expected revision and timeout are required")
	}
	if err := s.ExpectedTreeDigest.Validate(); err != nil {
		return err
	}
	if s.ReleaseID != "" {
		if err := s.ReleaseID.Validate(); err != nil {
			return err
		}
	}
	if s.Kind == OperationRestoreSnapshot {
		if err := s.SnapshotID.Validate(); err != nil {
			return fmt.Errorf("snapshot ID is required for snapshot restoration: %w", err)
		}
	} else if s.SnapshotID != "" {
		return fmt.Errorf("snapshot ID is only accepted for snapshot restoration")
	}
	if (s.Kind == OperationDeploy || s.Kind == OperationRollback) && s.ReleaseID == "" {
		return fmt.Errorf("release ID is required for deploy and rollback")
	}
	if len(s.Resources) == 0 {
		return fmt.Errorf("operation must lock at least its service")
	}
	seen := map[string]bool{}
	for _, resource := range s.Resources {
		if err := validateText(resource, "resource lock", 4096); err != nil {
			return err
		}
		if seen[resource] {
			return fmt.Errorf("duplicate resource lock")
		}
		seen[resource] = true
	}
	if !seen["service:"+string(s.ServiceID)] {
		return fmt.Errorf("operation must lock its service")
	}
	return nil
}

type OutcomeEvidence struct {
	ActualStateKnown   bool   `json:"actual_state_known"`
	ResultRecorded     bool   `json:"result_recorded"`
	ReturnedToPrevious bool   `json:"returned_to_previous"`
	Reason             string `json:"reason,omitempty"`
}

// QueueWait is a read-only observation added to API responses. It never belongs
// to the durable operation, its idempotency input or a state transition.
type QueueBlocker struct {
	Resource    string `json:"resource"`
	OperationID ID     `json:"operation_id"`
	Actor       ID     `json:"actor"`
}
type QueueWait struct {
	Reason   string         `json:"reason"`
	Blockers []QueueBlocker `json:"blockers"`
	Lane     string         `json:"lane"`
	Limit    uint32         `json:"limit"`
}

// Operation is a state-machine contract, not a durable job engine. The caller must
// persist every mutation intent before effects and evidence before acknowledging it.
type Operation struct {
	QueueWait       *QueueWait      `json:"queue_wait,omitempty"`
	Spec            OperationSpec   `json:"spec"`
	State           OperationState  `json:"state"`
	Stage           OperationStage  `json:"stage"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
	CancelRequested bool            `json:"cancel_requested"`
	MutationStarted bool            `json:"mutation_started"`
	RecoveryPointID ID              `json:"recovery_point_id,omitempty"`
	Outcome         OutcomeEvidence `json:"outcome"`
}

func (o Operation) Validate() error {
	if err := o.Spec.Validate(); err != nil {
		return err
	}
	if o.CreatedAt.IsZero() || o.UpdatedAt.Before(o.CreatedAt) {
		return fmt.Errorf("operation timestamps are invalid")
	}
	switch o.State {
	case OperationQueued, OperationRunning, OperationSucceeded, OperationFailed, OperationCancelled, OperationInterrupted, OperationRequiresRecovery:
	default:
		return fmt.Errorf("unknown operation state")
	}
	switch o.Stage {
	case StageValidation, StageCopying, StageBuilding, StageRecoveryPoint, StageSwitching, StageWarmup, StageFunctionalCheck, StageRecording, StageReconciliation:
	default:
		return fmt.Errorf("unknown operation stage")
	}
	if o.MutationStarted {
		switch o.Spec.Kind {
		case OperationDeploy, OperationRollback, OperationRecover:
			if err := o.RecoveryPointID.Validate(); err != nil {
				return err
			}
		}
	}
	return nil
}

func NewOperation(spec OperationSpec, at time.Time) (Operation, error) {
	if err := spec.Validate(); err != nil {
		return Operation{}, err
	}
	if at.IsZero() {
		return Operation{}, fmt.Errorf("operation timestamp is required")
	}
	spec.Resources = append([]string{}, spec.Resources...)
	sort.Strings(spec.Resources)
	return Operation{Spec: spec, State: OperationQueued, Stage: StageValidation, CreatedAt: at.UTC(), UpdatedAt: at.UTC()}, nil
}

func (o *Operation) RequestCancel(at time.Time) error {
	if o.State.Terminal() {
		return fmt.Errorf("terminal operation cannot be cancelled")
	}
	if at.Before(o.UpdatedAt) {
		return fmt.Errorf("operation timestamps must be monotonic")
	}
	o.CancelRequested = true
	o.UpdatedAt = at.UTC()
	return nil
}

// BeginMutation records the critical boundary. The job engine must durably persist
// the returned state before any change to active files or running containers.
func (o *Operation) BeginMutation(recoveryPoint ID, at time.Time) error {
	if o.CancelRequested {
		return fmt.Errorf("cancellation requested before mutation")
	}
	if o.State != OperationRunning || o.MutationStarted {
		return fmt.Errorf("mutation can begin once in a running operation")
	}
	if at.Before(o.UpdatedAt) {
		return fmt.Errorf("operation timestamps must be monotonic")
	}
	switch o.Spec.Kind {
	case OperationDeploy, OperationRollback, OperationRecover:
		if err := recoveryPoint.Validate(); err != nil {
			return fmt.Errorf("switching requires a recovery point: %w", err)
		}
	case OperationStart, OperationStop, OperationRestart:
		if recoveryPoint != "" {
			if err := recoveryPoint.Validate(); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("operation does not modify active state")
	}
	o.MutationStarted = true
	o.RecoveryPointID = recoveryPoint
	o.Stage = StageSwitching
	o.UpdatedAt = at.UTC()
	return nil
}

func (s OperationState) Terminal() bool {
	return s == OperationSucceeded || s == OperationFailed || s == OperationCancelled
}

func (o *Operation) Transition(next OperationState, evidence OutcomeEvidence, at time.Time) error {
	if at.Before(o.UpdatedAt) || at.IsZero() {
		return fmt.Errorf("operation timestamps must be present and monotonic")
	}
	allowed := false
	switch o.State {
	case OperationQueued:
		allowed = next == OperationRunning || next == OperationCancelled || next == OperationFailed
	case OperationRunning:
		allowed = next == OperationSucceeded || next == OperationFailed || next == OperationCancelled || next == OperationInterrupted || next == OperationRequiresRecovery
	case OperationInterrupted:
		allowed = next == OperationRunning || next == OperationSucceeded || next == OperationFailed || next == OperationCancelled || next == OperationRequiresRecovery
	case OperationRequiresRecovery:
		allowed = next == OperationInterrupted
	}
	if !allowed {
		return fmt.Errorf("invalid operation transition %s -> %s", o.State, next)
	}
	if next == OperationSucceeded && (!evidence.ActualStateKnown || !evidence.ResultRecorded) {
		return fmt.Errorf("success requires confirmed actual state and recorded outcome")
	}
	if next == OperationFailed && (!evidence.ActualStateKnown || !evidence.ResultRecorded) {
		return fmt.Errorf("failure with unknown actual state requires reconciliation or recovery")
	}
	if next == OperationCancelled && (o.MutationStarted && !evidence.ReturnedToPrevious || !evidence.ActualStateKnown || !evidence.ResultRecorded) {
		return fmt.Errorf("cancellation requires known state and confirmed return after mutation")
	}
	if o.State == OperationInterrupted && next == OperationRunning && !evidence.ActualStateKnown {
		return fmt.Errorf("interrupted work cannot resume before reconciliation")
	}
	if next == OperationRequiresRecovery && evidence.Reason == "" {
		return fmt.Errorf("recovery state requires a diagnostic reason")
	}
	if next == OperationFailed && evidence.Reason == "" {
		return fmt.Errorf("failure requires a diagnostic reason")
	}
	o.State = next
	o.Outcome = evidence
	o.UpdatedAt = at.UTC()
	if next == OperationInterrupted || next == OperationRequiresRecovery {
		o.Stage = StageReconciliation
	}
	return nil
}
