package domain

import (
	"fmt"
	"time"
)

type HealthSource string
type HealthState string

const (
	HealthContainer     HealthSource = "container"
	HealthDocker        HealthSource = "docker_healthcheck"
	HealthReadiness     HealthSource = "readiness"
	HealthFunctional    HealthSource = "local_functional"
	HealthManual        HealthSource = "manual"
	HealthExternal      HealthSource = "external_checker"
	HealthHealthy       HealthState  = "healthy"
	HealthUnhealthy     HealthState  = "unhealthy"
	HealthNotConfigured HealthState  = "not_configured"
	HealthUnknown       HealthState  = "unknown"
	HealthStale         HealthState  = "stale"
)

type HealthSignal struct {
	Source     HealthSource `json:"source"`
	State      HealthState  `json:"state"`
	ObservedAt time.Time    `json:"observed_at,omitempty"`
	ValidUntil time.Time    `json:"valid_until,omitempty"`
	Reason     string       `json:"reason,omitempty"`
}

func (h HealthSignal) Validate() error {
	switch h.Source {
	case HealthContainer, HealthDocker, HealthReadiness, HealthFunctional, HealthManual, HealthExternal:
	default:
		return fmt.Errorf("unknown health source")
	}
	switch h.State {
	case HealthHealthy, HealthUnhealthy, HealthNotConfigured, HealthUnknown, HealthStale:
	default:
		return fmt.Errorf("unknown health state")
	}
	if h.State == HealthHealthy || h.State == HealthUnhealthy || h.State == HealthStale {
		if h.ObservedAt.IsZero() || h.ValidUntil.IsZero() || h.ValidUntil.Before(h.ObservedAt) {
			return fmt.Errorf("observed health requires timestamp and validity period")
		}
	}
	return nil
}

func (h HealthSignal) EffectiveState(at time.Time) HealthState {
	if h.Validate() != nil {
		return HealthUnknown
	}
	if h.State == HealthNotConfigured || h.State == HealthUnknown {
		return h.State
	}
	if !at.Before(h.ValidUntil) {
		return HealthStale
	}
	return h.State
}

type ComponentObservation struct {
	Component         string    `json:"component"`
	ContainerID       string    `json:"container_id,omitempty"`
	ImageID           Digest    `json:"image_id,omitempty"`
	ObservedReleaseID ID        `json:"observed_release_id,omitempty"`
	ContainerState    string    `json:"container_state"`
	ObservedAt        time.Time `json:"observed_at"`
}

// ServiceStatus never infers the active version from a health check. Partial
// switches remain visible as distinct per-component observed versions.
type ServiceStatus struct {
	ServiceID                    ID                     `json:"service_id"`
	DesiredReleaseID             ID                     `json:"desired_release_id,omitempty"`
	CurrentReleaseID             ID                     `json:"current_release_id,omitempty"`
	LastLocallyVerifiedReleaseID ID                     `json:"last_locally_verified_release_id,omitempty"`
	BaselineSnapshotID           ID                     `json:"baseline_snapshot_id,omitempty"`
	Components                   []ComponentObservation `json:"components"`
	Health                       []HealthSignal         `json:"health"`
}

type ReleaseStatus string

const (
	ReleasePrepared        ReleaseStatus = "prepared"
	ReleaseActive          ReleaseStatus = "active"
	ReleaseLocallyVerified ReleaseStatus = "locally_verified"
	ReleaseFailed          ReleaseStatus = "failed"
	ReleaseRetired         ReleaseStatus = "retired"
)

// ReleaseEvent is append-only evidence, separate from the immutable ReleaseSpec.
type ReleaseEvent struct {
	ID          ID            `json:"id"`
	ReleaseID   ID            `json:"release_id"`
	At          time.Time     `json:"at"`
	Status      ReleaseStatus `json:"status"`
	Source      HealthSource  `json:"source,omitempty"`
	OperationID ID            `json:"operation_id,omitempty"`
	Reason      string        `json:"reason,omitempty"`
}

func (e ReleaseEvent) Validate() error {
	for _, id := range []ID{e.ID, e.ReleaseID} {
		if err := id.Validate(); err != nil {
			return err
		}
	}
	if e.At.IsZero() {
		return fmt.Errorf("release event requires timestamp")
	}
	if e.OperationID != "" {
		if err := e.OperationID.Validate(); err != nil {
			return err
		}
	}
	switch e.Status {
	case ReleasePrepared, ReleaseActive, ReleaseFailed, ReleaseRetired:
	case ReleaseLocallyVerified:
		if e.Source != HealthFunctional {
			return fmt.Errorf("local verification must originate from a local functional check")
		}
	default:
		return fmt.Errorf("unknown release status")
	}
	return nil
}

// RollbackAvailability is evaluated afresh against actual artifacts and current
// policy. A historical locally_verified event alone cannot authorize rollback.
type RollbackAvailability struct {
	ImagesPresent        bool `json:"images_present"`
	ManifestValid        bool `json:"manifest_valid"`
	ConfigurationPresent bool `json:"configuration_present"`
	SecretsAvailable     bool `json:"secrets_available"`
	CurrentPolicyAllows  bool `json:"current_policy_allows"`
	DataCompatible       bool `json:"data_compatible"`
	DriftResolved        bool `json:"drift_resolved"`
}

func (r RollbackAvailability) Available() bool {
	return r.ImagesPresent && r.ManifestValid && r.ConfigurationPresent && r.SecretsAvailable && r.CurrentPolicyAllows && r.DataCompatible && r.DriftResolved
}
