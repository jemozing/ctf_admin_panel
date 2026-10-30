package store

import (
	"context"
	"errors"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

// MaintenanceAudit contains no free text, file paths, secret bytes or errors.
// It identifies local OS actors separately from dashboard user identifiers.
type MaintenanceAudit struct {
	ID           domain.ID     `json:"id"`
	RequestID    domain.ID     `json:"request_id"`
	At           time.Time     `json:"at"`
	LocalUID     uint32        `json:"local_uid"`
	Action       string        `json:"action"`
	TargetDigest domain.Digest `json:"target_digest"`
	Mode         string        `json:"mode"`
	Result       string        `json:"result"`
}

func (v MaintenanceAudit) Validate() error {
	if err := v.ID.Validate(); err != nil {
		return err
	}
	if err := v.RequestID.Validate(); err != nil {
		return err
	}
	if err := v.TargetDigest.Validate(); err != nil {
		return err
	}
	if v.At.IsZero() {
		return errors.New("maintenance audit requires UTC time")
	}
	switch v.Action {
	case "backup.export", "secret.import", "secret.revoke", "secret.delete":
	default:
		return errors.New("unknown maintenance audit action")
	}
	switch v.Mode {
	case "metadata", "protected_full", "secret_version":
	default:
		return errors.New("unknown maintenance audit mode")
	}
	switch v.Result {
	case "started", "succeeded", "failed":
	default:
		return errors.New("unknown maintenance audit result")
	}
	return nil
}
func (s *Store) AppendMaintenanceAudit(ctx context.Context, v MaintenanceAudit) error {
	if err := v.Validate(); err != nil {
		return err
	}
	return s.PutImmutable(ctx, "maintenance_audit", v.ID, "executor", v)
}
