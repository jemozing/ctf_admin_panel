package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

// SnapshotDatabase uses SQLite's coordinated snapshot, including committed WAL
// pages. The destination must not exist; copying an open .db file is never safe.
func (s *Store) SnapshotDatabase(ctx context.Context, destination string) error {
	if !filepath.IsAbs(destination) {
		return errors.New("database backup destination must be absolute")
	}
	if _, err := os.Lstat(destination); err == nil {
		return errors.New("database backup destination already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO ?", destination); err != nil {
		return err
	}
	return os.Chmod(destination, 0600)
}

type MetadataRestoreMarker struct {
	ServiceID      domain.ID `json:"service_id"`
	PolicyRevision uint64    `json:"policy_revision"`
}

// MetadataRestoreNeedsReview blocks operations until a local administrator has
// replaced the exported catalog policy with a newly inspected, approved revision.
func (s *Store) MetadataRestoreNeedsReview(ctx context.Context, id domain.ID) (bool, error) {
	var marker MetadataRestoreMarker
	if err := s.Get(ctx, "metadata_restore", id, &marker); errors.Is(err, ErrNotFound) {
		return false, nil
	} else if err != nil {
		return true, err
	}
	service, err := s.GetService(ctx, id)
	if err != nil {
		return true, err
	}
	return service.PolicyRevision <= marker.PolicyRevision, nil
}

// ExportMetadata reconstructs a NEW database from typed whitelist fields. It
// never deletes secret rows from a copied DB: SQLite free pages may retain them.
// Frozen Compose, raw events, check URLs, command arguments and authoring bytes
// are deliberately omitted. Operational restoration uses an encrypted full backup.
func (s *Store) ExportMetadata(ctx context.Context, destination string) error {
	if _, err := os.Lstat(destination); err == nil {
		return errors.New("metadata destination already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	dst, err := Open(destination)
	if err != nil {
		return err
	}
	defer dst.Close()
	services, err := s.ListServices(ctx)
	if err != nil {
		return err
	}
	for _, service := range services {
		service.Name = string(service.ID)
		service.Description = ""
		service.Checks = nil
		if err := service.Validate(); err != nil {
			return err
		}
		raw, err := json.Marshal(service)
		if err != nil {
			return err
		}
		digest := domain.Hash(raw)
		if _, err = dst.db.ExecContext(ctx, "INSERT INTO services(id,revision,payload,digest) VALUES(?,?,?,?)", service.ID, service.PolicyRevision, raw, digest); err != nil {
			return err
		}
		if _, err = dst.db.ExecContext(ctx, "INSERT INTO service_revisions(service_id,revision,payload,digest) VALUES(?,?,?,?)", service.ID, service.PolicyRevision, raw, digest); err != nil {
			return err
		}
		if err := dst.PutImmutable(ctx, "metadata_restore", service.ID, service.ID, MetadataRestoreMarker{service.ID, service.PolicyRevision}); err != nil {
			return err
		}
	}
	for _, kind := range []string{"snapshot", "release"} {
		records, err := s.List(ctx, kind, "")
		if err != nil {
			return err
		}
		for _, record := range records {
			var value any
			if kind == "snapshot" {
				var snapshot domain.Snapshot
				if err := json.Unmarshal(record.Payload, &snapshot); err != nil {
					return err
				}
				if err := snapshot.Validate(); err != nil {
					return err
				}
				if len(snapshot.PinReasons) > 0 {
					snapshot.PinReasons = []string{"retained_export_pin"}
				}
				value = snapshot
			} else {
				var release domain.Release
				if err := json.Unmarshal(record.Payload, &release); err != nil {
					return err
				}
				spec := release.Spec()
				for i := range spec.Data {
					spec.Data[i].Evidence = "not exported; review required"
				}
				for i := range spec.Images {
					spec.Images[i].RegistryDigests = nil
				}
				rebuilt, err := domain.NewRelease(spec)
				if err != nil {
					return err
				}
				value = rebuilt
			}
			if err := dst.PutImmutable(ctx, kind, record.ID, record.ServiceID, value); err != nil {
				return err
			}
		}
	}
	for _, kind := range []string{"deleted_snapshot", "retired_release"} {
		records, err := s.List(ctx, kind, "")
		if err != nil {
			return err
		}
		for _, record := range records {
			var tombstone struct {
				ID     domain.ID `json:"id"`
				At     time.Time `json:"at"`
				Reason string    `json:"reason"`
			}
			if err := json.Unmarshal(record.Payload, &tombstone); err != nil {
				return err
			}
			if tombstone.ID != record.ID || tombstone.At.IsZero() {
				return errors.New("invalid retention tombstone")
			}
			tombstone.Reason = "retention"
			if err := dst.PutImmutable(ctx, kind, record.ID, record.ServiceID, tombstone); err != nil {
				return err
			}
		}
	}
	audits, err := s.List(ctx, "maintenance_audit", "")
	if err != nil {
		return err
	}
	for _, record := range audits {
		var audit MaintenanceAudit
		if err := json.Unmarshal(record.Payload, &audit); err != nil {
			return err
		}
		if audit.ID != record.ID || record.ServiceID != "executor" {
			return errors.New("invalid maintenance audit identity")
		}
		if err := audit.Validate(); err != nil {
			return err
		}
		if err := dst.AppendMaintenanceAudit(ctx, audit); err != nil {
			return err
		}
	}
	ops, err := s.ListOperations(ctx)
	if err != nil {
		return err
	}
	for _, op := range ops {
		op.Spec.IdempotencyKey = "restored-" + string(op.Spec.ID)
		if op.Outcome.Reason != "" {
			op.Outcome.Reason = "original diagnostic excluded from metadata export"
		}
		raw, err := json.Marshal(op)
		if err != nil {
			return err
		}
		if _, err := dst.db.ExecContext(ctx, "INSERT INTO operations(id,initiator,idempotency_key,input_hash,payload,updated_at) VALUES(?,?,?,?,?,?)", op.Spec.ID, op.Spec.Initiator, op.Spec.IdempotencyKey, domain.Hash(raw), raw, op.UpdatedAt.UnixNano()); err != nil {
			return err
		}
	}
	rows, err := s.db.QueryContext(ctx, "SELECT resource,operation_id FROM locks ORDER BY resource")
	if err != nil {
		return err
	}
	type held struct {
		resource  string
		operation domain.ID
	}
	locks := []held{}
	for rows.Next() {
		var l held
		if err := rows.Scan(&l.resource, &l.operation); err != nil {
			rows.Close()
			return err
		}
		locks = append(locks, l)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, l := range locks {
		if _, err := dst.db.ExecContext(ctx, "INSERT INTO locks(resource,operation_id) VALUES(?,?)", l.resource, l.operation); err != nil {
			return err
		}
	}
	return dst.CheckDatabase(ctx)
}

func (s *Store) CheckDatabase(ctx context.Context) error {
	var result string
	if err := s.db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result); err != nil {
		return err
	}
	if result != "ok" {
		return errors.New("executor backup database integrity check failed")
	}
	rows, err := s.db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	defer rows.Close()
	if rows.Next() {
		return errors.New("executor backup database has foreign key violations")
	}
	return rows.Err()
}

// PrepareRestoredState is intentionally offline. Historical queued work is
// cancelled; running work becomes interrupted and keeps every recovery lock.
func (s *Store) PrepareRestoredState(ctx context.Context, at time.Time) error {
	if at.IsZero() {
		return errors.New("restore timestamp is required")
	}
	if err := s.CheckDatabase(ctx); err != nil {
		return err
	}
	ops, err := s.ListOperations(ctx)
	if err != nil {
		return err
	}
	recoveries, err := s.List(ctx, "recovery_request", "")
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, op := range ops {
		if op.State != domain.OperationQueued && op.State != domain.OperationRunning {
			continue
		}
		when := at.UTC()
		if !when.After(op.UpdatedAt) {
			when = op.UpdatedAt.Add(time.Nanosecond)
		}
		next := domain.OperationInterrupted
		evidence := domain.OutcomeEvidence{Reason: "backup restored; explicit reconciliation is required"}
		if op.State == domain.OperationQueued {
			next = domain.OperationCancelled
			evidence = domain.OutcomeEvidence{ActualStateKnown: true, ResultRecorded: true, Reason: "queued operation disabled during backup restore"}
		}
		if err := op.Transition(next, evidence, when); err != nil {
			return err
		}
		raw, err := json.Marshal(op)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE operations SET payload=?,updated_at=? WHERE id=?", raw, when.UnixNano(), op.Spec.ID); err != nil {
			return err
		}
		if next == domain.OperationCancelled {
			if _, err := tx.ExecContext(ctx, "DELETE FROM locks WHERE operation_id=?", op.Spec.ID); err != nil {
				return err
			}
		}
		if err := insertEvent(ctx, tx, Event{OperationID: op.Spec.ID, At: when, Kind: "backup_restore", Message: evidence.Reason}); err != nil {
			return err
		}
	}
	// A recovery approval is a durable queue of its own. Restoring an old
	// approval must never replay compensation, even if its preview still matches.
	for _, record := range recoveries {
		var request struct {
			OperationID domain.ID `json:"operation_id"`
		}
		if err := json.Unmarshal(record.Payload, &request); err != nil {
			return err
		}
		if err := request.OperationID.Validate(); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO records(kind,id,service_id,payload,digest,created_at) VALUES('recovery_consumed',?,?,?,?,?)", record.ID, record.ServiceID, []byte("true"), domain.Hash([]byte("true")), at.UnixNano())
		if err != nil {
			return err
		}
		if count, err := result.RowsAffected(); err != nil {
			return err
		} else if count > 0 {
			if err := insertEvent(ctx, tx, Event{OperationID: request.OperationID, At: at.UTC(), Kind: "backup_restore", Message: "queued recovery approval disabled during backup restore; review a new preview"}); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// CheckpointDatabase leaves a self-contained DB in a staging directory that is
// about to be published. No live connection may remain when it is archived.
func (s *Store) CheckpointDatabase(ctx context.Context) error {
	var busy, log, checkpointed int
	if err := s.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &checkpointed); err != nil {
		return err
	}
	if busy != 0 {
		return fmt.Errorf("database checkpoint is busy")
	}
	return nil
}
