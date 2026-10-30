package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

// SaveHealthRecord serializes health policy/manual evidence with service changes.
// It uses the existing immutable record table; no schema migration is necessary.
func (s *Store) SaveHealthRecord(ctx context.Context, kind string, id, serviceID domain.ID, policyRevision, expectedRevision uint64, value any) error {
	if kind != "health_policy" && kind != "manual_health" {
		return fmt.Errorf("invalid health record kind")
	}
	if err := id.Validate(); err != nil {
		return err
	}
	if err := serviceID.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var revision uint64
	if err := tx.QueryRowContext(ctx, "SELECT revision FROM services WHERE id=?", serviceID).Scan(&revision); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if revision != policyRevision {
		return ErrConflict
	}
	rows, err := tx.QueryContext(ctx, "SELECT payload FROM operations")
	if err != nil {
		return err
	}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		var op domain.Operation
		if err := json.Unmarshal(raw, &op); err != nil {
			rows.Close()
			return err
		}
		if op.Spec.ServiceID == serviceID && !op.State.Terminal() {
			rows.Close()
			return &BusyError{Resource: "service:" + string(serviceID), Owner: op.Spec.ID}
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if kind == "health_policy" {
		rows, err := tx.QueryContext(ctx, "SELECT payload FROM records WHERE kind='health_policy' AND service_id=?", serviceID)
		if err != nil {
			return err
		}
		var latest uint64
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				return err
			}
			var record struct {
				Revision uint64 `json:"revision"`
			}
			if err := json.Unmarshal(raw, &record); err != nil {
				rows.Close()
				return err
			}
			if record.Revision > latest {
				latest = record.Revision
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if latest != expectedRevision {
			return ErrConflict
		}
		var record struct {
			Revision uint64 `json:"revision"`
		}
		if err := json.Unmarshal(data, &record); err != nil || record.Revision != latest+1 {
			return ErrConflict
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO records(kind,id,service_id,payload,digest,created_at) VALUES(?,?,?,?,?,?)", kind, id, serviceID, data, domain.Hash(data), time.Now().UTC().UnixNano()); err != nil {
		return err
	}
	return tx.Commit()
}
