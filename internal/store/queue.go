package store

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

// OperationQueueWaits observes actual held locks using exactly the conflict rule
// used by Acquire. The transaction keeps owner identities and queued resources
// in the same SQLite snapshot. It does not acquire resources or write events.
func (s *Store) OperationQueueWaits(ctx context.Context) (map[domain.ID][]domain.QueueBlocker, error) {
	result := map[domain.ID][]domain.QueueBlocker{}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT payload FROM operations ORDER BY id")
	if err != nil {
		return nil, err
	}
	queued := []domain.Operation{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, err
		}
		var op domain.Operation
		if err := json.Unmarshal(raw, &op); err != nil {
			rows.Close()
			return nil, err
		}
		if err := op.Validate(); err != nil {
			rows.Close()
			return nil, err
		}
		if op.State == domain.OperationQueued {
			queued = append(queued, op)
			result[op.Spec.ID] = []domain.QueueBlocker{}
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	rows, err = tx.QueryContext(ctx, "SELECT l.resource,l.operation_id,o.initiator FROM locks l JOIN operations o ON o.id=l.operation_id ORDER BY l.resource,l.operation_id")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var held domain.QueueBlocker
		if err := rows.Scan(&held.Resource, &held.OperationID, &held.Actor); err != nil {
			rows.Close()
			return nil, err
		}
		for _, op := range queued {
			if held.OperationID == op.Spec.ID {
				continue
			}
			for _, wanted := range op.Spec.Resources {
				if resourcesConflict(held.Resource, wanted) {
					result[op.Spec.ID] = append(result[op.Spec.ID], held)
					break
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return result, tx.Commit()
}
