package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

func (s *Store) BeginOperation(ctx context.Context, op domain.Operation, inputHash domain.Digest) (domain.Operation, bool, error) {
	if op.QueueWait != nil {
		return domain.Operation{}, false, fmt.Errorf("read-only queue observations cannot be persisted")
	}
	if err := op.Validate(); err != nil {
		return domain.Operation{}, false, err
	}
	if op.State != domain.OperationQueued || op.MutationStarted {
		return domain.Operation{}, false, fmt.Errorf("new operation must be queued without mutation")
	}
	if err := inputHash.Validate(); err != nil {
		return domain.Operation{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Operation{}, false, err
	}
	defer tx.Rollback()
	var existing []byte
	var hash domain.Digest
	err = tx.QueryRowContext(ctx, "SELECT payload,input_hash FROM operations WHERE initiator=? AND idempotency_key=?", op.Spec.Initiator, op.Spec.IdempotencyKey).Scan(&existing, &hash)
	if err == nil {
		if hash != inputHash {
			return domain.Operation{}, false, ErrIdempotencyConflict
		}
		var result domain.Operation
		if err := json.Unmarshal(existing, &result); err != nil {
			return domain.Operation{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return domain.Operation{}, false, err
		}
		return result, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return domain.Operation{}, false, err
	}
	payload, err := json.Marshal(op)
	if err != nil {
		return domain.Operation{}, false, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO operations(id,initiator,idempotency_key,input_hash,payload,updated_at) VALUES(?,?,?,?,?,?)", op.Spec.ID, op.Spec.Initiator, op.Spec.IdempotencyKey, inputHash, payload, op.UpdatedAt.UnixNano()); err != nil {
		return domain.Operation{}, false, err
	}
	if err := insertEvent(ctx, tx, Event{OperationID: op.Spec.ID, At: op.CreatedAt, Kind: "accepted", Message: "operation queued"}); err != nil {
		return domain.Operation{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return domain.Operation{}, false, err
	}
	return op, true, nil
}

func readOperation(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, id domain.ID) (domain.Operation, error) {
	var payload []byte
	if err := q.QueryRowContext(ctx, "SELECT payload FROM operations WHERE id=?", id).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Operation{}, ErrNotFound
		}
		return domain.Operation{}, err
	}
	var op domain.Operation
	if err := json.Unmarshal(payload, &op); err != nil {
		return op, err
	}
	return op, op.Validate()
}

func (s *Store) GetOperation(ctx context.Context, id domain.ID) (domain.Operation, error) {
	return readOperation(ctx, s.db, id)
}

func (s *Store) ListOperations(ctx context.Context) ([]domain.Operation, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT payload FROM operations ORDER BY updated_at,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []domain.Operation{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var op domain.Operation
		if err := json.Unmarshal(raw, &op); err != nil {
			return nil, err
		}
		if err := op.Validate(); err != nil {
			return nil, err
		}
		result = append(result, op)
	}
	return result, rows.Err()
}

func (s *Store) UpdateOperation(ctx context.Context, op domain.Operation, expectedUpdatedAt time.Time) error {
	if op.QueueWait != nil {
		return fmt.Errorf("read-only queue observations cannot be persisted")
	}
	if err := op.Validate(); err != nil {
		return err
	}
	if !op.UpdatedAt.After(expectedUpdatedAt) {
		return fmt.Errorf("%w: update time must advance", ErrConflict)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	previous, err := readOperation(ctx, tx, op.Spec.ID)
	if err != nil {
		return err
	}
	if !previous.UpdatedAt.Equal(expectedUpdatedAt) {
		return ErrConflict
	}
	if !reflect.DeepEqual(previous.Spec, op.Spec) || !previous.CreatedAt.Equal(op.CreatedAt) {
		return ErrImmutable
	}
	if op.State == domain.OperationRunning || op.MutationStarted && !previous.MutationStarted {
		for _, resource := range op.Spec.Resources {
			var owner domain.ID
			if err := tx.QueryRowContext(ctx, "SELECT operation_id FROM locks WHERE resource=?", resource).Scan(&owner); err != nil || owner != op.Spec.ID {
				return fmt.Errorf("running operation must own every specified resource lock")
			}
		}
	}
	check := previous
	if previous.MutationStarted && (!op.MutationStarted || previous.RecoveryPointID != op.RecoveryPointID) {
		return ErrImmutable
	}
	if !previous.MutationStarted && op.MutationStarted {
		if err := check.BeginMutation(op.RecoveryPointID, op.UpdatedAt); err != nil {
			return err
		}
	}
	if previous.CancelRequested && !op.CancelRequested {
		return ErrImmutable
	}
	if !previous.CancelRequested && op.CancelRequested {
		if err := check.RequestCancel(op.UpdatedAt); err != nil {
			return err
		}
	}
	if previous.State != op.State {
		if err := check.Transition(op.State, op.Outcome, op.UpdatedAt); err != nil {
			return err
		}
	} else if previous.State.Terminal() {
		return ErrImmutable
	}
	payload, err := json.Marshal(op)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, "UPDATE operations SET payload=?,updated_at=? WHERE id=? AND updated_at=?", payload, op.UpdatedAt.UnixNano(), op.Spec.ID, expectedUpdatedAt.UnixNano())
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return ErrConflict
	}
	if err := insertEvent(ctx, tx, Event{OperationID: op.Spec.ID, At: op.UpdatedAt, Kind: "state", Message: string(op.State) + ":" + string(op.Stage), Payload: payload}); err != nil {
		return err
	}
	// Terminal outcome and resource release are one durable commit. A crash
	// between recording cancellation/success and a later Release cannot strand
	// locks owned by a job which is no longer runnable.
	if op.State.Terminal() {
		if _, err := tx.ExecContext(ctx, "DELETE FROM locks WHERE operation_id=?", op.Spec.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type Event struct {
	Sequence    uint64          `json:"sequence"`
	OperationID domain.ID       `json:"operation_id"`
	At          time.Time       `json:"at"`
	Kind        string          `json:"kind"`
	Message     string          `json:"message"`
	Payload     json.RawMessage `json:"payload,omitempty"`
}

func insertEvent(ctx context.Context, tx *sql.Tx, event Event) error {
	if err := event.OperationID.Validate(); err != nil {
		return err
	}
	if event.At.IsZero() || !kindPattern.MatchString(event.Kind) || len(event.Message) > 16384 {
		return fmt.Errorf("invalid operation event")
	}
	if len(event.Payload) > 1024*1024 || len(event.Payload) > 0 && !json.Valid(event.Payload) {
		return fmt.Errorf("invalid event payload")
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO events(operation_id,at,kind,message,payload) VALUES(?,?,?,?,?)", event.OperationID, event.At.UnixNano(), event.Kind, event.Message, []byte(event.Payload))
	return err
}

func (s *Store) AppendEvent(ctx context.Context, event Event) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := insertEvent(ctx, tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Events(ctx context.Context, id domain.ID) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT sequence,at,kind,message,payload FROM events WHERE operation_id=? ORDER BY sequence", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Event{}
	for rows.Next() {
		event := Event{OperationID: id}
		var at int64
		var payload []byte
		if err := rows.Scan(&event.Sequence, &at, &event.Kind, &event.Message, &payload); err != nil {
			return nil, err
		}
		event.Payload = json.RawMessage(payload)
		event.At = time.Unix(0, at).UTC()
		result = append(result, event)
	}
	return result, rows.Err()
}

type BusyError struct {
	Resource string
	Owner    domain.ID
}

func (e *BusyError) Error() string {
	return fmt.Sprintf("resource %s is locked by operation %s", e.Resource, e.Owner)
}
func (e *BusyError) Unwrap() error { return ErrBusy }

func (s *Store) Acquire(ctx context.Context, id domain.ID, resources []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	op, err := readOperation(ctx, tx, id)
	if err != nil {
		return err
	}
	if op.State.Terminal() {
		return fmt.Errorf("terminal operation cannot acquire resources")
	}
	wanted := append([]string{}, resources...)
	sort.Strings(wanted)
	expected := append([]string{}, op.Spec.Resources...)
	sort.Strings(expected)
	if !reflect.DeepEqual(wanted, expected) {
		return fmt.Errorf("resource set must match immutable operation specification")
	}
	rows, err := tx.QueryContext(ctx, "SELECT resource,operation_id FROM locks ORDER BY resource")
	if err != nil {
		return err
	}
	for rows.Next() {
		var resource string
		var owner domain.ID
		if err := rows.Scan(&resource, &owner); err != nil {
			rows.Close()
			return err
		}
		if owner == id {
			continue
		}
		for _, candidate := range wanted {
			if resourcesConflict(resource, candidate) {
				rows.Close()
				return &BusyError{Resource: resource, Owner: owner}
			}
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, resource := range wanted {
		if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO locks(resource,operation_id) VALUES(?,?)", resource, id); err != nil {
			return err
		}
	}
	if err := insertEvent(ctx, tx, Event{OperationID: id, At: time.Now().UTC(), Kind: "locks_acquired", Message: "exclusive operation resources acquired"}); err != nil {
		return err
	}
	return tx.Commit()
}

func resourcesConflict(a, b string) bool {
	if a == b {
		return true
	}
	if strings.HasPrefix(a, "path:") && strings.HasPrefix(b, "path:") {
		return domain.PathsOverlap(strings.TrimPrefix(a, "path:"), strings.TrimPrefix(b, "path:"))
	}
	return false
}

func (s *Store) Release(ctx context.Context, id domain.ID) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	op, err := readOperation(ctx, tx, id)
	if err != nil {
		return err
	}
	if op.State != domain.OperationQueued && !op.State.Terminal() {
		return fmt.Errorf("active or unresolved operation must retain locks")
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM locks WHERE operation_id=?", id); err != nil {
		return err
	}
	if err := insertEvent(ctx, tx, Event{OperationID: id, At: time.Now().UTC(), Kind: "locks_released", Message: "operation resources released"}); err != nil {
		return err
	}
	return tx.Commit()
}

// MarkInterrupted preserves all locks and recovery references; no Docker or file
// action is replayed. Call once on executor startup before accepting new mutations.
func (s *Store) MarkInterrupted(ctx context.Context, at time.Time) ([]domain.Operation, error) {
	ops, err := s.ListOperations(ctx)
	if err != nil {
		return nil, err
	}
	result := []domain.Operation{}
	for _, op := range ops {
		if op.State != domain.OperationRunning {
			continue
		}
		previous := op.UpdatedAt
		timestamp := at
		if !timestamp.After(previous) {
			timestamp = previous.Add(time.Nanosecond)
		}
		if err := op.Transition(domain.OperationInterrupted, domain.OutcomeEvidence{Reason: "executor restarted before completion"}, timestamp); err != nil {
			return nil, err
		}
		if err := s.UpdateOperation(ctx, op, previous); err != nil {
			return nil, err
		}
		result = append(result, op)
	}
	return result, nil
}
