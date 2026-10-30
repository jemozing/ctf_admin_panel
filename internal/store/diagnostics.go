package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

const (
	OperationDiagnosticLimit = 20 << 20
	GlobalDiagnosticLimit    = 200 << 20
	DiagnosticChunkLimit     = 32 << 10
)

// Diagnostics deliberately do not share the immutable events table. Removing
// expendable command output must never remove acceptance, mutation intents,
// state transitions or the audit trail that explains the actual result.
const diagnosticSchema = `
CREATE TABLE IF NOT EXISTS operation_diagnostics(
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 operation_id TEXT NOT NULL REFERENCES operations(id),at INTEGER NOT NULL,
 stage TEXT NOT NULL,content TEXT NOT NULL,bytes INTEGER NOT NULL CHECK(bytes>=0)
);
CREATE INDEX IF NOT EXISTS diagnostic_operation ON operation_diagnostics(operation_id,sequence);
CREATE TABLE IF NOT EXISTS diagnostic_retention(
 operation_id TEXT PRIMARY KEY REFERENCES operations(id),dropped_bytes INTEGER NOT NULL DEFAULT 0
);
`

type DiagnosticChunk struct {
	Sequence uint64    `json:"sequence"`
	At       time.Time `json:"at"`
	Stage    string    `json:"stage"`
	Content  string    `json:"content"`
}
type DiagnosticLog struct {
	Chunks        []DiagnosticChunk `json:"chunks"`
	Bytes         uint64            `json:"bytes"`
	ReturnedBytes uint64            `json:"returned_bytes"`
	NextSequence  uint64            `json:"next_sequence"`
	HasMore       bool              `json:"has_more"`
	DroppedBytes  uint64            `json:"dropped_bytes"`
	Truncated     bool              `json:"truncated"`
}

// AppendDiagnostic accepts already redacted, display-safe text from executor.
// The tail is retained under both limits, with a permanent dropped byte count.
func (s *Store) AppendDiagnostic(ctx context.Context, operation domain.ID, stage, content string) error {
	return s.appendDiagnostic(ctx, operation, stage, content, OperationDiagnosticLimit, GlobalDiagnosticLimit)
}

func (s *Store) appendDiagnostic(ctx context.Context, operation domain.ID, stage, content string, operationLimit, globalLimit int64) error {
	if err := operation.Validate(); err != nil {
		return err
	}
	if !kindPattern.MatchString(stage) || len(content) > DiagnosticChunkLimit || !utf8.ValidString(content) {
		return fmt.Errorf("invalid bounded operation diagnostic")
	}
	if content == "" {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := readOperation(ctx, tx, operation); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO operation_diagnostics(operation_id,at,stage,content,bytes) VALUES(?,?,?,?,?)", operation, time.Now().UTC().UnixNano(), stage, content, len(content)); err != nil {
		return err
	}
	for _, scope := range []bool{true, false} {
		limit := globalLimit
		where, args := "", []any{}
		if scope {
			limit, where, args = operationLimit, " WHERE operation_id=?", []any{operation}
		}
		var used int64
		if err := tx.QueryRowContext(ctx, "SELECT COALESCE(SUM(bytes),0) FROM operation_diagnostics"+where, args...).Scan(&used); err != nil {
			return err
		}
		for used > limit {
			var sequence, size int64
			var owner domain.ID
			if err := tx.QueryRowContext(ctx, "SELECT sequence,operation_id,bytes FROM operation_diagnostics"+where+" ORDER BY sequence LIMIT 1", args...).Scan(&sequence, &owner, &size); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "INSERT INTO diagnostic_retention(operation_id,dropped_bytes) VALUES(?,?) ON CONFLICT(operation_id) DO UPDATE SET dropped_bytes=dropped_bytes+excluded.dropped_bytes", owner, size); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "DELETE FROM operation_diagnostics WHERE sequence=?", sequence); err != nil {
				return err
			}
			used -= size
		}
	}
	return tx.Commit()
}

func (s *Store) Diagnostics(ctx context.Context, operation domain.ID) (DiagnosticLog, error) {
	return s.DiagnosticsPage(ctx, operation, 0)
}

// DiagnosticsPage bounds a response to 32 chunks (at most 1 MiB before JSON
// escaping). The stable sequence cursor remains valid after output rotation.
func (s *Store) DiagnosticsPage(ctx context.Context, operation domain.ID, after uint64) (DiagnosticLog, error) {
	result := DiagnosticLog{Chunks: []DiagnosticChunk{}}
	if err := operation.Validate(); err != nil {
		return result, err
	}
	// A transaction keeps chunk bytes and the retention marker from different
	// concurrent writes out of the same response.
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	if _, err := readOperation(ctx, tx, operation); err != nil {
		return result, err
	}
	err = tx.QueryRowContext(ctx, "SELECT dropped_bytes FROM diagnostic_retention WHERE operation_id=?", operation).Scan(&result.DroppedBytes)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return result, err
	}
	if after > 1<<63-1 {
		return result, fmt.Errorf("invalid diagnostic cursor")
	}
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(SUM(bytes),0) FROM operation_diagnostics WHERE operation_id=?", operation).Scan(&result.Bytes); err != nil {
		return result, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT sequence,at,stage,content,bytes FROM operation_diagnostics WHERE operation_id=? AND sequence>? ORDER BY sequence LIMIT 33", operation, int64(after))
	if err != nil {
		return result, err
	}
	for rows.Next() {
		if len(result.Chunks) == 32 {
			result.HasMore = true
			break
		}
		var chunk DiagnosticChunk
		var at int64
		var size uint64
		if err := rows.Scan(&chunk.Sequence, &at, &chunk.Stage, &chunk.Content, &size); err != nil {
			rows.Close()
			return result, err
		}
		chunk.At = time.Unix(0, at).UTC()
		result.Chunks = append(result.Chunks, chunk)
		result.ReturnedBytes += size
		result.NextSequence = chunk.Sequence
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return result, err
	}
	if err := rows.Close(); err != nil {
		return result, err
	}
	result.Truncated = result.DroppedBytes > 0
	return result, tx.Commit()
}
