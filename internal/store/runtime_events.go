package store

import (
	"context"
	"fmt"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"time"
)

// Runtime events are observation history, independent of the immutable operation
// audit. Bounded retention is explicit; a Docker reconnect never proves no loss.
const RuntimeEventLimit = 10000
const runtimeEventSchema = `CREATE TABLE IF NOT EXISTS runtime_events(sequence INTEGER PRIMARY KEY AUTOINCREMENT,service_id TEXT NOT NULL,container_id TEXT NOT NULL,component TEXT NOT NULL,kind TEXT NOT NULL,at INTEGER NOT NULL,observed_at INTEGER NOT NULL,UNIQUE(container_id,kind,at)); CREATE INDEX IF NOT EXISTS runtime_events_service ON runtime_events(service_id,sequence);`

type RuntimeEvent struct {
	Sequence    uint64    `json:"sequence"`
	ServiceID   domain.ID `json:"service_id"`
	ContainerID string    `json:"container_id"`
	Component   string    `json:"component"`
	Kind        string    `json:"kind"`
	At          time.Time `json:"at"`
	ObservedAt  time.Time `json:"observed_at"`
}

func (s *Store) AppendRuntimeEvent(ctx context.Context, e RuntimeEvent) error {
	if e.ServiceID.Validate() != nil || len(e.ContainerID) != 64 || len(e.Component) > 128 || e.Component == "" || e.At.IsZero() || e.ObservedAt.IsZero() {
		return fmt.Errorf("invalid runtime event")
	}
	for _, c := range e.ContainerID {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return fmt.Errorf("invalid container ID")
		}
	}
	switch e.Kind {
	case "oom", "restart", "die", "start", "destroy":
	default:
		return fmt.Errorf("invalid runtime event kind")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO runtime_events(service_id,container_id,component,kind,at,observed_at) VALUES(?,?,?,?,?,?)", e.ServiceID, e.ContainerID, e.Component, e.Kind, e.At.UnixNano(), e.ObservedAt.UnixNano()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM runtime_events WHERE sequence <= (SELECT sequence FROM runtime_events ORDER BY sequence DESC LIMIT 1 OFFSET ?)", RuntimeEventLimit); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RuntimeEvents(ctx context.Context, id domain.ID) ([]RuntimeEvent, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT sequence,service_id,container_id,component,kind,at,observed_at FROM runtime_events WHERE service_id=? ORDER BY sequence DESC LIMIT 200", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RuntimeEvent{}
	for rows.Next() {
		var e RuntimeEvent
		var at, observed int64
		if err := rows.Scan(&e.Sequence, &e.ServiceID, &e.ContainerID, &e.Component, &e.Kind, &at, &observed); err != nil {
			return nil, err
		}
		e.At = time.Unix(0, at).UTC()
		e.ObservedAt = time.Unix(0, observed).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) RuntimeEventCursor(ctx context.Context) (time.Time, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(at),0) FROM runtime_events").Scan(&n); err != nil {
		return time.Time{}, err
	}
	if n == 0 {
		return time.Time{}, nil
	}
	return time.Unix(0, n).UTC(), nil
}
