// Package store owns executor metadata. Its SQLite file belongs to the executor
// UID and must live in an administrator-controlled directory, outside game mounts.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound            = errors.New("record not found")
	ErrImmutable           = errors.New("immutable record already exists with different content")
	ErrConflict            = errors.New("record changed or registration conflicts")
	ErrIdempotencyConflict = errors.New("idempotency key reused with different parameters")
	ErrBusy                = errors.New("resource is locked")
)

type Store struct{ db *sql.DB }

func Open(filename string) (*Store, error) {
	if !filepath.IsAbs(filename) {
		return nil, fmt.Errorf("executor database path must be absolute")
	}
	if info, err := os.Lstat(filename); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, fmt.Errorf("executor database must be a regular file accessible only to its owner")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		return nil, err
	}
	// Create exclusively at the requested mode; SQLite sidecars inherit DB mode.
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err == nil {
		if err := file.Close(); err != nil {
			return nil, err
		}
	} else if !os.IsExist(err) {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: filename}
	query := u.Query()
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_pragma", "synchronous(FULL)")
	u.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	fail := func(err error) (*Store, error) { _ = db.Close(); return nil, err }
	var journal string
	if err := db.QueryRow("PRAGMA journal_mode=WAL").Scan(&journal); err != nil {
		return fail(err)
	}
	if journal != "wal" {
		return fail(fmt.Errorf("executor database requires WAL mode"))
	}
	var synchronous, foreignKeys int
	if err := db.QueryRow("PRAGMA synchronous").Scan(&synchronous); err != nil {
		return fail(err)
	}
	if err := db.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		return fail(err)
	}
	if synchronous != 2 || foreignKeys != 1 {
		return fail(fmt.Errorf("executor database durability settings unavailable"))
	}
	if _, err := db.Exec(schema); err != nil {
		return fail(err)
	}
	if _, err := db.Exec(runtimeEventSchema); err != nil {
		return fail(err)
	}
	if _, err := db.Exec(diagnosticSchema); err != nil {
		return fail(err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Durability exposes the settings for preflight and acceptance tests.
func (s *Store) Durability(ctx context.Context) (journal string, synchronous int, err error) {
	if err = s.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
		return
	}
	err = s.db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous)
	return
}

const schema = `
CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY CHECK(version = 1));
INSERT OR IGNORE INTO schema_version(version) VALUES(1);
CREATE TABLE IF NOT EXISTS records(
 kind TEXT NOT NULL,id TEXT NOT NULL,service_id TEXT NOT NULL,payload BLOB NOT NULL,digest TEXT NOT NULL,created_at INTEGER NOT NULL,
 PRIMARY KEY(kind,id)
);
CREATE TRIGGER IF NOT EXISTS records_no_update BEFORE UPDATE ON records BEGIN SELECT RAISE(ABORT,'immutable record'); END;
CREATE TABLE IF NOT EXISTS proposals(
 id TEXT PRIMARY KEY,service_id TEXT NOT NULL,digest TEXT NOT NULL,payload BLOB NOT NULL,actor TEXT NOT NULL,created_at INTEGER NOT NULL
);
CREATE TRIGGER IF NOT EXISTS proposals_no_update BEFORE UPDATE ON proposals BEGIN SELECT RAISE(ABORT,'immutable proposal'); END;
CREATE TABLE IF NOT EXISTS approvals(proposal_id TEXT PRIMARY KEY REFERENCES proposals(id),actor TEXT NOT NULL,approved_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS services(id TEXT PRIMARY KEY,revision INTEGER NOT NULL,payload BLOB NOT NULL,digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS service_revisions(service_id TEXT NOT NULL,revision INTEGER NOT NULL,payload BLOB NOT NULL,digest TEXT NOT NULL,PRIMARY KEY(service_id,revision));
CREATE TRIGGER IF NOT EXISTS service_revisions_no_update BEFORE UPDATE ON service_revisions BEGIN SELECT RAISE(ABORT,'immutable policy revision'); END;
CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY,initiator TEXT NOT NULL,idempotency_key TEXT NOT NULL,input_hash TEXT NOT NULL,payload BLOB NOT NULL,updated_at INTEGER NOT NULL,UNIQUE(initiator,idempotency_key));
CREATE TABLE IF NOT EXISTS locks(resource TEXT PRIMARY KEY,operation_id TEXT NOT NULL REFERENCES operations(id));
CREATE TABLE IF NOT EXISTS events(sequence INTEGER PRIMARY KEY AUTOINCREMENT,operation_id TEXT NOT NULL REFERENCES operations(id),at INTEGER NOT NULL,kind TEXT NOT NULL,message TEXT NOT NULL,payload BLOB);
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'append-only journal'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'append-only journal'); END;
CREATE INDEX IF NOT EXISTS events_by_operation ON events(operation_id,sequence);
`
