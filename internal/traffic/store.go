package traffic

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/maintenance"
	_ "modernc.org/sqlite"
)

const MaxExchangeBytes = 256 << 10
const MaxBodyBytes = 64 << 10

var ErrNotFound = errors.New("traffic exchange not found")
var ErrQuota = errors.New("traffic recorder capacity exhausted")
var ErrConflict = errors.New("traffic exchange update conflicts with recorded identity or state")
var ErrExpired = errors.New("traffic exchange is outside the retention window")

type Config struct {
	StateDirectory   string           `json:"state_directory"`
	QuotaBytes       int64            `json:"quota_bytes,omitempty"`
	PerServiceBytes  int64            `json:"per_service_bytes,omitempty"`
	MinimumFreeBytes int64            `json:"minimum_free_bytes,omitempty"`
	Retention        time.Duration    `json:"-"`
	MaxRecords       int              `json:"max_records,omitempty"`
	Now              func() time.Time `json:"-"`
}

type Store struct {
	mu            sync.Mutex
	db            *sql.DB
	config        Config
	filename      string
	lock          *maintenance.Lock
	epoch         string
	started       time.Time
	previous      bool
	counters      Counters
	lastError     string
	closed        bool
	storageFailed bool
	totalBytes    int64
	totalRecords  int64
	serviceBytes  map[string]int64
	stop          chan struct{}
	done          chan struct{}
	closeOnce     sync.Once
	closeError    error
}

func Open(c Config) (*Store, error) {
	if c.QuotaBytes == 0 {
		c.QuotaBytes = 512 << 20
	}
	if c.PerServiceBytes == 0 {
		c.PerServiceBytes = 128 << 20
		if c.PerServiceBytes > c.QuotaBytes/4 {
			c.PerServiceBytes = c.QuotaBytes / 4
		}
	}
	if c.MinimumFreeBytes == 0 {
		c.MinimumFreeBytes = 64 << 20
	}
	if c.Retention == 0 {
		c.Retention = time.Hour
	}
	if c.MaxRecords == 0 {
		c.MaxRecords = 100000
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if !filepath.IsAbs(c.StateDirectory) || filepath.Clean(c.StateDirectory) != c.StateDirectory || c.StateDirectory == "/" {
		return nil, errors.New("traffic state must be a canonical absolute private directory")
	}
	if c.QuotaBytes < 4<<20 || c.QuotaBytes > 8<<30 || c.PerServiceBytes < MaxExchangeBytes || c.PerServiceBytes > c.QuotaBytes || c.Retention < time.Second || c.Retention > 24*time.Hour || c.MaxRecords < 1 || c.MaxRecords > 1000000 || c.MinimumFreeBytes < 0 {
		return nil, errors.New("traffic recorder limits are outside supported bounds")
	}
	if err := os.MkdirAll(c.StateDirectory, 0700); err != nil {
		return nil, err
	}
	lock, err := maintenance.Acquire(c.StateDirectory, true)
	if err != nil {
		return nil, errors.New("traffic recorder state is not private or already in use")
	}
	fail := func(err error) (*Store, error) { _ = lock.Close(); return nil, err }
	filename := filepath.Join(c.StateDirectory, "traffic.sqlite")
	if st, err := os.Lstat(filename); err == nil {
		if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
			return fail(errors.New("traffic database must be a private regular file"))
		}
	} else if !os.IsNotExist(err) {
		return fail(err)
	}
	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		_ = file.Close()
	} else if !os.IsExist(err) {
		return fail(err)
	}
	u := url.URL{Scheme: "file", Path: filename}
	q := u.Query()
	q.Add("_pragma", "busy_timeout(1000)")
	q.Add("_pragma", "synchronous(FULL)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return fail(err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	failDB := func(err error) (*Store, error) { _ = db.Close(); return fail(err) }
	// A bounded rollback journal is easier to account than an arbitrarily pinned
	// WAL. Only this recorder process opens the database and queries are short.
	for _, statement := range []string{"PRAGMA journal_mode=TRUNCATE", "PRAGMA auto_vacuum=INCREMENTAL", "PRAGMA secure_delete=ON", "PRAGMA temp_store=MEMORY", "PRAGMA cache_size=-2048"} {
		if _, err := db.Exec(statement); err != nil {
			return failDB(err)
		}
	}
	var pageSize int64
	if err := db.QueryRow("PRAGMA page_size").Scan(&pageSize); err != nil {
		return failDB(err)
	}
	// Keep half the physical quota for the rollback journal and SQLite metadata.
	// The maximum DB page count is enforced by SQLite, independently of estimates.
	maximumPages := (c.QuotaBytes * 45 / 100) / pageSize
	var appliedPages int64
	if err := db.QueryRow(fmt.Sprintf("PRAGMA max_page_count=%d", maximumPages)).Scan(&appliedPages); err != nil {
		return failDB(err)
	}
	if appliedPages > maximumPages {
		return failDB(errors.New("existing traffic database exceeds the new physical quota"))
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS recorder_meta(key TEXT PRIMARY KEY,value INTEGER NOT NULL);
INSERT OR IGNORE INTO recorder_meta VALUES('sequence',0),('retired',0),('opened',0);
CREATE TABLE IF NOT EXISTS exchanges(request_id TEXT PRIMARY KEY,sequence INTEGER NOT NULL UNIQUE,collector_epoch TEXT NOT NULL,service_id TEXT NOT NULL,route_id TEXT NOT NULL,at INTEGER NOT NULL,updated_at INTEGER NOT NULL,state TEXT NOT NULL,method TEXT NOT NULL,status INTEGER NOT NULL,url TEXT NOT NULL,waf TEXT NOT NULL,client_ip TEXT NOT NULL,ip BLOB NOT NULL,ip_family INTEGER NOT NULL,metadata BLOB NOT NULL,detail BLOB NOT NULL,bytes INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS traffic_service_sequence ON exchanges(service_id,sequence);
CREATE INDEX IF NOT EXISTS traffic_at ON exchanges(at);
CREATE INDEX IF NOT EXISTS traffic_ip ON exchanges(ip_family,ip);
CREATE INDEX IF NOT EXISTS traffic_route_sequence ON exchanges(route_id,sequence);`); err != nil {
		return failDB(err)
	}
	var opened int
	if err := db.QueryRow("SELECT value FROM recorder_meta WHERE key='opened'").Scan(&opened); err != nil {
		return failDB(err)
	}
	if _, err := db.Exec("UPDATE recorder_meta SET value=1 WHERE key='opened'"); err != nil {
		return failDB(err)
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return failDB(err)
	}
	s := &Store{db: db, config: c, filename: filename, lock: lock, epoch: hex.EncodeToString(token[:]), started: c.Now().UTC(), previous: opened != 0, stop: make(chan struct{}), done: make(chan struct{}), serviceBytes: map[string]int64{}}
	rows, err := db.Query("SELECT service_id,COALESCE(SUM(bytes),0),COUNT(*) FROM exchanges GROUP BY service_id")
	if err != nil {
		return failDB(err)
	}
	for rows.Next() {
		var id string
		var size, count int64
		if err := rows.Scan(&id, &size, &count); err != nil {
			rows.Close()
			return failDB(err)
		}
		s.serviceBytes[id] = size
		s.totalBytes += size
		s.totalRecords += count
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return failDB(err)
	}
	rows.Close()
	if err := s.rotateLocked(context.Background()); err != nil {
		return failDB(err)
	}
	go s.sweep()
	return s, nil
}

func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		close(s.stop)
		s.mu.Unlock()
		<-s.done
		s.mu.Lock()
		defer s.mu.Unlock()
		s.closeError = errors.Join(s.db.Close(), s.lock.Close())
	})
	return s.closeError
}

func (s *Store) sweep() {
	defer close(s.done)
	interval := s.config.Retention / 10
	if interval > time.Minute {
		interval = time.Minute
	}
	if interval < 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			s.mu.Lock()
			if !s.closed && !s.storageFailed {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				if err := s.rotateLocked(ctx); err != nil {
					s.writeError(err)
				}
				cancel()
			}
			s.mu.Unlock()
		}
	}
}

func (s *Store) Ingest(ctx context.Context, exchange Exchange) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.storageFailed {
		return 0, errors.New("traffic recorder closed")
	}
	if err := sanitizeExchange(&exchange, s.config.Now()); err != nil {
		s.counters.Rejected++
		return 0, err
	}
	if exchange.At.Before(s.config.Now().Add(-s.config.Retention)) {
		s.counters.Rejected++
		return 0, ErrExpired
	}
	exchange.Sequence = 0
	if err := s.rotateLocked(ctx); err != nil {
		return 0, s.writeError(err)
	}
	if err := s.reserveLocked(); err != nil {
		s.counters.Rejected++
		s.lastError = "free_space_reserve"
		return 0, err
	}
	var oldMetadata []byte
	var oldSize int64
	err := s.db.QueryRowContext(ctx, "SELECT metadata,bytes FROM exchanges WHERE request_id=?", exchange.RequestID).Scan(&oldMetadata, &oldSize)
	var old Metadata
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, s.writeError(err)
	}
	if exists {
		if err := json.Unmarshal(oldMetadata, &old); err != nil {
			return 0, s.writeError(err)
		}
		if old.CollectorEpoch != exchange.CollectorEpoch || old.ServiceID != exchange.ServiceID || old.RouteID != exchange.RouteID || !old.At.Equal(exchange.At) || old.PolicyRevision != exchange.PolicyRevision || old.PeerIP != exchange.PeerIP || old.ClientIP != exchange.ClientIP || old.HTTPProtocol != exchange.HTTPProtocol || old.Method != exchange.Method || old.URL != exchange.URL || old.Upstream != exchange.Upstream || exchange.UpdatedAt.Before(old.UpdatedAt) || exchange.RequestBytes < old.RequestBytes || exchange.ResponseBytes < old.ResponseBytes || (old.State != "in_progress" && exchange.State != old.State) {
			s.counters.Rejected++
			return 0, ErrConflict
		}
		if old.State != "in_progress" {
			var detail []byte
			if err := s.db.QueryRowContext(ctx, "SELECT detail FROM exchanges WHERE request_id=?", exchange.RequestID).Scan(&detail); err != nil {
				return 0, s.writeError(err)
			}
			exchange.Sequence = old.Sequence
			encoded, _ := json.Marshal(exchange)
			if string(encoded) == string(detail) {
				return old.Sequence, nil
			}
			s.counters.Rejected++
			return 0, ErrConflict
		}
	}
	var sequence int64
	if err := s.db.QueryRowContext(ctx, "SELECT value+1 FROM recorder_meta WHERE key='sequence'").Scan(&sequence); err != nil {
		return 0, s.writeError(err)
	}
	exchange.Sequence = sequence
	meta, err := json.Marshal(exchange.Metadata)
	if err != nil {
		return 0, err
	}
	detail, err := json.Marshal(exchange)
	if err != nil {
		return 0, err
	}
	size := int64(len(meta) + len(detail) + 512)
	if len(detail) > MaxExchangeBytes || size > s.config.PerServiceBytes {
		s.counters.Rejected++
		return 0, ErrQuota
	}
	// Deleting in separate small transactions bounds the rollback journal too.
	if err := s.makeRoomLocked(ctx, exchange.ServiceID, exchange.RequestID, size, oldSize, exists); err != nil {
		s.counters.Rejected++
		return 0, err
	}
	address, _ := netip.ParseAddr(exchange.ClientIP)
	address = address.Unmap()
	ip := address.As16()
	family := 6
	if address.Is4() {
		family = 4
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, s.writeError(err)
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO exchanges(request_id,sequence,collector_epoch,service_id,route_id,at,updated_at,state,method,status,url,waf,client_ip,ip,ip_family,metadata,detail,bytes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(request_id) DO UPDATE SET sequence=excluded.sequence,updated_at=excluded.updated_at,state=excluded.state,method=excluded.method,status=excluded.status,url=excluded.url,waf=excluded.waf,client_ip=excluded.client_ip,ip=excluded.ip,ip_family=excluded.ip_family,metadata=excluded.metadata,detail=excluded.detail,bytes=excluded.bytes`, exchange.RequestID, sequence, exchange.CollectorEpoch, exchange.ServiceID, exchange.RouteID, exchange.At.UnixNano(), exchange.UpdatedAt.UnixNano(), exchange.State, exchange.Method, exchange.Status, exchange.URL, exchange.WAFDecision, exchange.ClientIP, ip[:], family, meta, detail, size)
	if err == nil {
		_, err = tx.ExecContext(ctx, "UPDATE recorder_meta SET value=? WHERE key='sequence'", sequence)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		return 0, s.writeError(err)
	}
	s.totalBytes += size - oldSize
	s.serviceBytes[exchange.ServiceID] += size - oldSize
	if !exists {
		s.totalRecords++
	}
	s.lastError = ""
	if exists {
		s.counters.Updated++
	} else {
		s.counters.Ingested++
	}
	if !exists || old.State == "in_progress" {
		if exchange.State == "completed" {
			s.counters.Completed++
		}
		if exchange.State == "aborted" {
			s.counters.Aborted++
		}
		if exchange.State != "in_progress" && exchange.ResponseSource == "waf" {
			s.counters.WAFDenied++
		}
		if exchange.State != "in_progress" && exchange.ResponseSource == "proxy" && exchange.Status >= 500 {
			s.counters.UpstreamErrors++
		}
	}
	return sequence, nil
}

func (s *Store) writeError(err error) error {
	s.counters.WriteErrors++
	s.lastError = "storage_write_failed"
	s.storageFailed = true
	return fmt.Errorf("traffic recorder write failed: %w", err)
}

func (s *Store) reserveLocked() error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(s.config.StateDirectory, &st); err != nil {
		return err
	}
	if int64(st.Bavail)*int64(st.Bsize) < s.config.MinimumFreeBytes+s.config.QuotaBytes/2 || st.Ffree < 32 {
		return ErrQuota
	}
	return nil
}

func (s *Store) deleteLocked(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var seq int64
	var service string
	var size int64
	if err := tx.QueryRowContext(ctx, "SELECT sequence,service_id,bytes FROM exchanges WHERE request_id=?", id).Scan(&seq, &service, &size); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM exchanges WHERE request_id=?", id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE recorder_meta SET value=MAX(value,?) WHERE key='retired'", seq); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.totalBytes -= size
	s.totalRecords--
	s.serviceBytes[service] -= size
	if s.serviceBytes[service] == 0 {
		delete(s.serviceBytes, service)
	}
	s.counters.Rotated++
	return nil
}

func (s *Store) rotateLocked(ctx context.Context) error {
	cutoff := s.config.Now().Add(-s.config.Retention).UnixNano()
	for {
		var id string
		err := s.db.QueryRowContext(ctx, "SELECT request_id FROM exchanges WHERE at<? ORDER BY sequence LIMIT 1", cutoff).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := s.deleteLocked(ctx, id); err != nil {
			return err
		}
	}
}

func (s *Store) makeRoomLocked(ctx context.Context, service, id string, size, oldSize int64, exists bool) error {
	for {
		global, local, count := s.totalBytes-oldSize, s.serviceBytes[service]-oldSize, s.totalRecords
		if exists {
			count--
		}
		// Logical payload budget leaves index/page/journal headroom beneath the
		// independent physical max_page_count boundary.
		if global+size <= s.config.QuotaBytes/4 && local+size <= s.config.PerServiceBytes && count+1 <= int64(s.config.MaxRecords) {
			return nil
		}
		var victim string
		query := "SELECT request_id FROM exchanges WHERE request_id<>?"
		args := []any{id}
		if local+size > s.config.PerServiceBytes {
			query += " AND service_id=?"
			args = append(args, service)
		}
		query += " ORDER BY sequence LIMIT 1"
		if err := s.db.QueryRowContext(ctx, query, args...).Scan(&victim); errors.Is(err, sql.ErrNoRows) {
			return ErrQuota
		} else if err != nil {
			return err
		}
		if err := s.deleteLocked(ctx, victim); err != nil {
			return err
		}
	}
}

type cursor struct {
	Epoch     string `json:"e"`
	Sequence  int64  `json:"s"`
	Direction string `json:"d"`
}

func (s *Store) cursor(seq int64, direction string) string {
	b, _ := json.Marshal(cursor{s.epoch, seq, direction})
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Store) List(ctx context.Context, q Query) (Page, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	page := Page{Records: []Metadata{}, Epoch: s.epoch}
	if s.closed {
		return page, errors.New("traffic recorder closed")
	}
	if err := s.rotateIfWritableLocked(ctx); err != nil {
		return page, s.writeError(err)
	}
	where, args, err := querySQL(q)
	if err != nil {
		return page, err
	}
	where = append(where, "at>=?")
	args = append(args, s.config.Now().Add(-s.config.Retention).UnixNano())
	limit := q.Limit
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 200 {
		return page, errors.New("traffic limit must be 1..200")
	}
	var maxSeq, retired int64
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM recorder_meta WHERE key='sequence'").Scan(&maxSeq); err != nil {
		return page, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM recorder_meta WHERE key='retired'").Scan(&retired); err != nil {
		return page, err
	}
	cur := cursor{s.epoch, maxSeq + 1, "before"}
	if q.Cursor != "" {
		if len(q.Cursor) > 512 {
			return page, errors.New("invalid traffic cursor")
		}
		b, e := base64.RawURLEncoding.DecodeString(q.Cursor)
		if e != nil || json.Unmarshal(b, &cur) != nil || cur.Sequence < 0 || (cur.Direction != "before" && cur.Direction != "after") {
			return page, errors.New("invalid traffic cursor")
		}
		if cur.Epoch != s.epoch {
			page.Gap = true
			cur = cursor{s.epoch, maxSeq + 1, "before"}
		}
		if retired > 0 && cur.Sequence <= retired {
			page.Gap = true
		}
	}
	order := "DESC"
	comparison := "<"
	if cur.Direction == "after" {
		order = "ASC"
		comparison = ">"
	}
	where = append(where, "sequence"+comparison+"?")
	args = append(args, cur.Sequence)
	statement := "SELECT metadata FROM exchanges WHERE " + strings.Join(where, " AND ") + " ORDER BY sequence " + order + " LIMIT ?"
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return page, err
	}
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			rows.Close()
			return page, err
		}
		var m Metadata
		if err := json.Unmarshal(b, &m); err != nil {
			rows.Close()
			return page, err
		}
		page.Records = append(page.Records, m)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return page, err
	}
	if err := rows.Close(); err != nil {
		return page, err
	}
	page.HasMore = len(page.Records) > limit
	if page.HasMore {
		page.Records = page.Records[:limit]
	}
	if len(page.Records) > 0 {
		last := page.Records[len(page.Records)-1].Sequence
		if cur.Direction == "after" {
			page.LiveCursor = s.cursor(last, "after")
			if page.HasMore {
				page.NextCursor = page.LiveCursor
			}
		} else {
			page.NextCursor = s.cursor(last, "before")
			page.LiveCursor = s.cursor(maxSeq, "after")
			if retired >= last && retired < cur.Sequence {
				page.Gap = true
			}
		}
	} else if cur.Direction == "after" {
		page.LiveCursor = s.cursor(cur.Sequence, "after")
	} else {
		page.LiveCursor = s.cursor(maxSeq, "after")
		if q.Cursor != "" && retired > 0 && retired < cur.Sequence {
			page.Gap = true
		}
	}
	page.Counters, err = s.statusLocked(ctx)
	return page, err
}

func (s *Store) Detail(ctx context.Context, id string) (Exchange, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var e Exchange
	if s.closed {
		return e, errors.New("traffic recorder closed")
	}
	if !validID(id) {
		return e, errors.New("invalid request ID")
	}
	if err := s.rotateIfWritableLocked(ctx); err != nil {
		return e, s.writeError(err)
	}
	var b []byte
	err := s.db.QueryRowContext(ctx, "SELECT detail FROM exchanges WHERE request_id=? AND at>=?", id, s.config.Now().Add(-s.config.Retention).UnixNano()).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	if err != nil {
		return e, err
	}
	err = json.Unmarshal(b, &e)
	return e, err
}

func (s *Store) Status(ctx context.Context) (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Status{}, errors.New("traffic recorder closed")
	}
	if err := s.rotateIfWritableLocked(ctx); err != nil {
		return Status{}, s.writeError(err)
	}
	return s.statusLocked(ctx)
}

func (s *Store) rotateIfWritableLocked(ctx context.Context) error {
	if s.storageFailed {
		return nil
	}
	return s.rotateLocked(ctx)
}
func (s *Store) statusLocked(ctx context.Context) (Status, error) {
	v := Status{
		Available: !s.closed && !s.storageFailed, Epoch: s.epoch, StartedAt: s.started,
		CountersScope: "current_recorder_epoch", PreviousEpochCountersUnknown: s.previous,
		Counters: s.counters, QuotaBytes: s.config.QuotaBytes,
		PayloadBudgetBytes: s.config.QuotaBytes / 4, PerServiceBytes: s.config.PerServiceBytes,
		RetentionSeconds: int64(s.config.Retention / time.Second), MaxRecords: s.config.MaxRecords,
		LastError:     s.lastError,
		StoredRecords: s.totalRecords, StoredBytes: s.totalBytes,
	}
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM recorder_meta WHERE key='retired'").Scan(&v.RetiredSequence); err != nil {
		return v, err
	}
	for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
		if st, err := os.Lstat(s.filename + suffix); err == nil {
			v.DiskBytes += st.Size()
		}
	}
	return v, nil
}

func querySQL(q Query) ([]string, []any, error) {
	where, args := []string{"1=1"}, []any{}
	if len(q.ServiceIDs) > 32 {
		return nil, nil, errors.New("too many traffic service filters")
	}
	if len(q.ServiceIDs) > 0 {
		seen := map[string]bool{}
		ids := []string{}
		for _, id := range q.ServiceIDs {
			if !validID(id) {
				return nil, nil, errors.New("invalid service filter")
			}
			if !seen[id] {
				ids = append(ids, id)
				seen[id] = true
			}
		}
		sort.Strings(ids)
		marks := []string{}
		for _, id := range ids {
			marks = append(marks, "?")
			args = append(args, id)
		}
		where = append(where, "service_id IN ("+strings.Join(marks, ",")+")")
	}
	if q.RouteID != "" {
		if !validID(q.RouteID) {
			return nil, nil, errors.New("invalid route filter")
		}
		where = append(where, "route_id=?")
		args = append(args, q.RouteID)
	}
	var from, until time.Time
	for _, value := range []struct{ name, text, op string }{{"from", q.From, ">="}, {"until", q.Until, "<="}} {
		if value.text != "" {
			at, err := time.Parse(time.RFC3339Nano, value.text)
			if err != nil {
				return nil, nil, errors.New("invalid traffic time filter")
			}
			where = append(where, "at"+value.op+"?")
			args = append(args, at.UnixNano())
			if value.name == "from" {
				from = at
			} else {
				until = at
			}
		}
	}
	if !from.IsZero() && !until.IsZero() && from.After(until) {
		return nil, nil, errors.New("traffic from is after until")
	}
	if q.Method != "" {
		if !validToken(q.Method, 32) {
			return nil, nil, errors.New("invalid method filter")
		}
		where = append(where, "method=?")
		args = append(args, q.Method)
	}
	if q.Status != "" {
		if len(q.Status) == 3 && q.Status[1:] == "xx" && q.Status[0] >= '1' && q.Status[0] <= '5' {
			low := int(q.Status[0]-'0') * 100
			where = append(where, "status>=? AND status<?")
			args = append(args, low, low+100)
		} else {
			n, err := strconv.Atoi(q.Status)
			if err != nil || n < 100 || n > 599 {
				return nil, nil, errors.New("invalid HTTP status filter")
			}
			where = append(where, "status=?")
			args = append(args, n)
		}
	}
	if q.URL != "" {
		if len(q.URL) > 1024 {
			return nil, nil, errors.New("URL search exceeds bound")
		}
		where = append(where, "instr(url,?)>0")
		args = append(args, q.URL)
	}
	if q.WAF != "" {
		if !validToken(q.WAF, 64) {
			return nil, nil, errors.New("invalid WAF filter")
		}
		where = append(where, "waf=?")
		args = append(args, q.WAF)
	}
	if q.IP != "" {
		prefix, err := netip.ParsePrefix(q.IP)
		if err != nil {
			a, e := netip.ParseAddr(q.IP)
			if e != nil {
				return nil, nil, errors.New("invalid IP/CIDR filter")
			}
			a = a.Unmap()
			prefix = netip.PrefixFrom(a, a.BitLen())
		}
		a := prefix.Addr()
		bits := prefix.Bits()
		if a.Is4In6() {
			if bits < 96 {
				return nil, nil, errors.New("ambiguous mapped IP prefix")
			}
			a = a.Unmap()
			bits -= 96
			prefix = netip.PrefixFrom(a, bits)
		}
		prefix = prefix.Masked()
		lo := prefix.Addr().As16()
		hi := lo
		family := 6
		offset := 0
		if prefix.Addr().Is4() {
			family = 4
			offset = 96
		}
		for bit := offset + prefix.Bits(); bit < 128; bit++ {
			hi[bit/8] |= 1 << uint(7-bit%8)
		}
		where = append(where, "ip_family=? AND ip>=? AND ip<=?")
		args = append(args, family, lo[:], hi[:])
	}
	return where, args, nil
}

func validID(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("_.:-", c)) {
			return false
		}
	}
	return true
}
func validToken(s string, max int) bool {
	if len(s) < 1 || len(s) > max {
		return false
	}
	for _, c := range s {
		if c > 127 || !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return false
		}
	}
	return true
}

func validDuration(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v <= float64(24*time.Hour/time.Millisecond)
}
