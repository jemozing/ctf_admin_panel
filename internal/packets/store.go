package packets

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/maintenance"
	_ "modernc.org/sqlite"
)

var (
	ErrNotFound = errors.New("packet not found")
	ErrQuota    = errors.New("packet archive capacity exhausted")
	ErrConflict = errors.New("packet identity conflicts with stored record")
	ErrExpired  = errors.New("packet is outside retention window")
	ErrInvalid  = errors.New("invalid archive analysis request or descriptor binding")
)

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
	mu                       sync.Mutex
	db                       *sql.DB
	config                   Config
	filename                 string
	lock                     *maintenance.Lock
	epoch                    string
	started                  time.Time
	previous                 bool
	counters                 Counters
	lastError                string
	closed, storageFailed    bool
	totalBytes, totalRecords int64
	serviceBytes             map[string]int64
	stop, done               chan struct{}
	closeOnce                sync.Once
	closeError               error
}

func Open(c Config) (*Store, error) {
	if c.QuotaBytes == 0 {
		c.QuotaBytes = 256 << 20
	}
	if c.PerServiceBytes == 0 {
		c.PerServiceBytes = c.QuotaBytes / 4
	}
	if c.MinimumFreeBytes == 0 {
		c.MinimumFreeBytes = 1 << 30
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
		return nil, errors.New("packet state must be a canonical absolute private directory")
	}
	if c.QuotaBytes < 4<<20 || c.QuotaBytes > 8<<30 || c.PerServiceBytes < MaxRecordBytes || c.PerServiceBytes > c.QuotaBytes/4 || c.Retention < time.Second || c.Retention > 24*time.Hour || c.MaxRecords < 1 || c.MaxRecords > 1000000 || c.MinimumFreeBytes < 0 {
		return nil, errors.New("packet archive limits outside supported bounds")
	}
	if err := os.MkdirAll(c.StateDirectory, 0700); err != nil {
		return nil, err
	}
	lock, err := maintenance.Acquire(c.StateDirectory, true)
	if err != nil {
		return nil, errors.New("packet state not private or already in use")
	}
	fail := func(err error) (*Store, error) { _ = lock.Close(); return nil, err }
	filename := filepath.Join(c.StateDirectory, "packets.sqlite")
	if st, err := os.Lstat(filename); err == nil {
		if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
			return fail(errors.New("packet database must be a private regular file"))
		}
	} else if !os.IsNotExist(err) {
		return fail(err)
	}
	f, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		_ = f.Close()
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
	for _, stmt := range []string{"PRAGMA journal_mode=TRUNCATE", "PRAGMA auto_vacuum=INCREMENTAL", "PRAGMA secure_delete=ON", "PRAGMA temp_store=MEMORY", "PRAGMA cache_size=-2048"} {
		if _, err := db.Exec(stmt); err != nil {
			return failDB(err)
		}
	}
	var pageSize, applied int64
	if err := db.QueryRow("PRAGMA page_size").Scan(&pageSize); err != nil {
		return failDB(err)
	}
	maximum := (c.QuotaBytes * 45 / 100) / pageSize
	if err := db.QueryRow(fmt.Sprintf("PRAGMA max_page_count=%d", maximum)).Scan(&applied); err != nil {
		return failDB(err)
	}
	if applied > maximum {
		return failDB(errors.New("existing packet database exceeds physical quota"))
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS packet_meta(key TEXT PRIMARY KEY,value INTEGER NOT NULL);
INSERT OR IGNORE INTO packet_meta VALUES('sequence',0),('retired',0),('opened',0);
CREATE TABLE IF NOT EXISTS packets(packet_id TEXT PRIMARY KEY,sequence INTEGER NOT NULL UNIQUE,at INTEGER NOT NULL,protocol TEXT NOT NULL,direction TEXT NOT NULL,source_port INTEGER NOT NULL,destination_port INTEGER NOT NULL,source_ip BLOB NOT NULL,source_family INTEGER NOT NULL,destination_ip BLOB NOT NULL,destination_family INTEGER NOT NULL,metadata BLOB NOT NULL,payload BLOB NOT NULL,bytes INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS packet_services(packet_id TEXT NOT NULL,service_id TEXT NOT NULL,component TEXT NOT NULL,PRIMARY KEY(packet_id,service_id,component));
CREATE INDEX IF NOT EXISTS packet_service_filter ON packet_services(service_id,component,packet_id);
CREATE INDEX IF NOT EXISTS packet_at ON packets(at);
CREATE INDEX IF NOT EXISTS packet_source ON packets(source_family,source_ip);
CREATE INDEX IF NOT EXISTS packet_destination ON packets(destination_family,destination_ip);`); err != nil {
		return failDB(err)
	}
	var opened int
	if err := db.QueryRow("SELECT value FROM packet_meta WHERE key='opened'").Scan(&opened); err != nil {
		return failDB(err)
	}
	if _, err := db.Exec("UPDATE packet_meta SET value=1 WHERE key='opened'"); err != nil {
		return failDB(err)
	}
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return failDB(err)
	}
	s := &Store{db: db, config: c, filename: filename, lock: lock, epoch: hex.EncodeToString(entropy[:]), started: c.Now().UTC(), previous: opened != 0, serviceBytes: map[string]int64{}, stop: make(chan struct{}), done: make(chan struct{})}
	if err := db.QueryRow("SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM packets").Scan(&s.totalRecords, &s.totalBytes); err != nil {
		return failDB(err)
	}
	rows, err := db.Query("SELECT ps.service_id,COALESCE(SUM(p.bytes),0) FROM (SELECT DISTINCT packet_id,service_id FROM packet_services) ps JOIN packets p ON p.packet_id=ps.packet_id GROUP BY ps.service_id")
	if err != nil {
		return failDB(err)
	}
	for rows.Next() {
		var id string
		var size int64
		if err := rows.Scan(&id, &size); err != nil {
			rows.Close()
			return failDB(err)
		}
		s.serviceBytes[id] = size
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return failDB(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.rotateLocked(ctx); err != nil {
		return failDB(err)
	}
	// Reopening with smaller limits must enforce those limits before advertising
	// an available recorder, even when no new packets are arriving.
	if err := s.makeRoomLocked(ctx, nil, 0, 0); err != nil {
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
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
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

func (s *Store) Ingest(ctx context.Context, r Record) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.storageFailed {
		return 0, errors.New("packet archive unavailable")
	}
	if err := validateRecord(&r, s.config.Now()); err != nil {
		s.counters.Rejected++
		return 0, err
	}
	if r.At.Before(s.config.Now().Add(-s.config.Retention)) {
		s.counters.Rejected++
		return 0, ErrExpired
	}
	if err := s.rotateLocked(ctx); err != nil {
		return 0, s.writeError(err)
	}
	var oldMeta, oldPayload []byte
	err := s.db.QueryRowContext(ctx, "SELECT metadata,payload FROM packets WHERE packet_id=?", r.PacketID).Scan(&oldMeta, &oldPayload)
	if err == nil {
		var old Metadata
		if json.Unmarshal(oldMeta, &old) != nil {
			return 0, s.writeError(errors.New("corrupt packet metadata"))
		}
		r.Sequence = old.Sequence
		b, _ := json.Marshal(r.Metadata)
		if string(b) == string(oldMeta) && string(r.Data) == string(oldPayload) {
			return old.Sequence, nil
		}
		s.counters.Rejected++
		return 0, ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, s.writeError(err)
	}
	if err := s.reserveLocked(); err != nil {
		s.counters.Rejected++
		s.storageFailed = true
		s.lastError = "free_space_reserve"
		return 0, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT value+1 FROM packet_meta WHERE key='sequence'").Scan(&r.Sequence); err != nil {
		return 0, s.writeError(err)
	}
	meta, _ := json.Marshal(r.Metadata)
	associations := recordCandidates(r.Metadata)
	size := int64(len(meta) + len(r.Data) + 512 + len(associations)*128)
	services := candidateServices(associations)
	if size > s.config.PerServiceBytes || size > s.config.QuotaBytes/4 {
		s.counters.Rejected++
		return 0, ErrQuota
	}
	if err := s.makeRoomLocked(ctx, services, size, 1); err != nil {
		s.counters.Rejected++
		if !errors.Is(err, ErrQuota) {
			return 0, s.writeError(err)
		}
		return 0, err
	}
	src, _ := netip.ParseAddr(r.SourceIP)
	dst, _ := netip.ParseAddr(r.DestinationIP)
	sa, da := src.As16(), dst.As16()
	sf, df := 6, 6
	if src.Is4() {
		sf = 4
	}
	if dst.Is4() {
		df = 4
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, s.writeError(err)
	}
	defer tx.Rollback()
	payload := r.Data
	if payload == nil {
		payload = []byte{}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO packets(packet_id,sequence,at,protocol,direction,source_port,destination_port,source_ip,source_family,destination_ip,destination_family,metadata,payload,bytes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, r.PacketID, r.Sequence, r.At.UnixNano(), r.Protocol, r.Direction, r.SourcePort, r.DestinationPort, sa[:], sf, da[:], df, meta, payload, size)
	for _, c := range associations {
		if err != nil {
			break
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO packet_services(packet_id,service_id,component) VALUES(?,?,?)", r.PacketID, c.ServiceID, c.Component)
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, "UPDATE packet_meta SET value=? WHERE key='sequence'", r.Sequence)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		return 0, s.writeError(err)
	}
	s.totalBytes += size
	s.totalRecords++
	for _, id := range services {
		s.serviceBytes[id] += size
	}
	s.counters.Ingested++
	s.lastError = ""
	return r.Sequence, nil
}

func (s *Store) writeError(err error) error {
	s.counters.WriteErrors++
	s.lastError = "storage_write_failed"
	s.storageFailed = true
	return fmt.Errorf("packet archive write failed: %w", err)
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
	var seq, size int64
	var b []byte
	if err := tx.QueryRowContext(ctx, "SELECT sequence,bytes,metadata FROM packets WHERE packet_id=?", id).Scan(&seq, &size, &b); err != nil {
		return err
	}
	var m Metadata
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	for _, stmt := range []string{"DELETE FROM packet_services WHERE packet_id=?", "DELETE FROM packets WHERE packet_id=?"} {
		if _, err := tx.ExecContext(ctx, stmt, id); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE packet_meta SET value=MAX(value,?) WHERE key='retired'", seq); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.totalRecords--
	s.totalBytes -= size
	for _, service := range candidateServices(recordCandidates(m)) {
		s.serviceBytes[service] -= size
		if s.serviceBytes[service] == 0 {
			delete(s.serviceBytes, service)
		}
	}
	s.counters.Rotated++
	return nil
}
func (s *Store) rotateLocked(ctx context.Context) error {
	cutoff := s.config.Now().Add(-s.config.Retention).UnixNano()
	for {
		var id string
		err := s.db.QueryRowContext(ctx, "SELECT packet_id FROM packets WHERE at<? ORDER BY sequence LIMIT 1", cutoff).Scan(&id)
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
func (s *Store) makeRoomLocked(ctx context.Context, services []string, size, count int64) error {
	for {
		overService := ""
		for _, id := range services {
			if s.serviceBytes[id]+size > s.config.PerServiceBytes {
				overService = id
				break
			}
		}
		// Also enforce per-service reductions when opening an existing archive.
		if size == 0 {
			for id, n := range s.serviceBytes {
				if n > s.config.PerServiceBytes && (overService == "" || id < overService) {
					overService = id
				}
			}
		}
		if s.totalBytes+size <= s.config.QuotaBytes/4 && s.totalRecords+count <= int64(s.config.MaxRecords) && overService == "" {
			return nil
		}
		stmt := "SELECT p.packet_id FROM packets p"
		args := []any{}
		if overService != "" {
			stmt += " WHERE EXISTS(SELECT 1 FROM packet_services ps WHERE ps.packet_id=p.packet_id AND ps.service_id=?)"
			args = append(args, overService)
		}
		stmt += " ORDER BY sequence LIMIT 1"
		var id string
		err := s.db.QueryRowContext(ctx, stmt, args...).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrQuota
		}
		if err != nil {
			return err
		}
		if err := s.deleteLocked(ctx, id); err != nil {
			return err
		}
	}
}

func recordCandidates(m Metadata) []Candidate {
	if m.Attribution == "unique" {
		return []Candidate{{m.ServiceID, m.Component}}
	}
	return m.Candidates
}
func candidateServices(candidates []Candidate) []string {
	m := map[string]bool{}
	for _, c := range candidates {
		m[c.ServiceID] = true
	}
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func validateRecord(r *Record, now time.Time) error {
	if !validID(r.PacketID) || !validID(r.CollectorEpoch) || r.PolicyRevision == 0 || r.Sequence != 0 {
		return errors.New("invalid packet identity")
	}
	if r.At.IsZero() || r.At.Unix() < 0 || r.At.Unix() > 4294967295 || r.At.After(now.Add(5*time.Minute)) {
		return errors.New("invalid packet timestamp")
	}
	r.At = r.At.UTC()
	if !validInterface(r.Interface) || r.IfIndex < 1 || r.IfIndex > 1<<30 || (r.Direction != "ingress" && r.Direction != "egress" && r.Direction != "ambiguous") || (r.Protocol != "tcp" && r.Protocol != "udp") {
		return errors.New("invalid packet interface or transport")
	}
	for _, ip := range []*string{&r.SourceIP, &r.DestinationIP} {
		a, err := netip.ParseAddr(*ip)
		if err != nil || a.Zone() != "" {
			return errors.New("invalid packet IP")
		}
		*ip = a.Unmap().String()
	}
	if r.SourcePort < 0 || r.SourcePort > 65535 || r.DestinationPort < 0 || r.DestinationPort > 65535 || r.Protocol == "udp" && r.TCPFlags != 0 {
		return errors.New("invalid packet transport fields")
	}
	if r.LinkType != 1 || r.WireLength < 14 || r.WireLength > 1<<20 || r.CapturedLength < 0 || r.CapturedLength > MaxPacketBytes || r.CapturedLength != len(r.Data) || r.CapturedLength > r.WireLength || r.Truncated != (r.CapturedLength < r.WireLength) {
		return errors.New("invalid packet lengths or link type")
	}
	if r.CapturedLength == 0 {
		if r.NotCapturedReason != "metadata_only" {
			return errors.New("missing packet capture reason")
		}
	} else if r.NotCapturedReason != "" {
		return errors.New("unexpected packet capture reason")
	}
	if r.Attribution == "unique" {
		if !validID(r.ServiceID) || !validID(r.Component) || len(r.Candidates) != 0 {
			return errors.New("invalid unique attribution")
		}
	} else if r.Attribution == "ambiguous" {
		if r.ServiceID != "" || r.Component != "" || len(r.Candidates) < 2 || len(r.Candidates) > 256 {
			return errors.New("invalid ambiguous attribution")
		}
		r.Candidates = append([]Candidate(nil), r.Candidates...)
		seen := map[Candidate]bool{}
		for _, c := range r.Candidates {
			if !validID(c.ServiceID) || !validID(c.Component) || seen[c] {
				return errors.New("invalid attribution candidate")
			}
			seen[c] = true
		}
		sort.Slice(r.Candidates, func(i, j int) bool {
			a, b := r.Candidates[i], r.Candidates[j]
			if a.ServiceID == b.ServiceID {
				return a.Component < b.Component
			}
			return a.ServiceID < b.ServiceID
		})
	} else {
		return errors.New("unattributed packets may not be stored")
	}
	if err := validateVersionBindings(r); err != nil {
		return err
	}
	b, _ := json.Marshal(r)
	if len(b) > MaxRecordBytes {
		return errors.New("packet exceeds bounded record size")
	}
	return nil
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
func validInterface(s string) bool { return len(s) <= 15 && validID(s) && !strings.Contains(s, ":") }

func (s *Store) Status(ctx context.Context) (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Status{}, errors.New("packet archive closed")
	}
	if !s.storageFailed {
		if err := s.rotateLocked(ctx); err != nil {
			return Status{}, s.writeError(err)
		}
	}
	return s.statusLocked(ctx)
}
func (s *Store) statusLocked(ctx context.Context) (Status, error) {
	v := Status{Available: !s.closed && !s.storageFailed, Epoch: s.epoch, StartedAt: s.started, CountersScope: "current_recorder_epoch", PreviousEpochCountersUnknown: s.previous, Counters: s.counters, StoredRecords: s.totalRecords, StoredBytes: s.totalBytes, QuotaBytes: s.config.QuotaBytes, PayloadBudgetBytes: s.config.QuotaBytes / 4, PerServiceBytes: s.config.PerServiceBytes, RetentionSeconds: int64(s.config.Retention / time.Second), MaxRecords: s.config.MaxRecords, LastError: s.lastError}
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM packet_meta WHERE key='retired'").Scan(&v.RetiredSequence); err != nil {
		return v, err
	}
	for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
		if st, err := os.Lstat(s.filename + suffix); err == nil {
			v.DiskBytes += st.Size()
		}
	}
	return v, nil
}

func (s *Store) Detail(ctx context.Context, id string) (Metadata, error) {
	r, err := s.detail(ctx, id, false)
	return r.Metadata, err
}
func (s *Store) Raw(ctx context.Context, id string) (Record, error) { return s.detail(ctx, id, true) }
func (s *Store) detail(ctx context.Context, id string, raw bool) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var r Record
	if s.closed {
		return r, errors.New("packet archive closed")
	}
	if !validID(id) {
		return r, errors.New("invalid packet ID")
	}
	if !s.storageFailed {
		if err := s.rotateLocked(ctx); err != nil {
			return r, s.writeError(err)
		}
	}
	var b []byte
	stmt := "SELECT metadata FROM packets WHERE packet_id=? AND at>=?"
	if raw {
		stmt = "SELECT metadata,payload FROM packets WHERE packet_id=? AND at>=?"
	}
	row := s.db.QueryRowContext(ctx, stmt, id, s.config.Now().Add(-s.config.Retention).UnixNano())
	var err error
	if raw {
		err = row.Scan(&b, &r.Data)
	} else {
		err = row.Scan(&b)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(b, &r.Metadata)
	return r, err
}
