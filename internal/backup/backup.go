// Package backup exports panel state while both processes are stopped. It has no
// Docker client and cannot start containers, restore game data, or run old jobs.
package backup

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/maintenance"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
)

type Mode string

const (
	Metadata        Mode  = "metadata"
	Protected       Mode  = "protected_full"
	DefaultMaxBytes int64 = 64 << 30
)

type Options struct {
	ExecutorState  string
	DashboardState string
	Configuration  string
	Destination    string
	Passphrase     []byte
	MaxBytes       int64
}
type RestoreOptions struct {
	Source      string
	Destination string
	Passphrase  []byte
	MaxBytes    int64
}
type Entry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}
type Owner struct {
	UID int `json:"uid"`
	GID int `json:"gid"`
}
type Missing struct {
	Kind      string    `json:"kind"`
	ServiceID domain.ID `json:"service_id,omitempty"`
	Reference string    `json:"reference"`
}
type Manifest struct {
	Version        int       `json:"version"`
	Mode           Mode      `json:"mode"`
	CreatedAt      time.Time `json:"created_at"`
	ExecutorOwner  Owner     `json:"executor_owner"`
	DashboardOwner Owner     `json:"dashboard_owner"`
	Entries        []Entry   `json:"entries"`
	Missing        []Missing `json:"missing"`
	Excluded       []string  `json:"excluded"`
}
type Report struct {
	AuditRequestID               domain.ID `json:"audit_request_id,omitempty"`
	Mode                         Mode      `json:"mode"`
	Destination                  string    `json:"destination"`
	Files                        int       `json:"files"`
	Bytes                        int64     `json:"bytes"`
	Missing                      []Missing `json:"missing"`
	RequiresRegistrationReview   bool      `json:"requires_registration_review"`
	OriginalStateDirectory       string    `json:"original_state_directory,omitempty"`
	SessionsRevoked              bool      `json:"sessions_revoked"`
	QueuedOperationsDisabled     bool      `json:"queued_operations_disabled"`
	GameDataIncluded             bool      `json:"game_data_included"`
	ProxyReconfigurationRequired bool      `json:"proxy_reconfiguration_required,omitempty"`
}
type archiveFile struct{ name, source string }

// Create defaults to a metadata-only export. Supplying a passphrase explicitly
// enables a complete encrypted panel-state backup, including protected sources.
func Create(ctx context.Context, options Options) (report Report, resultErr error) {
	if options.MaxBytes == 0 {
		options.MaxBytes = DefaultMaxBytes
	}
	if options.MaxBytes < 1 {
		return report, errors.New("backup size limit must be positive")
	}
	for _, p := range []string{options.ExecutorState, options.DashboardState, options.Configuration, options.Destination} {
		if err := absolute(p); err != nil {
			return report, err
		}
	}
	if domain.PathsOverlap(options.ExecutorState, options.DashboardState) {
		return report, errors.New("dashboard and executor state must be separate")
	}
	for _, state := range []string{options.ExecutorState, options.DashboardState} {
		if domain.PathsOverlap(state, options.Destination) {
			return report, errors.New("backup destination must be outside panel state")
		}
	}
	if _, err := os.Lstat(options.Destination); err == nil {
		return report, errors.New("backup destination already exists")
	} else if !os.IsNotExist(err) {
		return report, err
	}
	// Fixed lexical ordering avoids lock-order inversions between maintenance tools.
	roots := []string{options.ExecutorState, options.DashboardState}
	sort.Strings(roots)
	var locks []*maintenance.Lock
	defer func() {
		for i := len(locks) - 1; i >= 0; i-- {
			resultErr = errors.Join(resultErr, locks[i].Close())
		}
	}()
	for _, root := range roots {
		lock, err := maintenance.Acquire(root, true)
		if err != nil {
			return report, err
		}
		locks = append(locks, lock)
	}
	manifest := Manifest{Version: 1, Mode: Metadata, CreatedAt: time.Now().UTC(), Entries: []Entry{}, Missing: []Missing{}, Excluded: []string{"docker_images", "game_databases", "game_volumes", "active_projects", "source_workspaces", "dashboard_sessions"}}
	if len(options.Passphrase) > 0 {
		manifest.Mode = Protected
	} else {
		manifest.Excluded = append(manifest.Excluded, "secret_vault", "snapshot_content", "frozen_compose", "raw_operation_events", "operation_inputs", "check_urls", "free_text_diagnostics")
	}
	var err error
	manifest.ExecutorOwner, err = directoryOwner(options.ExecutorState)
	if err != nil {
		return report, err
	}
	manifest.DashboardOwner, err = directoryOwner(options.DashboardState)
	if err != nil {
		return report, err
	}
	staging, err := os.MkdirTemp(filepath.Dir(options.Destination), ".ctfm-backup-")
	if err != nil {
		return report, err
	}
	defer os.RemoveAll(staging)
	for _, filename := range []string{filepath.Join(options.ExecutorState, "executor.db"), filepath.Join(options.DashboardState, "dashboard.sqlite")} {
		checked, err := openSQLite(filename)
		if err != nil {
			return report, err
		}
		if err := checked.Close(); err != nil {
			return report, err
		}
	}
	executorSource, err := store.Open(filepath.Join(options.ExecutorState, "executor.db"))
	if err != nil {
		return report, err
	}
	defer executorSource.Close()
	requestID := auditID()
	if err := recordExportAudit(ctx, executorSource, requestID, manifest.Mode, options.Destination, "started"); err != nil {
		return report, err
	}
	report.AuditRequestID = requestID
	defer func() {
		result := "succeeded"
		if resultErr != nil {
			result = "failed"
		}
		resultErr = errors.Join(resultErr, recordExportAudit(ctx, executorSource, requestID, manifest.Mode, options.Destination, result))
	}()
	if err := executorSource.SnapshotDatabase(ctx, filepath.Join(staging, "consistent-executor.db")); err != nil {
		return report, err
	}
	consistent, err := store.Open(filepath.Join(staging, "consistent-executor.db"))
	if err != nil {
		return report, err
	}
	defer consistent.Close()
	if err := consistent.CheckDatabase(ctx); err != nil {
		return report, err
	}
	manifest.Missing, err = missingReferences(ctx, consistent, manifest.Mode)
	if err != nil {
		return report, err
	}
	executorSnapshot := filepath.Join(staging, "executor.db")
	if manifest.Mode == Protected {
		err = consistent.SnapshotDatabase(ctx, executorSnapshot)
	} else {
		err = consistent.ExportMetadata(ctx, executorSnapshot)
	}
	if err != nil {
		return report, err
	}
	dashboardSnapshot := filepath.Join(staging, "dashboard.sqlite")
	if err := snapshotDashboard(ctx, filepath.Join(options.DashboardState, "dashboard.sqlite"), dashboardSnapshot, manifest.Mode); err != nil {
		return report, err
	}
	bootstrap, err := config.Load(options.Configuration)
	if err != nil {
		return report, fmt.Errorf("read trusted bootstrap: %w", err)
	}
	if bootstrap.StateDirectory != options.ExecutorState {
		return report, errors.New("bootstrap executor state differs from requested backup state")
	}
	encoded, err := json.MarshalIndent(bootstrap, "", "  ")
	if err != nil {
		return report, err
	}
	configFile := filepath.Join(staging, "executor.json")
	if err := os.WriteFile(configFile, append(encoded, '\n'), 0600); err != nil {
		return report, err
	}
	files := []archiveFile{{"config/executor.json", configFile}, {"dashboard/dashboard.sqlite", dashboardSnapshot}, {"executor/executor.db", executorSnapshot}}
	if manifest.Mode == Protected {
		for _, directory := range []string{"snapshots", "secrets", "runtime-inputs"} {
			extra, err := collectFiles(ctx, options.ExecutorState, directory)
			if err != nil {
				return report, err
			}
			files = append(files, extra...)
		}
	}
	if len(files) > 200000 {
		return report, errors.New("backup exceeds 200000-file limit")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	outputPath := filepath.Join(staging, "archive.partial")
	output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return report, err
	}
	defer output.Close()
	var writer io.Writer = output
	var encrypted *encryptWriter
	if manifest.Mode == Protected {
		encrypted, err = newEncryptWriter(output, options.Passphrase)
		if err != nil {
			return report, err
		}
		writer = encrypted
	}
	archive := tar.NewWriter(writer)
	for _, file := range files {
		entry, err := writeArchiveFile(ctx, archive, file, options.MaxBytes-report.Bytes)
		if err != nil {
			return report, err
		}
		manifest.Entries = append(manifest.Entries, entry)
		report.Bytes += entry.Size
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return report, err
	}
	if len(manifestJSON) > 16<<20 {
		return report, errors.New("backup manifest exceeds 16 MiB")
	}
	if err := archive.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(manifestJSON)), Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
		return report, err
	}
	if _, err := archive.Write(manifestJSON); err != nil {
		return report, err
	}
	if err := archive.Close(); err != nil {
		return report, err
	}
	if encrypted != nil {
		if err := encrypted.Close(); err != nil {
			return report, err
		}
	}
	if err := output.Sync(); err != nil {
		return report, err
	}
	if err := output.Close(); err != nil {
		return report, err
	}
	// Link publishes only a complete file and never replaces an existing backup.
	if err := os.Link(outputPath, options.Destination); err != nil {
		return report, err
	}
	if err := syncDirectory(filepath.Dir(options.Destination)); err != nil {
		return report, err
	}
	report.Mode = manifest.Mode
	report.Destination = options.Destination
	report.Files = len(files)
	report.Missing = manifest.Missing
	report.RequiresRegistrationReview = manifest.Mode == Metadata
	if manifest.Mode == Protected {
		services, err := consistent.ListServices(ctx)
		if err != nil {
			return report, err
		}
		for _, service := range services {
			pending, err := consistent.MetadataRestoreNeedsReview(ctx, service.ID)
			if err != nil {
				return report, err
			}
			report.RequiresRegistrationReview = report.RequiresRegistrationReview || pending
		}
	}
	return report, nil
}

func missingReferences(ctx context.Context, s *store.Store, mode Mode) ([]Missing, error) {
	missing := []Missing{}
	services, err := s.ListServices(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	add := func(kind string, id domain.ID, reference string) {
		key := kind + "\x00" + string(id) + "\x00" + reference
		if !seen[key] {
			missing = append(missing, Missing{kind, id, reference})
			seen[key] = true
		}
	}
	for _, service := range services {
		add("external_active_project", service.ID, service.ProjectDirectory)
		add("external_source_workspace", service.ID, service.SourceDirectory)
		for _, container := range service.Containers {
			add("docker_image_not_included", service.ID, string(container.ImageID))
		}
		for _, data := range service.DataPaths {
			if data.Kind == domain.StorageBind || data.Kind == domain.StorageNamedVolume {
				add("external_game_data", service.ID, data.Source)
			}
		}
		if mode == Metadata {
			add("frozen_configuration", service.ID, "local administrator must re-register this service")
			for _, ref := range service.SecretVersions {
				add("secret_version", service.ID, string(ref.SecretID)+"/"+string(ref.Version))
			}
		}
	}
	for _, kind := range []string{"release", "snapshot"} {
		records, err := s.List(ctx, kind, "")
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			tombstoneKind := "retired_release"
			if kind == "snapshot" {
				tombstoneKind = "deleted_snapshot"
			}
			deleted, err := isTombstoned(ctx, s, tombstoneKind, record.ID)
			if err != nil {
				return nil, err
			}
			if deleted {
				continue
			}
			if kind == "snapshot" {
				if mode == Metadata {
					add("snapshot_content", record.ServiceID, string(record.ID))
				}
				continue
			}
			var release domain.Release
			if err := json.Unmarshal(record.Payload, &release); err != nil {
				return nil, err
			}
			spec := release.Spec()
			for _, image := range spec.Images {
				add("docker_image_not_included", spec.ServiceID, string(image.ImageID))
			}
			if mode == Metadata {
				add("frozen_configuration", spec.ServiceID, string(spec.ConfigurationDigest))
				for _, ref := range spec.Secrets {
					add("secret_version", spec.ServiceID, string(ref.SecretID)+"/"+string(ref.Version))
				}
			}
		}
	}
	sort.Slice(missing, func(i, j int) bool {
		a, b := missing[i], missing[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.ServiceID != b.ServiceID {
			return a.ServiceID < b.ServiceID
		}
		return a.Reference < b.Reference
	})
	return missing, nil
}

func isTombstoned(ctx context.Context, s *store.Store, kind string, id domain.ID) (bool, error) {
	var marker map[string]any
	err := s.Get(ctx, kind, id, &marker)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

func absolute(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" || strings.ContainsRune(p, 0) {
		return errors.New("backup paths must be canonical absolute paths other than /")
	}
	return nil
}
func directoryOwner(p string) (Owner, error) {
	info, err := os.Lstat(p)
	if err != nil {
		return Owner{}, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return Owner{}, errors.New("panel state must be a private directory")
	}
	return Owner{int(st.Uid), int(st.Gid)}, nil
}
func syncDirectory(p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func collectFiles(ctx context.Context, root, directory string) ([]archiveFile, error) {
	base := filepath.Join(root, directory)
	if _, err := os.Lstat(base); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	result := []archiveFile{}
	err := filepath.WalkDir(base, func(filename string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("backup refuses symbolic links in executor state")
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("backup refuses non-regular executor artifacts")
		}
		rel, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		if len(result) >= 200000 {
			return errors.New("backup contains too many artifacts")
		}
		result = append(result, archiveFile{"executor/" + filepath.ToSlash(rel), filename})
		return nil
	})
	return result, err
}

func writeArchiveFile(ctx context.Context, w *tar.Writer, item archiveFile, remaining int64) (Entry, error) {
	entry := Entry{Path: item.name}
	if err := validArchivePath(item.name); err != nil {
		return entry, err
	}
	info, err := os.Lstat(item.source)
	if err != nil {
		return entry, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Nlink != 1 {
		return entry, errors.New("backup input must be a regular file with one link")
	}
	if info.Size() > remaining {
		return entry, errors.New("backup exceeds configured byte limit")
	}
	file, err := os.Open(item.source)
	if err != nil {
		return entry, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return entry, err
	}
	if !os.SameFile(info, opened) {
		return entry, errors.New("backup input changed during open")
	}
	entry.Size = info.Size()
	entry.Mode = uint32(info.Mode().Perm())
	if err := w.WriteHeader(&tar.Header{Name: item.name, Mode: int64(entry.Mode), Size: entry.Size, Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
		return entry, err
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, hash), &contextReader{ctx, file})
	if err != nil {
		return entry, err
	}
	if n != entry.Size {
		return entry, errors.New("backup input size changed")
	}
	after, err := file.Stat()
	if err != nil {
		return entry, err
	}
	if !os.SameFile(opened, after) || !after.ModTime().Equal(opened.ModTime()) || after.Size() != opened.Size() {
		return entry, errors.New("backup input changed during export")
	}
	entry.SHA256 = hex.EncodeToString(hash.Sum(nil))
	return entry, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func validArchivePath(name string) error {
	if len(name) == 0 || len(name) > 4096 || name != path.Clean(name) || path.IsAbs(name) || strings.Contains(name, "\\") || strings.ContainsRune(name, 0) || strings.HasPrefix(name, "../") || name == ".." || strings.Count(name, "/") > 64 {
		return errors.New("backup contains an unsafe archive path")
	}
	if name == "executor/executor.db" || name == "dashboard/dashboard.sqlite" || name == "config/executor.json" || name == "manifest.json" {
		return nil
	}
	for _, prefix := range []string{"executor/snapshots/", "executor/secrets/", "executor/runtime-inputs/"} {
		if strings.HasPrefix(name, prefix) {
			return nil
		}
	}
	return errors.New("backup contains an unsupported archive path")
}

func openSQLite(filename string) (*sql.DB, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || st.Nlink != 1 {
		return nil, errors.New("backup database must be a private regular file with one link")
	}
	u := url.URL{Scheme: "file", Path: filename}
	q := u.Query()
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "trusted_schema(OFF)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

const dashboardSchema = `CREATE TABLE users(id TEXT PRIMARY KEY,username TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('admin','defender','viewer')),disabled INTEGER NOT NULL DEFAULT 0,sensitive_access INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL);
CREATE TABLE sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,csrf TEXT NOT NULL,expires_at INTEGER NOT NULL);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE TABLE audit(id INTEGER PRIMARY KEY AUTOINCREMENT,at TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,result TEXT NOT NULL,operation_id TEXT NOT NULL DEFAULT '');`

func snapshotDashboard(ctx context.Context, source, destination string, mode Mode) error {
	db, err := openSQLite(source)
	if err != nil {
		return err
	}
	defer db.Close()
	consistent := destination + ".consistent"
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", consistent); err != nil {
		return err
	}
	if err := os.Chmod(consistent, 0600); err != nil {
		return err
	}
	snapshot, err := openSQLite(consistent)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	if mode == Protected {
		// Reconstructing the full database through VACUUM after deleting sessions
		// also removes their token hashes and CSRF values from SQLite free pages.
		if _, err := snapshot.ExecContext(ctx, "DELETE FROM sessions"); err != nil {
			return err
		}
		if _, err := snapshot.ExecContext(ctx, "VACUUM INTO ?", destination); err != nil {
			return err
		}
		return os.Chmod(destination, 0600)
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	file.Close()
	target, err := openSQLite(destination)
	if err != nil {
		return err
	}
	defer target.Close()
	if _, err := target.ExecContext(ctx, dashboardSchema); err != nil {
		return err
	}
	rows, err := snapshot.QueryContext(ctx, "SELECT id,username,password_hash,role,disabled,sensitive_access,created_at FROM users ORDER BY id")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, username, passwordHash, role string
		var disabled, sensitive, created int64
		if err := rows.Scan(&id, &username, &passwordHash, &role, &disabled, &sensitive, &created); err != nil {
			return err
		}
		if _, err := target.ExecContext(ctx, "INSERT INTO users(id,username,password_hash,role,disabled,sensitive_access,created_at) VALUES(?,?,?,?,?,?,?)", id, username, passwordHash, role, disabled, sensitive, created); err != nil {
			return err
		}
	}
	return rows.Err()
}
