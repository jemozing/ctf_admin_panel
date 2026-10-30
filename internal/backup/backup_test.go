package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/maintenance"
	"github.com/ctf-service-manager/ctf-service-manager/internal/secrets"
	"github.com/ctf-service-manager/ctf-service-manager/internal/snapshots"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
)

const secretMarker = "NOT_EXPORT_PLAINTEXT_56cbe4986baae6ba"

var passphrase = []byte("correct-horse-backup-passphrase")

type fixture struct {
	root, executor, dashboard, configuration string
	snapshot                                 domain.Snapshot
	secret                                   domain.SecretVersionRef
	configurationDigest                      domain.Digest
	service                                  domain.Service
}

func makeFixture(t *testing.T) fixture {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	os.Chmod(root, 0700)
	f := fixture{root: root, executor: filepath.Join(root, "executor"), dashboard: filepath.Join(root, "dashboard"), configuration: filepath.Join(root, "config.json")}
	for _, directory := range []string{f.executor, f.dashboard, filepath.Join(root, "project", "code", "empty"), filepath.Join(root, "workspace"), filepath.Join(root, "backups")} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "project", "code", "app.txt"), []byte(secretMarker), 0644); err != nil {
		t.Fatal(err)
	}
	bootstrap := config.Config{StateDirectory: f.executor, Socket: filepath.Join(root, "runtime", "executor.sock"), DockerHost: "unix:///var/run/docker.sock", DockerBinary: "/usr/bin/true", DiscoveryRoots: []string{filepath.Join(root, "project")}, WorkspaceRoots: []string{filepath.Join(root, "workspace")}, WebUID: os.Geteuid(), Development: true}
	data, _ := json.Marshal(bootstrap)
	if err := os.WriteFile(f.configuration, data, 0600); err != nil {
		t.Fatal(err)
	}
	vault, err := secrets.Open(filepath.Join(f.executor, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	f.secret, err = vault.Import("environment", []byte(secretMarker))
	if err != nil {
		t.Fatal(err)
	}
	vault.Close()
	f.service = domain.Service{SchemaVersion: 1, ID: "demo", Name: secretMarker, Description: secretMarker, ProjectDirectory: filepath.Join(root, "project"), SourceDirectory: filepath.Join(root, "workspace"), ComposeProject: "demo", ComposeFiles: []string{"compose.yaml"}, ManagedPaths: []domain.ManagedPath{{Path: "code", Kind: domain.ManagedCode}}, Targets: []string{"app"}, Containers: []domain.ContainerRef{{Component: "app", ID: strings.Repeat("a", 64), ImageID: domain.Hash([]byte("image")), Role: domain.RoleApplication}}, PolicyRevision: 1, FileMapRevision: 1, SecretVersions: []domain.SecretVersionRef{f.secret}, DataPaths: []domain.DataPath{{Name: "volatile", Kind: domain.StorageWritableLayer, Target: "/tmp", Component: "app", LossAccepted: true}}}
	db, err := store.Open(filepath.Join(f.executor, "executor.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	configuration := map[string]any{"model": map[string]any{"services": map[string]any{"app": map[string]any{"command": []string{secretMarker}, "environment": map[string]any{"PASSWORD": secretMarker}}}}}
	encoded, _ := json.Marshal(configuration)
	f.configurationDigest = domain.Hash(encoded)
	if err := db.PutImmutable(ctx, "configuration", domain.ID(string(f.configurationDigest)[7:]), "demo", configuration); err != nil {
		t.Fatal(err)
	}
	proposal, err := db.CreateProposal(ctx, "proposal", f.service, f.configurationDigest, "admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ApproveProposal(ctx, proposal.ID, proposal.Digest, "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	artifacts, err := snapshots.NewStore(filepath.Join(f.executor, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot, err = artifacts.Create(ctx, domain.Snapshot{ID: "baseline", ServiceID: "demo", CreatedAt: time.Now(), Author: "admin", Purpose: domain.SnapshotBaseline, FileMapRevision: 1, Consistency: domain.ConsistencyCoordinated, PinReasons: []string{secretMarker}}, f.service.ProjectDirectory, f.service.ManagedPaths, nil)
	if err != nil {
		t.Fatal(err)
	}
	artifacts.Close()
	if err := db.PutImmutable(ctx, "snapshot", f.snapshot.ID, "demo", f.snapshot); err != nil {
		t.Fatal(err)
	}
	release, err := domain.NewRelease(domain.ReleaseSpec{SchemaVersion: 1, ID: "release", ServiceID: "demo", CreatedAt: time.Now(), Author: "admin", Source: domain.ReleaseImported, SnapshotID: f.snapshot.ID, TreeDigest: f.snapshot.ManifestDigest, ConfigurationDigest: f.configurationDigest, PolicyRevision: 1, FileMapRevision: 1, Images: []domain.ImageRef{{Component: "app", ImageID: f.service.Containers[0].ImageID, RetentionTag: "ctf-manager/demo:release-app"}}, Secrets: []domain.SecretVersionRef{f.secret}, Data: []domain.DataReference{{Name: "volatile", Identity: "writable_layer", Compatibility: domain.DataCompatible, Evidence: secretMarker}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.PutImmutable(ctx, "release", "release", "demo", release); err != nil {
		t.Fatal(err)
	}
	for _, id := range []domain.ID{"running", "queued"} {
		op, err := domain.NewOperation(domain.OperationSpec{ID: id, Kind: domain.OperationPrepare, Initiator: "admin", IdempotencyKey: string(id) + secretMarker, ServiceID: "demo", ExpectedPolicyRevision: 1, ExpectedTreeDigest: f.snapshot.ManifestDigest, Resources: []string{"service:demo"}, TimeoutSeconds: 30}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		op, _, err = db.BeginOperation(ctx, op, domain.Hash([]byte(string(id))))
		if err != nil {
			t.Fatal(err)
		}
		if id == "running" {
			if err := db.Acquire(ctx, id, op.Spec.Resources); err != nil {
				t.Fatal(err)
			}
			before := op.UpdatedAt
			if err := op.Transition(domain.OperationRunning, domain.OutcomeEvidence{}, before.Add(time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			if err := db.UpdateOperation(ctx, op, before); err != nil {
				t.Fatal(err)
			}
		}
		if err := db.AppendEvent(ctx, store.Event{OperationID: id, At: time.Now(), Kind: "detail", Message: secretMarker, Payload: json.RawMessage(`{"password":"` + secretMarker + `"}`)}); err != nil {
			t.Fatal(err)
		}
		if err := db.PutImmutable(ctx, "operation_input", id, "demo", map[string]any{"password": secretMarker}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.PutImmutable(ctx, "recovery_request", "old-approval", "demo", map[string]any{"operation_id": "running", "request": map[string]any{"password": secretMarker}}); err != nil {
		t.Fatal(err)
	}
	dashboardFile := filepath.Join(f.dashboard, "dashboard.sqlite")
	file, err := os.OpenFile(dashboardFile, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	dashboardDB, err := openSQLite(dashboardFile)
	if err != nil {
		t.Fatal(err)
	}
	defer dashboardDB.Close()
	if _, err := dashboardDB.Exec(dashboardSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := dashboardDB.Exec("INSERT INTO users VALUES(?,?,?,?,?,?,?)", "u-admin", "admin", "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "admin", 0, 1, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := dashboardDB.Exec("INSERT INTO sessions VALUES(?,?,?,?)", secretMarker, "u-admin", secretMarker, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := dashboardDB.Exec("INSERT INTO audit(at,actor,action,target,result) VALUES(?,?,?,?,?)", time.Now().Format(time.RFC3339), "u-admin", "login", secretMarker, secretMarker); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f fixture) options(name string) Options {
	return Options{ExecutorState: f.executor, DashboardState: f.dashboard, Configuration: f.configuration, Destination: filepath.Join(f.root, "backups", name)}
}

func TestMetadataExportReconstructsDatabasesWithoutSecretValues(t *testing.T) {
	f := makeFixture(t)
	ctx := context.Background()
	options := f.options("metadata.tar")
	report, err := Create(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	if report.Mode != Metadata || !report.RequiresRegistrationReview || len(report.Missing) == 0 {
		t.Fatalf("incorrect metadata scope: %#v", report)
	}
	data, err := os.ReadFile(options.Destination)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(secretMarker)) {
		t.Fatal("metadata export leaked secret values through SQLite pages or free text")
	}
	destination := filepath.Join(f.root, "restored")
	restored, err := Restore(ctx, RestoreOptions{Source: options.Destination, Destination: destination})
	if err != nil {
		t.Fatal(err)
	}
	if !restored.SessionsRevoked || !restored.QueuedOperationsDisabled || !restored.RequiresRegistrationReview {
		t.Fatalf("unsafe restore status: %#v", restored)
	}
	db, err := store.Open(filepath.Join(destination, "executor", "executor.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	service, err := db.GetService(ctx, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if service.Name != "demo" || service.Description != "" || len(service.Checks) != 0 {
		t.Fatal("free text was preserved")
	}
	pending, err := db.MetadataRestoreNeedsReview(ctx, "demo")
	if err != nil || !pending {
		t.Fatal("metadata registration review guard missing")
	}
	var model map[string]any
	if err := db.Get(ctx, "configuration", domain.ID(string(f.configurationDigest)[7:]), &model); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("metadata retained frozen Compose")
	}
	assertRestoredOperations(t, ctx, db)
	assertDashboardSessionRevoked(t, filepath.Join(destination, "dashboard", "dashboard.sqlite"))
	if _, err := os.Stat(filepath.Join(destination, "executor", "secrets")); !os.IsNotExist(err) {
		t.Fatal("metadata restored a secret vault")
	}
	if _, err := Restore(ctx, RestoreOptions{Source: options.Destination, Destination: destination}); err == nil {
		t.Fatal("restore replaced existing state")
	}
}

func TestProtectedFullBackupRestoresArtifactsAndRecoveryLocks(t *testing.T) {
	f := makeFixture(t)
	ctx := context.Background()
	options := f.options("protected.ctfmbak")
	options.Passphrase = passphrase
	report, err := Create(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	if report.Mode != Protected || report.RequiresRegistrationReview {
		t.Fatal("incorrect protected backup scope")
	}
	data, err := os.ReadFile(options.Destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte(encryptedMagic)) || bytes.Contains(data, []byte(secretMarker)) {
		t.Fatal("protected full backup contains plaintext")
	}
	destination := filepath.Join(f.root, "restored-protected")
	restored, err := Restore(ctx, RestoreOptions{Source: options.Destination, Destination: destination, Passphrase: passphrase})
	if err != nil {
		t.Fatal(err)
	}
	if restored.RequiresRegistrationReview {
		t.Fatal("full restore incorrectly lost configuration")
	}
	for _, missing := range restored.Missing {
		if strings.Contains(missing.Kind, "unavailable") {
			t.Fatalf("restored artifact unexpectedly missing: %#v", missing)
		}
	}
	db, err := store.Open(filepath.Join(destination, "executor", "executor.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var model map[string]any
	if err := db.Get(ctx, "configuration", domain.ID(string(f.configurationDigest)[7:]), &model); err != nil {
		t.Fatal(err)
	}
	var consumed bool
	if err := db.Get(ctx, "recovery_consumed", "old-approval", &consumed); err != nil || !consumed {
		t.Fatalf("old recovery approval can replay: %v", err)
	}
	encoded, _ := json.Marshal(model)
	if !bytes.Contains(encoded, []byte(secretMarker)) {
		t.Fatal("protected configuration not restored")
	}
	vault, err := secrets.Open(filepath.Join(destination, "executor", "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()
	secret, err := vault.Read(f.secret)
	if err != nil || string(secret) != secretMarker {
		t.Fatalf("vault not restored: %v", err)
	}
	artifacts, err := snapshots.NewStore(filepath.Join(destination, "executor", "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	defer artifacts.Close()
	loaded, err := artifacts.Load(ctx, f.snapshot.ID)
	if err != nil || loaded.ManifestDigest != f.snapshot.ManifestDigest {
		t.Fatalf("snapshot not restored: %v", err)
	}
	assertRestoredOperations(t, ctx, db)
	assertDashboardSessionRevoked(t, filepath.Join(destination, "dashboard", "dashboard.sqlite"))
	active, err := os.ReadFile(filepath.Join(f.service.ProjectDirectory, "code", "app.txt"))
	if err != nil || string(active) != secretMarker {
		t.Fatal("backup/restore changed active project")
	}
	for _, item := range []struct {
		name     string
		data     []byte
		password []byte
	}{{"wrong-password", data, []byte("wrong-password-123456789")}, {"truncated", data[:len(data)-9], passphrase}, {"corrupt", append([]byte{}, data...), passphrase}} {
		t.Run(item.name, func(t *testing.T) {
			if item.name == "corrupt" {
				item.data[cryptoHeaderSize+32] ^= 0x80
			}
			filename := filepath.Join(f.root, "backups", item.name)
			os.WriteFile(filename, item.data, 0600)
			target := filepath.Join(f.root, "restore-"+item.name)
			if _, err := Restore(ctx, RestoreOptions{Source: filename, Destination: target, Passphrase: item.password}); err == nil {
				t.Fatal("damaged or unauthenticated backup accepted")
			}
			if _, err := os.Lstat(target); !os.IsNotExist(err) {
				t.Fatal("failed restore published partial state")
			}
		})
	}
}

func assertRestoredOperations(t *testing.T, ctx context.Context, db *store.Store) {
	t.Helper()
	running, err := db.GetOperation(ctx, "running")
	if err != nil || running.State != domain.OperationInterrupted {
		t.Fatalf("running operation not interrupted: %#v %v", running, err)
	}
	queued, err := db.GetOperation(ctx, "queued")
	if err != nil || queued.State != domain.OperationCancelled {
		t.Fatalf("queued job can run after restore: %#v %v", queued, err)
	}
	other, err := domain.NewOperation(domain.OperationSpec{ID: "other", Kind: domain.OperationPrepare, Initiator: "admin", IdempotencyKey: "other", ServiceID: "demo", ExpectedPolicyRevision: 1, ExpectedTreeDigest: domain.Hash(nil), Resources: []string{"service:demo"}, TimeoutSeconds: 30}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.BeginOperation(ctx, other, domain.Hash([]byte("other"))); err != nil {
		t.Fatal(err)
	}
	if err := db.Acquire(ctx, "other", other.Spec.Resources); !errors.Is(err, store.ErrBusy) {
		t.Fatalf("recovery lock was dropped: %v", err)
	}
}

func assertDashboardSessionRevoked(t *testing.T, filename string) {
	t.Helper()
	db, err := openSQLite(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var users, sessions int
	if err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if users != 1 || sessions != 0 {
		t.Fatal("accounts lost or restored sessions accepted")
	}
}

func TestBackupRefusesLiveProcessesAndQuota(t *testing.T) {
	f := makeFixture(t)
	ctx := context.Background()
	lock, err := maintenance.Acquire(f.dashboard, false)
	if err != nil {
		t.Fatal(err)
	}
	options := f.options("active.tar")
	if _, err := Create(ctx, options); !errors.Is(err, maintenance.ErrActive) {
		t.Fatalf("backup accepted active dashboard: %v", err)
	}
	lock.Close()
	options = f.options("quota.tar")
	options.MaxBytes = 1
	if _, err := Create(ctx, options); err == nil {
		t.Fatal("backup ignored byte quota")
	}
	if _, err := os.Lstat(options.Destination); !os.IsNotExist(err) {
		t.Fatal("failed backup published partial file")
	}
}

func TestRetentionTombstonesSurviveBothBackupModes(t *testing.T) {
	for _, protected := range []bool{false, true} {
		t.Run(map[bool]string{false: "metadata", true: "protected"}[protected], func(t *testing.T) {
			f := makeFixture(t)
			ctx := context.Background()
			db, err := store.Open(filepath.Join(f.executor, "executor.db"))
			if err != nil {
				t.Fatal(err)
			}
			obsolete := f.snapshot
			obsolete.ID = "obsolete"
			obsolete.Purpose = domain.SnapshotManual
			obsolete.PinReasons = nil
			if err := db.PutImmutable(ctx, "snapshot", obsolete.ID, "demo", obsolete); err != nil {
				t.Fatal(err)
			}
			if err := db.PutImmutable(ctx, "deleted_snapshot", obsolete.ID, "demo", map[string]any{"id": obsolete.ID, "at": time.Now(), "reason": secretMarker}); err != nil {
				t.Fatal(err)
			}
			db.Close()
			options := f.options("retention.backup")
			if protected {
				options.Passphrase = passphrase
			}
			if _, err := Create(ctx, options); err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(f.root, "restored-retention")
			report, err := Restore(ctx, RestoreOptions{Source: options.Destination, Destination: destination, Passphrase: options.Passphrase})
			if err != nil {
				t.Fatal(err)
			}
			for _, missing := range report.Missing {
				if missing.Reference == "obsolete" {
					t.Fatal("intentionally deleted snapshot reported as missing")
				}
			}
			restored, err := store.Open(filepath.Join(destination, "executor", "executor.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer restored.Close()
			var tombstone map[string]any
			if err := restored.Get(ctx, "deleted_snapshot", "obsolete", &tombstone); err != nil {
				t.Fatal("snapshot deletion marker lost")
			}
			if !protected && tombstone["reason"] != "retention" {
				t.Fatal("metadata tombstone leaked diagnostic")
			}
		})
	}
}

func TestProtectedRestorePreservesProductionUIDSeparation(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("requires Linux root with CHOWN and DAC_OVERRIDE")
	}
	f := makeFixture(t)
	ctx := context.Background()
	if err := filepath.WalkDir(f.dashboard, func(filename string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(filename, 10001, 10001)
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.configuration)
	if err != nil {
		t.Fatal(err)
	}
	var bootstrap config.Config
	if err := json.Unmarshal(data, &bootstrap); err != nil {
		t.Fatal(err)
	}
	bootstrap.Development = false
	bootstrap.WebUID = 10001
	data, _ = json.Marshal(bootstrap)
	if err := os.WriteFile(f.configuration, data, 0600); err != nil {
		t.Fatal(err)
	}
	options := f.options("production.ctfmbak")
	options.Passphrase = passphrase
	if _, err := Create(ctx, options); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(f.root, "restored-production")
	if _, err := Restore(ctx, RestoreOptions{Source: options.Destination, Destination: destination, Passphrase: passphrase}); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		path string
		uid  uint32
		mode os.FileMode
	}{{"executor", 0, 0700}, {"executor/executor.db", 0, 0600}, {"dashboard", 10001, 0700}, {"dashboard/dashboard.sqlite", 10001, 0600}} {
		info, err := os.Stat(filepath.Join(destination, filepath.FromSlash(item.path)))
		if err != nil {
			t.Fatal(err)
		}
		st := info.Sys().(*syscall.Stat_t)
		if st.Uid != item.uid || info.Mode().Perm() != item.mode {
			t.Fatalf("incorrect restored owner/mode %s: UID %d mode %o", item.path, st.Uid, info.Mode().Perm())
		}
	}
}

func TestRestoreRejectsUnsafeArchivesAndHashCorruption(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	ctx := context.Background()
	for _, item := range []struct {
		name   string
		header tar.Header
	}{{"traversal", tar.Header{Name: "../victim", Mode: 0600, Typeflag: tar.TypeReg, Size: 1}}, {"symlink", tar.Header{Name: "executor/secrets/link", Mode: 0600, Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}}, {"hardlink", tar.Header{Name: "executor/secrets/link", Mode: 0600, Typeflag: tar.TypeLink, Linkname: "executor/executor.db"}}} {
		t.Run(item.name, func(t *testing.T) {
			filename := filepath.Join(root, item.name+".tar")
			file, _ := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			writer := tar.NewWriter(file)
			if err := writer.WriteHeader(&item.header); err != nil {
				t.Fatal(err)
			}
			if item.header.Size > 0 {
				writer.Write([]byte("x"))
			}
			writer.Close()
			file.Close()
			destination := filepath.Join(root, "restore-"+item.name)
			if _, err := Restore(ctx, RestoreOptions{Source: filename, Destination: destination}); err == nil {
				t.Fatal("unsafe archive accepted")
			}
			if _, err := os.Lstat(destination); !os.IsNotExist(err) {
				t.Fatal("unsafe restore published files")
			}
		})
	}
	f := makeFixture(t)
	options := f.options("metadata.tar")
	if _, err := Create(ctx, options); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(options.Destination)
	marker := []byte("SQLite format 3")
	index := bytes.Index(data, marker)
	if index < 0 {
		t.Fatal("test SQLite bytes missing")
	}
	data[index+120] ^= 0x80
	corrupt := filepath.Join(f.root, "backups", "hash-corrupt.tar")
	os.WriteFile(corrupt, data, 0600)
	if _, err := Restore(ctx, RestoreOptions{Source: corrupt, Destination: filepath.Join(f.root, "bad-restore")}); err == nil {
		t.Fatal("corrupted file hash accepted")
	}
}

func TestSQLiteSnapshotIncludesCommittedWAL(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.sqlite")
	file, _ := os.OpenFile(source, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	file.Close()
	db, err := openSQLite(source)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;" + dashboardSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO users VALUES('u-test','tester','hash','viewer',0,0,1)"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(source + "-wal"); err != nil {
		t.Fatal("test needs committed WAL")
	}
	target := filepath.Join(root, "snapshot.sqlite")
	if err := snapshotDashboard(context.Background(), source, target, Protected); err != nil {
		t.Fatal(err)
	}
	copied, err := openSQLite(target)
	if err != nil {
		t.Fatal(err)
	}
	defer copied.Close()
	var count int
	if err := copied.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil || count != 1 {
		t.Fatal("snapshot lost committed WAL changes")
	}
}

func TestCryptoAuthenticatesChunkOrderAndFinalRecord(t *testing.T) {
	var archive bytes.Buffer
	writer, err := newEncryptWriter(&archive, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	plain := bytes.Repeat([]byte("source"), chunkSize/2)
	if _, err := writer.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := newDecryptReader(bytes.NewReader(archive.Bytes()), passphrase)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("encrypted stream roundtrip failed: %v", err)
	}
	trailing := append(append([]byte{}, archive.Bytes()...), 0)
	reader, err = newDecryptReader(bytes.NewReader(trailing), passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); err == nil {
		t.Fatal("trailing bytes accepted")
	}
}
