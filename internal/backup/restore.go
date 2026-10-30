package backup

import (
	"archive/tar"
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/snapshots"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
)

// Restore validates every byte in an isolated staging directory, then publishes
// a newly created destination. It never overwrites existing panel state.
func Restore(ctx context.Context, options RestoreOptions) (report Report, resultErr error) {
	if options.MaxBytes == 0 {
		options.MaxBytes = DefaultMaxBytes
	}
	if options.MaxBytes < 1 {
		return report, errors.New("restore size limit must be positive")
	}
	for _, p := range []string{options.Source, options.Destination} {
		if err := absolute(p); err != nil {
			return report, err
		}
	}
	if domain.PathsOverlap(options.Source, options.Destination) {
		return report, errors.New("restore destination overlaps backup source")
	}
	if _, err := os.Lstat(options.Destination); err == nil {
		return report, errors.New("restore destination must not exist")
	} else if !os.IsNotExist(err) {
		return report, err
	}
	info, err := os.Lstat(options.Source)
	if err != nil {
		return report, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return report, errors.New("backup file must be a private regular file")
	}
	input, err := os.Open(options.Source)
	if err != nil {
		return report, err
	}
	defer input.Close()
	opened, err := input.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return report, errors.New("backup file changed during open")
	}
	reader := bufio.NewReader(&contextReader{ctx, input})
	prefix, err := reader.Peek(len(encryptedMagic))
	if err != nil {
		return report, errors.New("backup file is truncated")
	}
	encrypted := string(prefix) == encryptedMagic
	var archiveReader io.Reader = reader
	if encrypted {
		decrypted, err := newDecryptReader(reader, options.Passphrase)
		if err != nil {
			return report, err
		}
		archiveReader = decrypted
	} else if len(options.Passphrase) > 0 {
		return report, errors.New("passphrase supplied for an unencrypted metadata export")
	}
	staging, err := os.MkdirTemp(filepath.Dir(options.Destination), ".ctfm-restore-")
	if err != nil {
		return report, err
	}
	defer func() {
		if staging != "" {
			_ = os.RemoveAll(staging)
		}
	}()
	for _, directory := range []string{"executor", "dashboard", "config"} {
		if err := os.Mkdir(filepath.Join(staging, directory), 0700); err != nil {
			return report, err
		}
	}
	archive := tar.NewReader(archiveReader)
	actual := map[string]Entry{}
	var manifest Manifest
	manifestSeen := false
	for {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return report, errors.New("invalid or truncated backup archive")
		}
		if manifestSeen {
			return report, errors.New("backup manifest must be its final entry")
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return report, errors.New("backup refuses links, directories, devices and special archive entries")
		}
		if len(header.PAXRecords) > 0 {
			for key := range header.PAXRecords {
				if key != "path" && key != "size" {
					return report, errors.New("backup contains unsupported archive extensions")
				}
			}
		}
		if err := validArchivePath(header.Name); err != nil {
			return report, err
		}
		if header.Linkname != "" || header.Mode < 0 || header.Mode&^0777 != 0 || header.Size < 0 {
			return report, errors.New("invalid backup file metadata")
		}
		if _, ok := actual[header.Name]; ok {
			return report, errors.New("backup contains duplicate archive paths")
		}
		if header.Name == "manifest.json" {
			if header.Size > 16<<20 {
				return report, errors.New("backup manifest exceeds 16 MiB")
			}
			decoder := json.NewDecoder(io.LimitReader(archive, header.Size))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&manifest); err != nil {
				return report, errors.New("backup manifest is invalid")
			}
			if err := decoder.Decode(new(any)); err != io.EOF {
				return report, errors.New("backup manifest contains trailing JSON")
			}
			manifestSeen = true
			continue
		}
		if len(actual) >= 200000 || header.Size > options.MaxBytes-report.Bytes {
			return report, errors.New("backup exceeds restore file or byte limit")
		}
		filename := filepath.Join(staging, filepath.FromSlash(header.Name))
		if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			return report, err
		}
		file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return report, err
		}
		hash := sha256.New()
		n, copyErr := io.Copy(io.MultiWriter(file, hash), &contextReader{ctx, archive})
		syncErr := file.Sync()
		closeErr := file.Close()
		if err := errors.Join(copyErr, syncErr, closeErr); err != nil {
			return report, err
		}
		if n != header.Size {
			return report, errors.New("backup entry is truncated")
		}
		actual[header.Name] = Entry{header.Name, n, hex.EncodeToString(hash.Sum(nil)), uint32(header.Mode)}
		report.Bytes += n
	}
	// tar stops at its zero blocks. Read through the encryption final record so
	// truncation cannot pass validation merely because a complete tar was seen.
	if err := validateTrailer(archiveReader); err != nil {
		return report, err
	}
	if !manifestSeen || manifest.Version != 1 || (manifest.Mode != Metadata && manifest.Mode != Protected) || manifest.CreatedAt.IsZero() {
		return report, errors.New("unsupported backup manifest")
	}
	if encrypted != (manifest.Mode == Protected) {
		return report, errors.New("backup encryption does not match manifest mode")
	}
	if len(manifest.Entries) != len(actual) {
		return report, errors.New("backup manifest entry count does not match archive")
	}
	verified := map[string]bool{}
	for _, entry := range manifest.Entries {
		if err := validArchivePath(entry.Path); err != nil {
			return report, err
		}
		found, ok := actual[entry.Path]
		if !ok || verified[entry.Path] || entry != found {
			return report, errors.New("backup hash, size or permission verification failed")
		}
		if manifest.Mode == Metadata && entry.Path != "executor/executor.db" && entry.Path != "dashboard/dashboard.sqlite" && entry.Path != "config/executor.json" {
			return report, errors.New("metadata export unexpectedly contains protected artifacts")
		}
		verified[entry.Path] = true
	}
	for _, required := range []string{"executor/executor.db", "dashboard/dashboard.sqlite", "config/executor.json"} {
		if !verified[required] {
			return report, errors.New("backup is missing a required database or configuration")
		}
	}
	for _, owner := range []Owner{manifest.ExecutorOwner, manifest.DashboardOwner} {
		// 0xffffffff is chown's "unchanged" sentinel; larger integers may wrap.
		if owner.UID < 0 || owner.GID < 0 || uint64(owner.UID) >= uint64(^uint32(0)) || uint64(owner.GID) >= uint64(^uint32(0)) {
			return report, errors.New("invalid state ownership in backup")
		}
	}
	bootstrap, err := config.Load(filepath.Join(staging, "config", "executor.json"))
	if err != nil {
		return report, fmt.Errorf("backup bootstrap is invalid: %w", err)
	}
	for _, entry := range manifest.Entries {
		if err := os.Chmod(filepath.Join(staging, filepath.FromSlash(entry.Path)), os.FileMode(entry.Mode)); err != nil {
			return report, err
		}
	}
	// Restoring panel state must not republish an old routing/WAF policy to a
	// live independent proxy. Reconnecting that module needs a new local review.
	if bootstrap.Proxy.Enabled {
		bootstrap.Proxy.Enabled = false
		raw, err := json.MarshalIndent(bootstrap, "", "  ")
		if err != nil {
			return report, err
		}
		if err := os.WriteFile(filepath.Join(staging, "config", "executor.json"), append(raw, '\n'), 0600); err != nil {
			return report, err
		}
		report.ProxyReconfigurationRequired = true
	}
	db, err := store.Open(filepath.Join(staging, "executor", "executor.db"))
	if err != nil {
		return report, err
	}
	if err := db.PrepareRestoredState(ctx, time.Now().UTC()); err != nil {
		db.Close()
		return report, err
	}
	requiresReview := manifest.Mode == Metadata
	services, err := db.ListServices(ctx)
	if err != nil {
		db.Close()
		return report, err
	}
	for _, service := range services {
		pending, err := db.MetadataRestoreNeedsReview(ctx, service.ID)
		if err != nil {
			db.Close()
			return report, err
		}
		if manifest.Mode == Metadata && !pending {
			db.Close()
			return report, errors.New("metadata export is missing its registration review guard")
		}
		requiresReview = requiresReview || pending
	}
	additional, err := checkRestoredArtifacts(ctx, db, staging, manifest.Mode)
	if err != nil {
		db.Close()
		return report, err
	}
	if err := db.CheckpointDatabase(ctx); err != nil {
		db.Close()
		return report, err
	}
	if err := db.Close(); err != nil {
		return report, err
	}
	dashboardDB, err := openSQLite(filepath.Join(staging, "dashboard", "dashboard.sqlite"))
	if err != nil {
		return report, err
	}
	var integrity string
	if err := dashboardDB.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		dashboardDB.Close()
		return report, errors.New("dashboard backup integrity check failed")
	}
	if _, err := dashboardDB.ExecContext(ctx, "DELETE FROM sessions"); err != nil {
		dashboardDB.Close()
		return report, err
	}
	if err := dashboardDB.Close(); err != nil {
		return report, err
	}
	report.Mode = manifest.Mode
	report.Files = len(actual)
	report.Destination = options.Destination
	report.Missing = append(manifest.Missing, additional...)
	report.RequiresRegistrationReview = requiresReview
	report.OriginalStateDirectory = bootstrap.StateDirectory
	report.SessionsRevoked = true
	report.QueuedOperationsDisabled = true
	reportBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return report, err
	}
	if err := os.WriteFile(filepath.Join(staging, "restore-report.json"), append(reportBytes, '\n'), 0600); err != nil {
		return report, err
	}
	// Retain the original UID separation. A non-root caller may restore only
	// their own UID; root may prepare a new dashboard directory for its UID.
	for _, item := range []struct {
		directory string
		owner     Owner
	}{{"executor", manifest.ExecutorOwner}, {"dashboard", manifest.DashboardOwner}} {
		if os.Geteuid() != 0 && item.owner.UID != os.Geteuid() {
			return report, errors.New("restoring original state ownership requires root")
		}
		if err := ownTree(filepath.Join(staging, item.directory), item.owner); err != nil {
			return report, err
		}
	}
	if err := syncTree(staging); err != nil {
		return report, err
	}
	// Match the installation root: the dashboard UID may traverse the parent,
	// while each database/configuration directory retains its private mode.
	if err := os.Chmod(staging, 0755); err != nil {
		return report, err
	}
	if err := syncDirectory(staging); err != nil {
		return report, err
	}
	if err := publishDirectory(staging, options.Destination); err != nil {
		return report, err
	}
	staging = ""
	if err := syncDirectory(filepath.Dir(options.Destination)); err != nil {
		return report, err
	}
	return report, nil
}

func validateTrailer(reader io.Reader) error {
	buffer := make([]byte, 4096)
	remaining := int64(16 << 20)
	for {
		n, err := reader.Read(buffer)
		remaining -= int64(n)
		if remaining < 0 {
			return errors.New("backup trailer exceeds limit")
		}
		for _, value := range buffer[:n] {
			if value != 0 {
				return errors.New("unexpected data after backup archive")
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
func ownTree(root string, owner Owner) error {
	if os.Geteuid() != 0 {
		return nil
	}
	return filepath.WalkDir(root, func(filename string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("restore staging contains a symbolic link")
		}
		return os.Chown(filename, owner.UID, owner.GID)
	})
}
func syncTree(root string) error {
	directories := []string{}
	err := filepath.WalkDir(root, func(filename string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			directories = append(directories, filename)
			return nil
		}
		file, err := os.Open(filename)
		if err != nil {
			return err
		}
		return errors.Join(file.Sync(), file.Close())
	})
	if err != nil {
		return err
	}
	for i := len(directories) - 1; i >= 0; i-- {
		if err := syncDirectory(directories[i]); err != nil {
			return err
		}
	}
	return nil
}

func checkRestoredArtifacts(ctx context.Context, db *store.Store, root string, mode Mode) ([]Missing, error) {
	result := []Missing{}
	if mode == Metadata {
		return result, nil
	}
	artifacts, err := snapshots.NewStore(filepath.Join(root, "executor", "snapshots"))
	if err != nil {
		return nil, err
	}
	defer artifacts.Close()
	for _, kind := range []string{"snapshot", "release"} {
		records, err := db.List(ctx, kind, "")
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			tombstoneKind := "retired_release"
			if kind == "snapshot" {
				tombstoneKind = "deleted_snapshot"
			}
			deleted, err := isTombstoned(ctx, db, tombstoneKind, record.ID)
			if err != nil {
				return nil, err
			}
			if deleted {
				continue
			}
			if kind == "snapshot" {
				if _, err := os.Stat(filepath.Join(root, "executor", "snapshots", string(record.ID), "snapshot.json")); os.IsNotExist(err) {
					result = append(result, Missing{"snapshot_content_unavailable", record.ServiceID, string(record.ID)})
					continue
				} else if err != nil {
					return nil, err
				}
				var snapshot domain.Snapshot
				if err := json.Unmarshal(record.Payload, &snapshot); err != nil {
					return nil, err
				}
				if err := snapshot.Validate(); err != nil {
					return nil, err
				}
				// Empty managed directories are represented by the hashed snapshot
				// manifest even when no archive file needs their parent directory.
				content := filepath.Join(root, "executor", "snapshots", string(record.ID), "content")
				if err := os.MkdirAll(content, 0700); err != nil {
					return nil, err
				}
				for _, entry := range snapshot.Manifest.Entries() {
					if entry.Type == domain.EntryDirectory {
						if err := os.MkdirAll(filepath.Join(content, filepath.FromSlash(entry.Path)), 0700); err != nil {
							return nil, err
						}
					}
				}
				loaded, err := artifacts.Load(ctx, record.ID)
				if err != nil {
					return nil, fmt.Errorf("restored snapshot failed verification: %w", err)
				}
				if loaded.ManifestDigest != snapshot.ManifestDigest {
					return nil, errors.New("restored snapshot does not match its database record")
				}
				continue
			}
			var release domain.Release
			if err := json.Unmarshal(record.Payload, &release); err != nil {
				return nil, err
			}
			spec := release.Spec()
			var configuration map[string]any
			if err := db.Get(ctx, "configuration", domain.ID(strings.TrimPrefix(string(spec.ConfigurationDigest), "sha256:")), &configuration); errors.Is(err, store.ErrNotFound) {
				result = append(result, Missing{"frozen_configuration_unavailable", spec.ServiceID, string(spec.ConfigurationDigest)})
			} else if err != nil {
				return nil, err
			}
			for _, ref := range spec.Secrets {
				name := string(ref.SecretID) + "--" + string(ref.Version) + ".secret"
				filename := filepath.Join(root, "executor", "secrets", name)
				if _, err := os.Stat(filename); os.IsNotExist(err) {
					result = append(result, Missing{"secret_version_unavailable", spec.ServiceID, string(ref.SecretID) + "/" + string(ref.Version)})
				} else if err != nil {
					return nil, err
				}
				if _, err := os.Stat(filename + ".revoked"); err == nil {
					result = append(result, Missing{"secret_version_revoked", spec.ServiceID, string(ref.SecretID) + "/" + string(ref.Version)})
				} else if !os.IsNotExist(err) {
					return nil, err
				}
			}
		}
	}
	return result, nil
}
