package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/filesystem"
	"github.com/ctf-service-manager/ctf-service-manager/internal/storage"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"github.com/moby/moby/client"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

func stagingPath(state string) string { return filepath.Join(state, "staging") }
func (m *Manager) dockerStorage(ctx context.Context) (uint64, *storage.Space, error) {
	if m.Engine == nil {
		return 0, nil, errors.New("Docker pressure measurement unavailable")
	}
	usage, err := m.Engine.Client.DiskUsage(ctx, client.DiskUsageOptions{Images: true, BuildCache: true, Containers: true, Volumes: true})
	if err != nil {
		return 0, nil, errors.New("Docker disk usage unavailable; heavy operation refused")
	}
	total := uint64(0)
	for _, value := range []int64{usage.Images.TotalSize, usage.BuildCache.TotalSize, usage.Containers.TotalSize, usage.Volumes.TotalSize} {
		if value < 0 || uint64(value) > math.MaxUint64-total {
			return 0, nil, errors.New("Docker storage accounting incomplete or overflowed")
		}
		total += uint64(value)
	}
	if m.Config.DockerStorageDirectory == "" {
		return total, nil, nil
	}
	info, err := m.Engine.Client.Info(ctx, client.InfoOptions{})
	if err != nil {
		return total, nil, err
	}
	if info.Info.DockerRootDir != m.Config.DockerStorageDirectory {
		return total, nil, errors.New("configured Docker storage path does not match daemon data root")
	}
	space, err := storage.Capacity(m.Config.DockerStorageDirectory)
	if err != nil {
		return total, nil, err
	}
	return total, &space, nil
}
func (m *Manager) StorageStatus(ctx context.Context) (transport.StorageStatus, error) {
	result := transport.StorageStatus{Policy: m.Config.Storage.Effective()}
	var err error
	result.State, err = storage.Measure(ctx, m.Config.StateDirectory)
	if err != nil {
		return result, err
	}
	result.Snapshots, err = storage.Measure(ctx, filepath.Join(m.Config.StateDirectory, "snapshots"))
	if err != nil {
		return result, err
	}
	if err := ensureStaging(m.Config.StateDirectory); err != nil {
		return result, err
	}
	result.Staging, err = storage.Measure(ctx, stagingPath(m.Config.StateDirectory))
	if err != nil && !os.IsNotExist(err) {
		return result, err
	}
	result.StateCapacity, err = storage.Capacity(m.Config.StateDirectory)
	if err != nil {
		return result, err
	}
	result.DockerUsageBytes, result.DockerCapacity, err = m.dockerStorage(ctx)
	if err != nil {
		return result, err
	}
	result.Plan, err = m.retentionPlan(ctx, time.Now().UTC(), false)
	return result, err
}
func (m *Manager) checkLocalAllocation(ctx context.Context, root string, additional, files, max uint64) error {
	policy := m.Config.Storage.Effective()
	usage, err := storage.Measure(ctx, root)
	if err != nil {
		return err
	}
	space, err := storage.Capacity(root)
	if err != nil {
		return err
	}
	if err := storage.CheckQuota(usage.Bytes, additional, max, space, policy.MinimumFreeBytes, policy.MinimumFreeInodes, files); err != nil {
		return err
	}
	all, err := storage.Measure(ctx, m.Config.StateDirectory)
	if err != nil {
		return err
	}
	return storage.CheckQuota(all.Bytes, additional, policy.StateMaxBytes, space, policy.MinimumFreeBytes, policy.MinimumFreeInodes, files)
}
func (m *Manager) preflightAllocation(ctx context.Context, root string, additional, files, max uint64) error {
	err := m.checkLocalAllocation(ctx, root, additional, files, max)
	if err == nil {
		return nil
	}
	var quota *storage.QuotaError
	if !errors.As(err, &quota) {
		return err
	}
	if err := m.reclaim(ctx, true); err != nil {
		return err
	}
	return m.checkLocalAllocation(ctx, root, additional, files, max)
}
func (m *Manager) preflightSnapshot(ctx context.Context, s domain.Service, source string) (domain.Manifest, error) {
	observed, err := filesystem.Observe(ctx, source, s.ManagedPaths, nil)
	if err != nil {
		return observed, err
	}
	metadata, _ := json.Marshal(observed)
	needed := uint64(observed.TotalBytes()) + uint64(len(metadata)) + 4096
	err = m.preflightAllocation(ctx, filepath.Join(m.Config.StateDirectory, "snapshots"), needed, uint64(len(observed.Entries())+3), m.Config.Storage.Effective().SnapshotMaxBytes)
	return observed, err
}
func (m *Manager) checkDockerBudget(ctx context.Context, additional uint64) error {
	used, space, err := m.dockerStorage(ctx)
	if err != nil {
		return err
	}
	policy := m.Config.Storage.Effective()
	reserved, _, err := m.dockerBuildReservations(ctx, allocationOperation(ctx))
	if err != nil {
		return err
	}
	if reserved > math.MaxUint64-additional {
		return errors.New("Docker reservation accounting overflow")
	}
	additional += reserved
	if used > policy.DockerMaxBytes || additional > policy.DockerMaxBytes-used {
		return &storage.QuotaError{Kind: "docker", Requested: additional, Available: remaining(policy.DockerMaxBytes, used)}
	}
	if space != nil {
		return storage.CheckQuota(0, additional, 0, *space, policy.MinimumFreeBytes, policy.MinimumFreeInodes, 1)
	}
	return nil
}
func remaining(max, used uint64) uint64 {
	if used >= max {
		return 0
	}
	return max - used
}
func (m *Manager) verifyCapturedQuota(ctx context.Context, id domain.ID) error {
	if err := m.checkLocalAllocation(ctx, filepath.Join(m.Config.StateDirectory, "snapshots"), 0, 0, m.Config.Storage.Effective().SnapshotMaxBytes); err != nil {
		if deleteErr := m.Snapshots.Remove(context.WithoutCancel(ctx), id); deleteErr != nil {
			return errors.Join(err, fmt.Errorf("unpublished snapshot cleanup failed: %w", deleteErr))
		}
		return err
	}
	return nil
}

func ensureStaging(state string) error {
	path := stagingPath(state)
	err := os.Mkdir(path, 0700)
	if err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("staging must be a private real directory")
	}
	return nil
}
func (m *Manager) loadSnapshot(ctx context.Context, id domain.ID) (domain.Snapshot, error) {
	retired, err := m.isRetired(ctx, "deleted_snapshot", id)
	if err != nil {
		return domain.Snapshot{}, err
	}
	if retired {
		return domain.Snapshot{}, store.ErrNotFound
	}
	var registered domain.Snapshot
	if err := m.Store.Get(ctx, "snapshot", id, &registered); err != nil {
		return domain.Snapshot{}, err
	}
	artifact, err := m.Snapshots.Load(ctx, id)
	if err != nil {
		return artifact, err
	}
	if artifact.ManifestDigest != registered.ManifestDigest || artifact.ServiceID != registered.ServiceID || artifact.FileMapRevision != registered.FileMapRevision || artifact.Purpose != registered.Purpose || !reflect.DeepEqual(artifact.GitSource, registered.GitSource) {
		return domain.Snapshot{}, errors.New("snapshot artifact differs from registered immutable metadata")
	}
	return artifact, nil
}
