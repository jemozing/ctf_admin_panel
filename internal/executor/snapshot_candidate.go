package executor

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

// snapshotCandidateSource is also called during Preview so an invalid source
// never becomes a confirmed restore plan. Restoration does not import an old
// runtime policy, secret version or image: Build continues under current policy.
func (m *Manager) snapshotCandidateSource(ctx context.Context, s domain.Service, id domain.ID) (domain.Snapshot, error) {
	source, err := m.loadSnapshot(ctx, id)
	if err != nil {
		return source, err
	}
	if source.ServiceID != s.ID || source.FileMapRevision != s.FileMapRevision {
		return source, errors.New("snapshot belongs to another service or stale file map")
	}
	switch source.Purpose {
	case domain.SnapshotBaseline, domain.SnapshotManual, domain.SnapshotCandidate:
	default:
		return source, errors.New("recovery snapshots can only be used by the recovery procedure")
	}
	// The immutable file map revision must name the same paths in the current
	// approved service. Clone enforces actual membership again before publish.
	for _, ref := range s.SecretVersions {
		if m.Vault == nil {
			return source, errors.New("current secret vault unavailable")
		}
		if _, err := m.Vault.Read(ref); err != nil {
			return source, errors.New("current policy secret version unavailable")
		}
	}
	return source, nil
}

func (m *Manager) restoreSnapshotCandidate(ctx context.Context, s domain.Service, st *runtimeState, op domain.Operation, sourceID domain.ID) error {
	source, err := m.snapshotCandidateSource(ctx, s, sourceID)
	if err != nil {
		return err
	}
	if err := m.stage(ctx, op.Spec.ID, domain.StageCopying); err != nil {
		return err
	}
	metadataBytes, _ := json.Marshal(source)
	needed := uint64(source.Manifest.TotalBytes()) + uint64(len(metadataBytes)) + 4096
	if err := m.preflightAllocation(ctx, filepath.Join(m.Config.StateDirectory, "snapshots"), needed, uint64(len(source.Manifest.Entries())+3), m.Config.Storage.Effective().SnapshotMaxBytes); err != nil {
		return err
	}
	// Recheck after pressure collection. The queued operation's snapshot pin
	// protects this source, and tombstoned sources are never resurrected.
	if _, err := m.snapshotCandidateSource(ctx, s, sourceID); err != nil {
		return err
	}
	id := NewID("snap-")
	if err := m.Store.PutImmutable(ctx, "snapshot_allocation", id, s.ID, allocation{ID: id, OperationID: op.Spec.ID, CreatedAt: time.Now().UTC()}); err != nil {
		return err
	}
	metadata := domain.Snapshot{ID: id, ServiceID: s.ID, CreatedAt: time.Now().UTC(), Author: op.Spec.Initiator, Purpose: domain.SnapshotCandidate, FileMapRevision: s.FileMapRevision, Consistency: source.Consistency, GitSource: source.GitSource}
	candidate, err := m.Snapshots.Clone(ctx, source.ID, metadata, s.ManagedPaths)
	if err != nil {
		return err
	}
	if err := m.verifyCapturedQuota(ctx, candidate.ID); err != nil {
		return err
	}
	if err := m.Store.PutImmutable(ctx, "snapshot", candidate.ID, s.ID, candidate); err != nil {
		return err
	}
	origin := struct {
		SourceSnapshotID domain.ID `json:"source_snapshot_id"`
		CandidateID      domain.ID `json:"candidate_id"`
		OperationID      domain.ID `json:"operation_id"`
	}{source.ID, candidate.ID, op.Spec.ID}
	if err := m.Store.PutImmutable(ctx, "snapshot_origin", candidate.ID, s.ID, origin); err != nil {
		return err
	}
	st.CandidateID = candidate.ID
	if err := m.saveState(ctx, st); err != nil {
		return err
	}
	return m.event(ctx, op.Spec.ID, "candidate_restored", string(candidate.ID))
}
