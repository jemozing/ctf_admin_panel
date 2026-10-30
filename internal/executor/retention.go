package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

type RetentionPlan = transport.RetentionPlan

type retirement struct {
	ID     domain.ID `json:"id"`
	At     time.Time `json:"at"`
	Reason string    `json:"reason"`
}

func (m *Manager) isRetired(ctx context.Context, kind string, id domain.ID) (bool, error) {
	var v retirement
	err := m.Store.Get(ctx, kind, id, &v)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}
func addPin(pins map[domain.ID][]string, id domain.ID, reason string) {
	if id != "" {
		for _, v := range pins[id] {
			if v == reason {
				return
			}
		}
		pins[id] = append(pins[id], reason)
	}
}
func (m *Manager) retentionPlan(ctx context.Context, now time.Time, pressure bool) (RetentionPlan, error) {
	p := RetentionPlan{At: now, RetireReleases: []domain.ID{}, DeleteSnapshots: []domain.ID{}, ProtectedSnapshots: map[domain.ID][]string{}, ProtectedReleases: map[domain.ID][]string{}}
	releases := map[domain.ID]domain.Release{}
	byService := map[domain.ID][]domain.Release{}
	snapshots := map[domain.ID]domain.Snapshot{}
	records, err := m.Store.List(ctx, "release", "")
	if err != nil {
		return p, err
	}
	for _, rec := range records {
		retired, err := m.isRetired(ctx, "retired_release", rec.ID)
		if err != nil {
			return p, err
		}
		if retired {
			continue
		}
		var r domain.Release
		if err := json.Unmarshal(rec.Payload, &r); err != nil {
			return p, err
		}
		releases[rec.ID] = r
		byService[rec.ServiceID] = append(byService[rec.ServiceID], r)
		if r.Spec().Source == domain.ReleaseImported {
			addPin(p.ProtectedReleases, rec.ID, "imported_release")
		}
	}
	records, err = m.Store.List(ctx, "snapshot", "")
	if err != nil {
		return p, err
	}
	for _, rec := range records {
		retired, err := m.isRetired(ctx, "deleted_snapshot", rec.ID)
		if err != nil {
			return p, err
		}
		if retired {
			continue
		}
		var s domain.Snapshot
		if err := json.Unmarshal(rec.Payload, &s); err != nil {
			return p, err
		}
		snapshots[s.ID] = s
		if s.Purpose == domain.SnapshotBaseline {
			addPin(p.ProtectedSnapshots, s.ID, "baseline")
		}
		for _, reason := range s.PinReasons {
			addPin(p.ProtectedSnapshots, s.ID, "explicit:"+reason)
		}
	}
	needsReview := map[domain.ID]bool{}
	services, err := m.Store.ListServices(ctx)
	if err != nil {
		return p, err
	}
	for _, s := range services {
		needs, err := m.Store.MetadataRestoreNeedsReview(ctx, s.ID)
		if err != nil {
			return p, err
		}
		if needs {
			needsReview[s.ID] = true
			for id, r := range releases {
				if r.Spec().ServiceID == s.ID {
					addPin(p.ProtectedReleases, id, "metadata_restore_review")
				}
			}
			for id, snap := range snapshots {
				if snap.ServiceID == s.ID {
					addPin(p.ProtectedSnapshots, id, "metadata_restore_review")
				}
			}
		}
		st, err := m.state(ctx, s)
		if err != nil {
			return p, err
		}
		addPin(p.ProtectedReleases, st.CurrentReleaseID, "current_release")
		addPin(p.ProtectedSnapshots, st.ActiveSnapshotID, "active_tree")
		addPin(p.ProtectedSnapshots, st.BaselineID, "baseline")
		addPin(p.ProtectedSnapshots, st.CandidateID, "latest_candidate")
	}
	// Registration can advance before a new baseline is captured. Preserve the
	// last actually observed tree/release even when state() resets policy fields.
	observedStates, err := m.Store.List(ctx, "runtime_state", "")
	if err != nil {
		return p, err
	}
	latestObserved := map[domain.ID]runtimeState{}
	for _, record := range observedStates {
		var st runtimeState
		if err := json.Unmarshal(record.Payload, &st); err != nil {
			return p, err
		}
		if st.Sequence >= latestObserved[st.ServiceID].Sequence {
			latestObserved[st.ServiceID] = st
		}
	}
	for _, st := range latestObserved {
		addPin(p.ProtectedReleases, st.CurrentReleaseID, "last_observed_release")
		addPin(p.ProtectedSnapshots, st.ActiveSnapshotID, "last_observed_tree")
	}
	verified := map[domain.ID]bool{}
	records, err = m.Store.List(ctx, "check_observation", "")
	if err != nil {
		return p, err
	}
	for _, rec := range records {
		var v checkObservation
		if err := json.Unmarshal(rec.Payload, &v); err != nil {
			return p, err
		}
		hasFunctional, healthy := false, true
		for _, signal := range v.Signals {
			hasFunctional = hasFunctional || signal.Source == domain.HealthFunctional
			healthy = healthy && signal.State == domain.HealthHealthy
		}
		if hasFunctional && healthy {
			verified[v.ReleaseID] = true
		}
	}
	policy := m.Config.Storage.Effective()
	for _, list := range byService {
		sort.Slice(list, func(i, j int) bool { return list[i].Spec().CreatedAt.After(list[j].Spec().CreatedAt) })
		keptVerified, keptPrepared := uint32(0), uint32(0)
		for _, r := range list {
			id := r.Spec().ID
			if verified[id] {
				alreadyPinned := len(p.ProtectedReleases[id]) > 0
				if !alreadyPinned && keptVerified < policy.VerifiedReleases {
					addPin(p.ProtectedReleases, id, "recent_locally_verified")
				}
				if !alreadyPinned {
					keptVerified++
				}
			} else if !pressure && keptPrepared < policy.CandidateSnapshots && now.Sub(r.Spec().CreatedAt) < time.Duration(policy.CandidateMaxAgeHours)*time.Hour {
				addPin(p.ProtectedReleases, id, "recent_prepared")
				keptPrepared++
			}
		}
	}
	ops, err := m.Store.ListOperations(ctx)
	if err != nil {
		return p, err
	}
	for _, op := range ops {
		if op.State.Terminal() || needsReview[op.Spec.ServiceID] {
			continue
		}
		addPin(p.ProtectedReleases, op.Spec.ReleaseID, "operation:"+string(op.Spec.ID))
		addPin(p.ProtectedSnapshots, op.RecoveryPointID, "recovery:"+string(op.Spec.ID))
		if op.RecoveryPointID != "" {
			var point recoveryPoint
			err := m.Store.Get(ctx, "recovery_point", op.RecoveryPointID, &point)
			if err == nil {
				addPin(p.ProtectedReleases, point.ReleaseID, "recovery_release:"+string(op.Spec.ID))
				addPin(p.ProtectedSnapshots, point.SnapshotID, "recovery_tree:"+string(op.Spec.ID))
				addPin(p.ProtectedSnapshots, point.State.BaselineID, "recovery_baseline:"+string(op.Spec.ID))
				addPin(p.ProtectedSnapshots, point.State.CandidateID, "recovery_candidate:"+string(op.Spec.ID))
				addPin(p.ProtectedSnapshots, point.State.ActiveSnapshotID, "recovery_active_tree:"+string(op.Spec.ID))
				addPin(p.ProtectedReleases, point.State.CurrentReleaseID, "recovery_current_release:"+string(op.Spec.ID))
			} else {
				return p, fmt.Errorf("retention recovery graph incomplete: %w", err)
			}
		}
		var input operationInput
		err := m.Store.Get(ctx, "operation_input", op.Spec.ID, &input)
		if err == nil {
			addPin(p.ProtectedSnapshots, input.Plan.CandidateID, "candidate_operation:"+string(op.Spec.ID))
			addPin(p.ProtectedSnapshots, input.Plan.SnapshotID, "restore_snapshot_operation:"+string(op.Spec.ID))
		} else {
			return p, fmt.Errorf("retention operation graph incomplete: %w", err)
		}
	}
	for id, r := range releases {
		if len(p.ProtectedReleases[id]) > 0 {
			addPin(p.ProtectedSnapshots, r.Spec().SnapshotID, "release:"+string(id))
		} else {
			p.RetireReleases = append(p.RetireReleases, id)
		}
	}
	for id := range p.ProtectedReleases {
		if _, ok := releases[id]; !ok {
			return p, fmt.Errorf("retention graph references unavailable release %s", id)
		}
	}
	for id := range p.ProtectedSnapshots {
		if _, ok := snapshots[id]; !ok {
			return p, fmt.Errorf("retention graph references unavailable snapshot %s", id)
		}
	}
	groups := map[string][]domain.Snapshot{}
	for id, s := range snapshots {
		if len(p.ProtectedSnapshots[id]) > 0 {
			continue
		}
		if s.Purpose == domain.SnapshotManual || s.Purpose == domain.SnapshotCandidate {
			key := string(s.ServiceID) + "/" + string(s.Purpose)
			groups[key] = append(groups[key], s)
		} else {
			p.DeleteSnapshots = append(p.DeleteSnapshots, id)
		}
	}
	for _, list := range groups {
		sort.Slice(list, func(i, j int) bool {
			if list[i].CreatedAt.Equal(list[j].CreatedAt) {
				return list[i].ID > list[j].ID
			}
			return list[i].CreatedAt.After(list[j].CreatedAt)
		})
		for i, s := range list {
			keep := policy.ManualSnapshots
			if s.Purpose == domain.SnapshotCandidate {
				keep = policy.CandidateSnapshots
			}
			expired := s.Purpose == domain.SnapshotCandidate && now.Sub(s.CreatedAt) >= time.Duration(policy.CandidateMaxAgeHours)*time.Hour
			if pressure || i >= int(keep) || expired {
				p.DeleteSnapshots = append(p.DeleteSnapshots, s.ID)
			}
		}
	}
	sort.Slice(p.RetireReleases, func(i, j int) bool { return p.RetireReleases[i] < p.RetireReleases[j] })
	sort.Slice(p.DeleteSnapshots, func(i, j int) bool { return p.DeleteSnapshots[i] < p.DeleteSnapshots[j] })
	return p, nil
}

// rotateLocked is called only while artifactMu AND submitMu are held. All
// reference acquisition occurs in Submit or the single worker under those gates.
func (m *Manager) rotateLocked(ctx context.Context, pressure bool) (RetentionPlan, error) {
	if err := m.cleanupAllocations(ctx); err != nil {
		return RetentionPlan{}, err
	}
	p, err := m.retentionPlan(ctx, time.Now().UTC(), pressure)
	if err != nil {
		return p, err
	}
	if len(p.RetireReleases)+len(p.DeleteSnapshots) > 0 {
		if err := m.Store.PutImmutable(ctx, "retention_event", NewID("rotation-"), "executor", p); err != nil {
			return p, err
		}
	}
	for _, id := range p.RetireReleases {
		var r domain.Release
		if err := m.Store.Get(ctx, "release", id, &r); err != nil {
			return p, err
		}
		if err := m.Store.PutImmutable(ctx, "retired_release", id, r.Spec().ServiceID, retirement{id, p.At, "retention"}); err != nil {
			return p, err
		}
	}
	for _, id := range p.DeleteSnapshots {
		var s domain.Snapshot
		if err := m.Store.Get(ctx, "snapshot", id, &s); err != nil {
			return p, err
		}
		if err := m.Store.PutImmutable(ctx, "deleted_snapshot", id, s.ServiceID, retirement{id, p.At, "retention"}); err != nil {
			return p, err
		}
		if err := m.Snapshots.Remove(ctx, id); err != nil {
			return p, fmt.Errorf("snapshot retirement recorded but cleanup incomplete for %s: %w", id, err)
		}
	}
	// A crash after the tombstone but before unlink is retried idempotently.
	deleted, err := m.Store.List(ctx, "deleted_snapshot", "")
	if err != nil {
		return p, err
	}
	for _, record := range deleted {
		needs, err := m.Store.MetadataRestoreNeedsReview(ctx, record.ServiceID)
		if err != nil {
			return p, err
		}
		if needs {
			continue
		}
		if err := m.Snapshots.Remove(ctx, record.ID); err != nil {
			return p, err
		}
	}
	if err := m.cleanupRetiredImageTags(ctx); err != nil {
		return p, err
	}
	return p, nil
}
func (m *Manager) Rotate(ctx context.Context) (RetentionPlan, error) {
	m.artifactMu.Lock()
	defer m.artifactMu.Unlock()
	m.submitMu.Lock()
	defer m.submitMu.Unlock()
	return m.rotateLocked(ctx, false)
}
func (m *Manager) reclaim(ctx context.Context, pressure bool) error {
	m.submitMu.Lock()
	defer m.submitMu.Unlock()
	_, err := m.rotateLocked(ctx, pressure)
	return err
}
