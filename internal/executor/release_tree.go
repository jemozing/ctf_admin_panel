package executor

import (
	"context"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/filesystem"
)

// A recovery point can contain reviewed manual changes which were never part of
// an immutable release. Its image lineage does not make that release active or
// transfer new health evidence to the historical release.
func (m *Manager) activeReleaseTreeMatches(ctx context.Context, s domain.Service, st runtimeState) (bool, error) {
	if st.CurrentReleaseID == "" || st.ActiveSnapshotID == "" {
		return false, nil
	}
	var release domain.Release
	if err := m.Store.Get(ctx, "release", st.CurrentReleaseID, &release); err != nil {
		return false, err
	}
	var snapshot domain.Snapshot
	if err := m.Store.Get(ctx, "snapshot", st.ActiveSnapshotID, &snapshot); err != nil {
		return false, err
	}
	return release.Spec().ServiceID == s.ID && snapshot.ServiceID == s.ID && release.Spec().TreeDigest == snapshot.ManifestDigest, nil
}

func (m *Manager) healthReleaseID(ctx context.Context, s domain.Service, st runtimeState) (domain.ID, error) {
	matched, err := m.activeReleaseTreeMatches(ctx, s, st)
	if err != nil {
		return "", err
	}
	if matched {
		var snapshot domain.Snapshot
		if err := m.Store.Get(ctx, "snapshot", st.ActiveSnapshotID, &snapshot); err != nil {
			return "", err
		}
		current, err := filesystem.Observe(ctx, s.ProjectDirectory, s.ManagedPaths, nil)
		if err != nil {
			return "", err
		}
		if current.Digest() == snapshot.ManifestDigest {
			return st.CurrentReleaseID, nil
		}
	}
	return "", nil
}
