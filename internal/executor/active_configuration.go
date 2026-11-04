package executor

import (
	"context"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func (m *Manager) activeConfigurationDigest(ctx context.Context, s domain.Service, st runtimeState) (domain.Digest, error) {
	if st.CurrentReleaseID == "" {
		return m.Store.GetServiceConfiguration(ctx, s.ID, s.PolicyRevision)
	}
	release, err := m.loadRelease(ctx, s, st.CurrentReleaseID)
	if err != nil {
		return "", err
	}
	return release.Spec().ConfigurationDigest, nil
}

func (m *Manager) currentConfigurationDigest(ctx context.Context, s domain.Service) (domain.Digest, error) {
	st, err := m.state(ctx, s)
	if err != nil {
		return "", err
	}
	return m.activeConfigurationDigest(ctx, s, st)
}

func (m *Manager) requireNoRuntimePortOverlay(ctx context.Context, s domain.Service) error {
	overlay, err := m.runtimePortOverlay(ctx, s.ID)
	if err != nil {
		return err
	}
	if overlay.Active {
		return &transport.ComposeEditorError{Message: "return the service ports from HTTP Proxy before switching Compose configuration"}
	}
	return nil
}
