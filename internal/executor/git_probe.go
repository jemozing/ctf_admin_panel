package executor

import (
	"context"
	"errors"

	"github.com/ctf-service-manager/ctf-service-manager/internal/sourcegit"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

// Interactive Git reads share a process-wide limit on network subprocesses.
var gitProbeSlots = make(chan struct{}, 2)

func acquireGitReadSlot(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case gitProbeSlots <- struct{}{}:
		return nil
	default:
		return store.ErrBusy
	}
}

func (m *Manager) ProbeGitSource(ctx context.Context, input transport.GitProbeRequest) (transport.GitProbeResult, error) {
	if err := input.Validate(); err != nil {
		return transport.GitProbeResult{}, err
	}
	if err := acquireGitReadSlot(ctx); err != nil {
		return transport.GitProbeResult{}, err
	}
	defer func() { <-gitProbeSlots }()
	configuration, token, err := m.prepareGitProbe(ctx, input)
	if err != nil {
		return transport.GitProbeResult{}, err
	}
	defer clear(token)
	return sourcegit.Probe(ctx, configuration, token)
}

func (m *Manager) BrowseGitDirectories(ctx context.Context, input transport.GitDirectoriesRequest) (transport.GitDirectoryListing, error) {
	if err := input.Validate(); err != nil {
		return transport.GitDirectoryListing{}, err
	}
	if err := acquireGitReadSlot(ctx); err != nil {
		return transport.GitDirectoryListing{}, err
	}
	defer func() { <-gitProbeSlots }()
	input.Source.Subdirectory = ""
	configuration, token, err := m.prepareGitProbe(ctx, transport.GitProbeRequest{
		Source: input.Source, ServiceID: input.ServiceID,
	})
	if err != nil {
		return transport.GitDirectoryListing{}, err
	}
	defer clear(token)
	return sourcegit.BrowseDirectories(ctx, configuration, token, input.Directory)
}

// prepareGitProbe snapshots only the already-saved credential reference, then
// reads the immutable secret. It never imports a token or changes configuration,
// candidates, operations, service files, or runtime state.
func (m *Manager) prepareGitProbe(ctx context.Context, input transport.GitProbeRequest) (sourcegit.Config, []byte, error) {
	if err := input.Validate(); err != nil {
		return sourcegit.Config{}, nil, err
	}
	if err := ctx.Err(); err != nil {
		return sourcegit.Config{}, nil, err
	}
	configuration := input.Source.Configuration()
	if input.ServiceID == "" {
		return configuration, []byte(input.Source.Token), nil
	}
	if m.Store == nil {
		return sourcegit.Config{}, nil, store.ErrNotFound
	}
	if _, err := m.Store.GetService(ctx, input.ServiceID); err != nil {
		return sourcegit.Config{}, nil, err
	}
	if input.Source.Token != "" || input.Source.ClearCredentials {
		return configuration, []byte(input.Source.Token), nil
	}
	previous, err := m.gitConfiguration(ctx, input.ServiceID)
	if errors.Is(err, store.ErrNotFound) {
		return configuration, nil, nil
	}
	if err != nil {
		return sourcegit.Config{}, nil, err
	}
	if previous.Credential == nil || configuration.URL != previous.Configuration.URL || configuration.Username != previous.Configuration.Username {
		return configuration, nil, nil
	}
	if m.Vault == nil {
		return sourcegit.Config{}, nil, &sourcegit.ProbeError{Code: "git_credentials_unavailable", Message: "Git credentials unavailable; configure a new token"}
	}
	token, err := m.Vault.Read(*previous.Credential)
	if err != nil {
		return sourcegit.Config{}, nil, &sourcegit.ProbeError{Code: "git_credentials_unavailable", Message: "Git credentials unavailable; configure a new token"}
	}
	return configuration, token, nil
}
