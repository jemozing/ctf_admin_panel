package executor

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/sourcegit"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

type gitSourceConfiguration struct {
	Configuration sourcegit.Config         `json:"configuration"`
	Revision      uint64                   `json:"revision"`
	Credential    *domain.SecretVersionRef `json:"credential,omitempty"`
	CreatedAt     time.Time                `json:"created_at"`
}

func (m *Manager) gitConfiguration(ctx context.Context, id domain.ID) (gitSourceConfiguration, error) {
	var latest gitSourceConfiguration
	records, err := m.Store.List(ctx, "git_source", id)
	if err != nil {
		return latest, err
	}
	for _, record := range records {
		var value gitSourceConfiguration
		if err := json.Unmarshal(record.Payload, &value); err != nil {
			return latest, err
		}
		if value.Revision > latest.Revision {
			latest = value
		}
	}
	if latest.Revision == 0 {
		return latest, store.ErrNotFound
	}
	return latest, latest.Configuration.Validate()
}
func (m *Manager) GitSource(ctx context.Context, id domain.ID) (transport.GitSourceView, error) {
	view := transport.GitSourceView{}
	if _, err := m.Store.GetService(ctx, id); err != nil {
		return view, err
	}
	c, err := m.gitConfiguration(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return view, nil
	}
	if err != nil {
		return view, err
	}
	view = transport.GitSourceView{Configured: true, URL: c.Configuration.URL, Ref: c.Configuration.Ref, Subdirectory: c.Configuration.Subdirectory, Username: c.Configuration.Username, HasCredentials: c.Credential != nil, Revision: c.Revision}
	records, err := m.Store.List(ctx, "snapshot", id)
	if err != nil {
		return view, err
	}
	for _, record := range records {
		var snap domain.Snapshot
		if err := json.Unmarshal(record.Payload, &snap); err != nil {
			return view, err
		}
		if snap.GitSource == nil || snap.GitSource.SourceRevision != c.Revision {
			continue
		}
		if view.LastFetch == nil || snap.CreatedAt.After(view.LastFetch.At) {
			view.LastFetch = &transport.GitFetchSummary{Commit: snap.GitSource.Commit, SnapshotID: snap.ID, At: snap.CreatedAt}
		}
	}
	return view, nil
}
func (m *Manager) ConfigureGitSource(ctx context.Context, id domain.ID, input transport.GitSourceRequest) (transport.GitSourceView, error) {
	if err := input.Validate(); err != nil {
		return transport.GitSourceView{}, err
	}
	m.submitMu.Lock()
	defer m.submitMu.Unlock()
	if _, err := m.Store.GetService(ctx, id); err != nil {
		return transport.GitSourceView{}, err
	}
	ops, err := m.Store.ListOperations(ctx)
	if err != nil {
		return transport.GitSourceView{}, err
	}
	for _, op := range ops {
		if op.Spec.ServiceID == id && op.Spec.Kind == domain.OperationFetchSource && !op.State.Terminal() {
			return transport.GitSourceView{}, store.ErrBusy
		}
	}
	previous, err := m.gitConfiguration(ctx, id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return transport.GitSourceView{}, err
	}
	c := gitSourceConfiguration{Configuration: input.Configuration(), Revision: previous.Revision + 1, CreatedAt: time.Now().UTC()}
	if !input.ClearCredentials && input.Token == "" && c.Configuration.URL == previous.Configuration.URL && c.Configuration.Username == previous.Configuration.Username {
		c.Credential = previous.Credential
	}
	if input.Token != "" {
		ref, err := m.Vault.Import(NewID("git-token-"), []byte(input.Token))
		if err != nil {
			return transport.GitSourceView{}, err
		}
		c.Credential = &ref
	}
	if err := m.Store.PutImmutable(ctx, "git_source", NewID("git-source-"), id, c); err != nil {
		return transport.GitSourceView{}, err
	}
	return m.GitSource(ctx, id)
}
func (m *Manager) fetchGitSource(ctx context.Context, s domain.Service, st runtimeState, op domain.Operation) error {
	c, err := m.gitConfiguration(ctx, s.ID)
	if err != nil {
		return err
	}
	var token []byte
	if c.Credential != nil {
		token, err = m.Vault.Read(*c.Credential)
		if err != nil {
			return errors.New("Git credentials unavailable; configure a new token")
		}
		defer clear(token)
	}
	if err := m.stage(ctx, op.Spec.ID, domain.StageCopying); err != nil {
		return err
	}
	var tree *sourcegit.Tree
	err = m.withArtifactReleased(ctx, func(ctx context.Context) error {
		var err error
		tree, err = sourcegit.Fetch(ctx, c.Configuration, token)
		return err
	})
	if err != nil {
		return err
	}
	defer tree.Close()
	hostOnlyCompose, err := m.preserveGitComposeInputs(ctx, s, st, tree.Directory)
	if err != nil {
		return err
	}
	provenance := &domain.GitProvenance{
		URL: c.Configuration.URL, Ref: c.Configuration.Ref, Subdirectory: c.Configuration.Subdirectory,
		Commit: tree.Commit, SourceRevision: c.Revision, HostComposeInputs: hostOnlyCompose,
	}
	snap, err := m.capture(ctx, s, op.Spec.Initiator, domain.SnapshotCandidate, tree.Directory, provenance)
	if err != nil {
		return err
	}
	st.CandidateID = snap.ID
	if err := m.saveState(ctx, &st); err != nil {
		return err
	}
	return m.event(ctx, op.Spec.ID, "git_candidate_created", string(snap.ID)+" commit "+tree.Commit)
}
