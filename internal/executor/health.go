package executor

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"github.com/moby/moby/client"
)

type healthPolicyRecord struct {
	Revision              uint64                  `json:"revision"`
	ServicePolicyRevision uint64                  `json:"service_policy_revision"`
	Input                 domain.SecretVersionRef `json:"input"`
	Actor                 domain.ID               `json:"actor"`
	CreatedAt             time.Time               `json:"created_at"`
}

func (m *Manager) healthPolicyMetadata(ctx context.Context, id domain.ID) (healthPolicyRecord, error) {
	var latest healthPolicyRecord
	records, err := m.Store.List(ctx, "health_policy", id)
	if err != nil {
		return latest, err
	}
	for _, record := range records {
		var v healthPolicyRecord
		if err := json.Unmarshal(record.Payload, &v); err != nil {
			return latest, err
		}
		if v.Revision > latest.Revision {
			latest = v
		}
	}
	return latest, nil
}
func (m *Manager) healthPolicy(ctx context.Context, s domain.Service) (domain.HealthCheckPolicy, uint64, error) {
	policy := (domain.HealthCheckPolicy{Checks: s.Checks}).Effective()
	latest, err := m.healthPolicyMetadata(ctx, s.ID)
	if err != nil {
		return policy, 0, err
	}
	if latest.Revision == 0 || latest.ServicePolicyRevision != s.PolicyRevision {
		return policy, latest.Revision, policy.Validate()
	}
	data, err := m.Vault.Read(latest.Input)
	if err != nil {
		return policy, latest.Revision, errors.New("health check inputs unavailable; configure a new policy")
	}
	defer clear(data)
	if err := json.Unmarshal(data, &policy); err != nil {
		return policy, latest.Revision, errors.New("health policy integrity invalid")
	}
	policy = policy.Effective()
	return policy, latest.Revision, policy.Validate()
}

func summarizeChecks(checks []domain.HTTPCheck) []transport.CheckSummary {
	out := []transport.CheckSummary{}
	for _, check := range checks {
		summary := transport.CheckSummary{ID: check.ID, Kind: check.EffectiveKind(), Source: check.Source, TimeoutSeconds: check.TimeoutSeconds, Targets: []string{}, Steps: 1, CleanupSteps: len(check.CleanupSteps)}
		add := func(raw string) {
			u, err := url.Parse(raw)
			if err == nil && u.Host != "" {
				target := u.Scheme + "://" + u.Host
				for _, v := range summary.Targets {
					if v == target {
						return
					}
				}
				summary.Targets = append(summary.Targets, target)
			}
		}
		switch check.EffectiveKind() {
		case domain.CheckTCP:
			summary.Targets = append(summary.Targets, check.Address)
		case domain.CheckHTTP:
			add(check.URL)
		case domain.CheckHTTPSequence:
			summary.Steps = len(check.Steps)
			for _, step := range check.Steps {
				add(step.URL)
			}
		}
		out = append(out, summary)
	}
	return out
}

// healthRuntimeDigest includes Docker StartedAt, so a restart with the same ID
// invalidates a manual confirmation. It is observation, never a health verdict.
func (m *Manager) healthRuntimeDigest(ctx context.Context, s domain.Service) (domain.Digest, bool, error) {
	st, err := m.state(ctx, s)
	if err != nil {
		return "", false, err
	}
	items, err := m.Engine.Inventory(ctx, s.ComposeProject)
	if err != nil {
		return "", false, err
	}
	type observation struct{ Component, ID, Image, State, StartedAt string }
	observed := []observation{}
	running := len(items) > 0 && len(items) == len(st.Containers)
	seen := map[string]bool{}
	for _, item := range items {
		registered := false
		for _, ref := range st.Containers {
			if ref.Component == item.Component && ref.ID == item.ID && string(ref.ImageID) == item.ImageID {
				registered = true
				break
			}
		}
		running = running && registered && !seen[item.Component]
		seen[item.Component] = true
		info, err := m.Engine.Client.ContainerInspect(ctx, item.ID, client.ContainerInspectOptions{})
		if err != nil {
			return "", false, err
		}
		started := ""
		if info.Container.State != nil {
			started = info.Container.State.StartedAt
		}
		observed = append(observed, observation{item.Component, item.ID, item.ImageID, item.State, started})
		running = running && item.State == "running"
	}
	sort.Slice(observed, func(i, j int) bool { return observed[i].Component < observed[j].Component })
	data, _ := json.Marshal(observed)
	return domain.Hash(data), running, nil
}

func (m *Manager) HealthChecks(ctx context.Context, id domain.ID) (transport.HealthChecksView, error) {
	view := transport.HealthChecksView{Checks: []transport.CheckSummary{}, ManualConfirmations: []transport.ManualHealthView{}}
	s, err := m.Store.GetService(ctx, id)
	if err != nil {
		return view, err
	}
	policy, revision, err := m.healthPolicy(ctx, s)
	if err != nil {
		latest, metadataErr := m.healthPolicyMetadata(ctx, s.ID)
		if metadataErr != nil {
			return view, metadataErr
		}
		revision = latest.Revision
		policy = (domain.HealthCheckPolicy{}).Effective()
		view.Warning = "Configured check inputs are unavailable. Save a complete replacement before service operations."
	}
	st, err := m.state(ctx, s)
	if err != nil {
		return view, err
	}
	digest, _, err := m.healthRuntimeDigest(ctx, s)
	if err != nil {
		return view, err
	}
	view.Revision = revision
	view.ServicePolicyRevision = s.PolicyRevision
	view.Settings = policy
	view.Settings.Checks = []domain.HTTPCheck{}
	view.Checks = summarizeChecks(policy.Checks)
	view.CurrentReleaseID, err = m.healthReleaseID(ctx, s, st)
	if err != nil {
		return view, err
	}
	if st.CurrentReleaseID != "" && view.CurrentReleaseID == "" {
		view.Warning = "Recovered files do not belong to the immutable release; prepare and build a release before attaching manual evidence"
	}
	view.StateSequence = st.Sequence
	view.RuntimeDigest = digest
	records, err := m.Store.List(ctx, "manual_health", s.ID)
	if err != nil {
		return view, err
	}
	for i := len(records) - 1; i >= 0 && len(view.ManualConfirmations) < 10; i-- {
		var v transport.ManualHealthView
		if err := json.Unmarshal(records[i].Payload, &v); err != nil {
			return view, err
		}
		v = effectiveManual(v, st, digest, time.Now().UTC())
		view.ManualConfirmations = append(view.ManualConfirmations, v)
	}
	return view, nil
}

func (m *Manager) ConfigureHealthChecks(ctx context.Context, id domain.ID, input transport.HealthChecksRequest) (transport.HealthChecksView, error) {
	if err := input.Validate(); err != nil {
		return transport.HealthChecksView{}, err
	}
	if err := input.Actor.Validate(); err != nil {
		return transport.HealthChecksView{}, errors.New("health policy actor is required")
	}
	m.submitMu.Lock()
	defer m.submitMu.Unlock()
	s, err := m.Store.GetService(ctx, id)
	if err != nil {
		return transport.HealthChecksView{}, err
	}
	previous, err := m.healthPolicyMetadata(ctx, s.ID)
	revision := previous.Revision
	if err != nil {
		return transport.HealthChecksView{}, err
	}
	if input.ExpectedRevision != revision {
		return transport.HealthChecksView{}, store.ErrConflict
	}
	policy := input.Policy.Effective()
	data, err := json.Marshal(policy)
	if err != nil {
		return transport.HealthChecksView{}, err
	}
	defer clear(data)
	ref, err := m.Vault.Import(NewID("health-input-"), data)
	if err != nil {
		return transport.HealthChecksView{}, err
	}
	record := healthPolicyRecord{Revision: revision + 1, ServicePolicyRevision: s.PolicyRevision, Input: ref, Actor: input.Actor, CreatedAt: time.Now().UTC()}
	if err := m.Store.SaveHealthRecord(ctx, "health_policy", NewID("health-policy-"), s.ID, s.PolicyRevision, revision, record); err != nil {
		return transport.HealthChecksView{}, err
	}
	return m.HealthChecks(ctx, id)
}

func (m *Manager) ConfirmManualHealth(ctx context.Context, id domain.ID, input transport.ManualHealthRequest) (transport.ManualHealthView, error) {
	out := transport.ManualHealthView{}
	if err := input.Validate(); err != nil {
		return out, err
	}
	if err := input.Actor.Validate(); err != nil {
		return out, errors.New("manual confirmation actor is required")
	}
	m.submitMu.Lock()
	defer m.submitMu.Unlock()
	s, err := m.Store.GetService(ctx, id)
	if err != nil {
		return out, err
	}
	st, err := m.state(ctx, s)
	if err != nil {
		return out, err
	}
	matchedRelease, err := m.healthReleaseID(ctx, s, st)
	if err != nil {
		return out, err
	}
	if matchedRelease == "" {
		return out, errors.New("manual evidence requires an immutable release matching the active file tree")
	}
	digest, running, err := m.healthRuntimeDigest(ctx, s)
	if err != nil {
		return out, err
	}
	if st.CurrentReleaseID != input.ExpectedReleaseID || st.Sequence != input.ExpectedStateSequence || digest != input.ExpectedRuntimeDigest {
		return out, store.ErrConflict
	}
	if input.Healthy && !running {
		return out, errors.New("positive manual confirmation requires the registered container identities to be running")
	}
	now := time.Now().UTC()
	state := domain.HealthUnhealthy
	if input.Healthy {
		state = domain.HealthHealthy
	}
	out = transport.ManualHealthView{ID: NewID("manual-health-"), ServiceID: id, ReleaseID: st.CurrentReleaseID, StateSequence: st.Sequence, RuntimeDigest: digest, Actor: input.Actor, Comment: input.Comment, ObservedAt: now, ValidUntil: now.Add(time.Duration(input.TTLSeconds) * time.Second), State: state}
	if err := m.Store.SaveHealthRecord(ctx, "manual_health", out.ID, id, s.PolicyRevision, 0, out); err != nil {
		return transport.ManualHealthView{}, err
	}
	return out, nil
}
func effectiveManual(v transport.ManualHealthView, st runtimeState, digest domain.Digest, now time.Time) transport.ManualHealthView {
	if v.ReleaseID != st.CurrentReleaseID || v.StateSequence != st.Sequence || v.RuntimeDigest != digest || !now.Before(v.ValidUntil) {
		v.State = domain.HealthStale
	}
	return v
}
func (m *Manager) recordedManualHealth(ctx context.Context, s domain.Service, st runtimeState, signals []domain.HealthSignal) ([]domain.HealthSignal, error) {
	records, err := m.Store.List(ctx, "manual_health", s.ID)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return append(signals, domain.HealthSignal{Source: domain.HealthManual, State: domain.HealthNotConfigured}), nil
	}
	var latest transport.ManualHealthView
	if err := json.Unmarshal(records[len(records)-1].Payload, &latest); err != nil {
		return nil, err
	}
	digest, _, err := m.healthRuntimeDigest(ctx, s)
	if err != nil {
		return append(signals, domain.HealthSignal{Source: domain.HealthManual, State: domain.HealthUnknown, Reason: "current runtime unavailable"}), nil
	}
	latest = effectiveManual(latest, st, digest, time.Now().UTC())
	return append(signals, domain.HealthSignal{Source: domain.HealthManual, State: latest.State, ObservedAt: latest.ObservedAt, ValidUntil: latest.ValidUntil, Reason: "manual confirmation by " + string(latest.Actor) + "; independent of automatic checks"}), nil
}
