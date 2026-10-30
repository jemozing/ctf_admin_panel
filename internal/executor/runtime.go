package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/filesystem"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"github.com/moby/moby/client"
)

// State is an append-only executor observation. It is separate from registration
// policy and advances only under the durable service lock held by the worker.
type runtimeState struct {
	PolicyRevision   uint64                `json:"policy_revision"`
	Sequence         uint64                `json:"sequence"`
	ServiceID        domain.ID             `json:"service_id"`
	CurrentReleaseID domain.ID             `json:"current_release_id,omitempty"`
	ActiveSnapshotID domain.ID             `json:"active_snapshot_id,omitempty"`
	BaselineID       domain.ID             `json:"baseline_id,omitempty"`
	CandidateID      domain.ID             `json:"candidate_id,omitempty"`
	Containers       []domain.ContainerRef `json:"containers"`
}

func (m *Manager) state(ctx context.Context, s domain.Service) (runtimeState, error) {
	state := runtimeState{ServiceID: s.ID, PolicyRevision: s.PolicyRevision, Containers: append([]domain.ContainerRef{}, s.Containers...)}
	records, err := m.Store.List(ctx, "runtime_state", s.ID)
	if err != nil {
		return state, err
	}
	for _, record := range records {
		var v runtimeState
		if err := json.Unmarshal(record.Payload, &v); err != nil {
			return state, err
		}
		if v.ServiceID != s.ID {
			return state, errors.New("state service mismatch")
		}
		if v.Sequence > state.Sequence {
			state = v
		}
	}
	if state.PolicyRevision > 0 && state.PolicyRevision != s.PolicyRevision {
		state = runtimeState{Sequence: state.Sequence, ServiceID: s.ID, PolicyRevision: s.PolicyRevision, Containers: append([]domain.ContainerRef{}, s.Containers...)}
	}
	return state, nil
}
func (m *Manager) saveState(ctx context.Context, s *runtimeState) error {
	s.Sequence++
	return m.Store.PutImmutable(ctx, "runtime_state", NewID("state-"), s.ServiceID, *s)
}
func (m *Manager) ListServices(ctx context.Context) ([]domain.Service, error) {
	services, err := m.Store.ListServices(ctx)
	for i := range services {
		services[i].Checks = nil
	}
	return services, err
}
func (m *Manager) ListOperations(ctx context.Context) ([]domain.Operation, error) {
	operations, err := m.Store.ListOperations(ctx)
	if err == nil {
		err = m.observeOperationQueue(ctx, operations)
	}
	return operations, err
}
func (m *Manager) GetOperation(ctx context.Context, id domain.ID) (domain.Operation, error) {
	op, err := m.Store.GetOperation(ctx, id)
	if err != nil || op.State != domain.OperationQueued {
		return op, err
	}
	operations, err := m.ListOperations(ctx)
	if err != nil {
		return op, err
	}
	for _, value := range operations {
		if value.Spec.ID == id {
			return value, nil
		}
	}
	return op, nil
}
func (m *Manager) OperationEvents(ctx context.Context, id domain.ID) ([]store.Event, error) {
	if _, err := m.Store.GetOperation(ctx, id); err != nil {
		return nil, err
	}
	return m.Store.Events(ctx, id)
}
func (m *Manager) ServiceDetails(ctx context.Context, id domain.ID) (transport.ServiceDetails, error) {
	result := transport.ServiceDetails{Releases: []domain.Release{}, Snapshots: []transport.SnapshotSummary{}, Health: []domain.HealthSignal{}, Capabilities: map[string]bool{}}
	s, err := m.Store.GetService(ctx, id)
	if err != nil {
		return result, err
	}
	result.Service = s
	result.Service.Checks = nil
	st, err := m.state(ctx, s)
	if err != nil {
		return result, err
	}
	result.CurrentReleaseID = st.CurrentReleaseID
	result.CandidateID = st.CandidateID
	result.Containers, err = m.Engine.Inventory(ctx, s.ComposeProject)
	if err != nil {
		return result, err
	}
	checks := []struct{ state, health string }{}
	for _, c := range result.Containers {
		checks = append(checks, struct{ state, health string }{c.State, c.Health})
	}
	result.Health = healthSignals(checks)
	result.Health, err = m.recordedChecks(ctx, s, st, result.Health)
	if err != nil {
		return result, err
	}
	result.ObservedState = "registered"
	if st.CurrentReleaseID != "" {
		result.ObservedState = "observed"
	}
	for _, c := range result.Containers {
		if c.State != "running" {
			result.ObservedState = "stopped_or_partial"
		}
	}
	for _, kind := range []string{"release", "snapshot"} {
		records, err := m.Store.List(ctx, kind, s.ID)
		if err != nil {
			return result, err
		}
		for _, r := range records {
			tombstone := "deleted_snapshot"
			if kind == "release" {
				tombstone = "retired_release"
			}
			retired, err := m.isRetired(ctx, tombstone, r.ID)
			if err != nil {
				return result, err
			}
			if retired {
				continue
			}
			if kind == "release" {
				var v domain.Release
				if err := json.Unmarshal(r.Payload, &v); err != nil {
					return result, err
				}
				result.Releases = append(result.Releases, v)
			} else {
				var v domain.Snapshot
				if err := json.Unmarshal(r.Payload, &v); err != nil {
					return result, err
				}
				result.Snapshots = append(result.Snapshots, transport.SnapshotSummary{ID: v.ID, Purpose: v.Purpose, CreatedAt: v.CreatedAt, TreeDigest: v.ManifestDigest, Bytes: v.Manifest.TotalBytes(), GitSource: v.GitSource})
			}
		}
	}
	for _, a := range []string{"snapshot", "start", "stop", "restart"} {
		result.Capabilities[a] = a == "snapshot" || st.BaselineID != ""
	}
	initialized, err := m.registrationInitialized(ctx, s, st.BaselineID)
	if err != nil {
		return result, err
	}
	result.Capabilities["prepare"] = initialized
	source, err := m.GitSource(ctx, s.ID)
	if err != nil {
		return result, err
	}
	result.Capabilities["fetch_source"] = initialized && source.Configured
	result.Capabilities["build"] = initialized && st.CandidateID != ""
	result.Capabilities["deploy"] = len(result.Releases) > 0
	result.Capabilities["rollback"] = len(result.Releases) > 1
	ops, err := m.Store.ListOperations(ctx)
	if err != nil {
		return result, err
	}
	for _, op := range ops {
		if op.Spec.ServiceID == s.ID && (op.State == domain.OperationInterrupted || op.State == domain.OperationRequiresRecovery) {
			result.ObservedState = string(op.State)
			for a := range result.Capabilities {
				result.Capabilities[a] = false
			}
			result.Capabilities["recover"] = true
		}
	}
	m.detailObservations(ctx, s, st, &result)
	return result, nil
}
func (m *Manager) Logs(ctx context.Context, id domain.ID, component string, tail int) (transport.LogResult, error) {
	result := transport.LogResult{}
	if tail < 1 || tail > 500 {
		return result, errors.New("invalid tail limit")
	}
	s, err := m.Store.GetService(ctx, id)
	if err != nil {
		return result, err
	}
	redact, err := m.displayRedactor(ctx, s)
	if err != nil {
		return result, err
	}
	items, err := m.Engine.Inventory(ctx, s.ComposeProject)
	if err != nil {
		return result, err
	}
	known := false
	for _, c := range s.Containers {
		known = known || c.Component == component
	}
	if !known {
		return result, errors.New("component is outside service policy")
	}
	for _, c := range items {
		if c.Component != component {
			continue
		}
		res, err := m.Engine.Client.ContainerLogs(ctx, c.ID, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Tail: strconv.Itoa(tail)})
		if err != nil {
			return result, err
		}
		defer res.Close()
		limited := &boundedBuffer{limit: 1 << 20}
		_, err = copyDockerLogs(limited, limited, io.LimitReader(res, (1<<20)+65536))
		if err != nil && !limited.truncated {
			return result, errors.New("container log stream unavailable")
		}
		if limited.truncated {
			limited.data = completeLogPrefix(limited.data)
		}
		result.Content = safeLogTextForFile(redact(string(limited.data)))
		result.Truncated = limited.truncated
		return result, nil
	}
	return result, store.ErrNotFound
}
func (m *Manager) Preview(ctx context.Context, req transport.SubmitRequest) (transport.PreviewResult, error) {
	result := transport.PreviewResult{ServiceID: req.ServiceID, Action: req.Action, Targets: []string{}, ChangedFiles: []transport.FileChange{}}
	s, err := m.Store.GetService(ctx, req.ServiceID)
	if err != nil {
		return result, err
	}
	st, err := m.state(ctx, s)
	if err != nil {
		return result, err
	}
	checkPolicy, checkRevision, err := m.healthPolicy(ctx, s)
	if err != nil {
		return result, err
	}
	result.HealthCheckRevision = checkRevision
	result.CheckSummaries = summarizeChecks(checkPolicy.Checks)
	checkPolicy.Checks = nil
	result.HealthSettings = checkPolicy
	result.Targets = append(result.Targets, s.Targets...)
	sort.Strings(result.Targets)
	result.PolicyRevision = s.PolicyRevision
	result.ActiveReleaseID = st.CurrentReleaseID
	result.CandidateID = st.CandidateID
	result.HasRollback = st.CurrentReleaseID != ""
	manifest, err := filesystem.Observe(ctx, s.ProjectDirectory, s.ManagedPaths, nil)
	if err != nil {
		return result, err
	}
	result.CurrentTreeDigest = manifest.Digest()
	if req.Action == domain.OperationPrepare || req.Action == domain.OperationFetchSource || req.Action == domain.OperationBuild || req.Action == domain.OperationRestoreSnapshot {
		initialized, err := m.registrationInitialized(ctx, s, st.BaselineID)
		if err != nil {
			return result, err
		}
		if !initialized {
			return result, errors.New("complete source workspace initialization with Snapshot before preparing, fetching or building a candidate")
		}
	}
	var target domain.Manifest
	switch req.Action {
	case domain.OperationRestoreSnapshot:
		var source domain.Snapshot
		source, err = m.snapshotCandidateSource(ctx, s, req.SnapshotID)
		target = source.Manifest
		result.SnapshotID = req.SnapshotID
	case domain.OperationSnapshot:
	case domain.OperationStart, domain.OperationStop, domain.OperationRestart:
		if st.BaselineID == "" {
			return result, errors.New("create the baseline snapshot before lifecycle operations")
		}
	case domain.OperationPrepare:
		if st.BaselineID == "" {
			return result, errors.New("create the baseline snapshot first")
		}
		target, err = filesystem.Observe(ctx, s.SourceDirectory, s.ManagedPaths, nil)
	case domain.OperationFetchSource:
		if st.BaselineID == "" {
			return result, errors.New("create the baseline snapshot first")
		}
		source, sourceErr := m.GitSource(ctx, s.ID)
		if sourceErr != nil {
			return result, sourceErr
		}
		if !source.Configured {
			return result, errors.New("configure a Git source first")
		}
		result.GitSource = &source
		// Remote branch changes are intentionally resolved by the durable fetch.
		// The preview binds source configuration, not a promised remote tree.
	case domain.OperationBuild:
		id := req.CandidateID
		if id == "" {
			id = st.CandidateID
		}
		if id == "" {
			return result, errors.New("prepare an immutable source candidate first")
		}
		var snap domain.Snapshot
		snap, err = m.loadSnapshot(ctx, id)
		if err == nil && (snap.ServiceID != s.ID || snap.Purpose != domain.SnapshotCandidate) {
			err = errors.New("invalid source candidate")
		}
		target = snap.Manifest
		result.CandidateID = id
	case domain.OperationRecover:
		return m.previewRecovery(ctx, s, st, req, manifest)
	case domain.OperationDeploy, domain.OperationRollback:
		if st.ActiveSnapshotID != "" {
			active, activeErr := m.loadSnapshot(ctx, st.ActiveSnapshotID)
			if activeErr != nil {
				return result, activeErr
			}
			result.ActiveFileDrift = manifest.Digest() != active.ManifestDigest
			if result.ActiveFileDrift {
				result.DriftChangedFiles = manifestDiff(active.Manifest, manifest)
			}
			result.AcceptedFileDrift = result.ActiveFileDrift && req.AcceptFileDrift
		}
		var release domain.Release
		release, err = m.loadRelease(ctx, s, req.ReleaseID)
		if err != nil {
			break
		}
		spec := release.Spec()
		result.TargetReleaseID = spec.ID
		result.Images = spec.Images
		var snap domain.Snapshot
		snap, err = m.loadSnapshot(ctx, spec.SnapshotID)
		target = snap.Manifest
		for _, d := range s.DataPaths {
			result.DataCompatibilityRequired = result.DataCompatibilityRequired || d.Significant
		}
	default:
		return result, errors.New("operation is not enabled in this stage")
	}
	if err != nil {
		return result, err
	}
	if req.Action == domain.OperationPrepare || req.Action == domain.OperationBuild || req.Action == domain.OperationDeploy || req.Action == domain.OperationRollback || req.Action == domain.OperationRestoreSnapshot {
		result.ChangedFiles = manifestDiff(manifest, target)
	}
	// The digest binds concrete file trees, targets, release and policy revision.
	// It does not bind request IDs or checkbox state, allowing safe idempotent retry.
	data, _ := json.Marshal(struct {
		Plan     transport.PreviewResult
		Sequence uint64
		Target   domain.Digest
	}{result, st.Sequence, target.Digest()})
	result.PlanDigest = domain.Hash(data)
	// Capacity changes with monitoring/journal writes. It is display evidence,
	// never part of the reviewed plan hash; actual quotas are checked by the job.
	result.Space = m.previewSpace(req.Action, manifest, target)
	return result, nil
}
func manifestDiff(from, to domain.Manifest) []transport.FileChange {
	result := []transport.FileChange{}
	old := map[string]domain.ManifestEntry{}
	for _, e := range from.Entries() {
		old[e.Path] = e
	}
	for _, e := range to.Entries() {
		previous, exists := old[e.Path]
		delete(old, e.Path)
		if !exists {
			result = append(result, transport.FileChange{Path: e.Path, Change: "added"})
		} else {
			a, _ := json.Marshal(previous)
			b, _ := json.Marshal(e)
			if string(a) != string(b) {
				result = append(result, transport.FileChange{Path: e.Path, Change: "modified"})
			}
		}
	}
	for p := range old {
		result = append(result, transport.FileChange{Path: p, Change: "deleted"})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result
}
func (m *Manager) loadRelease(ctx context.Context, s domain.Service, id domain.ID) (domain.Release, error) {
	var r domain.Release
	retired, err := m.isRetired(ctx, "retired_release", id)
	if err != nil {
		return r, err
	}
	if retired {
		return r, store.ErrNotFound
	}
	if err := m.Store.Get(ctx, "release", id, &r); err != nil {
		return r, err
	}
	v := r.Spec()
	if v.ServiceID != s.ID || v.PolicyRevision != s.PolicyRevision || v.FileMapRevision != s.FileMapRevision {
		return r, errors.New("release does not match current approved policy")
	}
	return r, nil
}
func (m *Manager) verifyRuntime(ctx context.Context, s domain.Service, st runtimeState, model map[string]any) ([]docker.Container, error) {
	if err := m.applyRuntimePorts(ctx, s, model); err != nil {
		return nil, err
	}
	actual, err := m.Engine.Inventory(ctx, s.ComposeProject)
	if err != nil {
		return nil, err
	}
	if len(actual) != len(st.Containers) {
		return nil, errors.New("runtime component count drift")
	}
	for _, ref := range st.Containers {
		found := false
		for _, c := range actual {
			if c.Component != ref.Component {
				continue
			}
			if c.ID != ref.ID || c.ImageID != string(ref.ImageID) {
				return nil, errors.New("runtime container/image identity drift")
			}
			if issues := c.RuntimeIssues(model, s.ComposeProject); len(issues) > 0 {
				return nil, fmt.Errorf("runtime configuration drift in %s (%s)", c.Component, issues[0].Code)
			}
			found = true
		}
		if !found {
			return nil, errors.New("registered runtime component missing")
		}
	}
	return actual, nil
}

type boundedBuffer struct {
	data      []byte
	limit     int
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - len(b.data)
	if n > remaining {
		b.truncated = true
		p = p[:remaining]
	}
	b.data = append(b.data, p...)
	return n, nil
}
func (m *Manager) event(ctx context.Context, id domain.ID, kind, message string) error {
	return m.Store.AppendEvent(ctx, store.Event{OperationID: id, At: time.Now().UTC(), Kind: kind, Message: message})
}
func hasTarget(s domain.Service, name string) bool {
	for _, v := range s.Targets {
		if v == name {
			return true
		}
	}
	return false
}
func retentionTag(s domain.Service, release domain.ID, component string) string {
	return "ctf-manager/" + string(s.ID) + ":" + string(release) + "-" + component
}
func dataReferences(s domain.Service) []domain.DataReference {
	out := []domain.DataReference{}
	for _, v := range s.DataPaths {
		if !v.Significant {
			continue
		}
		identity := string(v.Kind) + ":" + v.Source + ":" + v.Target
		out = append(out, domain.DataReference{Name: v.Name, Identity: identity, Compatibility: domain.DataUnconfirmed, Evidence: "application compatibility must be reviewed before switching; persistent data is excluded from file rollback"})
	}
	return out
}
func redact(data string, values []string) string {
	for _, value := range values {
		if value != "" {
			data = strings.ReplaceAll(data, value, "[redacted]")
		}
	}
	return data
}
