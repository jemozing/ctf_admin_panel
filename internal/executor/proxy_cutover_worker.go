package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	proxyengine "github.com/ctf-service-manager/ctf-service-manager/internal/proxy"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

type cutoverRuntimeDriver interface {
	Inventory(context.Context, string) ([]docker.Container, error)
	Recreate(context.Context, domain.Service, map[string]any, string) error
	Verify(context.Context, domain.Service, []docker.Container, []docker.Container, string, map[string]any) ([]domain.ContainerRef, error)
	Health(context.Context, domain.Service) error
}

type dockerCutoverDriver struct{ m *Manager }

func (d dockerCutoverDriver) Inventory(ctx context.Context, p string) ([]docker.Container, error) {
	return d.m.Engine.Inventory(ctx, p)
}
func (d dockerCutoverDriver) Recreate(ctx context.Context, s domain.Service, model map[string]any, component string) error {
	d.m.pauseCapture(ctx)
	// One explicitly selected target and --no-deps are enforced by ComposeAction.
	// No down, volume removal, build, pull or source-tree mutation is performed.
	output := &boundedBuffer{limit: 65536}
	return docker.ComposeAction(ctx, d.m.Config, s.ComposeProject, s.ProjectDirectory, model, "up", []string{component}, output)
}
func (d dockerCutoverDriver) Verify(ctx context.Context, s domain.Service, before, after []docker.Container, component string, model map[string]any) ([]domain.ContainerRef, error) {
	return cutoverVerifyContainers(s, before, after, component, model)
}
func (d dockerCutoverDriver) Health(ctx context.Context, s domain.Service) error {
	if err := d.m.warmupObserved(ctx, s); err != nil {
		return err
	}
	policy, revision, err := d.m.healthPolicy(ctx, s)
	if err != nil {
		return err
	}
	checkCtx, cancel := context.WithTimeout(ctx, time.Duration(policy.OverallTimeoutSeconds)*time.Second)
	defer cancel()
	signals := []domain.HealthSignal{}
	failed := false
	for _, check := range policy.Checks {
		signal := retryProbe(checkCtx, check, policy)
		signals = append(signals, signal)
		failed = failed || signal.State != domain.HealthHealthy
	}
	if err = d.m.Store.PutImmutable(ctx, "proxy_cutover_checks", NewID("cutover-check-"), s.ID, struct {
		Revision uint64                `json:"revision"`
		Signals  []domain.HealthSignal `json:"signals"`
	}{revision, signals}); err != nil {
		return err
	}
	if failed {
		return errors.New("configured local check failed after port transfer")
	}
	return nil
}
func (m *Manager) cutoverDriver() cutoverRuntimeDriver {
	if m.cutoverRuntime != nil {
		return m.cutoverRuntime
	}
	return dockerCutoverDriver{m}
}

func cutoverBaseline(p proxyCutoverProposal) []docker.Container {
	if len(p.RecoveryBaseline) != 0 {
		return p.RecoveryBaseline
	}
	return p.Containers
}

func (m *Manager) cutoverOutcome(record *proxyCutoverRecord, state, stage, message string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = m.saveCutover(ctx, record, state, stage, message)
}

func (m *Manager) launchCutover(p proxyCutoverProposal, record proxyCutoverRecord) {
	base := m.cutoverCtx
	if base == nil {
		base = context.Background()
	}
	m.cutoverWG.Add(1)
	go func() {
		defer m.cutoverWG.Done()
		ctx, cancel := context.WithTimeout(base, 5*time.Minute)
		defer cancel()
		// TryLock avoids reversing artifact -> submit used by retention. The
		// durable queued guard already prevents any new service operation.
		for {
			m.proxyMu.Lock()
			m.registrationMu.Lock()
			m.submitMu.Lock()
			if m.artifactMu.TryLock() {
				break
			}
			m.submitMu.Unlock()
			m.registrationMu.Unlock()
			m.proxyMu.Unlock()
			select {
			case <-ctx.Done():
				m.proxyMu.Lock()
				m.cutoverOutcome(&record, "requires_recovery", "interrupted", "Transfer did not acquire the executor gate; review a new return plan")
				m.proxyMu.Unlock()
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
		defer m.artifactMu.Unlock()
		defer m.submitMu.Unlock()
		defer m.registrationMu.Unlock()
		defer m.proxyMu.Unlock()
		unlock, err := proxyengine.LockPolicyDirectory(m.Config.Proxy.PolicyDirectory)
		if err != nil {
			m.cutoverOutcome(&record, "requires_recovery", "policy_lock_unavailable", "Proxy policy lock unavailable; review recovery")
			return
		}
		defer unlock()
		if err = m.cutoverFresh(ctx, p); err != nil {
			state := "failed"
			if p.Mode == "return" {
				state = "requires_recovery"
			}
			m.cutoverOutcome(&record, state, "stale", err.Error())
			return
		}
		if p.Mode == "return" {
			err = m.runCutoverReturn(ctx, p, &record)
		} else {
			err = m.runCutoverForward(ctx, p, &record)
		}
		if err == nil {
			return
		}
		if p.Mode == "cutover" && !record.mutationAttempted {
			// A failed intent write must never trigger a compensating container
			// command: no runtime mutation was attempted in the first place.
			m.cutoverOutcome(&record, "failed", "validation_failed", err.Error())
			return
		}
		// Cancellation/unknown external policy never causes an unchecked retry.
		recoverCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
		defer stop()
		if p.Mode == "cutover" && record.Stage != "queued" && record.Stage != "validated" {
			if restoreErr := m.compensateCutover(recoverCtx, p, &record); restoreErr == nil {
				m.cutoverOutcome(&record, "rolled_back", "original_runtime_restored", "Transfer failed; original bindings restored: "+err.Error())
				return
			}
		}
		m.cutoverOutcome(&record, "requires_recovery", "reconciliation_required", "Transfer incomplete; review actual runtime before returning ports: "+err.Error())
	}()
}

func (m *Manager) cutoverModel(ctx context.Context, p proxyCutoverProposal, ports []map[string]any) (domain.Service, runtimeState, map[string]any, error) {
	s, err := m.Store.GetService(ctx, p.ServiceID)
	if err != nil {
		return s, runtimeState{}, nil, err
	}
	st, err := m.state(ctx, s)
	if err != nil {
		return s, st, nil, err
	}
	if s.PolicyRevision != p.PolicyRevision || st.CurrentReleaseID != p.CurrentReleaseID {
		return s, st, nil, errors.New("service release changed during port transfer")
	}
	c, err := m.LoadConfiguration(ctx, p.ConfigurationDigest)
	if err != nil {
		return s, st, nil, err
	}
	model, err := m.materializedConfiguration(c)
	if err != nil {
		return s, st, nil, err
	}
	release, err := m.loadRelease(ctx, s, st.CurrentReleaseID)
	if err != nil {
		return s, st, nil, err
	}
	pinModelImages(model, release.Spec().Images)
	services, _ := model["services"].(map[string]any)
	component, _ := services[p.Component].(map[string]any)
	if component == nil {
		return s, st, nil, errors.New("application component missing from frozen configuration")
	}
	component["ports"] = cutoverPortValues(ports)
	return s, st, model, nil
}

func (m *Manager) commitCutoverOverlay(ctx context.Context, p proxyCutoverProposal, active bool, st *runtimeState, refs []domain.ContainerRef) error {
	// Legacy test/one-target entrypoint. Group workers commit observed per-entry
	// state instead of publishing a final overlay before the group has moved.
	entries, err := cutoverProposalEntries(p)
	if err != nil {
		return err
	}
	for i := range entries {
		entries[i].Active = active
	}
	return m.commitCutoverEntries(ctx, p, entries, st, refs)
}
func (m *Manager) commitCutoverEntries(ctx context.Context, p proxyCutoverProposal, entries []runtimePortOverlayEntry, st *runtimeState, refs []domain.ContainerRef) error {
	old, err := m.runtimePortOverlay(ctx, p.ServiceID)
	if err != nil {
		return err
	}
	active := false
	for _, entry := range entries {
		active = active || entry.Active
	}
	v := runtimePortOverlay{SchemaVersion: 2, Entries: entries, ServiceID: p.ServiceID, PolicyRevision: p.PolicyRevision, ConfigurationDigest: p.ConfigurationDigest, Sequence: old.Sequence + 1, CutoverID: p.CutoverID, Active: active}
	if len(entries) == 1 {
		v.Component = entries[0].Component
		v.Original = entries[0].Original
		v.Replacement = entries[0].Replacement
	}
	encoded, err := json.Marshal(struct {
		Overlay runtimePortOverlay
		State   runtimeState
	}{v, *st})
	if err != nil {
		return err
	}
	if err = m.checkLocalAllocation(ctx, m.Config.StateDirectory, uint64(len(encoded)+16384), 3, m.Config.Storage.Effective().StateMaxBytes); err != nil {
		return err
	}
	if err = m.Store.PutImmutable(ctx, "runtime_port_overlay", domain.ID(string(domain.Hash([]byte(fmt.Sprintf("runtime-ports:%s:%020d", p.ServiceID, v.Sequence))))[7:]), p.ServiceID, v); err != nil {
		return err
	}
	st.Containers = refs
	return m.saveState(ctx, st)
}

func (m *Manager) publishCutoverPolicy(ctx context.Context, p proxyCutoverProposal, policy proxyengine.Policy, record *proxyCutoverRecord) error {
	latest, _, _, err := m.effectiveProxyRevision(ctx)
	if err != nil {
		return err
	}
	if latest.Policy.Revision != policy.Revision-1 {
		return errors.New("proxy policy revision changed during transfer")
	}
	r := proxyRevision{Policy: policy, ProposalID: p.ProposalID, Digest: p.Digest, Actor: p.Actor, At: time.Now().UTC()}
	if err = m.Store.PutImmutable(ctx, "proxy_revision", domain.ID(fmt.Sprintf("proxy-policy-%020d", policy.Revision)), "proxy", r); err != nil {
		return err
	}
	record.ProxyRevision = policy.Revision
	if err = m.saveCutover(ctx, record, "running", "proxy_policy_committed", ""); err != nil {
		return err
	}
	if err = m.exportProxyPolicy(policy); err != nil {
		return err
	}
	return m.waitCutoverPolicy(ctx, policy, record)
}

func (m *Manager) waitCutoverPolicy(ctx context.Context, policy proxyengine.Policy, record *proxyCutoverRecord) error {
	wait, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		var status proxyengine.Status
		if err := m.proxyRPC(wait, "GET", "/v1/status", nil, &status); err == nil {
			if status.AppliedRevision == policy.Revision && status.PolicyDigest == string(proxyengine.PolicyDigest(policy)) {
				record.AppliedRevision = status.AppliedRevision
				return m.saveCutover(ctx, record, "running", "proxy_applied", "")
			}
			if status.AppliedRevision > policy.Revision {
				return errors.New("a newer external proxy policy became active")
			}
		}
		select {
		case <-wait.Done():
			return errors.New("exact proxy revision was not observed active before timeout")
		case <-ticker.C:
		}
	}
}

func (m *Manager) runCutoverForward(ctx context.Context, p proxyCutoverProposal, record *proxyCutoverRecord) error {
	if err := m.saveCutover(ctx, record, "running", "validated", ""); err != nil {
		return err
	}
	var preflight any
	if err := m.proxyRPC(ctx, "POST", "/v1/preflight-cutover", proxyengine.CutoverPreflightRequest{Policy: p.Policy, ReleasedListeners: p.OriginalBindings, PendingUpstreams: cutoverPrivateOrigins(p)}, &preflight); err != nil {
		return err
	}
	if err := m.cutoverFresh(ctx, p); err != nil {
		return err
	}
	if err := m.preflightCutoverHTTP2(ctx, p.Policy, p.Targets); err != nil {
		return err
	}
	if err := m.moveCutoverComponents(ctx, p, record, true); err != nil {
		return err
	}
	if err := m.proxyRPC(ctx, "POST", "/v1/preflight", p.Policy, &preflight); err != nil {
		return err
	}
	if err := m.publishCutoverPolicy(ctx, p, p.Policy, record); err != nil {
		return err
	}
	s, err := m.Store.GetService(ctx, p.ServiceID)
	if err != nil {
		return err
	}
	if err = m.cutoverDriver().Health(ctx, s); err != nil {
		return err
	}
	record.ActiveComponent = ""
	return m.saveCutover(ctx, record, "active", "checks_complete", "")
}

// Reconcile chooses one complete known port shape per selected component. It
// never accepts a mixture of original/private target ports inside one app.
func (m *Manager) cutoverReconcile(ctx context.Context, p proxyCutoverProposal, actual []docker.Container) error {
	s, _, model, _, err := m.cutoverMixedModel(ctx, p, actual, "", nil)
	if err != nil {
		return err
	}
	_, err = m.verifyCutoverGroup(ctx, s, cutoverBaseline(p), actual, cutoverComponents(p), model)
	return err
}

func cutoverPrivatePorts(p proxyCutoverProposal) []int {
	entries, _ := cutoverProposalEntries(p)
	out := []int{}
	for _, entry := range entries {
		for _, port := range entry.Replacement {
			n, e := cutoverPortNumber(port["published"])
			if e == nil {
				out = append(out, n)
			}
		}
	}
	return out
}
func cutoverPrivateOrigins(p proxyCutoverProposal) []string {
	out := []string{}
	for _, port := range cutoverPrivatePorts(p) {
		out = append(out, "http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	}
	return out
}

// Mixed model is constructed only from frozen inputs and independently known
// whole-component shapes. It keeps nonselected settings/images unchanged.
func (m *Manager) cutoverMixedModel(ctx context.Context, p proxyCutoverProposal, actual []docker.Container, change string, ports []map[string]any) (domain.Service, runtimeState, map[string]any, []runtimePortOverlayEntry, error) {
	entries, err := cutoverProposalEntries(p)
	if err != nil {
		return domain.Service{}, runtimeState{}, nil, nil, err
	}
	s, st, model, err := m.cutoverBaseModel(ctx, p)
	if err != nil {
		return s, st, nil, nil, err
	}
	services, _ := model["services"].(map[string]any)
	observed := map[string]docker.Container{}
	for _, c := range actual {
		if _, ok := observed[c.Component]; ok {
			return s, st, nil, nil, errors.New("duplicate component prevents port reconciliation")
		}
		observed[c.Component] = c
	}
	for i := range entries {
		entry := &entries[i]
		entry.Active = false
		if c, ok := observed[entry.Component]; ok {
			if cutoverContainerPortsEqual(c, entry.Original) {
			} else if cutoverContainerPortsEqual(c, entry.Replacement) {
				entry.Active = true
			} else {
				return s, st, nil, nil, errors.New("unknown or mixed application publication prevents port recovery")
			}
		}
		component, ok := services[entry.Component].(map[string]any)
		if !ok {
			return s, st, nil, nil, errors.New("selected application disappeared from approved configuration")
		}
		value := entry.Original
		if entry.Active {
			value = entry.Replacement
		}
		if entry.Component == change {
			value = ports
			entry.Active = reflect.DeepEqual(ports, entry.Replacement)
		}
		component["ports"] = cutoverPortValues(value)
	}
	return s, st, model, entries, nil
}

func (m *Manager) cutoverBaseModel(ctx context.Context, p proxyCutoverProposal) (domain.Service, runtimeState, map[string]any, error) {
	s, err := m.Store.GetService(ctx, p.ServiceID)
	if err != nil {
		return s, runtimeState{}, nil, err
	}
	st, err := m.state(ctx, s)
	if err != nil {
		return s, st, nil, err
	}
	if s.PolicyRevision != p.PolicyRevision || st.CurrentReleaseID != p.CurrentReleaseID {
		return s, st, nil, errors.New("service release changed during port transfer")
	}
	c, err := m.LoadConfiguration(ctx, p.ConfigurationDigest)
	if err != nil {
		return s, st, nil, err
	}
	model, err := m.materializedConfiguration(c)
	if err != nil {
		return s, st, nil, err
	}
	release, err := m.loadRelease(ctx, s, st.CurrentReleaseID)
	if err != nil {
		return s, st, nil, err
	}
	pinModelImages(model, release.Spec().Images)
	return s, st, model, nil
}

// Every component has its own fsynced intent, fresh before-check, recreation,
// observed runtime/state publication and progress event. Unknown partial shapes
// stay blocked; no step is blindly replayed after a restart.
func (m *Manager) moveCutoverComponents(ctx context.Context, p proxyCutoverProposal, record *proxyCutoverRecord, private bool) error {
	entries, err := cutoverProposalEntries(p)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Component < entries[j].Component })
	s, err := m.Store.GetService(ctx, p.ServiceID)
	if err != nil {
		return err
	}
	checkpoint, err := m.cutoverDriver().Inventory(ctx, s.ComposeProject)
	if err != nil {
		return err
	}
	if private {
		st, e := m.state(ctx, s)
		if e != nil {
			return e
		}
		if cutoverRuntimeDigest(checkpoint) != p.RuntimeDigest || st.Sequence != p.StateSequence {
			return errors.New("runtime changed before the first component mutation")
		}
		if e = cutoverExactIdentities(st, checkpoint); e != nil {
			return e
		}
	}
	if err = m.cutoverReconcile(ctx, p, checkpoint); err != nil {
		return err
	}
	record.CompletedComponents = nil
	for _, entry := range entries {
		fresh, e := m.cutoverDriver().Inventory(ctx, s.ComposeProject)
		if e != nil {
			return e
		}
		if cutoverStepDigest(fresh) != cutoverStepDigest(checkpoint) {
			return errors.New("runtime changed between component transfer steps")
		}
		_, _, beforeModel, _, e := m.cutoverMixedModel(ctx, p, fresh, "", nil)
		if e != nil {
			return e
		}
		if _, e = m.cutoverDriver().Verify(ctx, s, fresh, fresh, "", beforeModel); e != nil {
			return e
		}
		desired := entry.Original
		if private {
			desired = entry.Replacement
		}

		alreadyDesired := false
		for _, current := range fresh {
			if current.Component == entry.Component {
				alreadyDesired = cutoverContainerPortsEqual(current, desired)
			}
		}
		if alreadyDesired {
			_, st, _, overlay, e := m.cutoverMixedModel(ctx, p, fresh, "", nil)
			if e != nil {
				return e
			}
			refs, e := m.verifyCutoverGroup(ctx, s, cutoverBaseline(p), fresh, cutoverComponents(p), beforeModel)
			if e != nil {
				return e
			}
			if e = m.commitCutoverEntries(ctx, p, overlay, &st, refs); e != nil {
				return e
			}
			record.CompletedComponents = append(record.CompletedComponents, entry.Component)
			record.ActiveComponent = ""
			if e = m.saveCutover(ctx, record, "running", "component_already_observed", ""); e != nil {
				return e
			}
			continue
		}
		_, st, model, overlay, e := m.cutoverMixedModel(ctx, p, fresh, entry.Component, desired)
		if e != nil {
			return e
		}
		// Only the current component may change its ID in this step; a missing
		// selected app obtains image/mount proof from the reviewed recovery baseline.
		before := append([]docker.Container{}, fresh...)
		found := false
		for _, c := range before {
			found = found || c.Component == entry.Component
		}
		if !found {
			for _, c := range cutoverBaseline(p) {
				if c.Component == entry.Component {
					before = append(before, c)
					found = true
					break
				}
			}
		}
		if !found {
			return errors.New("missing application has no approved recovery evidence")
		}
		record.ActiveComponent = entry.Component
		stage := "original_runtime_mutation_started"
		if private {
			stage = "mutation_started"
		}
		if e = m.saveCutover(ctx, record, "running", stage, ""); e != nil {
			return e
		}
		record.mutationAttempted = true
		composeErr := m.cutoverDriver().Recreate(ctx, s, model, entry.Component)
		observeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		observed, observeErr := m.cutoverDriver().Inventory(observeCtx, s.ComposeProject)
		cancel()
		if composeErr != nil || observeErr != nil {
			return errors.Join(composeErr, observeErr)
		}
		refs, e := m.cutoverDriver().Verify(ctx, s, before, observed, entry.Component, model)
		if e != nil {
			return e
		}
		if e = m.commitCutoverEntries(ctx, p, overlay, &st, refs); e != nil {
			return e
		}
		checkpoint = observed
		record.CompletedComponents = append(record.CompletedComponents, entry.Component)
		stage = "original_component_observed"
		if private {
			stage = "private_runtime_observed"
		}
		if e = m.saveCutover(ctx, record, "running", stage, ""); e != nil {
			return e
		}
	}
	record.ActiveComponent = ""
	return nil
}

func (m *Manager) compensateCutover(ctx context.Context, p proxyCutoverProposal, record *proxyCutoverRecord) error {
	s, err := m.Store.GetService(ctx, p.ServiceID)
	if err != nil {
		return err
	}
	actual, err := m.cutoverDriver().Inventory(ctx, s.ComposeProject)
	if err != nil {
		return err
	}
	if err = m.cutoverReconcile(ctx, p, actual); err != nil {
		return err
	}
	latest, _, _, err := m.effectiveProxyRevision(ctx)
	if err != nil {
		return err
	}
	if proxyengine.PolicyDigest(latest.Policy) != proxyengine.PolicyDigest(p.PreviousPolicy) && proxyengine.PolicyDigest(latest.Policy) != proxyengine.PolicyDigest(p.Policy) {
		return errors.New("unknown proxy policy prevents automatic rollback")
	}
	if latest.Policy.Revision == p.Policy.Revision {
		restore := p.PreviousPolicy
		restore.Revision = latest.Policy.Revision + 1
		if err = m.publishCutoverPolicy(ctx, p, restore, record); err != nil {
			return err
		}
	} else {
		if err = m.exportProxyPolicy(latest.Policy); err != nil {
			return err
		}
		if err = m.waitCutoverPolicy(ctx, latest.Policy, record); err != nil {
			return err
		}
	}
	return m.restoreCutoverBindings(ctx, p, record)
}

func (m *Manager) restoreCutoverBindings(ctx context.Context, p proxyCutoverProposal, record *proxyCutoverRecord) error {
	if err := m.moveCutoverComponents(ctx, p, record, false); err != nil {
		return err
	}
	s, err := m.Store.GetService(ctx, p.ServiceID)
	if err != nil {
		return err
	}
	return m.cutoverDriver().Health(ctx, s)
}

func (m *Manager) runCutoverReturn(ctx context.Context, p proxyCutoverProposal, record *proxyCutoverRecord) error {
	if err := m.saveCutover(ctx, record, "running", "return_validated", ""); err != nil {
		return err
	}
	s, err := m.Store.GetService(ctx, p.ServiceID)
	if err != nil {
		return err
	}
	actual, err := m.cutoverDriver().Inventory(ctx, s.ComposeProject)
	if err != nil {
		return err
	}
	if err = m.cutoverReconcile(ctx, p, actual); err != nil {
		return err
	}
	var preflight any
	if err = m.proxyRPC(ctx, "POST", "/v1/preflight", p.Policy, &preflight); err != nil {
		return err
	}
	if err = m.publishCutoverPolicy(ctx, p, p.Policy, record); err != nil {
		return err
	}
	if err = m.restoreCutoverBindings(ctx, p, record); err != nil {
		return err
	}
	return m.saveCutover(ctx, record, "returned", "original_runtime_restored", "")
}

func (m *Manager) ProxyCutoverReturnPreview(ctx context.Context, in transport.ProxyCutoverReturnRequest) (transport.ProxyCutoverPreview, error) {
	m.proxyMu.Lock()
	defer m.proxyMu.Unlock()
	var empty transport.ProxyCutoverPreview
	if err := m.requireProxy(); err != nil {
		return empty, err
	}
	if in.Initiator.Validate() != nil {
		return empty, proxyInput("Authenticated actor required")
	}
	records, err := m.cutoverRecords(ctx)
	if err != nil {
		return empty, err
	}
	record, ok := records[in.CutoverID]
	if !ok || (!record.CanReturn && !record.RequiresRecovery) {
		return empty, proxyInput("Transfer is not ready for a reviewed return")
	}
	for id, r := range records {
		if id != record.ID && cutoverPending(r.State) {
			return empty, proxyInput("Resolve the other pending transfer first")
		}
	}
	var origin proxyCutoverProposal
	if err = m.Store.Get(ctx, "proxy_cutover_proposal", record.OriginProposalID, &origin); err != nil {
		return empty, err
	}
	s, st, _, _, actual, err := m.cutoverFrozen(ctx, record.ServiceID)
	if err != nil {
		return empty, err
	}
	p := origin
	if err = hydrateCutoverPreview(&p); err != nil {
		return empty, err
	}
	p.Mode = "return"
	p.ProposalID = NewID("cutover-return-")
	p.Digest = ""
	p.Actor = in.Initiator
	p.ExpiresAt = time.Now().UTC().Add(5 * time.Minute)
	p.ExpectedCutoverSequence = record.Sequence
	p.CurrentReleaseID = st.CurrentReleaseID
	p.StateSequence = st.Sequence
	p.RuntimeDigest = cutoverRuntimeDigest(actual)
	p.Containers = actual
	p.Authority = m.proxyAuthority()
	knownPolicies := []proxyengine.Policy{origin.PreviousPolicy, origin.Policy}
	// For a normal return, current release images and mounts replace the original
	// cutover evidence. Old images are never restored after a later Deploy.
	if record.State == "active" {
		if err = cutoverExactIdentities(st, actual); err != nil {
			return empty, err
		}
	} else {
		var prior proxyCutoverProposal
		if err = m.Store.Get(ctx, "proxy_cutover_proposal", record.ProposalID, &prior); err != nil {
			return empty, err
		}
		knownPolicies = append(knownPolicies, prior.PreviousPolicy, prior.Policy)
		if err = m.cutoverReconcile(ctx, prior, actual); err != nil {
			return empty, err
		}
		p.RecoveryBaseline = cutoverBaseline(prior)
	}
	if s.PolicyRevision != origin.PolicyRevision {
		return empty, proxyInput("Service registration changed; manual reconciliation is required")
	}
	p.MissingApplications = nil
	present := map[string]bool{}
	for _, c := range actual {
		present[c.Component] = true
	}
	for _, component := range cutoverComponents(p) {
		if !present[component] {
			p.MissingApplications = append(p.MissingApplications, component)
		}
	}
	p.ApplicationMissing = len(cutoverComponents(p)) == 1 && len(p.MissingApplications) == 1

	_, p.HealthRevision, err = m.healthPolicy(ctx, s)
	if err != nil {
		return empty, err
	}
	if err = m.cutoverReconcile(ctx, p, actual); err != nil {
		return empty, err
	}
	latest, count, _, fileDigest, err := m.effectiveProxySnapshot(ctx)
	if err != nil {
		return empty, err
	}
	if count >= 1023 {
		return empty, proxyInput("Proxy history budget exhausted")
	}
	var status proxyengine.Status
	if err = m.proxyRPC(ctx, "GET", "/v1/status", nil, &status); err != nil {
		return empty, err
	}
	knownPolicies = append(knownPolicies, latest.Policy)
	knownApplied := false
	for _, policy := range knownPolicies {
		knownApplied = knownApplied || (policy.Revision == status.AppliedRevision && string(proxyengine.PolicyDigest(policy)) == status.PolicyDigest)
	}
	if !knownApplied || status.AppliedRevision > latest.Policy.Revision {
		return empty, proxyInput("Applied proxy policy is unknown; reconcile it before reviewing a return")
	}
	owned := map[string]bool{}
	for _, r := range origin.Policy.Routes {
		for _, b := range origin.OriginalBindings {
			if r.Listen == b && r.ServiceID == string(s.ID) && cutoverHasComponent(origin, r.Component) {
				owned[r.ID] = true
			}
		}
	}
	wanted := latest.Policy
	wanted.Revision++
	wanted.Routes = []proxyengine.Route{}
	for _, r := range latest.Policy.Routes {
		if owned[r.ID] {
			continue
		}
		if cutoverUsesAnyBackend(r.Upstream, p) {
			return empty, proxyInput("Another proxy route uses this private backend; remove or update it before returning ports")
		}
		for _, b := range p.OriginalBindings {
			if r.Listen == b {
				return empty, proxyInput("Another proxy route now shares an original listener; remove it before returning ports")
			}
		}
		wanted.Routes = append(wanted.Routes, r)
	}
	p.PreviousPolicy = latest.Policy
	p.Policy = wanted
	p.ProxyRevision = latest.Policy.Revision
	p.AppliedRevision = status.AppliedRevision
	p.AppliedPolicyDigest = status.PolicyDigest
	p.DesiredFileDigest = fileDigest
	p.Changes = []string{"Remove only this transfer's routes and wait for their listeners to close", "Recreate all selected applications on their original bindings with CURRENT release images and unchanged mounts"}
	p.Warnings = []string{"Application connections are interrupted during return; persistent data is not restored or copied", "Unknown container, mount or external policy changes require administrator reconciliation"}
	var preflight any
	if err = m.proxyRPC(ctx, "POST", "/v1/preflight", wanted, &preflight); err != nil {
		return empty, err
	}
	return m.saveCutoverProposal(ctx, p)
}

func cutoverUsesBackend(raw string, port int) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return false
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || ip.Unmap() != netip.MustParseAddr("127.0.0.1") {
		return false
	}
	n := 80
	if u.Port() != "" {
		n, err = strconv.Atoi(u.Port())
		if err != nil {
			return false
		}
	}
	return n == port
}

func cutoverHasComponent(p proxyCutoverProposal, component string) bool {
	for _, value := range cutoverComponents(p) {
		if value == component {
			return true
		}
	}
	return false
}
func cutoverUsesAnyBackend(raw string, p proxyCutoverProposal) bool {
	for _, port := range cutoverPrivatePorts(p) {
		if cutoverUsesBackend(raw, port) {
			return true
		}
	}
	return false
}
func hydrateCutoverPreview(p *proxyCutoverProposal) error {
	entries, err := cutoverProposalEntries(*p)
	if err != nil {
		return err
	}
	p.Components = cutoverComponents(*p)
	if len(p.Targets) == 0 {
		for _, entry := range entries {
			byTarget := map[int][]string{}
			for _, port := range entry.Original {
				n, _ := cutoverPortNumber(port["target"])
				pub, _ := cutoverPortNumber(port["published"])
				ip, _ := port["host_ip"].(string)
				byTarget[n] = append(byTarget[n], net.JoinHostPort(ip, strconv.Itoa(pub)))
			}
			for _, port := range entry.Replacement {
				n, _ := cutoverPortNumber(port["target"])
				pub, _ := cutoverPortNumber(port["published"])
				p.Targets = append(p.Targets, transport.ProxyCutoverTargetPlan{Component: entry.Component, UpstreamPort: n, PrivatePort: pub, OriginalBindings: byTarget[n], PrivateBinding: net.JoinHostPort("127.0.0.1", strconv.Itoa(pub))})
			}
		}
	}
	return nil
}
