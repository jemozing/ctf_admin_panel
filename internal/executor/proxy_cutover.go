package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	proxyengine "github.com/ctf-service-manager/ctf-service-manager/internal/proxy"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

const cutoverHistoryLimit = 128
const cutoverJournalLimit = cutoverHistoryLimit * 128
const cutoverJournalReservation = 64

type proxyCutoverProposal struct {
	SchemaVersion int                       `json:"schema_version,omitempty"`
	Entries       []runtimePortOverlayEntry `json:"entries,omitempty"`
	transport.ProxyCutoverPreview
	Actor                   domain.ID        `json:"actor"`
	Authority               domain.Digest    `json:"authority"`
	DesiredFileDigest       domain.Digest    `json:"desired_file_digest"`
	AppliedPolicyDigest     string           `json:"applied_policy_digest"`
	OriginalPorts           []map[string]any `json:"original_ports"`
	ReplacementPorts        []map[string]any `json:"replacement_ports"`
	OriginProposalID        domain.ID        `json:"origin_proposal_id"`
	CurrentReleaseID        domain.ID        `json:"current_release_id"`
	HealthRevision          uint64           `json:"health_revision"`
	ExpectedCutoverSequence uint64           `json:"expected_cutover_sequence"`
}

type proxyCutoverRecord struct {
	transport.ProxyCutoverView
	OriginProposalID  domain.ID `json:"origin_proposal_id"`
	mutationAttempted bool
}

func cutoverPending(state string) bool {
	return state != "active" && state != "returned" && state != "rolled_back" && state != "failed"
}

func (m *Manager) cutoverRecords(ctx context.Context) (map[domain.ID]proxyCutoverRecord, error) {
	records, err := m.Store.List(ctx, "proxy_cutover", "proxy")
	if err != nil {
		return nil, err
	}
	if len(records) > cutoverJournalLimit {
		return nil, errors.New("cutover journal history budget exceeded; administrator maintenance required")
	}
	latest := map[domain.ID]proxyCutoverRecord{}
	for _, r := range records {
		var v proxyCutoverRecord
		if err := json.Unmarshal(r.Payload, &v); err != nil {
			return nil, err
		}
		if v.ID.Validate() != nil || v.Sequence == 0 {
			return nil, errors.New("invalid cutover journal")
		}
		if v.Sequence > latest[v.ID].Sequence {
			latest[v.ID] = v
		}
	}
	if len(latest) > cutoverHistoryLimit {
		return nil, errors.New("cutover operation history budget exhausted")
	}
	return latest, nil
}

func (m *Manager) requireNoPendingCutover(ctx context.Context) error {
	records, err := m.cutoverRecords(ctx)
	if err != nil {
		return err
	}
	for _, record := range records {
		if cutoverPending(record.State) {
			return proxyInput("A port transfer is running or requires recovery; return its ports before other changes")
		}
	}
	return nil
}

func (m *Manager) ProxyCutovers(ctx context.Context) ([]transport.ProxyCutoverView, error) {
	records, err := m.cutoverRecords(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]transport.ProxyCutoverView, 0, len(records))
	for _, record := range records {
		result = append(result, record.ProxyCutoverView)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].UpdatedAt.After(result[j].UpdatedAt) })
	return result, nil
}

func (m *Manager) saveCutover(ctx context.Context, record *proxyCutoverRecord, state, stage, message string) error {
	record.State, record.Stage, record.Error = state, stage, message
	record.RequiresRecovery = state == "requires_recovery"
	record.Recoverable = state == "active" || record.RequiresRecovery
	record.CanReturn = record.Recoverable
	record.UpdatedAt = time.Now().UTC()
	record.Sequence++
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err = m.checkLocalAllocation(ctx, m.Config.StateDirectory, uint64(len(raw)+8192), 2, m.Config.Storage.Effective().StateMaxBytes); err != nil {
		return err
	}
	return m.Store.PutImmutable(ctx, "proxy_cutover", domain.ID(fmt.Sprintf("%s-%020d", record.ID, record.Sequence)), "proxy", record)
}

// On startup no container command is replayed. A durable intent without its final
// observation remains blocked until a newly reviewed return/recovery proposal.
func (m *Manager) reconcileCutoversOnStart(ctx context.Context) error {
	records, err := m.cutoverRecords(ctx)
	if err != nil {
		return err
	}
	for _, record := range records {
		if cutoverPending(record.State) && record.State != "requires_recovery" {
			if err := m.saveCutover(ctx, &record, "requires_recovery", "interrupted", "Executor restarted before transfer completion; review actual runtime and return ports"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *Manager) cutoverFrozen(ctx context.Context, id domain.ID) (domain.Service, runtimeState, Configuration, map[string]any, []docker.Container, error) {
	s, err := m.Store.GetService(ctx, id)
	if err != nil {
		return s, runtimeState{}, Configuration{}, nil, nil, err
	}
	st, err := m.state(ctx, s)
	if err != nil {
		return s, st, Configuration{}, nil, nil, err
	}
	if st.CurrentReleaseID == "" || st.BaselineID == "" {
		return s, st, Configuration{}, nil, nil, proxyInput("Initialize the service baseline before transferring ports")
	}
	digest, err := m.activeConfigurationDigest(ctx, s, st)
	if err != nil {
		return s, st, Configuration{}, nil, nil, err
	}
	c, err := m.LoadConfiguration(ctx, digest)
	if err != nil {
		return s, st, c, nil, nil, err
	}
	model, err := m.observationConfiguration(ctx, s)
	if err != nil {
		return s, st, c, nil, nil, err
	}
	release, err := m.loadRelease(ctx, s, st.CurrentReleaseID)
	if err != nil {
		return s, st, c, nil, nil, err
	}
	pinModelImages(model, release.Spec().Images)
	actual, err := m.cutoverDriver().Inventory(ctx, s.ComposeProject)
	return s, st, c, model, actual, err
}

func cutoverExactIdentities(st runtimeState, actual []docker.Container) error {
	if len(st.Containers) != len(actual) {
		return errors.New("registered runtime component count changed")
	}
	seen := map[string]bool{}
	for _, ref := range st.Containers {
		found := false
		for _, c := range actual {
			if c.Component == ref.Component {
				if found || seen[c.Component] || c.ID != ref.ID || c.ImageID != string(ref.ImageID) {
					return errors.New("registered runtime identity changed")
				}
				found = true
				seen[c.Component] = true
			}
		}
		if !found {
			return errors.New("registered component disappeared")
		}
	}
	return nil
}

// One frozen component may expose several TCP targets and several explicit
// addresses per target. All of them are part of one service transfer.
func (m *Manager) cutoverComponentBindings(s domain.Service, component string, model map[string]any, actual []docker.Container) ([]map[string]any, map[int][]string, error) {
	role := domain.ComponentRole("")
	for _, r := range s.Containers {
		if r.Component == component {
			role = r.Role
		}
	}
	if role != domain.RoleApplication || !hasTarget(s, component) {
		return nil, nil, proxyInput("Only approved application components can transfer ports")
	}
	services, _ := model["services"].(map[string]any)
	c, _ := services[component].(map[string]any)
	ports, err := cutoverModelPorts(c)
	if err != nil {
		return nil, nil, proxyInput(err.Error())
	}
	allowed := map[string]bool{}
	for _, raw := range m.Config.Proxy.AllowedListenIPs {
		ip, e := netip.ParseAddr(raw)
		if e == nil {
			allowed[ip.Unmap().String()] = true
		}
	}
	groups := map[int][]string{}
	seen := map[string]bool{}
	for _, p := range ports {
		target, _ := cutoverPortNumber(p["target"])
		published, _ := cutoverPortNumber(p["published"])
		raw, _ := p["host_ip"].(string)
		ip, e := netip.ParseAddr(raw)
		if e != nil || ip.Zone() != "" || !allowed[ip.Unmap().String()] || published < m.Config.Proxy.ListenPortMin || published > m.Config.Proxy.ListenPortMax {
			return nil, nil, proxyInput("Every original binding must be inside the administrator-approved listener range")
		}
		binding := net.JoinHostPort(ip.Unmap().String(), strconv.Itoa(published))
		if seen[binding] {
			return nil, nil, proxyInput("Duplicate publication is ambiguous")
		}
		seen[binding] = true
		groups[target] = append(groups[target], binding)
	}
	found := 0
	observed := map[string]bool{}
	for _, c := range actual {
		if c.Component != component {
			continue
		}
		found++
		if c.State != "running" {
			return nil, nil, proxyInput("Every selected application must be running before preview")
		}
		for _, raw := range c.Ports {
			ip, pub, target, _, ok := privatePublication(raw)
			binding := net.JoinHostPort(ip, strconv.Itoa(pub))
			matched := false
			for _, expected := range groups[target] {
				matched = matched || expected == binding
			}
			if !ok || !matched || observed[binding] {
				return nil, nil, proxyInput("All actual TCP publications must match explicit frozen bindings; UDP and implicit bindings require reconciliation")
			}
			observed[binding] = true
		}
	}
	if found != 1 || len(observed) != len(seen) {
		return nil, nil, proxyInput("Application publications differ from the reviewed component")
	}
	for target := range groups {
		sort.Strings(groups[target])
	}
	return ports, groups, nil
}

// Kept for legacy package callers; new service plans use the grouped helper.
func (m *Manager) cutoverBindings(s domain.Service, component string, model map[string]any, actual []docker.Container) ([]map[string]any, []string, int, error) {
	ports, groups, err := m.cutoverComponentBindings(s, component, model, actual)
	if err != nil {
		return nil, nil, 0, err
	}
	if len(groups) != 1 {
		return nil, nil, 0, proxyInput("Use a grouped transfer for multiple TCP targets")
	}
	for target, bindings := range groups {
		return ports, bindings, target, nil
	}
	return nil, nil, 0, proxyInput("No application ports")
}

func (m *Manager) cutoverServiceTargets(s domain.Service, model map[string]any, actual []docker.Container) ([]transport.ProxyCutoverTarget, map[string][]map[string]any, error) {
	result := []transport.ProxyCutoverTarget{}
	original := map[string][]map[string]any{}
	services, _ := model["services"].(map[string]any)
	listeners := 0
	for _, ref := range s.Containers {
		if ref.Role != domain.RoleApplication {
			continue
		}
		component, _ := services[ref.Component].(map[string]any)
		raw, _ := component["ports"].([]any)
		if len(raw) == 0 {
			continue
		}
		ports, groups, err := m.cutoverComponentBindings(s, ref.Component, model, actual)
		if err != nil {
			return nil, nil, err
		}
		original[ref.Component] = ports
		for target, bindings := range groups {
			result = append(result, transport.ProxyCutoverTarget{ServiceID: s.ID, ServiceName: s.Name, Component: ref.Component, UpstreamPort: target, OriginalBindings: bindings})
			listeners += len(bindings)
		}
	}
	if len(result) == 0 || len(result) > transport.MaxProxyCutoverTargets || len(original) > transport.MaxProxyCutoverComponents || listeners > transport.MaxProxyCutoverListeners {
		return nil, nil, proxyInput("The complete service publication set exceeds transfer limits or is empty")
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Component == result[j].Component {
			return result[i].UpstreamPort < result[j].UpstreamPort
		}
		return result[i].Component < result[j].Component
	})
	return result, original, nil
}

func (m *Manager) ProxyCutoverTargets(ctx context.Context) (transport.ProxyCutoverTargets, error) {
	lo, hi := m.Config.Proxy.BackendPorts()
	result := transport.ProxyCutoverTargets{Targets: []transport.ProxyCutoverTarget{}, Unavailable: []transport.ProxyUnavailableTarget{}, AllowedListenIPs: append([]string{}, m.Config.Proxy.AllowedListenIPs...), ListenPortMin: m.Config.Proxy.ListenPortMin, ListenPortMax: m.Config.Proxy.ListenPortMax, BackendPortMin: lo, BackendPortMax: hi, MaxComponents: transport.MaxProxyCutoverComponents, MaxTargets: transport.MaxProxyCutoverTargets, MaxListeners: transport.MaxProxyCutoverListeners}
	if err := m.requireProxy(); err != nil {
		return result, err
	}
	services, err := m.Store.ListServices(ctx)
	if err != nil {
		return result, err
	}
	for _, s := range services {
		_, st, _, model, actual, e := m.cutoverFrozen(ctx, s.ID)
		if e == nil {
			e = cutoverExactIdentities(st, actual)
		}
		if e == nil {
			_, e = m.cutoverDriver().Verify(ctx, s, actual, actual, "", model)
		}
		var targets []transport.ProxyCutoverTarget
		if e == nil {
			targets, _, e = m.cutoverServiceTargets(s, model, actual)
		}
		overlay, overlayErr := m.runtimePortOverlay(ctx, s.ID)
		if e == nil {
			e = overlayErr
		}
		if overlay.Active {
			e = proxyInput("This service already has an active port transfer")
		}
		if e == nil {
			result.Targets = append(result.Targets, targets...)
			continue
		}
		for _, ref := range s.Containers {
			if ref.Role == domain.RoleApplication {
				result.Unavailable = append(result.Unavailable, transport.ProxyUnavailableTarget{ServiceID: s.ID, Component: ref.Component, Reason: "The complete application publication set must be verified, supported and without an active transfer"})
			}
		}
	}
	return result, nil
}

func (m *Manager) ProxyCutoverPreview(ctx context.Context, in transport.ProxyCutoverPreviewRequest) (transport.ProxyCutoverPreview, error) {
	m.proxyMu.Lock()
	defer m.proxyMu.Unlock()
	var empty transport.ProxyCutoverPreview
	if err := m.requireProxy(); err != nil {
		return empty, err
	}
	if err := m.requireNoPendingCutover(ctx); err != nil {
		return empty, err
	}
	if in.Initiator.Validate() != nil || in.ServiceID.Validate() != nil || len(in.Routes) == 0 || len(in.Routes) > transport.MaxProxyCutoverListeners {
		return empty, proxyInput("Authenticated service and bounded routes are required")
	}
	if err := transport.ValidateProxyCutoverSelection(in); err != nil {
		return empty, err
	}
	selections := in.Targets
	if selections == nil {
		selections = []transport.ProxyCutoverSelection{{Component: in.Component, UpstreamPort: in.UpstreamPort, PrivatePort: in.PrivatePort}}
	}
	s, st, _, model, actual, err := m.cutoverFrozen(ctx, in.ServiceID)
	if err != nil {
		return empty, err
	}
	if err = cutoverExactIdentities(st, actual); err != nil {
		return empty, err
	}
	if _, err = m.cutoverDriver().Verify(ctx, s, actual, actual, "", model); err != nil {
		return empty, err
	}
	overlay, err := m.runtimePortOverlay(ctx, s.ID)
	if err != nil {
		return empty, err
	}
	if overlay.Active {
		return empty, proxyInput("Return the existing transfer before moving this service")
	}
	expected, original, err := m.cutoverServiceTargets(s, model, actual)
	if err != nil {
		return empty, err
	}
	if len(expected) != len(selections) {
		return empty, proxyInput("Transfer every published application component and TCP target together")
	}
	selected := map[string]transport.ProxyCutoverSelection{}
	lo, hi := m.Config.Proxy.BackendPorts()
	privatePorts := []int{}
	for _, selection := range selections {
		if selection.PrivatePort < lo || selection.PrivatePort > hi {
			return empty, proxyInput("Private port is outside the approved backend range")
		}
		selected[cutoverTargetKey(selection.Component, selection.UpstreamPort)] = selection
		privatePorts = append(privatePorts, selection.PrivatePort)
	}
	plans := []transport.ProxyCutoverTargetPlan{}
	entries := []runtimePortOverlayEntry{}
	byComponent := map[string][]map[string]any{}
	bindings := []string{}
	privateBindings := []string{}
	origins := []string{}
	pairPlans := map[string]transport.ProxyCutoverTargetPlan{}
	for _, target := range expected {
		key := cutoverTargetKey(target.Component, target.UpstreamPort)
		selection, ok := selected[key]
		if !ok {
			return empty, proxyInput("All application publications must be included; leaving a bypass is forbidden")
		}
		private := net.JoinHostPort("127.0.0.1", strconv.Itoa(selection.PrivatePort))
		plan := transport.ProxyCutoverTargetPlan{Component: target.Component, UpstreamPort: target.UpstreamPort, PrivatePort: selection.PrivatePort, OriginalBindings: target.OriginalBindings, PrivateBinding: private}
		plans = append(plans, plan)
		pairPlans[key] = plan
		bindings = append(bindings, target.OriginalBindings...)
		privateBindings = append(privateBindings, private)
		origins = append(origins, "http://"+private)
		byComponent[target.Component] = append(byComponent[target.Component], map[string]any{"target": float64(target.UpstreamPort), "published": strconv.Itoa(selection.PrivatePort), "host_ip": "127.0.0.1", "protocol": "tcp"})
	}
	components := []string{}
	for component := range original {
		components = append(components, component)
	}
	sort.Strings(components)
	for _, component := range components {
		entries = append(entries, runtimePortOverlayEntry{Component: component, Original: original[component], Replacement: byComponent[component]})
	}
	if err = m.cutoverPrivatePortsAvailable(ctx, privatePorts); err != nil {
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
	if status.AppliedRevision != latest.Policy.Revision || status.PolicyDigest != proxyengine.PolicyDigest(latest.Policy) {
		return empty, proxyInput("Wait for the exact desired proxy policy to become active")
	}
	wanted := latest.Policy
	wanted.Revision++
	wanted.Routes = append([]proxyengine.Route{}, latest.Policy.Routes...)
	if len(wanted.Routes)+len(in.Routes) > 32 {
		return empty, proxyInput("Combined proxy route budget exceeded")
	}
	seen, ids := map[string]bool{}, map[string]bool{}
	for _, r := range wanted.Routes {
		if m.Config.Proxy.AllowPublicBackendObservation && r.ServiceID == string(s.ID) {
			return empty, proxyInput("Remove existing HTTP Proxy routes for this service before transferring its ports")
		}
		ids[r.ID] = true
		for _, b := range bindings {
			if r.Listen == b {
				return empty, proxyInput("An original application port is already owned by a proxy route")
			}
		}
	}
	for _, r := range in.Routes {
		plan, ok := pairPlans[cutoverTargetKey(r.Component, r.UpstreamPort)]
		if !ok || r.ServiceID != s.ID || seen[r.Listen] {
			return empty, proxyInput("Routes must uniquely cover the selected application TCP targets")
		}
		matched := false
		for _, binding := range plan.OriginalBindings {
			matched = matched || binding == r.Listen
		}
		if !matched {
			return empty, proxyInput("Route listener must equal its original application binding")
		}
		seen[r.Listen] = true
		if r.WAF.Mode != "" && r.WAF.Mode != "observe_only" {
			return empty, proxyInput("Transferred routes must start in observe_only mode")
		}
		id := r.ID
		if id == "" {
			id = string(NewID("route-"))
		}
		if ids[id] {
			return empty, proxyInput("Transfer requires unique new route IDs")
		}
		ids[id] = true
		wanted.Routes = append(wanted.Routes, proxyengine.Route{ID: id, ServiceID: string(s.ID), Component: r.Component, Listen: r.Listen, Host: r.Host, Upstream: "http://" + plan.PrivateBinding, Protocol: r.Protocol, TLS: r.TLS, TrustedProxyCIDRs: r.TrustedProxyCIDRs, Capture: r.Capture, WAF: r.WAF, Limits: r.Limits})
	}
	if len(seen) != len(bindings) {
		return empty, proxyInput("Every original binding must be transferred; leaving a bypass is forbidden")
	}
	wanted, err = proxyengine.NormalizePolicy(wanted)
	if err != nil {
		return empty, proxyInput(err.Error())
	}
	if err = m.preflightCutoverHTTP2(ctx, wanted, plans); err != nil {
		return empty, err
	}
	var preflight any
	if err = m.proxyRPC(ctx, "POST", "/v1/preflight-cutover", proxyengine.CutoverPreflightRequest{Policy: wanted, ReleasedListeners: bindings, PendingUpstreams: origins}, &preflight); err != nil {
		return empty, err
	}
	digest, err := m.activeConfigurationDigest(ctx, s, st)
	if err != nil {
		return empty, err
	}
	_, healthRevision, err := m.healthPolicy(ctx, s)
	if err != nil {
		return empty, err
	}
	preview := transport.ProxyCutoverPreview{ProposalID: NewID("cutover-plan-"), Mode: "cutover", CutoverID: NewID("cutover-"), ServiceID: s.ID, Targets: plans, Components: components, PolicyRevision: s.PolicyRevision, StateSequence: st.Sequence, ConfigurationDigest: digest, RuntimeDigest: cutoverRuntimeDigest(actual), ProxyRevision: latest.Policy.Revision, AppliedRevision: status.AppliedRevision, OriginalBindings: bindings, PrivateBindings: privateBindings, Containers: actual, Policy: wanted, PreviousPolicy: latest.Policy, ExpiresAt: time.Now().UTC().Add(5 * time.Minute), Changes: []string{"Recreate each selected application once with ALL its private TCP publications and its CURRENT image", "Verify images, mounts and all untouched dependencies after every component", "Activate all proxy routes only after the entire private group is verified"}, Warnings: []string{"Application connections are interrupted per component; mounted data is preserved, writable layers are recreated", "Configured local checks run after group activation; competition checker verification remains independent"}}
	p := proxyCutoverProposal{SchemaVersion: 2, Entries: entries, ProxyCutoverPreview: preview, Actor: in.Initiator, Authority: m.proxyAuthority(), DesiredFileDigest: fileDigest, CurrentReleaseID: st.CurrentReleaseID, HealthRevision: healthRevision, AppliedPolicyDigest: status.PolicyDigest}
	if len(plans) == 1 {
		p.Component = plans[0].Component
		p.UpstreamPort = plans[0].UpstreamPort
		p.PrivatePort = plans[0].PrivatePort
		p.OriginalPorts = entries[0].Original
		p.ReplacementPorts = entries[0].Replacement
	}
	p.OriginProposalID = p.ProposalID
	return m.saveCutoverProposal(ctx, p)
}

func cutoverTargetKey(component string, port int) string { return component + ":" + strconv.Itoa(port) }

func (m *Manager) saveCutoverProposal(ctx context.Context, p proxyCutoverProposal) (transport.ProxyCutoverPreview, error) {
	var empty transport.ProxyCutoverPreview
	records, err := m.Store.List(ctx, "proxy_cutover_proposal", "proxy")
	if err != nil {
		return empty, err
	}
	if len(records) >= cutoverHistoryLimit*4 {
		return empty, proxyInput("Cutover preview history budget exhausted")
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return empty, err
	}
	p.Digest = domain.Hash(raw)
	if err = m.checkLocalAllocation(ctx, m.Config.StateDirectory, uint64(len(raw)+8192), 2, m.Config.Storage.Effective().StateMaxBytes); err != nil {
		return empty, err
	}
	if err = m.Store.PutImmutable(ctx, "proxy_cutover_proposal", p.ProposalID, "proxy", p); err != nil {
		return empty, err
	}
	return p.ProxyCutoverPreview, nil
}

func (m *Manager) cutoverNoJobs(ctx context.Context) error {
	ops, err := m.Store.ListOperations(ctx)
	if err != nil {
		return err
	}
	for _, op := range ops {
		if !op.State.Terminal() {
			return proxyInput("Finish or recover all service operations before transferring ports")
		}
	}
	return nil
}

func (m *Manager) cutoverFresh(ctx context.Context, p proxyCutoverProposal) error {
	if time.Now().After(p.ExpiresAt) || p.Authority != m.proxyAuthority() {
		return proxyInput("Port transfer preview expired or installation policy changed")
	}
	s, st, _, model, actual, err := m.cutoverFrozen(ctx, p.ServiceID)
	if err != nil {
		return err
	}
	digest, err := m.activeConfigurationDigest(ctx, s, st)
	if err != nil {
		return err
	}
	_, hr, err := m.healthPolicy(ctx, s)
	if err != nil {
		return err
	}
	if s.PolicyRevision != p.PolicyRevision || st.Sequence != p.StateSequence || st.CurrentReleaseID != p.CurrentReleaseID || digest != p.ConfigurationDigest || cutoverRuntimeDigest(actual) != p.RuntimeDigest || hr != p.HealthRevision {
		return proxyInput("Service runtime, release or checks changed after preview")
	}
	if p.Mode == "cutover" {
		if err = cutoverExactIdentities(st, actual); err != nil {
			return err
		}
		if _, err = m.cutoverDriver().Verify(ctx, s, actual, actual, "", model); err != nil {
			return err
		}
		if err = m.cutoverPrivatePortsAvailable(ctx, cutoverPrivatePorts(p)); err != nil {
			return err
		}
	} else if err = m.cutoverReconcile(ctx, p, actual); err != nil {
		return err
	}
	latest, _, _, fileDigest, err := m.effectiveProxySnapshot(ctx)
	if err != nil {
		return err
	}
	if latest.Policy.Revision != p.ProxyRevision || fileDigest != p.DesiredFileDigest {
		return proxyInput("Proxy policy changed after preview")
	}
	var status proxyengine.Status
	if err = m.proxyRPC(ctx, "GET", "/v1/status", nil, &status); err != nil {
		return err
	}
	if status.AppliedRevision != p.AppliedRevision || status.PolicyDigest != p.AppliedPolicyDigest {
		return proxyInput("Applied proxy policy changed after preview")
	}
	return m.cutoverNoJobs(ctx)
}

// Docker can reserve a published port using NAT without a host listening
// process. Probe the daemon's global publication inventory as well as the
// proxy's host-namespace bind preflight; foreign identities are never exposed.
func (m *Manager) cutoverPrivatePortAvailable(ctx context.Context, port int) error {
	return m.cutoverPrivatePortsAvailable(ctx, []int{port})
}
func (m *Manager) cutoverPrivatePortsAvailable(ctx context.Context, ports []int) error {
	wanted := map[int]bool{}
	for _, p := range ports {
		wanted[p] = true
	}
	containers, err := m.cutoverDriver().Inventory(ctx, "")
	if err != nil {
		return errors.New("global Docker port reservation inventory is unavailable")
	}
	for _, c := range containers {
		if c.State != "running" && c.State != "paused" && c.State != "restarting" {
			continue
		}
		for _, raw := range c.Ports {
			host, published, _, _, ok := privatePublication(raw)
			if !ok && strings.HasPrefix(raw, ":") && !strings.HasPrefix(raw, "::") {
				host, published, _, _, ok = privatePublication("0.0.0.0" + raw)
			}
			if !ok || !wanted[published] {
				continue
			}
			ip, e := netip.ParseAddr(host)
			if e == nil && (ip.Unmap().IsUnspecified() || ip.Unmap().IsLoopback()) {
				return proxyInput("Private backend port is already reserved by a Docker publication; choose another approved port")
			}
		}
	}
	return nil
}

func (m *Manager) ProxyCutoverConfirm(ctx context.Context, in transport.ProxyConfirmRequest) (transport.ProxyCutoverView, error) {
	m.proxyMu.Lock()
	defer m.proxyMu.Unlock()
	m.registrationMu.Lock()
	defer m.registrationMu.Unlock()
	m.submitMu.Lock()
	defer m.submitMu.Unlock()
	var empty transport.ProxyCutoverView
	unlockAdmission, err := m.lockCutoverAdmission()
	if err != nil {
		return empty, err
	}
	defer unlockAdmission()
	if m.cutoverClosing {
		return empty, proxyInput("Executor is shutting down")
	}
	if !m.cutoverReady {
		return empty, proxyInput("Executor worker is starting; wait for startup reconciliation")
	}
	if err := m.requireProxy(); err != nil {
		return empty, err
	}
	if in.Initiator.Validate() != nil {
		return empty, proxyInput("Authenticated actor required")
	}
	var p proxyCutoverProposal
	if err := m.Store.Get(ctx, "proxy_cutover_proposal", in.ProposalID, &p); err != nil {
		return empty, err
	}
	if p.Digest != in.Digest {
		return empty, proxyInput("Confirmation digest differs from the reviewed transfer")
	}
	records, err := m.cutoverRecords(ctx)
	if err != nil {
		return empty, err
	}
	for _, record := range records {
		if record.ProposalID == in.ProposalID {
			return record.ProxyCutoverView, nil
		}
	}
	journal, err := m.Store.List(ctx, "proxy_cutover", "proxy")
	if err != nil {
		return empty, err
	}
	if len(journal)+cutoverJournalReservation > cutoverJournalLimit {
		return empty, proxyInput("Port transfer journal budget exhausted before mutation; administrator maintenance is required")
	}
	if p.Mode == "cutover" {
		if err = m.requireNoPendingCutover(ctx); err != nil {
			return empty, err
		}
		if len(records) >= cutoverHistoryLimit {
			return empty, proxyInput("Cutover operation history budget exhausted")
		}
	}
	if p.Mode == "return" {
		old, ok := records[p.CutoverID]
		if !ok || old.Sequence != p.ExpectedCutoverSequence || (!old.CanReturn && !old.RequiresRecovery) {
			return empty, proxyInput("Transfer changed after return preview")
		}
	}
	if err = m.cutoverFresh(ctx, p); err != nil {
		return empty, err
	}
	if !m.artifactMu.TryLock() {
		return empty, proxyInput("Executor is busy; retry confirmation after current maintenance")
	}
	m.artifactMu.Unlock()
	record := proxyCutoverRecord{ProxyCutoverView: transport.ProxyCutoverView{ID: p.CutoverID, ProposalID: p.ProposalID, Mode: p.Mode, ServiceID: p.ServiceID, Component: p.Component, Components: cutoverComponents(p), Targets: p.Targets, Digest: p.Digest, OriginalBindings: p.OriginalBindings, PrivateBindings: p.PrivateBindings, ProxyRevision: p.ProxyRevision, AppliedRevision: p.AppliedRevision}, OriginProposalID: p.OriginProposalID}
	if old, ok := records[p.CutoverID]; ok {
		record.Sequence = old.Sequence
	}
	if err = m.saveCutover(ctx, &record, "queued", "queued", ""); err != nil {
		return empty, err
	}
	m.launchCutover(p, record)
	return record.ProxyCutoverView, nil
}
