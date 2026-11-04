package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	proxyengine "github.com/ctf-service-manager/ctf-service-manager/internal/proxy"
	"github.com/ctf-service-manager/ctf-service-manager/internal/traffic"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

type proxyBinding struct {
	ServiceID      domain.ID     `json:"service_id"`
	PolicyRevision uint64        `json:"policy_revision"`
	StateSequence  uint64        `json:"state_sequence"`
	Configuration  domain.Digest `json:"configuration"`
	RuntimeDigest  domain.Digest `json:"runtime_digest"`
}
type proxyProposal struct {
	transport.ProxyPreview
	BaseRevision      uint64         `json:"base_revision"`
	AppliedRevision   uint64         `json:"expected_applied_revision"`
	DesiredFileDigest domain.Digest  `json:"desired_file_digest"`
	Bindings          []proxyBinding `json:"bindings"`
	Authority         domain.Digest  `json:"authority"`
	Actor             domain.ID      `json:"actor"`
}
type proxyRevision struct {
	Policy     proxyengine.Policy `json:"policy"`
	ProposalID domain.ID          `json:"proposal_id"`
	Digest     domain.Digest      `json:"digest"`
	Actor      domain.ID          `json:"actor"`
	At         time.Time          `json:"at"`
}

func proxyInput(message string) error { return &transport.ProxyInputError{Message: message} }
func (m *Manager) requireProxy() error {
	if !m.Config.Proxy.Enabled {
		return proxyInput("HTTP Proxy is not configured in this installation")
	}
	return nil
}
func readProxyToken(name string) (string, error) {
	before, err := os.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0027 != 0 {
		return "", errors.New("proxy credential file must be private and regular")
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() || st.Nlink != 1 {
		return "", errors.New("proxy credential ownership is invalid")
	}
	fd, err := syscall.Open(name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", errors.New("proxy credentials unavailable")
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return "", errors.New("proxy credential file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return "", errors.New("proxy credentials unavailable")
	}
	value := strings.TrimSuffix(string(raw), "\n")
	if len(value) < 32 || len(value) > 4096 || strings.ContainsAny(value, " \t\r\n\x00") {
		return "", errors.New("invalid proxy credential")
	}
	return value, nil
}
func (m *Manager) proxyRPC(ctx context.Context, method, path string, input, out any) error {
	if err := m.requireProxy(); err != nil {
		return err
	}
	return localDataPlaneRPC(ctx, m.Config.Proxy.ControlURL, m.Config.Proxy.ControlTokenFile, method, path, input, out)
}

func localDataPlaneRPC(ctx context.Context, controlURL, tokenFile, method, path string, input, out any) error {
	token, err := readProxyToken(tokenFile)
	if err != nil {
		return err
	}
	u, err := url.Parse(controlURL)
	if err != nil {
		return errors.New("invalid proxy control configuration")
	}
	tr := &http.Transport{Proxy: nil, ResponseHeaderTimeout: 6 * time.Second, MaxIdleConns: 1}
	origin := controlURL
	if u.Scheme == "unix" {
		socket := u.Path
		origin = "http://proxy-control"
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socket)
		}
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var body io.Reader
	if input != nil {
		raw, e := json.Marshal(input)
		if e != nil {
			return e
		}
		if len(raw) > 256*1024 {
			return proxyInput("proxy policy exceeds request budget")
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, origin+path, body)
	if err != nil {
		return errors.New("proxy request unavailable")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("proxy control is unavailable")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024+1))
	if err != nil || len(raw) > 4*1024*1024 {
		return errors.New("proxy control response exceeded budget")
	}
	if resp.StatusCode != 200 {
		return proxyInput("Proxy rejected the request; the last working policy is retained")
	}
	if out != nil && json.Unmarshal(raw, out) != nil {
		return errors.New("invalid proxy control response")
	}
	return nil
}
func (m *Manager) trafficClient() (*traffic.Client, error) {
	if err := m.requireProxy(); err != nil {
		return nil, err
	}
	token, err := readProxyToken(m.Config.Proxy.TrafficTokenFile)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(m.Config.Proxy.TrafficURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "unix" {
		return traffic.NewUnixClient(u.Path, token)
	}
	return traffic.NewClient(m.Config.Proxy.TrafficURL, token)
}
func (m *Manager) TrafficList(ctx context.Context, q traffic.Query) (traffic.Page, error) {
	c, e := m.trafficClient()
	if e != nil {
		return traffic.Page{}, e
	}
	defer c.Close()
	return c.List(ctx, q)
}
func (m *Manager) TrafficDetail(ctx context.Context, id string) (traffic.Exchange, error) {
	c, e := m.trafficClient()
	if e != nil {
		return traffic.Exchange{}, e
	}
	defer c.Close()
	return c.Detail(ctx, id)
}
func (m *Manager) latestProxyRevision(ctx context.Context) (proxyRevision, int, error) {
	var latest proxyRevision
	records, e := m.Store.List(ctx, "proxy_revision", "proxy")
	if e != nil {
		return latest, 0, e
	}
	for _, r := range records {
		var v proxyRevision
		if json.Unmarshal(r.Payload, &v) != nil {
			return latest, 0, errors.New("invalid stored proxy policy")
		}
		if v.Policy.Revision > latest.Policy.Revision {
			latest = v
		}
	}
	if latest.Policy.SchemaVersion == 0 {
		latest.Policy = proxyengine.Policy{SchemaVersion: 1, Routes: []proxyengine.Route{}}
	}
	return latest, len(records), nil
}

// The emergency CLI is a separate authorized writer. A higher valid revision
// in the shared desired file is visible to the panel and is never overwritten
// with an older database record.
func (m *Manager) proxyFileSnapshot() (proxyengine.Policy, domain.Digest, bool, error) {
	var p proxyengine.Policy
	info, err := os.Lstat(m.Config.Proxy.PolicyDirectory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return p, "", false, errors.New("trusted proxy policy directory unavailable")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Geteuid() {
		return p, "", false, errors.New("proxy policy directory ownership invalid")
	}
	root, err := os.OpenRoot(m.Config.Proxy.PolicyDirectory)
	if err != nil {
		return p, "", false, err
	}
	defer root.Close()
	before, err := root.Lstat("policy.json")
	if os.IsNotExist(err) {
		return p, domain.Hash([]byte("missing-policy-file")), false, nil
	}
	if err != nil {
		return p, "", false, err
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !before.Mode().IsRegular() || before.Mode().Perm()&0027 != 0 || !ok || int(st.Uid) != os.Geteuid() || st.Nlink != 1 {
		return p, "", false, errors.New("proxy desired policy must be a private executor-owned regular file")
	}
	f, err := root.OpenFile("policy.json", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return p, "", false, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return p, "", false, errors.New("proxy desired policy changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(f, proxyengine.MaxPolicyBytes+1))
	if err != nil {
		return p, "", false, err
	}
	digest := domain.Hash(raw)
	if len(raw) > proxyengine.MaxPolicyBytes {
		return p, digest, true, errors.New("proxy desired policy exceeds bounded file budget")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF {
		return p, digest, true, errors.New("invalid desired proxy policy; use local recovery")
	}
	p, err = proxyengine.NormalizePolicy(p)
	if err != nil {
		return p, digest, true, errors.New("invalid desired proxy policy; last-known-good remains active")
	}
	return p, digest, true, nil
}
func (m *Manager) effectiveProxySnapshot(ctx context.Context) (proxyRevision, int, bool, domain.Digest, error) {
	v, count, err := m.latestProxyRevision(ctx)
	if err != nil {
		return v, count, false, "", err
	}
	if !m.Config.Proxy.Enabled {
		return v, count, false, domain.Hash([]byte("proxy-disabled")), nil
	}
	desired, digest, exists, err := m.proxyFileSnapshot()
	if err != nil {
		return v, count, false, digest, err
	}
	if exists && desired.Revision > v.Policy.Revision {
		v.Policy = desired
		return v, count, true, digest, nil
	}
	if exists && desired.Revision == v.Policy.Revision && proxyengine.PolicyDigest(desired) != proxyengine.PolicyDigest(v.Policy) {
		return v, count, false, digest, errors.New("same proxy revision has changed; use local recovery")
	}
	return v, count, false, digest, nil
}
func (m *Manager) effectiveProxyRevision(ctx context.Context) (proxyRevision, int, bool, error) {
	v, n, external, _, err := m.effectiveProxySnapshot(ctx)
	return v, n, external, err
}
func (m *Manager) ProxyStatus(ctx context.Context) (transport.ProxyStatus, error) {
	result := transport.ProxyStatus{Configured: m.Config.Proxy.Enabled}
	if !result.Configured {
		return result, nil
	}
	v, _, _, err := m.effectiveProxyRevision(ctx)
	if err != nil {
		return result, err
	}
	result.DesiredRevision = v.Policy.Revision
	if err = m.proxyRPC(ctx, "GET", "/v1/status", nil, &result.Proxy); err != nil {
		result.Error = "Proxy is unavailable"
	} else {
		result.AppliedRevision = result.Proxy.AppliedRevision
	}
	c, err := m.trafficClient()
	if err != nil {
		result.Error = "Recorder connection is not configured"
	} else {
		defer c.Close()
		if result.Recorder, err = c.Status(ctx); err != nil {
			result.Error = "Traffic recorder is unavailable"
		}
	}
	m.proxyMu.Lock()
	if m.proxyError != "" {
		result.Error = m.proxyError
	}
	m.proxyMu.Unlock()
	return result, nil
}
func (m *Manager) ProxyPolicy(ctx context.Context) (transport.ProxyPolicyView, error) {
	v, _, external, err := m.effectiveProxyRevision(ctx)
	if err != nil {
		return transport.ProxyPolicyView{}, err
	}
	result := transport.ProxyPolicyView{Configured: m.Config.Proxy.Enabled, Policy: v.Policy, DesiredRevision: v.Policy.Revision, Activation: "disabled", ExternalRevision: external}
	if !result.Configured {
		return result, nil
	}
	var status proxyengine.Status
	if m.proxyRPC(ctx, "GET", "/v1/status", nil, &status) != nil {
		result.Activation = "unavailable"
		result.Error = "Proxy control is unavailable"
		return result, nil
	}
	result.AppliedRevision = status.AppliedRevision
	result.Activation = "pending"
	if result.DesiredRevision == 0 {
		result.Activation = "empty"
	} else if result.AppliedRevision == result.DesiredRevision {
		result.Activation = "applied"
	}
	if status.LastError != "" {
		result.Error = status.LastError
	}
	return result, nil
}

// privatePublication describes an observed fixed TCP publication.
func privatePublication(raw string) (host string, published, target int, private bool, ok bool) {
	left, right, found := strings.Cut(raw, "->")
	if !found {
		return
	}
	r, proto, found := strings.Cut(right, "/")
	if !found || proto != "tcp" {
		return
	}
	i := strings.LastIndex(left, ":")
	if i < 0 {
		return
	}
	ip, err := netip.ParseAddr(strings.Trim(left[:i], "[]"))
	if err != nil {
		return
	}
	published, err = strconv.Atoi(left[i+1:])
	if err != nil || published < 1 || published > 65535 {
		return
	}
	target, err = strconv.Atoi(r)
	if err != nil || target < 1 || target > 65535 {
		return
	}
	host = ip.Unmap().String()
	private = ip.Unmap().IsLoopback()
	ok = true
	return
}
func proxyCandidateTargets(s domain.Service, actual []docker.Container, allowPublicObservation bool, model map[string]any) []transport.ProxyTarget {
	roles := map[string]domain.ComponentRole{}
	for _, v := range s.Containers {
		roles[v.Component] = v.Role
	}
	components, _ := model["services"].(map[string]any)
	selected := map[string]transport.ProxyTarget{}
	for _, c := range actual {
		if roles[c.Component] != domain.RoleApplication || c.State != "running" {
			continue
		}
		public := false
		for _, raw := range c.Ports {
			_, _, _, private, ok := privatePublication(raw)
			if ok && !private {
				public = true
			}
		}
		if public && !allowPublicObservation {
			continue
		}
		approved, _ := components[c.Component].(map[string]any)
		for _, raw := range c.Ports {
			ip, published, target, private, ok := privatePublication(raw)
			if !ok || (public && !approvedProxyObservationPort(approved, ip, published, target)) {
				continue
			}
			if !private {
				if ip != "0.0.0.0" {
					continue
				}
				// An observed IPv4 wildcard publication also answers on
				// loopback. Never dial a container IP or external address.
				ip = "127.0.0.1"
			}
			value := transport.ProxyTarget{ServiceID: s.ID, ServiceName: s.Name, Component: c.Component, UpstreamPort: target, UpstreamAddress: "http://" + net.JoinHostPort(ip, strconv.Itoa(published)), PrivateBinding: !public}
			key := c.Component + ":" + strconv.Itoa(target)
			if old, exists := selected[key]; !exists || value.UpstreamAddress < old.UpstreamAddress {
				selected[key] = value
			}
		}
	}
	result := []transport.ProxyTarget{}
	for _, v := range selected {
		result = append(result, v)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Component+result[i].UpstreamAddress < result[j].Component+result[j].UpstreamAddress
	})
	return result
}

// An automatically assigned or mismatched Docker host port must not become a
// saved observation route. An omitted approved host IP is the IPv4 wildcard.
func approvedProxyObservationPort(component map[string]any, host string, published, target int) bool {
	ports, _ := component["ports"].([]any)
	for _, raw := range ports {
		port, _ := raw.(map[string]any)
		protocol, _ := port["protocol"].(string)
		if protocol != "" && protocol != "tcp" {
			continue
		}
		hostIP, _ := port["host_ip"].(string)
		if hostIP == "" {
			hostIP = "0.0.0.0"
		}
		ip, err := netip.ParseAddr(hostIP)
		if err != nil || ip.Unmap().String() != host {
			continue
		}
		portPublished, err := cutoverPortNumber(port["published"])
		if err != nil || portPublished != published {
			continue
		}
		portTarget, err := cutoverPortNumber(port["target"])
		if err == nil && portTarget == target {
			return true
		}
	}
	return false
}

func (m *Manager) proxyServiceTargets(ctx context.Context, s domain.Service) ([]transport.ProxyTarget, proxyBinding, error) {
	var binding proxyBinding
	st, e := m.state(ctx, s)
	if e != nil {
		return nil, binding, e
	}
	digest, e := m.activeConfigurationDigest(ctx, s, st)
	if e != nil {
		return nil, binding, e
	}
	model, e := m.observationConfiguration(ctx, s)
	if e != nil {
		return nil, binding, e
	}
	if st.CurrentReleaseID != "" {
		release, e := m.loadRelease(ctx, s, st.CurrentReleaseID)
		if e != nil {
			return nil, binding, e
		}
		pinModelImages(model, release.Spec().Images)
	}
	actual, e := m.verifyRuntime(ctx, s, st, model)
	if e != nil {
		return nil, binding, e
	}
	targets := proxyCandidateTargets(s, actual, m.Config.Proxy.AllowPublicBackendObservation, model)
	raw, _ := json.Marshal(struct {
		Containers []domain.ContainerRef
		Targets    []transport.ProxyTarget
	}{st.Containers, targets})
	binding = proxyBinding{ServiceID: s.ID, PolicyRevision: s.PolicyRevision, StateSequence: st.Sequence, Configuration: digest, RuntimeDigest: domain.Hash(raw)}
	return targets, binding, nil
}
func (m *Manager) proxyTargets(ctx context.Context) (transport.ProxyTargets, []proxyBinding, error) {
	result := transport.ProxyTargets{
		Targets: []transport.ProxyTarget{}, Unavailable: []transport.ProxyUnavailableTarget{},
		AllowedListenIPs: append([]string{}, m.Config.Proxy.AllowedListenIPs...), AllowedListenEndpoints: append([]string(nil), m.Config.Proxy.AllowedListenEndpoints...),
		ListenPortMin: m.Config.Proxy.ListenPortMin, ListenPortMax: m.Config.Proxy.ListenPortMax,
	}
	if e := m.requireProxy(); e != nil {
		return result, nil, nil
	}
	services, e := m.Store.ListServices(ctx)
	if e != nil {
		return result, nil, e
	}
	bindings := []proxyBinding{}
	for _, s := range services {
		targets, binding, e := m.proxyServiceTargets(ctx, s)
		if e == nil {
			result.Targets = append(result.Targets, targets...)
			bindings = append(bindings, binding)
		}
		for _, c := range s.Containers {
			if c.Role != domain.RoleApplication {
				continue
			}
			found := false
			for _, v := range targets {
				found = found || v.Component == c.Component
			}
			if found {
				continue
			}
			reason := "Application requires a running, verified private loopback TCP publication; occupied/public ports need a separate cutover plan"
			if m.Config.Proxy.AllowPublicBackendObservation {
				reason = "Application requires a running, verified loopback or IPv4 wildcard TCP publication"
			}
			if e != nil {
				reason = "Approved runtime could not be verified; resolve service drift or initialization first"
			}
			result.Unavailable = append(result.Unavailable, transport.ProxyUnavailableTarget{ServiceID: s.ID, Component: c.Component, Reason: reason})
		}
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].ServiceID < bindings[j].ServiceID })
	sort.Slice(result.Targets, func(i, j int) bool {
		a, b := result.Targets[i], result.Targets[j]
		return string(a.ServiceID)+a.Component+a.UpstreamAddress < string(b.ServiceID)+b.Component+b.UpstreamAddress
	})
	return result, bindings, nil
}
func (m *Manager) ProxyTargets(ctx context.Context) (transport.ProxyTargets, error) {
	v, _, e := m.proxyTargets(ctx)
	return v, e
}
func (m *Manager) proxyAuthority() domain.Digest {
	raw, _ := json.Marshal(m.Config.Proxy)
	return domain.Hash(raw)
}

func validateProxyBackendMode(target transport.ProxyTarget, listen netip.Addr, wafMode string) error {
	if target.PrivateBinding {
		return nil
	}
	if !listen.Unmap().IsLoopback() || (wafMode != "" && wafMode != "observe_only") {
		return proxyInput("A directly published backend requires a loopback proxy listener and observe_only WAF")
	}
	return nil
}

func (m *Manager) ProxyPreview(ctx context.Context, in transport.ProxyPreviewRequest) (transport.ProxyPreview, error) {
	m.proxyMu.Lock()
	defer m.proxyMu.Unlock()
	var empty transport.ProxyPreview
	if err := m.requireNoPendingCutover(ctx); err != nil {
		return empty, err
	}
	if err := m.requireProxy(); err != nil {
		return empty, err
	}
	if in.Initiator.Validate() != nil || len(in.Routes) > 32 {
		return empty, proxyInput("Invalid actor or route budget")
	}
	latest, count, _, fileDigest, err := m.effectiveProxySnapshot(ctx)
	if err != nil {
		return empty, err
	}
	if count >= 1024 {
		return empty, proxyInput("Proxy policy history budget is exhausted")
	}
	if latest.Policy.Revision != in.ExpectedRevision {
		return empty, proxyInput("Proxy policy changed; refresh before preview")
	}
	var observed proxyengine.Status
	if err = m.proxyRPC(ctx, "GET", "/v1/status", nil, &observed); err != nil {
		return empty, err
	}
	targets, bindings, err := m.proxyTargets(ctx)
	if err != nil {
		return empty, err
	}
	wanted := proxyengine.Policy{SchemaVersion: 1, Revision: max(latest.Policy.Revision, observed.AppliedRevision) + 1, Routes: []proxyengine.Route{}}
	existing := map[string]proxyengine.Route{}
	for _, r := range latest.Policy.Routes {
		existing[r.ID] = r
	}
	observesPublic := false
	for _, r := range in.Routes {
		ip, port, e := net.SplitHostPort(r.Listen)
		addr, ipErr := netip.ParseAddr(ip)
		p, portErr := strconv.Atoi(port)
		if e != nil || ipErr != nil || portErr != nil || !m.Config.Proxy.AllowsListener(addr, p) {
			return empty, proxyInput("Listener is outside the administrator-approved IP/port range and exact endpoints")
		}
		var target transport.ProxyTarget
		matches := 0
		for _, t := range targets.Targets {
			if t.ServiceID == r.ServiceID && t.Component == r.Component && t.UpstreamPort == r.UpstreamPort {
				target = t
				matches++
			}
		}
		if matches != 1 {
			return empty, proxyInput("Choose a unique verified publication of a registered application component")
		}
		if err := validateProxyBackendMode(target, addr, r.WAF.Mode); err != nil {
			return empty, err
		}
		observesPublic = observesPublic || !target.PrivateBinding
		id := r.ID
		if id == "" {
			id = string(NewID("route-"))
		}
		old, exists := existing[id]
		if !exists && r.WAF.Mode != "" && r.WAF.Mode != "observe_only" {
			return empty, proxyInput("A new route must start in observe_only mode")
		}
		if exists && (old.ServiceID != string(r.ServiceID) || old.Component != r.Component) {
			return empty, proxyInput("An existing route cannot be reassigned to another service or component")
		}
		if r.WAF.Mode == "enforce" && !in.ConfirmChecker {
			return empty, proxyInput("Confirm checker and observe-only verification before enabling enforcement")
		}
		wanted.Routes = append(wanted.Routes, proxyengine.Route{ID: id, ServiceID: string(r.ServiceID), Component: r.Component, Listen: net.JoinHostPort(addr.Unmap().String(), strconv.Itoa(p)), Host: r.Host, Upstream: target.UpstreamAddress, Protocol: r.Protocol, TLS: r.TLS, TrustedProxyCIDRs: r.TrustedProxyCIDRs, Capture: r.Capture, WAF: r.WAF, Limits: r.Limits})
	}
	wanted, err = proxyengine.NormalizePolicy(wanted)
	if err != nil {
		return empty, proxyInput(err.Error())
	}
	if err = m.validateActiveCutoverRoutes(ctx, wanted); err != nil {
		return empty, err
	}
	var preflight any
	if err = m.proxyRPC(ctx, "POST", "/v1/preflight", wanted, &preflight); err != nil {
		return empty, err
	}
	proposals, err := m.Store.List(ctx, "proxy_proposal", "proxy")
	if err != nil {
		return empty, err
	}
	if len(proposals) >= 1024 {
		return empty, proxyInput("Proxy preview history budget is exhausted")
	}
	warnings := []string{"This plan adds proxy listeners without moving existing game ports.", "Checker/NAT exceptions and limits must be verified before enforce."}
	if observesPublic {
		warnings = append(warnings, "Requests to the existing direct ports bypass the proxy and its traffic log.")
	}
	p := proxyProposal{ProxyPreview: transport.ProxyPreview{ProposalID: NewID("proxy-plan-"), Policy: wanted, PreviousPolicy: latest.Policy, ObservedAppliedRevision: observed.AppliedRevision, Warnings: warnings, ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}, BaseRevision: latest.Policy.Revision, AppliedRevision: observed.AppliedRevision, Bindings: bindings, Authority: m.proxyAuthority(), DesiredFileDigest: fileDigest, Actor: in.Initiator}
	raw, _ := json.Marshal(p)
	p.Digest = domain.Hash(raw)
	if err = m.checkLocalAllocation(ctx, m.Config.StateDirectory, uint64(len(raw)+8192), 2, m.Config.Storage.Effective().StateMaxBytes); err != nil {
		return empty, err
	}
	if err = m.Store.PutImmutable(ctx, "proxy_proposal", p.ProposalID, "proxy", p); err != nil {
		return empty, err
	}
	return p.ProxyPreview, nil
}
func (m *Manager) ProxyConfirm(ctx context.Context, in transport.ProxyConfirmRequest) (transport.ProxyPolicyView, error) {
	m.proxyMu.Lock()
	defer m.proxyMu.Unlock()
	// Registration approval queues a baseline while holding registrationMu.
	// Keep that same order when excluding concurrent submissions here.
	m.registrationMu.Lock()
	defer m.registrationMu.Unlock()
	m.submitMu.Lock()
	defer m.submitMu.Unlock()
	var empty transport.ProxyPolicyView
	if err := m.requireNoPendingCutover(ctx); err != nil {
		return empty, err
	}
	if e := m.requireProxy(); e != nil {
		return empty, e
	}
	fileLock, e := proxyengine.LockPolicyDirectory(m.Config.Proxy.PolicyDirectory)
	if e != nil {
		return empty, e
	}
	defer fileLock()
	if in.Initiator.Validate() != nil {
		return empty, proxyInput("Authenticated actor required")
	}
	records, err := m.Store.List(ctx, "proxy_revision", "proxy")
	if err != nil {
		return empty, err
	}
	for _, r := range records {
		var old proxyRevision
		if json.Unmarshal(r.Payload, &old) != nil {
			return empty, errors.New("invalid proxy history")
		}
		if old.ProposalID == in.ProposalID {
			if old.Digest != in.Digest {
				return empty, proxyInput("Confirmation digest mismatch")
			}
			current, _, _, e := m.effectiveProxyRevision(ctx)
			if e != nil {
				return empty, e
			}
			if current.Policy.Revision > old.Policy.Revision {
				view, e := m.ProxyPolicy(ctx)
				view.Activation = "superseded"
				return view, e
			}
			if err = m.exportProxyPolicy(old.Policy); err != nil {
				return empty, err
			}
			return m.ProxyPolicy(ctx)
		}
	}
	var p proxyProposal
	if err = m.Store.Get(ctx, "proxy_proposal", in.ProposalID, &p); err != nil {
		return empty, err
	}
	if p.Digest != in.Digest || time.Now().After(p.ExpiresAt) || p.Authority != m.proxyAuthority() {
		return empty, proxyInput("Proxy preview expired or configuration changed; request a new preview")
	}
	latest, _, _, currentFileDigest, err := m.effectiveProxySnapshot(ctx)
	if err != nil {
		return empty, err
	}
	if latest.Policy.Revision != p.BaseRevision || currentFileDigest != p.DesiredFileDigest {
		return empty, proxyInput("Another proxy policy was confirmed; refresh preview")
	}
	_, bindings, err := m.proxyTargets(ctx)
	if err != nil {
		return empty, err
	}
	a, _ := json.Marshal(bindings)
	b, _ := json.Marshal(p.Bindings)
	if !bytes.Equal(a, b) {
		return empty, proxyInput("Registered runtime changed after preview")
	}
	ops, err := m.Store.ListOperations(ctx)
	if err != nil {
		return empty, err
	}
	for _, op := range ops {
		if !op.State.Terminal() {
			return empty, proxyInput("Finish queued/running service operations before changing proxy routes")
		}
	}
	var observed proxyengine.Status
	if err = m.proxyRPC(ctx, "GET", "/v1/status", nil, &observed); err != nil {
		return empty, err
	}
	if observed.AppliedRevision != p.AppliedRevision {
		return empty, proxyInput("Applied proxy revision changed after preview")
	}
	var preflight any
	if err = m.proxyRPC(ctx, "POST", "/v1/preflight", p.Policy, &preflight); err != nil {
		return empty, err
	}
	record := proxyRevision{Policy: p.Policy, ProposalID: in.ProposalID, Digest: in.Digest, Actor: in.Initiator, At: time.Now().UTC()}
	raw, _ := json.Marshal(record)
	if err = m.checkLocalAllocation(ctx, m.Config.StateDirectory, uint64(len(raw)+8192), 2, m.Config.Storage.Effective().StateMaxBytes); err != nil {
		return empty, err
	}
	if err = m.Store.PutImmutable(ctx, "proxy_revision", domain.ID(fmt.Sprintf("proxy-policy-%020d", p.Policy.Revision)), "proxy", record); err != nil {
		return empty, err
	}
	if err = m.exportProxyPolicy(p.Policy); err != nil {
		m.proxyError = "Confirmed policy is waiting for publication"
		return empty, err
	}
	m.proxyError = ""
	return m.ProxyPolicy(ctx)
}

func (m *Manager) exportProxyPolicy(p proxyengine.Policy) error {
	dir := m.Config.Proxy.PolicyDirectory
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return errors.New("Proxy policy output directory is unavailable or writable by others")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return errors.New("Proxy policy directory ownership invalid")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	name := ".policy-" + string(NewID(""))
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		return err
	}
	defer root.Remove(name)
	if !m.Config.Development {
		if err = f.Chown(os.Geteuid(), m.Config.Proxy.ProxyGID); err != nil {
			f.Close()
			return err
		}
	}
	raw, err := json.Marshal(p)
	if err == nil {
		_, err = f.Write(append(raw, '\n'))
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = root.Rename(name, "policy.json"); err != nil {
		return err
	}
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// reconcileProxyPublication retries only an already confirmed export. A valid
// higher emergency revision is never replaced by an older database record.
func (m *Manager) reconcileProxyPublication(ctx context.Context) error {
	if !m.Config.Proxy.Enabled {
		return nil
	}
	if err := m.requireNoPendingCutover(ctx); err != nil {
		return err
	}
	v, _, err := m.latestProxyRevision(ctx)
	if err != nil || v.Policy.Revision == 0 {
		return err
	}
	unlock, err := proxyengine.LockPolicyDirectory(m.Config.Proxy.PolicyDirectory)
	if err != nil {
		return err
	}
	defer unlock()
	_, _, external, err := m.effectiveProxyRevision(ctx)
	if err != nil || external {
		return err
	}
	current, _, exists, err := m.proxyFileSnapshot()
	if err != nil {
		return err
	}
	if exists && proxyengine.PolicyDigest(current) == proxyengine.PolicyDigest(v.Policy) {
		return nil
	}
	return m.exportProxyPolicy(v.Policy)
}
func (m *Manager) startProxyPublication() {
	if !m.Config.Proxy.Enabled {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.proxyCancel = cancel
	m.proxyWG.Add(1)
	go func() {
		defer m.proxyWG.Done()
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			m.proxyMu.Lock()
			err := m.reconcileProxyPublication(ctx)
			if err != nil {
				m.proxyError = "Confirmed proxy policy is not published"
			} else {
				m.proxyError = ""
			}
			m.proxyMu.Unlock()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
func (m *Manager) ProxyBans(ctx context.Context) (transport.ProxyBansPage, error) {
	var v transport.ProxyBansPage
	if !m.Config.Proxy.Enabled {
		v.Bans = []proxyengine.Ban{}
		return v, nil
	}
	err := m.proxyRPC(ctx, "GET", "/v1/bans", nil, &v)
	return v, err
}
func (m *Manager) ProxyBan(ctx context.Context, in transport.ProxyBanRequest) (proxyengine.Ban, error) {
	var out proxyengine.Ban
	if in.Initiator.Validate() != nil {
		return out, proxyInput("Authenticated actor required")
	}
	err := m.proxyRPC(ctx, "POST", "/v1/bans", in.BanRequest, &out)
	return out, err
}
func (m *Manager) ProxyUnban(ctx context.Context, in transport.ProxyUnbanRequest) error {
	if in.Initiator.Validate() != nil {
		return proxyInput("Authenticated actor required")
	}
	var out any
	return m.proxyRPC(ctx, "POST", "/v1/unban", in.UnbanRequest, &out)
}
