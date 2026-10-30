package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/packetcapture"
	"github.com/ctf-service-manager/ctf-service-manager/internal/packets"
	proxyengine "github.com/ctf-service-manager/ctf-service-manager/internal/proxy"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

type captureRevision struct {
	Policy     packetcapture.Policy `json:"policy"`
	TargetIDs  []string             `json:"target_ids"`
	ProposalID domain.ID            `json:"proposal_id"`
	Authority  domain.Digest        `json:"authority"`
	Actor      domain.ID            `json:"actor"`
	At         time.Time            `json:"at"`
}
type captureProposal struct {
	transport.CapturePreview
	BaseRevision uint64        `json:"base_revision"`
	FileDigest   string        `json:"file_digest"`
	Authority    domain.Digest `json:"authority"`
	Actor        domain.ID     `json:"actor"`
}

func defaultCapturePolicy() packetcapture.Policy {
	return packetcapture.Policy{SchemaVersion: 1, Revision: 1, Snaplen: 0, MaxPacketsPerSecond: 1000, Interfaces: []packetcapture.InterfacePolicy{}}
}
func captureLease(p packetcapture.Policy) packetcapture.Policy {
	if p.Enabled {
		p.LeaseUntil = time.Now().UTC().Add(10 * time.Second)
	} else {
		p.LeaseUntil = time.Time{}
	}
	return p
}
func captureDigest(p packetcapture.Policy) (string, error) {
	p, e := packetcapture.NormalizePolicy(captureLease(p))
	if e != nil {
		return "", e
	}
	return packetcapture.PolicyDigest(p), nil
}
func (m *Manager) captureAuthority() domain.Digest {
	raw, _ := json.Marshal(m.Config.Capture)
	return domain.Hash(raw)
}
func (m *Manager) latestCapture(ctx context.Context) (captureRevision, int, error) {
	latest := captureRevision{Policy: defaultCapturePolicy(), TargetIDs: []string{}}
	records, e := m.Store.List(ctx, "capture_revision", "capture")
	if e != nil {
		return latest, 0, e
	}
	for _, r := range records {
		var v captureRevision
		if json.Unmarshal(r.Payload, &v) != nil {
			return latest, 0, errors.New("invalid stored capture policy")
		}
		if v.Policy.Revision > latest.Policy.Revision {
			latest = v
		}
	}
	return latest, len(records), nil
}
func (m *Manager) captureRoot() (*os.Root, error) {
	dir := m.Config.Capture.PolicyDirectory
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("private capture policy directory unavailable")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return nil, errors.New("capture policy owner invalid")
	}
	return os.OpenRoot(dir)
}
func (m *Manager) captureFile() (packetcapture.Policy, string, error) {
	var p packetcapture.Policy
	root, e := m.captureRoot()
	if e != nil {
		return p, "", e
	}
	defer root.Close()
	before, e := root.Lstat("policy.json")
	if os.IsNotExist(e) {
		return p, "missing", nil
	}
	if e != nil {
		return p, "", e
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() || st.Nlink != 1 || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 {
		return p, "", errors.New("capture desired policy must be a private regular executor-owned file")
	}
	f, e := root.OpenFile("policy.json", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return p, "", e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(before, opened) {
		return p, "", errors.New("capture desired policy changed")
	}
	raw, e := io.ReadAll(io.LimitReader(f, packetcapture.MaxPolicyBytes+1))
	if e != nil || len(raw) > packetcapture.MaxPolicyBytes {
		return p, "", errors.New("capture policy exceeds budget")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF {
		return p, "", errors.New("invalid capture desired policy")
	}
	digest, e := captureDigest(p)
	return p, digest, e
}
func (m *Manager) exportCapture(p packetcapture.Policy) error {
	root, e := m.captureRoot()
	if e != nil {
		return e
	}
	defer root.Close()
	name := ".policy-" + string(NewID(""))
	f, e := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer root.Remove(name)
	raw, e := json.Marshal(p)
	if e == nil {
		_, e = f.Write(append(raw, '\n'))
	}
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	if e = root.Rename(name, "policy.json"); e != nil {
		return e
	}
	d, e := root.Open(".")
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func (m *Manager) captureFileCurrent(latest captureRevision) (string, error) {
	p, d, e := m.captureFile()
	if e != nil {
		return "", e
	}
	if d == "missing" {
		return d, nil
	}
	want, e := captureDigest(latest.Policy)
	if e != nil {
		return "", e
	}
	if p.Revision > latest.Policy.Revision || p.Revision == latest.Policy.Revision && d != want {
		return "", proxyInput("Capture desired file changed outside confirmed history; local review is required")
	}
	return d, nil
}
func (m *Manager) CapturePolicy(ctx context.Context) (transport.CapturePolicyView, error) {
	m.captureMu.Lock()
	defer m.captureMu.Unlock()
	v, _, e := m.latestCapture(ctx)
	if e != nil {
		return transport.CapturePolicyView{}, e
	}
	return m.captureView(ctx, v), nil
}
func (m *Manager) captureView(ctx context.Context, v captureRevision) transport.CapturePolicyView {
	out := transport.CapturePolicyView{Configured: m.Config.Capture.Enabled, Policy: v.Policy, SelectedTargetIDs: append([]string{}, v.TargetIDs...), DesiredRevision: v.Policy.Revision, Activation: "disabled"}
	if !out.Configured {
		return out
	}
	var status packetcapture.Status
	if e := m.captureRPC(ctx, "GET", "/v1/status", nil, &status); e != nil {
		out.Activation = "unavailable"
		out.Error = "Capture control unavailable"
	} else {
		out.AppliedRevision = status.Revision
		desiredDigest, _ := captureDigest(v.Policy)
		matches := status.Revision == v.Policy.Revision && status.Digest == desiredDigest
		if v.Policy.Enabled {
			out.Activation = "pending"
			if matches && status.Running && !status.LeaseExpired {
				out.Activation = "active"
			}
			if status.LeaseExpired {
				out.Activation = "paused"
				out.Error = "Runtime lease expired; review current targets"
			}
		} else if status.Running || !matches {
			out.Activation = "pending"
		}
	}
	if m.captureError != "" {
		out.Error = m.captureError
		out.Activation = "paused"
	}
	return out
}
func (m *Manager) CapturePreview(ctx context.Context, in transport.CapturePreviewRequest) (transport.CapturePreview, error) {
	// Match registration/admission lock order; cutover may hold both before it
	// pauses capture. Capture publication never acquires these locks in reverse.
	m.registrationMu.Lock()
	defer m.registrationMu.Unlock()
	m.submitMu.Lock()
	defer m.submitMu.Unlock()
	m.captureMu.Lock()
	defer m.captureMu.Unlock()
	var empty transport.CapturePreview
	if !m.Config.Capture.Enabled {
		return empty, proxyInput("Packet capture is not configured")
	}
	if in.Initiator.Validate() != nil {
		return empty, proxyInput("Authenticated actor required")
	}
	if e := m.requireNoPendingCutover(ctx); e != nil {
		return empty, e
	}
	latest, count, e := m.latestCapture(ctx)
	if e != nil {
		return empty, e
	}
	if count >= 512 {
		return empty, proxyInput("Capture policy history budget exhausted")
	}
	if latest.Policy.Revision != in.ExpectedRevision {
		return empty, proxyInput("Capture policy changed; refresh")
	}
	fileDigest, e := m.captureFileCurrent(latest)
	if e != nil {
		return empty, e
	}
	proposals, e := m.Store.List(ctx, "capture_proposal", "capture")
	if e != nil {
		return empty, e
	}
	if len(proposals) >= 1024 {
		return empty, proxyInput("Capture preview history budget exhausted")
	}
	var observed packetcapture.Status
	if e = m.captureRPC(ctx, "GET", "/v1/status", nil, &observed); e != nil {
		return empty, e
	}
	targets, e := m.CaptureTargets(ctx)
	if e != nil {
		return empty, e
	}
	selected, e := captureSelection(targets, in.TargetIDs)
	if e != nil {
		return empty, e
	}
	policy, e := capturePolicyFor(max(latest.Policy.Revision, observed.Revision)+1, in, selected)
	if e != nil {
		return empty, e
	}
	if e = m.captureIdle(ctx, policy); e != nil {
		return empty, e
	}
	if e = m.captureRPC(ctx, "POST", "/v1/preflight", captureLease(policy), new(any)); e != nil {
		return empty, e
	}
	ids := append([]string{}, in.TargetIDs...)
	sort.Strings(ids)
	p := captureProposal{CapturePreview: transport.CapturePreview{ProposalID: NewID("capture-preview-"), Policy: policy, SelectedTargetIDs: ids, PreviousPolicy: latest.Policy, ObservedAppliedRevision: observed.Revision, Warnings: []string{"Passive capture does not forward or block traffic. Only one verified private Docker bridge per application is supported.", "After a container or interface identity change, capture pauses and requires a fresh preview. Kernel drops are unknown unless reported explicitly.", "TCP streams and gRPC decoding are not part of packet capture. TLS bytes remain encrypted; full payload capture may include flags and credentials."}, ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}, BaseRevision: latest.Policy.Revision, FileDigest: fileDigest, Authority: m.captureAuthority(), Actor: in.Initiator}
	raw, _ := json.Marshal(p)
	p.Digest = domain.Hash(raw)
	if e = m.Store.PutImmutable(ctx, "capture_proposal", p.ProposalID, "capture", p); e != nil {
		return empty, e
	}
	return p.CapturePreview, nil
}
func (m *Manager) CaptureConfirm(ctx context.Context, in transport.ProxyConfirmRequest) (transport.CapturePolicyView, error) {
	m.registrationMu.Lock()
	defer m.registrationMu.Unlock()
	m.submitMu.Lock()
	defer m.submitMu.Unlock()
	m.captureMu.Lock()
	defer m.captureMu.Unlock()
	var empty transport.CapturePolicyView
	if !m.Config.Capture.Enabled || in.Initiator.Validate() != nil || in.ProposalID.Validate() != nil || in.Digest.Validate() != nil {
		return empty, proxyInput("Valid capture proposal, digest and authenticated actor required")
	}
	unlock, e := proxyengine.LockPolicyDirectory(m.Config.Capture.PolicyDirectory)
	if e != nil {
		return empty, e
	}
	defer unlock()
	var p captureProposal
	if e = m.Store.Get(ctx, "capture_proposal", in.ProposalID, &p); e != nil {
		return empty, e
	}
	if p.Digest != in.Digest || p.Actor != in.Initiator {
		return empty, proxyInput("Capture digest or actor mismatch")
	}
	latest, count, e := m.latestCapture(ctx)
	if e != nil {
		return empty, e
	}
	if latest.ProposalID == in.ProposalID {
		return m.captureView(ctx, latest), nil
	}
	if count >= 512 || !p.ExpiresAt.After(time.Now()) || latest.Policy.Revision != p.BaseRevision || p.Authority != m.captureAuthority() {
		return empty, proxyInput("Capture preview expired or installation policy changed")
	}
	fileDigest, e := m.captureFileCurrent(latest)
	if e != nil {
		return empty, e
	}
	if fileDigest != p.FileDigest {
		return empty, proxyInput("Capture desired policy changed after preview")
	}
	if e = m.requireNoPendingCutover(ctx); e != nil {
		return empty, e
	}
	if e = m.captureIdle(ctx, p.Policy); e != nil {
		return empty, e
	}
	targets, e := m.CaptureTargets(ctx)
	if e != nil {
		return empty, e
	}
	selected, e := captureSelection(targets, p.SelectedTargetIDs)
	if e != nil {
		return empty, e
	}
	fresh, e := capturePolicyFor(p.Policy.Revision, transport.CapturePreviewRequest{Enabled: p.Policy.Enabled, Snaplen: p.Policy.Snaplen, MaxPacketsPerSecond: p.Policy.MaxPacketsPerSecond}, selected)
	if e != nil {
		return empty, e
	}
	a, _ := captureDigest(fresh)
	b, _ := captureDigest(p.Policy)
	if a != b {
		return empty, proxyInput("Capture endpoint mapping changed")
	}
	var status packetcapture.Status
	if e = m.captureRPC(ctx, "GET", "/v1/status", nil, &status); e != nil {
		return empty, e
	}
	if status.Revision != p.ObservedAppliedRevision {
		return empty, proxyInput("Capture applied revision changed after preview")
	}
	if e = m.captureRPC(ctx, "POST", "/v1/preflight", captureLease(p.Policy), new(any)); e != nil {
		return empty, e
	}
	record := captureRevision{Policy: p.Policy, TargetIDs: p.SelectedTargetIDs, ProposalID: p.ProposalID, Authority: p.Authority, Actor: p.Actor, At: time.Now().UTC()}
	if e = m.Store.PutImmutable(ctx, "capture_revision", domain.ID(fmt.Sprintf("capture-policy-%020d", p.Policy.Revision)), "capture", record); e != nil {
		return empty, e
	}
	if e = m.exportCapture(captureLease(record.Policy)); e != nil {
		m.captureError = "Confirmed policy publication pending"
	} else {
		m.captureError = ""
	}
	return m.captureView(ctx, record), nil
}
func (m *Manager) captureIdle(ctx context.Context, p packetcapture.Policy) error {
	selected := map[domain.ID]bool{}
	for _, i := range p.Interfaces {
		for _, e := range i.Endpoints {
			selected[domain.ID(e.ServiceID)] = true
		}
	}
	operations, e := m.Store.ListOperations(ctx)
	if e != nil {
		return e
	}
	for _, op := range operations {
		if selected[op.Spec.ServiceID] && (op.State == domain.OperationRunning || op.State == domain.OperationQueued) {
			return proxyInput("Selected service has pending operations; capture is paused until runtime is stable")
		}
	}
	return m.requireNoPendingCutover(ctx)
}
func (m *Manager) packetsClient() (*packets.Client, error) {
	if !m.Config.Capture.Enabled {
		return nil, proxyInput("Packet capture is not configured")
	}
	token, e := readProxyToken(m.Config.Capture.PacketsTokenFile)
	if e != nil {
		return nil, e
	}
	return packets.NewUnixClient(strings.TrimPrefix(m.Config.Capture.PacketsURL, "unix://"), token)
}
func (m *Manager) PacketList(ctx context.Context, q packets.Query) (packets.Page, error) {
	c, e := m.packetsClient()
	if e != nil {
		return packets.Page{}, e
	}
	defer c.Close()
	return c.List(ctx, q)
}
func (m *Manager) PacketRaw(ctx context.Context, id string) (packets.Record, error) {
	c, e := m.packetsClient()
	if e != nil {
		return packets.Record{}, e
	}
	defer c.Close()
	return c.Raw(ctx, id)
}
func (m *Manager) PacketExport(ctx context.Context, q packets.ExportRequest) (packets.Export, error) {
	c, e := m.packetsClient()
	if e != nil {
		return packets.Export{}, e
	}
	defer c.Close()
	return c.ExportPCAP(ctx, q)
}
func (m *Manager) PacketStatus(ctx context.Context) (transport.PacketStatus, error) {
	out := transport.PacketStatus{Configured: m.Config.Capture.Enabled}
	if !out.Configured {
		return out, nil
	}
	if e := m.captureRPC(ctx, "GET", "/v1/status", nil, &out.Capture); e != nil {
		out.Error = "Capture control unavailable"
	}
	if c, e := m.packetsClient(); e == nil {
		defer c.Close()
		if out.Store, e = c.Status(ctx); e != nil {
			out.Error = "Packet archive unavailable"
		}
	} else {
		out.Error = "Packet archive unavailable"
	}
	m.captureMu.Lock()
	if m.captureError != "" {
		out.Error = m.captureError
	}
	m.captureMu.Unlock()
	return out, nil
}

// Only the unique executor worker owns runtime leases. Read-only Manager.Open
// users do not start a publisher. A crashed worker cannot leave stale scope on.
func (m *Manager) runCapturePublisher(ctx context.Context) func() {
	if !m.Config.Capture.Enabled {
		return func() {}
	}
	run, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			m.captureMu.Lock()
			attempt, stop := context.WithTimeout(run, 6*time.Second)
			e := m.publishCapture(attempt)
			stop()
			if e != nil {
				m.captureError = "Capture paused: runtime or policy changed; refresh targets and confirm a new preview"
			} else {
				m.captureError = ""
			}
			m.captureMu.Unlock()
			select {
			case <-run.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return func() { cancel(); <-done; m.pauseCapture(context.Background()) }
}
func (m *Manager) publishCapture(ctx context.Context) error {
	latest, count, e := m.latestCapture(ctx)
	if e != nil || count == 0 {
		return e
	}
	if latest.Authority != m.captureAuthority() {
		return errors.New("capture authority changed")
	}
	unlock, e := proxyengine.LockPolicyDirectory(m.Config.Capture.PolicyDirectory)
	if e != nil {
		return e
	}
	defer unlock()
	if _, e = m.captureFileCurrent(latest); e != nil {
		return e
	}
	if latest.Policy.Enabled {
		if e = m.captureIdle(ctx, latest.Policy); e != nil {
			return e
		}
		targets, e := m.CaptureTargets(ctx)
		if e != nil {
			return e
		}
		if _, e = captureSelection(targets, latest.TargetIDs); e != nil {
			return e
		}
	}
	return m.exportCapture(captureLease(latest.Policy))
}

// Stop observation before executor-controlled recreation, including cutover.
// If control is down, waiting out the bounded last lease keeps IP reuse safe;
// game forwarding never depends on the packet archive.
func (m *Manager) pauseCapture(ctx context.Context) {
	if !m.Config.Capture.Enabled {
		return
	}
	m.captureMu.Lock()
	defer m.captureMu.Unlock()
	pause, stop := context.WithTimeout(ctx, 2*time.Second)
	var status packetcapture.Status
	e := m.captureRPC(pause, "POST", "/v1/pause", nil, &status)
	stop()
	if e != nil {
		select {
		case <-ctx.Done():
		case <-time.After(11 * time.Second):
		}
	}
	m.captureError = "Capture paused while service runtime changes"
}
