package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/packetcapture"
	"github.com/ctf-service-manager/ctf-service-manager/internal/packets"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

type captureOfflineSink struct{}

func (captureOfflineSink) Submit(packets.Record) bool { return true }

type captureOfflineSource struct{}

func (captureOfflineSource) Read(ctx context.Context) (packetcapture.Frame, error) {
	<-ctx.Done()
	return packetcapture.Frame{}, ctx.Err()
}
func (captureOfflineSource) Close() error { return nil }

// Empty registry and injected Ethernet sources exercise real SQLite, policy
// preview/publication, authenticated control and leases without using Docker
// or opening a raw socket. HTTP is fixture-only; production config requires Unix.
func captureControlFixture(t *testing.T) (*Manager, *packetcapture.Engine) {
	t.Helper()
	base := t.TempDir()
	state, desired := filepath.Join(base, "executor"), filepath.Join(base, "desired")
	for _, dir := range []string{state, desired} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	db, err := store.Open(filepath.Join(state, "executor.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	engine, err := packetcapture.New(packetcapture.Options{Sink: captureOfflineSink{}, Interfaces: func() ([]packetcapture.Interface, error) {
		return []packetcapture.Interface{{Name: "br-test", Index: 7, Up: true, Supported: true}}, nil
	}, OpenSource: func(packetcapture.Interface) (packetcapture.Source, error) { return captureOfflineSource{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := engine.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	if err := engine.Apply(defaultCapturePolicy()); err != nil {
		t.Fatal(err)
	}
	const token = "capture-offline-control-000000000000000000"
	handler, err := engine.ControlHandler(token)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	tokenFile := filepath.Join(base, "token")
	if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Store: db, Config: config.Config{Development: true, StateDirectory: state, Storage: config.StoragePolicy{MinimumFreeBytes: 1, MinimumFreeInodes: 1}, Capture: config.CapturePolicy{Enabled: true, PolicyDirectory: desired, ControlURL: server.URL, ControlTokenFile: tokenFile, AllowedInterfaces: []string{"br-test"}}}}
	if err := m.exportCapture(defaultCapturePolicy()); err != nil {
		t.Fatal(err)
	}
	return m, engine
}
func captureEmptyPreview(t *testing.T, m *Manager, revision uint64) transport.CapturePreview {
	t.Helper()
	p, err := m.CapturePreview(context.Background(), transport.CapturePreviewRequest{ExpectedRevision: revision, Enabled: false, Snaplen: 0, MaxPacketsPerSecond: 1000, TargetIDs: []string{}, Initiator: "admin-test"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func captureConfirmInput(p transport.CapturePreview) transport.ProxyConfirmRequest {
	return transport.ProxyConfirmRequest{ProposalID: p.ProposalID, Digest: p.Digest, Initiator: "admin-test"}
}
func captureRevisionCount(t *testing.T, m *Manager) int {
	t.Helper()
	rows, err := m.Store.List(context.Background(), "capture_revision", "capture")
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}
func capturePublished(t *testing.T, m *Manager) packetcapture.Policy {
	t.Helper()
	p, _, err := m.captureFile()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCapturePreviewConfirmIdentityAndActivation(t *testing.T) {
	ctx := context.Background()
	m, engine := captureControlFixture(t)
	p := captureEmptyPreview(t, m, 1)
	if p.Policy.Revision != 2 || p.PreviousPolicy.Revision != 1 || p.ObservedAppliedRevision != 1 || p.Digest == "" || p.ProposalID == "" {
		t.Fatalf("preview missing frozen state: %+v", p)
	}
	if capturePublished(t, m).Revision != 1 || captureRevisionCount(t, m) != 0 {
		t.Fatal("preview published unconfirmed changes")
	}
	valid := captureConfirmInput(p)
	for _, mutate := range []func(*transport.ProxyConfirmRequest){func(in *transport.ProxyConfirmRequest) { in.Digest = domain.Hash([]byte("other")) }, func(in *transport.ProxyConfirmRequest) { in.Initiator = "other-admin" }} {
		bad := valid
		mutate(&bad)
		if _, err := m.CaptureConfirm(ctx, bad); err == nil {
			t.Fatal("digest/actor mismatch accepted")
		}
	}
	view, err := m.CaptureConfirm(ctx, valid)
	if err != nil || view.DesiredRevision != 2 || view.AppliedRevision != 1 || view.Activation != "pending" {
		t.Fatalf("confirmed desire confused with applied state: %+v %v", view, err)
	}
	if capturePublished(t, m).Revision != 2 || captureRevisionCount(t, m) != 1 {
		t.Fatal("confirmation did not publish exactly one immutable revision")
	}
	info, err := os.Stat(filepath.Join(m.Config.Capture.PolicyDirectory, "policy.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("published desired policy permissions")
	}
	if err := engine.Apply(captureLease(p.Policy)); err != nil {
		t.Fatal(err)
	}
	view, err = m.CapturePolicy(ctx)
	if err != nil || view.AppliedRevision != 2 || view.Activation != "disabled" {
		t.Fatalf("disabled runtime acknowledgement: %+v %v", view, err)
	}
	if _, err := m.CaptureConfirm(ctx, valid); err != nil {
		t.Fatal(err)
	}
	if captureRevisionCount(t, m) != 1 {
		t.Fatal("retry duplicated confirmed history")
	}
	rows, _ := m.Store.List(ctx, "capture_revision", "capture")
	var stored captureRevision
	if json.Unmarshal(rows[0].Payload, &stored) != nil || stored.Actor != "admin-test" || stored.ProposalID != p.ProposalID || stored.Authority != m.captureAuthority() {
		t.Fatal("confirmed history lost authority or authenticated actor")
	}
}

func TestCapturePreviewRejectsConcurrentChanges(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *Manager, *packetcapture.Engine)
	}{
		{"authority", func(t *testing.T, m *Manager, _ *packetcapture.Engine) {
			m.Config.Capture.AllowedInterfaces = append(m.Config.Capture.AllowedInterfaces, "br-other")
		}},
		{"applied", func(t *testing.T, _ *Manager, e *packetcapture.Engine) {
			p := defaultCapturePolicy()
			p.Revision = 7
			if err := e.Apply(p); err != nil {
				t.Fatal(err)
			}
		}},
		{"desired", func(t *testing.T, m *Manager, _ *packetcapture.Engine) {
			p := defaultCapturePolicy()
			p.Revision = 9
			if err := m.exportCapture(p); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, e := captureControlFixture(t)
			p := captureEmptyPreview(t, m, 1)
			tc.change(t, m, e)
			if _, err := m.CaptureConfirm(context.Background(), captureConfirmInput(p)); err == nil {
				t.Fatal("concurrent authority/runtime/file change accepted")
			}
			if captureRevisionCount(t, m) != 0 {
				t.Fatal("stale proposal entered confirmed history")
			}
		})
	}
	m, e := captureControlFixture(t)
	p := defaultCapturePolicy()
	p.Revision = 7
	if err := e.Apply(p); err != nil {
		t.Fatal(err)
	}
	preview := captureEmptyPreview(t, m, 1)
	if preview.Policy.Revision != 8 || preview.ObservedAppliedRevision != 7 {
		t.Fatalf("new preview failed to advance runtime revision: %+v", preview)
	}
	if _, err := m.CapturePreview(context.Background(), transport.CapturePreviewRequest{ExpectedRevision: 9, MaxPacketsPerSecond: 1000, Initiator: "admin-test"}); err == nil {
		t.Fatal("wrong expected revision accepted")
	}
}

func TestCapturePublisherOnlyConfirmedAndRetryAfterWrite(t *testing.T) {
	ctx := context.Background()
	m, _ := captureControlFixture(t)
	p := captureEmptyPreview(t, m, 1)
	if err := m.publishCapture(ctx); err != nil {
		t.Fatal(err)
	}
	if capturePublished(t, m).Revision != 1 {
		t.Fatal("publisher applied unconfirmed proposal")
	}
	if _, err := m.CaptureConfirm(ctx, captureConfirmInput(p)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(m.Config.Capture.PolicyDirectory, "policy.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CaptureConfirm(ctx, captureConfirmInput(p)); err != nil {
		t.Fatalf("confirmed retry rejected after desired-file loss: %v", err)
	}
	if err := m.publishCapture(ctx); err != nil {
		t.Fatal(err)
	}
	if capturePublished(t, m).Revision != 2 || captureRevisionCount(t, m) != 1 {
		t.Fatal("confirmed publication recovery diverged")
	}
	emergency := defaultCapturePolicy()
	emergency.Revision = 99
	if err := m.exportCapture(emergency); err != nil {
		t.Fatal(err)
	}
	if err := m.publishCapture(ctx); err == nil {
		t.Fatal("publisher overwrote external newer revision")
	}
	if capturePublished(t, m).Revision != 99 {
		t.Fatal("newer desired policy lost")
	}
}

func TestCaptureConfirmedWriteSurvivesPublicationFailure(t *testing.T) {
	ctx := context.Background()
	m, engine := captureControlFixture(t)
	p := captureEmptyPreview(t, m, 1)
	token, err := os.ReadFile(m.Config.Capture.ControlTokenFile)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := engine.ControlHandler(string(token))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(m.Config.Capture.PolicyDirectory, "policy.json")
	backup := filepath.Join(m.Config.Capture.PolicyDirectory, "policy-backup.json")
	var injected atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
		if r.Method == http.MethodPost && r.URL.Path == "/v1/preflight" && injected.CompareAndSwap(false, true) {
			// Inject failure after file-CAS/preflight, immediately before the
			// immutable confirmation and desired-file publication boundary.
			if err := os.Rename(path, backup); err != nil {
				t.Error(err)
				return
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Error(err)
			}
		}
	}))
	defer server.Close()
	// Bind a fresh fixture proposal to the wrapped local control origin before
	// confirmation; production proposals are immutable after the real preview.
	var saved captureProposal
	if err := m.Store.Get(ctx, "capture_proposal", p.ProposalID, &saved); err != nil {
		t.Fatal(err)
	}
	m.Config.Capture.ControlURL = server.URL
	saved.Authority = m.captureAuthority()
	saved.ProposalID = NewID("capture-preview-")
	raw, _ := json.Marshal(saved)
	saved.Digest = domain.Hash(raw)
	if err := m.Store.PutImmutable(ctx, "capture_proposal", saved.ProposalID, "capture", saved); err != nil {
		t.Fatal(err)
	}
	in := transport.ProxyConfirmRequest{ProposalID: saved.ProposalID, Digest: saved.Digest, Initiator: "admin-test"}
	view, err := m.CaptureConfirm(ctx, in)
	if err != nil || !injected.Load() || captureRevisionCount(t, m) != 1 || view.DesiredRevision != 2 || view.Error == "" {
		t.Fatalf("confirmed history lost after publication failure: %+v %v", view, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, path); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CaptureConfirm(ctx, in); err != nil {
		t.Fatalf("confirmed retry failed: %v", err)
	}
	if err := m.publishCapture(ctx); err != nil {
		t.Fatal(err)
	}
	if capturePublished(t, m).Revision != 2 || captureRevisionCount(t, m) != 1 {
		t.Fatal("publication recovery duplicated or lost confirmed revision")
	}
}

func TestCapturePolicyFileSafety(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"mode", func(t *testing.T, path string) {
			if err := os.Chmod(path, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink", func(t *testing.T, path string) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(t.TempDir(), "other")
			if err := os.WriteFile(outside, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, path); err != nil {
				t.Fatal(err)
			}
		}},
		{"hardlink", func(t *testing.T, path string) {
			if err := os.Link(path, filepath.Join(t.TempDir(), "other")); err != nil {
				t.Fatal(err)
			}
		}},
		{"fifo", func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized", func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte(strings.Repeat(" ", packetcapture.MaxPolicyBytes+1)), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"unknownJSON", func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte(`{"schema_version":1,"revision":1,"enabled":false,"snaplen":0,"max_packets_per_second":1000,"interfaces":[],"unexpected":true}`), 0600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := captureControlFixture(t)
			tc.mutate(t, filepath.Join(m.Config.Capture.PolicyDirectory, "policy.json"))
			if _, err := m.CapturePreview(context.Background(), transport.CapturePreviewRequest{ExpectedRevision: 1, MaxPacketsPerSecond: 1000, Initiator: "admin-test"}); err == nil {
				t.Fatal("unsafe desired file accepted")
			}
			if captureRevisionCount(t, m) != 0 {
				t.Fatal("unsafe file entered history")
			}
		})
	}
}

func testCaptureTarget() transport.CaptureTarget {
	return transport.CaptureTarget{ID: "target-a", ServiceID: "game-a", Component: "web", Interface: "br-test", IfIndex: 7, Protocol: "tcp", TargetPort: 8080, Addresses: []string{"172.20.0.2"}}
}
func enabledTestCapturePolicy(t *testing.T) packetcapture.Policy {
	t.Helper()
	p, err := capturePolicyFor(2, transport.CapturePreviewRequest{Enabled: true, Snaplen: 0, MaxPacketsPerSecond: 1000}, []transport.CaptureTarget{testCaptureTarget()})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestCaptureSelectionAndLeaseScope(t *testing.T) {
	a := testCaptureTarget()
	targets := transport.CaptureTargets{Targets: []transport.CaptureTarget{a}}
	for _, ids := range [][]string{{"missing"}, {a.ID, a.ID}} {
		if _, err := captureSelection(targets, ids); err == nil {
			t.Fatal("stale/duplicate target accepted")
		}
	}
	p := enabledTestCapturePolicy(t)
	if !p.LeaseUntil.IsZero() || len(p.Interfaces) != 1 || p.Interfaces[0].Endpoints[0].Address != "172.20.0.2" || p.Interfaces[0].Endpoints[0].Port != 8080 {
		t.Fatalf("desired policy did not freeze derived endpoint: %+v", p)
	}
	leased := captureLease(p)
	if !leased.LeaseUntil.After(time.Now().Add(9*time.Second)) || leased.LeaseUntil.After(time.Now().Add(11*time.Second)) {
		t.Fatal("runtime lease not bounded10seconds")
	}
	if packetcapture.PolicyDigest(leased) != packetcapture.PolicyDigest(p) {
		t.Fatal("lease renewal changed reviewed configuration digest")
	}
	other := a
	other.ID = "target-b"
	other.Interface = "br-other"
	other.IfIndex = 8
	if _, err := capturePolicyFor(2, transport.CapturePreviewRequest{Enabled: true, MaxPacketsPerSecond: 1000}, []transport.CaptureTarget{a, other}); err == nil {
		t.Fatal("same endpoint observed on two interfaces")
	}
	if _, err := capturePolicyFor(2, transport.CapturePreviewRequest{Enabled: false, MaxPacketsPerSecond: 1000}, []transport.CaptureTarget{a}); err == nil {
		t.Fatal("disabled policy retained observation targets")
	}
}

func TestCapturePublisherRefusesStaleAuthorityTargetsAndBusyService(t *testing.T) {
	for _, name := range []string{"authority", "stale-target", "busy-service", "running-service"} {
		t.Run(name, func(t *testing.T) {
			m, _ := captureControlFixture(t)
			p := enabledTestCapturePolicy(t)
			record := captureRevision{Policy: p, TargetIDs: []string{"missing-runtime-target"}, ProposalID: "confirmed", Authority: m.captureAuthority(), Actor: "admin-test", At: time.Now().UTC()}
			if name == "authority" {
				record.Authority = domain.Hash([]byte("old installation"))
			}
			if err := m.Store.PutImmutable(context.Background(), "capture_revision", "capture-policy-00000000000000000002", "capture", record); err != nil {
				t.Fatal(err)
			}
			if name == "busy-service" || name == "running-service" {
				spec := domain.OperationSpec{ID: "queued-capture-service", Kind: domain.OperationRestart, Initiator: "admin-test", IdempotencyKey: "capture-test", ServiceID: "game-a", ExpectedPolicyRevision: 1, ExpectedTreeDigest: domain.Hash([]byte("tree")), Resources: []string{"service:game-a"}, TimeoutSeconds: 60}
				op, err := domain.NewOperation(spec, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := m.Store.BeginOperation(context.Background(), op, domain.Hash([]byte("queued"))); err != nil {
					t.Fatal(err)
				}
				if name == "running-service" {
					if err := m.Store.Acquire(context.Background(), op.Spec.ID, op.Spec.Resources); err != nil {
						t.Fatal(err)
					}
					previous := op.UpdatedAt
					op.State = domain.OperationRunning
					op.UpdatedAt = previous.Add(time.Nanosecond)
					if err := m.Store.UpdateOperation(context.Background(), op, previous); err != nil {
						t.Fatal(err)
					}
				}
				if err := m.captureIdle(context.Background(), p); err == nil {
					t.Fatal("queued mutation did not block capture")
				}
			}
			if err := m.publishCapture(context.Background()); err == nil {
				t.Fatal("publisher renewed unverified authority/scope")
			}
			published := capturePublished(t, m)
			if published.Revision != 1 || published.Enabled || !published.LeaseUntil.IsZero() {
				t.Fatal("failed publication renewed runtime lease")
			}
		})
	}
}

func TestCapturePauseAcknowledgedBeforeMutation(t *testing.T) {
	m, engine := captureControlFixture(t)
	p := enabledTestCapturePolicy(t)
	if err := engine.Apply(captureLease(p)); err != nil {
		t.Fatal(err)
	}
	if !engine.Status().Running {
		t.Fatal("fixture not capturing")
	}
	m.pauseCapture(context.Background())
	status := engine.Status()
	if status.Running || !status.Paused {
		t.Fatalf("pause not acknowledged: %+v", status)
	}
	if m.captureError == "" {
		t.Fatal("pause status invisible")
	}
}

func TestCaptureRecoveryCompensationPausesOnlyAfterMutation(t *testing.T) {
	for _, mutated := range []bool{false, true} {
		t.Run(fmt.Sprint(mutated), func(t *testing.T) {
			m, engine := captureControlFixture(t)
			if err := engine.Apply(captureLease(enabledTestCapturePolicy(t))); err != nil {
				t.Fatal(err)
			}
			spec := domain.OperationSpec{ID: "recovery-operation", Kind: domain.OperationRestart, Initiator: "admin-test", IdempotencyKey: "capture-recovery", ServiceID: "missing-service", ExpectedPolicyRevision: 1, ExpectedTreeDigest: domain.Hash([]byte("tree")), Resources: []string{"service:missing-service"}, TimeoutSeconds: 60}
			op, err := domain.NewOperation(spec, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := m.Store.BeginOperation(context.Background(), op, domain.Hash([]byte("recovery"))); err != nil {
				t.Fatal(err)
			}
			op.MutationStarted = mutated
			err = m.compensate(context.Background(), op, transport.SubmitRequest{}, transport.PreviewResult{})
			if mutated {
				if err == nil || engine.Status().Running || !engine.Status().Paused {
					t.Fatalf("compensation did not pause before service lookup: %v %+v", err, engine.Status())
				}
			} else if err != nil || !engine.Status().Running || engine.Status().Paused {
				t.Fatalf("no-mutation compensation changed capture: %v %+v", err, engine.Status())
			}
		})
	}
}

func TestCaptureViewRequiresMatchingDigestAndDisabledAcknowledgement(t *testing.T) {
	m, engine := captureControlFixture(t)
	p := enabledTestCapturePolicy(t)
	if err := engine.Apply(captureLease(p)); err != nil {
		t.Fatal(err)
	}
	want := p
	want.Snaplen = 128
	view := m.captureView(context.Background(), captureRevision{Policy: want})
	if view.Activation == "active" {
		t.Fatal("same revision with different payload scope reported active")
	}
	disabled := defaultCapturePolicy()
	disabled.Revision = 3
	view = m.captureView(context.Background(), captureRevision{Policy: disabled})
	if view.Activation != "pending" {
		t.Fatalf("older live capture reported disabled: %+v", view)
	}
	if err := engine.Apply(disabled); err != nil {
		t.Fatal(err)
	}
	view = m.captureView(context.Background(), captureRevision{Policy: disabled})
	if view.Activation != "disabled" {
		t.Fatalf("disabled acknowledgement missing: %+v", view)
	}
}
