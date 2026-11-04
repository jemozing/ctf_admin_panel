package executor

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	proxyengine "github.com/ctf-service-manager/ctf-service-manager/internal/proxy"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func TestPublicProxyBackendRequiresLoopbackObservation(t *testing.T) {
	for _, tc := range []struct {
		listen, waf string
		allowed     bool
	}{
		{"127.0.0.1", "observe_only", true},
		{"::1", "", true},
		{"127.0.0.1", "enforce", false},
		{"127.0.0.1", "off", false},
		{"0.0.0.0", "observe_only", false},
		{"192.0.2.1", "observe_only", false},
	} {
		target := transport.ProxyTarget{PrivateBinding: false}
		err := validateProxyBackendMode(target, netip.MustParseAddr(tc.listen), tc.waf)
		if (err == nil) != tc.allowed {
			t.Errorf("listener %s with WAF %q: %v", tc.listen, tc.waf, err)
		}
	}
}

// No Docker client is constructed: an empty registry still exercises the real
// database, preview digest, authenticated control API, and policy publication.
func proxyControlFixture(t *testing.T) (*Manager, *proxyengine.Engine) {
	t.Helper()
	base := t.TempDir()
	state, desired := filepath.Join(base, "executor"), filepath.Join(base, "desired")
	for name, mode := range map[string]os.FileMode{state: 0700, desired: 0750} {
		if err := os.Mkdir(name, mode); err != nil {
			t.Fatal(err)
		}
	}
	db, err := store.Open(filepath.Join(state, "executor.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	engine, err := proxyengine.NewEngine(proxyengine.Options{StateDirectory: filepath.Join(base, "runtime")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close(context.Background()) })
	policy := proxyengine.Policy{SchemaVersion: 1, Revision: 1, Routes: []proxyengine.Route{}}
	if err = engine.Apply(policy); err != nil {
		t.Fatal(err)
	}
	const token = "isolated-test-control-token-00000000000000"
	handler, err := engine.ControlHandler(token)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	tokenFile := filepath.Join(base, "control-token")
	if err = os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Store: db, Config: config.Config{Development: true, StateDirectory: state, Storage: config.StoragePolicy{MinimumFreeBytes: 1, MinimumFreeInodes: 1}, Proxy: config.ProxyPolicy{Enabled: true, PolicyDirectory: desired, ControlURL: server.URL, ControlTokenFile: tokenFile, AllowedListenIPs: []string{"127.0.0.1"}, ListenPortMin: 18000, ListenPortMax: 18100, ProxyGID: 11004}}}
	if err = m.exportProxyPolicy(policy); err != nil {
		t.Fatal(err)
	}
	return m, engine
}

func proxyEmptyPreview(t *testing.T, m *Manager, revision uint64) transport.ProxyPreview {
	t.Helper()
	p, err := m.ProxyPreview(context.Background(), transport.ProxyPreviewRequest{ExpectedRevision: revision, Routes: []transport.ProxyRouteInput{}, Initiator: "admin-test"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func proxyPublishedPolicy(t *testing.T, m *Manager) proxyengine.Policy {
	t.Helper()
	p, err := proxyengine.LoadPolicyFile(filepath.Join(m.Config.Proxy.PolicyDirectory, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func proxyRevisionCount(t *testing.T, m *Manager) int {
	t.Helper()
	records, err := m.Store.List(context.Background(), "proxy_revision", "proxy")
	if err != nil {
		t.Fatal(err)
	}
	return len(records)
}

func TestProxyPreviewConfirmPublicationAndActivation(t *testing.T) {
	ctx := context.Background()
	m, engine := proxyControlFixture(t)
	p := proxyEmptyPreview(t, m, 1)
	if p.Policy.Revision != 2 || p.PreviousPolicy.Revision != 1 || p.ObservedAppliedRevision != 1 || p.Digest == "" || p.ProposalID == "" {
		t.Fatalf("preview did not freeze before/after and observed state: %+v", p)
	}
	if got := proxyPublishedPolicy(t, m).Revision; got != 1 {
		t.Fatalf("preview published revision %d", got)
	}
	confirmation := transport.ProxyConfirmRequest{ProposalID: p.ProposalID, Digest: p.Digest, Initiator: "admin-test"}
	tampered := confirmation
	tampered.Digest = domain.Hash([]byte("different policy"))
	if _, err := m.ProxyConfirm(ctx, tampered); err == nil {
		t.Fatal("confirmation accepted a digest the administrator did not review")
	}
	if proxyRevisionCount(t, m) != 0 || proxyPublishedPolicy(t, m).Revision != 1 {
		t.Fatal("rejected digest changed immutable history or desired policy")
	}
	result, err := m.ProxyConfirm(ctx, confirmation)
	if err != nil {
		t.Fatal(err)
	}
	if result.DesiredRevision != 2 || result.AppliedRevision != 1 || result.Activation != "pending" {
		t.Fatalf("confirmation confused publication with activation: %+v", result)
	}
	if got := proxyPublishedPolicy(t, m); proxyengine.PolicyDigest(got) != proxyengine.PolicyDigest(p.Policy) {
		t.Fatal("published policy differs from the reviewed policy")
	}
	info, err := os.Stat(filepath.Join(m.Config.Proxy.PolicyDirectory, "policy.json"))
	if err != nil || info.Mode().Perm()&0027 != 0 {
		t.Fatalf("desired policy permissions are too broad: %v %v", info, err)
	}
	view, err := m.ProxyPolicy(ctx)
	if err != nil || view.DesiredRevision != 2 || view.AppliedRevision != 1 || view.Activation != "pending" {
		t.Fatalf("desired/applied readback before runtime apply: %+v %v", view, err)
	}
	if err = engine.Apply(p.Policy); err != nil {
		t.Fatal(err)
	}
	view, err = m.ProxyPolicy(ctx)
	if err != nil || view.DesiredRevision != 2 || view.AppliedRevision != 2 || view.Activation != "applied" {
		t.Fatalf("runtime activation was not observed: %+v %v", view, err)
	}
	if _, err = m.ProxyConfirm(ctx, confirmation); err != nil {
		t.Fatalf("idempotent confirmation retry failed: %v", err)
	}
	if got := proxyRevisionCount(t, m); got != 1 {
		t.Fatalf("confirmation retry created %d immutable revisions", got)
	}
	records, _ := m.Store.List(ctx, "proxy_revision", "proxy")
	var stored proxyRevision
	if json.Unmarshal(records[0].Payload, &stored) != nil || stored.ProposalID != p.ProposalID || stored.Digest != p.Digest || stored.Actor != "admin-test" || stored.Policy.Revision != 2 {
		t.Fatal("confirmed history lost the reviewed identity or authenticated actor")
	}
}

func TestProxyEmergencyRevisionSurvivesStaleConfirmAndPublisher(t *testing.T) {
	ctx := context.Background()
	m, _ := proxyControlFixture(t)
	first := proxyEmptyPreview(t, m, 1)
	confirmed := transport.ProxyConfirmRequest{ProposalID: first.ProposalID, Digest: first.Digest, Initiator: "admin-test"}
	if _, err := m.ProxyConfirm(ctx, confirmed); err != nil {
		t.Fatal(err)
	}
	stale := proxyEmptyPreview(t, m, 2)
	emergency := proxyengine.Policy{SchemaVersion: 1, Revision: 9, Routes: []proxyengine.Route{}}
	unlock, err := proxyengine.LockPolicyDirectory(m.Config.Proxy.PolicyDirectory)
	if err != nil {
		t.Fatal(err)
	}
	err = proxyengine.WriteDesiredPolicy(filepath.Join(m.Config.Proxy.PolicyDirectory, "policy.json"), emergency, proxyengine.PolicyDigest(first.Policy))
	unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.ProxyConfirm(ctx, transport.ProxyConfirmRequest{ProposalID: stale.ProposalID, Digest: stale.Digest, Initiator: "admin-test"}); err == nil {
		t.Fatal("stale preview replaced a higher emergency revision")
	}
	view, err := m.ProxyConfirm(ctx, confirmed)
	if err != nil || view.DesiredRevision != 9 || view.Activation != "superseded" {
		t.Fatalf("retry of old confirmation failed to expose superseding policy: %+v %v", view, err)
	}
	if err = m.reconcileProxyPublication(ctx); err != nil {
		t.Fatal(err)
	}
	if proxyPublishedPolicy(t, m).Revision != 9 || proxyRevisionCount(t, m) != 1 {
		t.Fatal("publisher or stale retry rolled back the emergency policy")
	}
	view, err = m.ProxyPolicy(ctx)
	if err != nil || !view.ExternalRevision || view.DesiredRevision != 9 || view.AppliedRevision != 1 {
		t.Fatalf("higher external desired revision is not visible: %+v %v", view, err)
	}
	next := proxyEmptyPreview(t, m, 9)
	if next.PreviousPolicy.Revision != 9 || next.Policy.Revision != 10 || next.ObservedAppliedRevision != 1 {
		t.Fatalf("next preview did not use emergency revision as its base: %+v", next)
	}
}

func TestProxyPublisherRecoversOnlyConfirmedPolicy(t *testing.T) {
	ctx := context.Background()
	m, _ := proxyControlFixture(t)
	p := proxyEmptyPreview(t, m, 1)
	if err := m.reconcileProxyPublication(ctx); err != nil {
		t.Fatal(err)
	}
	if proxyPublishedPolicy(t, m).Revision != 1 {
		t.Fatal("publication worker exported an unconfirmed proposal")
	}
	if _, err := m.ProxyConfirm(ctx, transport.ProxyConfirmRequest{ProposalID: p.ProposalID, Digest: p.Digest, Initiator: "admin-test"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(m.Config.Proxy.PolicyDirectory, "policy.json")); err != nil {
		t.Fatal(err)
	}
	if err := m.reconcileProxyPublication(ctx); err != nil {
		t.Fatal(err)
	}
	if got := proxyPublishedPolicy(t, m); proxyengine.PolicyDigest(got) != proxyengine.PolicyDigest(p.Policy) || proxyRevisionCount(t, m) != 1 {
		t.Fatal("publication recovery lost or duplicated the confirmed policy")
	}
}

func TestProxyConfirmationRejectsChangedAppliedRevision(t *testing.T) {
	m, engine := proxyControlFixture(t)
	p := proxyEmptyPreview(t, m, 1)
	if err := engine.Apply(proxyengine.Policy{SchemaVersion: 1, Revision: 7, Routes: []proxyengine.Route{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ProxyConfirm(context.Background(), transport.ProxyConfirmRequest{ProposalID: p.ProposalID, Digest: p.Digest, Initiator: "admin-test"}); err == nil {
		t.Fatal("confirmation accepted an unreviewed runtime revision change")
	}
	if proxyPublishedPolicy(t, m).Revision != 1 || proxyRevisionCount(t, m) != 0 {
		t.Fatal("stale applied revision mutated desired state")
	}
	next := proxyEmptyPreview(t, m, 1)
	if next.Policy.Revision != 8 || next.ObservedAppliedRevision != 7 {
		t.Fatalf("preview did not advance beyond the runtime's revision: %+v", next)
	}
}

func TestProxyConfirmationDoesNotDeadlockRegistrationSubmission(t *testing.T) {
	m, _ := proxyControlFixture(t)
	registrationReady := make(chan struct{})
	allowSubmit := make(chan struct{})
	registrationDone := make(chan bool, 1)
	go func() {
		// ApproveRegistration owns this lock before entering Submit. Keep the
		// same ownership, but bound its second acquisition so a regression can
		// release its own first lock and let Confirm and fixture cleanup finish.
		m.registrationMu.Lock()
		defer m.registrationMu.Unlock()
		close(registrationReady)
		<-allowSubmit
		deadline := time.NewTimer(500 * time.Millisecond)
		defer deadline.Stop()
		retry := time.NewTicker(time.Millisecond)
		defer retry.Stop()
		for {
			if m.submitMu.TryLock() {
				m.submitMu.Unlock()
				registrationDone <- true
				return
			}
			select {
			case <-deadline.C:
				registrationDone <- false
				return
			case <-retry.C:
			}
		}
	}()
	<-registrationReady
	confirmationDone := make(chan error, 1)
	go func() {
		_, err := m.ProxyConfirm(context.Background(), transport.ProxyConfirmRequest{ProposalID: "missing-proxy-preview", Digest: domain.Hash([]byte("unavailable proposal")), Initiator: "admin-test"})
		confirmationDone <- err
	}()
	// Give Confirm time to reach the held registration lock. With the old
	// inversion it holds submitMu here, so the registration flow cannot enter
	// Submit; with the shared order it leaves submitMu available.
	time.Sleep(100 * time.Millisecond)
	close(allowSubmit)
	var registrationSucceeded bool
	select {
	case registrationSucceeded = <-registrationDone:
	case <-time.After(2 * time.Second):
		t.Fatal("registration-shaped submission did not leave its bounded wait")
	}
	select {
	case err := <-confirmationDone:
		if err == nil {
			t.Error("confirmation unexpectedly accepted a missing proposal")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("confirmation did not finish after the registration lock was released")
	}
	if !registrationSucceeded {
		t.Fatal("Confirm acquired submitMu while waiting for registrationMu, blocking registration submission")
	}
}
