package executor

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	proxyengine "github.com/ctf-service-manager/ctf-service-manager/internal/proxy"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

// Fake Docker/Compose preserves externally owned data and permits realistic
// partial effects before an error. The real durable SQLite journal and policy
// publication path remain in use; no Docker daemon is contacted.
type fakeCutoverRuntime struct {
	mu                  sync.Mutex
	containers          []docker.Container
	calls               []string
	failAfterMutation   bool
	changeMount         bool
	failHealth          bool
	afterRecreate       func() error
	inventoryCalls      int
	blockInventoryCall  int
	entered             chan struct{}
	releaseInventory    chan struct{}
	removedApplication  *docker.Container
	privateRuntimeDrift bool
	foreignContainers   []docker.Container
}

func (f *fakeCutoverRuntime) Inventory(ctx context.Context, project string) ([]docker.Container, error) {
	f.mu.Lock()
	if project == "cutover-game" {
		f.inventoryCalls++
	}
	block := project == "cutover-game" && f.blockInventoryCall == f.inventoryCalls
	if block {
		f.mu.Unlock()
		close(f.entered)
		select {
		case <-f.releaseInventory:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		f.mu.Lock()
	}
	defer f.mu.Unlock()
	if project != "cutover-game" && project != "" {
		return nil, errors.New("unscoped inventory forbidden")
	}
	containers := append([]docker.Container{}, f.containers...)
	if project == "" {
		containers = append(containers, f.foreignContainers...)
	}
	raw, _ := json.Marshal(containers)
	var out []docker.Container
	_ = json.Unmarshal(raw, &out)
	return out, nil
}
func (f *fakeCutoverRuntime) Recreate(_ context.Context, s domain.Service, model map[string]any, component string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if component != "app" {
		return errors.New("dependency recreation forbidden")
	}
	c := model["services"].(map[string]any)[component].(map[string]any)
	ports, err := cutoverModelPorts(c)
	if err != nil {
		return err
	}
	f.calls = append(f.calls, component)
	if f.removedApplication != nil {
		copy := *f.removedApplication
		f.containers = append(f.containers, copy)
		f.removedApplication = nil
	}
	for i := range f.containers {
		if f.containers[i].Component == component {
			f.containers[i].ID = strings.Repeat(fmt.Sprintf("%x", len(f.calls)+2), 64)
			f.containers[i].ImageID = c["image"].(string)
			f.containers[i].State = "running"
			f.containers[i].Ports = nil
			for _, p := range ports {
				target, _ := cutoverPortNumber(p["target"])
				f.containers[i].Ports = append(f.containers[i].Ports, fmt.Sprintf("%s:%s->%d/tcp", p["host_ip"], p["published"], target))
			}
			if f.changeMount {
				f.containers[i].Mounts[0].Source = "foreign-volume"
			}
		}
	}
	if f.failAfterMutation {
		f.failAfterMutation = false
		return errors.New("simulated Compose connection failure after recreation")
	}
	if f.afterRecreate != nil {
		hook := f.afterRecreate
		f.afterRecreate = nil
		return hook()
	}
	return nil
}
func (f *fakeCutoverRuntime) Verify(_ context.Context, s domain.Service, before, after []docker.Container, component string, model map[string]any) ([]domain.ContainerRef, error) {
	f.mu.Lock()
	drift := f.privateRuntimeDrift
	f.mu.Unlock()
	if drift {
		return nil, errors.New("private runtime inspection drift")
	}
	if len(before) != len(after) {
		return nil, errors.New("component count changed")
	}
	refs := []domain.ContainerRef{}
	seen := map[string]bool{}
	for _, c := range after {
		if seen[c.Component] {
			return nil, errors.New("duplicate component")
		}
		seen[c.Component] = true
		var old *docker.Container
		for i := range before {
			if before[i].Component == c.Component {
				old = &before[i]
			}
		}
		if old == nil || old.ImageID != c.ImageID || !reflect.DeepEqual(old.Mounts, c.Mounts) || (component != c.Component && old.ID != c.ID) {
			return nil, errors.New("image/mount/dependency identity drift")
		}
		settings := model["services"].(map[string]any)[c.Component].(map[string]any)
		if settings["image"] != c.ImageID {
			return nil, errors.New("model image differs")
		}
		if c.Component == "app" {
			ports, err := cutoverModelPorts(settings)
			if err != nil {
				return nil, err
			}
			expected := []string{}
			for _, p := range ports {
				n, _ := cutoverPortNumber(p["target"])
				expected = append(expected, fmt.Sprintf("%s:%s->%d/tcp", p["host_ip"], p["published"], n))
			}
			if !reflect.DeepEqual(expected, c.Ports) {
				return nil, errors.New("unexpected runtime ports")
			}
		}
		role := domain.RoleApplication
		if c.Component == "db" {
			role = domain.RoleDatabase
		}
		refs = append(refs, domain.ContainerRef{Component: c.Component, ID: c.ID, ImageID: domain.Digest(c.ImageID), Role: role})
	}
	return refs, nil
}
func (f *fakeCutoverRuntime) Health(context.Context, domain.Service) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failHealth {
		f.failHealth = false
		return errors.New("checker failed")
	}
	return nil
}

type cutoverFixture struct {
	m             *Manager
	s             domain.Service
	driver        *fakeCutoverRuntime
	configuration Configuration
	digest        domain.Digest
	data          string
}

func newCutoverFixture(t *testing.T) *cutoverFixture {
	t.Helper()
	base := t.TempDir()
	state := filepath.Join(base, "state")
	desired := filepath.Join(base, "desired")
	for _, p := range []string{state, desired} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	db, err := store.Open(filepath.Join(state, "executor.db"))
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{Store: db, Config: config.Config{Development: true, StateDirectory: state, Storage: config.StoragePolicy{MinimumFreeBytes: 1, MinimumFreeInodes: 1}, Proxy: config.ProxyPolicy{Enabled: true, PolicyDirectory: desired, AllowedListenIPs: []string{"0.0.0.0", "127.0.0.1"}, ListenPortMin: 18000, ListenPortMax: 18100, BackendPortMin: 29000, BackendPortMax: 29100, ProxyGID: 11004}}}
	m.cutoverCtx, m.cutoverCancel = context.WithCancel(context.Background())
	m.cutoverReady = true
	t.Cleanup(func() { m.cutoverCancel(); m.cutoverWG.Wait(); _ = db.Close() })
	appImage, dbImage := domain.Hash([]byte("app-v1")), domain.Hash([]byte("db-fixed"))
	s := domain.Service{SchemaVersion: domain.SchemaVersion, ID: "cutover-game", Name: "Cutover", ProjectDirectory: filepath.Join(base, "active"), SourceDirectory: filepath.Join(base, "workspace"), ComposeProject: "cutover-game", ComposeFiles: []string{"compose.yaml"}, ManagedPaths: []domain.ManagedPath{{Path: "app", Kind: domain.ManagedCode}}, Targets: []string{"app"}, PolicyRevision: 1, FileMapRevision: 1, Containers: []domain.ContainerRef{{Component: "app", ID: strings.Repeat("a", 64), ImageID: appImage, Role: domain.RoleApplication}, {Component: "db", ID: strings.Repeat("b", 64), ImageID: dbImage, Role: domain.RoleDatabase}}, DataPaths: []domain.DataPath{{Name: "flags", Kind: domain.StorageNamedVolume, Source: "game-flags", Target: "/data", Component: "app", Significant: true}}}
	c := Configuration{Model: map[string]any{"services": map[string]any{"app": map[string]any{"image": string(appImage), "ports": []any{map[string]any{"target": float64(8080), "published": "18080", "host_ip": "0.0.0.0", "protocol": "tcp"}}, "volumes": []any{map[string]any{"type": "volume", "source": "flags", "target": "/data"}}}, "db": map[string]any{"image": string(dbImage)}}, "volumes": map[string]any{"flags": map[string]any{"name": "game-flags", "external": true}}}, Environment: map[string]domain.SecretVersionRef{}, FileInputs: map[string]domain.SecretVersionRef{}}
	raw, _ := json.Marshal(c)
	digest := domain.Hash(raw)
	if err = db.PutImmutable(t.Context(), "configuration", domain.ID(string(digest)[7:]), s.ID, c); err != nil {
		t.Fatal(err)
	}
	proposal, err := db.CreateProposal(t.Context(), "cutover-registration", s, digest, "admin", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ApproveProposal(t.Context(), proposal.ID, proposal.Digest, "admin", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	fixture := &cutoverFixture{m: m, s: s, configuration: c, digest: digest, data: filepath.Join(base, "flags-data")}
	fixture.release(t, "release-v1", appImage)
	st := runtimeState{ServiceID: s.ID, PolicyRevision: 1, CurrentReleaseID: "release-v1", BaselineID: "baseline", ActiveSnapshotID: "baseline", Containers: s.Containers}
	if err = m.saveState(t.Context(), &st); err != nil {
		t.Fatal(err)
	}
	driver := &fakeCutoverRuntime{containers: []docker.Container{{Component: "app", Project: s.ComposeProject, ID: s.Containers[0].ID, ImageID: string(appImage), State: "running", Health: "not_configured", Ports: []string{"0.0.0.0:18080->8080/tcp"}, Mounts: []docker.Mount{{Type: "volume", Source: "game-flags", Target: "/data"}}}, {Component: "db", Project: s.ComposeProject, ID: s.Containers[1].ID, ImageID: string(dbImage), State: "running", Health: "not_configured", Mounts: []docker.Mount{}, Ports: []string{}}}}
	m.cutoverRuntime = driver
	fixture.driver = driver
	if err = os.WriteFile(fixture.data, []byte("competition-flag-state\x00v1"), 0600); err != nil {
		t.Fatal(err)
	}
	const token = "cutover-private-test-control-token-000000000000"
	tokenFile := filepath.Join(base, "control-token")
	if err = os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	m.Config.Proxy.ControlTokenFile = tokenFile
	initial := proxyengine.Policy{SchemaVersion: 1, Revision: 1, Routes: []proxyengine.Route{}}
	if err = m.exportProxyPolicy(initial); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/v1/status":
			p, e := proxyengine.LoadPolicyFile(filepath.Join(desired, "policy.json"))
			if e != nil {
				w.WriteHeader(503)
				return
			}
			_ = json.NewEncoder(w).Encode(proxyengine.Status{Available: true, AppliedRevision: p.Revision, DesiredRevision: p.Revision, PolicyDigest: string(proxyengine.PolicyDigest(p))})
		case "/v1/preflight", "/v1/preflight-cutover":
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	m.Config.Proxy.ControlURL = server.URL
	return fixture
}
func (f *cutoverFixture) release(t *testing.T, id domain.ID, image domain.Digest) {
	t.Helper()
	release, err := domain.NewRelease(domain.ReleaseSpec{SchemaVersion: 1, ID: id, ServiceID: f.s.ID, Author: "admin", CreatedAt: time.Now().UTC(), Source: domain.ReleaseImported, SnapshotID: "baseline", TreeDigest: domain.Hash([]byte("files")), ConfigurationDigest: f.digest, PolicyRevision: 1, FileMapRevision: 1, Images: []domain.ImageRef{{Component: "app", ImageID: image, RetentionTag: retentionTag(f.s, id, "app")}, {Component: "db", ImageID: f.s.Containers[1].ImageID, RetentionTag: retentionTag(f.s, id, "db")}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.m.Store.PutImmutable(t.Context(), "release", id, f.s.ID, release); err != nil {
		t.Fatal(err)
	}
}
func (f *cutoverFixture) preview(t *testing.T) transport.ProxyCutoverPreview {
	t.Helper()
	p, err := f.m.ProxyCutoverPreview(t.Context(), transport.ProxyCutoverPreviewRequest{ServiceID: f.s.ID, Component: "app", UpstreamPort: 8080, PrivatePort: 29080, Initiator: "admin", Routes: []transport.ProxyRouteInput{{ServiceID: f.s.ID, Component: "app", UpstreamPort: 8080, Listen: "0.0.0.0:18080", Protocol: "http1", WAF: proxyengine.WAFPolicy{Mode: "observe_only"}}}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func (f *cutoverFixture) confirm(t *testing.T, p transport.ProxyCutoverPreview) transport.ProxyCutoverView {
	t.Helper()
	v, err := f.m.ProxyCutoverConfirm(t.Context(), transport.ProxyConfirmRequest{ProposalID: p.ProposalID, Digest: p.Digest, Initiator: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if v.State != "queued" {
		t.Fatalf("confirmation did not return durable queued state: %+v", v)
	}
	f.m.cutoverWG.Wait()
	views, err := f.m.ProxyCutovers(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range views {
		if v.ID == p.CutoverID {
			return v
		}
	}
	t.Fatal("cutover disappeared")
	return v
}

func TestProxyCutoverRoundTripKeepsCurrentDeploymentAndData(t *testing.T) {
	f := newCutoverFixture(t)
	p := f.preview(t)
	if len(f.driver.calls) != 0 {
		t.Fatal("preview changed containers")
	}
	v := f.confirm(t, p)
	if v.State != "active" || !v.CanReturn || v.AppliedRevision != p.Policy.Revision {
		t.Fatalf("transfer not active: %+v", v)
	}
	model, err := f.m.runtimeConfiguration(t.Context(), f.s, f.configuration)
	if err != nil {
		t.Fatal(err)
	}
	ports, _ := cutoverModelPorts(model["services"].(map[string]any)["app"].(map[string]any))
	if ports[0]["published"] != "29080" || ports[0]["host_ip"] != "127.0.0.1" {
		t.Fatal("future Deploy would expose original ports")
	}
	// Simulate a successful later Deploy using the shared runtime overlay. The
	// return must preserve its new image/release and exact named volume identity.
	newImage := domain.Hash([]byte("app-v2-after-deploy"))
	f.release(t, "release-v2", newImage)
	pinModelImages(model, []domain.ImageRef{{Component: "app", ImageID: newImage}})
	if err = f.driver.Recreate(t.Context(), f.s, model, "app"); err != nil {
		t.Fatal(err)
	}
	st, err := f.m.state(t.Context(), f.s)
	if err != nil {
		t.Fatal(err)
	}
	actual, _ := f.driver.Inventory(t.Context(), f.s.ComposeProject)
	st.CurrentReleaseID = "release-v2"
	for i := range st.Containers {
		if st.Containers[i].Component == "app" {
			st.Containers[i].ID = actual[0].ID
			st.Containers[i].ImageID = newImage
		}
	}
	if err = f.m.saveState(t.Context(), &st); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.data, []byte("competition-flag-state\x00v2"), 0600); err != nil {
		t.Fatal(err)
	}
	back, err := f.m.ProxyCutoverReturnPreview(t.Context(), transport.ProxyCutoverReturnRequest{CutoverID: p.CutoverID, Initiator: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	v = f.confirm(t, back)
	if v.State != "returned" || v.CanReturn || v.RequiresRecovery {
		t.Fatalf("return incomplete: %+v", v)
	}
	actual, _ = f.driver.Inventory(t.Context(), f.s.ComposeProject)
	if actual[0].ImageID != string(newImage) || actual[1].ID != f.s.Containers[1].ID || actual[0].Mounts[0].Source != "game-flags" || actual[0].Ports[0] != "0.0.0.0:18080->8080/tcp" {
		t.Fatalf("return changed current release/data/dependency: %+v", actual)
	}
	st, _ = f.m.state(t.Context(), f.s)
	if st.CurrentReleaseID != "release-v2" {
		t.Fatal("return restored an old release")
	}
	data, _ := os.ReadFile(f.data)
	if string(data) != "competition-flag-state\x00v2" {
		t.Fatal("game data changed")
	}
	frozen, err := f.m.LoadConfiguration(t.Context(), f.digest)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(frozen)
	if domain.Hash(raw) != f.digest {
		t.Fatal("frozen Compose was edited")
	}
}

func TestProxyCutoverReconcilesPartialComposeAndRefusesForeignMounts(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(strconv.FormatBool(foreign), func(t *testing.T) {
			f := newCutoverFixture(t)
			p := f.preview(t)
			f.driver.failAfterMutation = true
			f.driver.changeMount = foreign
			v := f.confirm(t, p)
			if foreign {
				if v.State != "requires_recovery" || !v.RequiresRecovery || len(f.driver.calls) != 1 {
					t.Fatalf("unknown state blindly retried: %+v calls=%v", v, f.driver.calls)
				}
				if err := f.m.requireNoPendingCutover(t.Context()); err == nil {
					t.Fatal("unknown runtime did not block new jobs")
				}
			} else {
				if v.State != "rolled_back" || v.RequiresRecovery || len(f.driver.calls) != 2 {
					t.Fatalf("known partial effect not restored: %+v calls=%v", v, f.driver.calls)
				}
				if err := f.m.requireNoPendingCutover(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestProxyCutoverCASAndStartupRequireFreshRecovery(t *testing.T) {
	f := newCutoverFixture(t)
	p := f.preview(t)
	st, _ := f.m.state(t.Context(), f.s)
	if err := f.m.saveState(t.Context(), &st); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.ProxyCutoverConfirm(t.Context(), transport.ProxyConfirmRequest{ProposalID: p.ProposalID, Digest: p.Digest, Initiator: "admin"}); err == nil {
		t.Fatal("stale service sequence was accepted")
	}
	if len(f.driver.calls) != 0 {
		t.Fatal("stale preview mutated containers")
	}
	record := proxyCutoverRecord{ProxyCutoverView: transport.ProxyCutoverView{ID: "interrupted-cutover", ServiceID: f.s.ID, ProposalID: p.ProposalID}, OriginProposalID: p.ProposalID}
	if err := f.m.saveCutover(t.Context(), &record, "running", "mutation_started", ""); err != nil {
		t.Fatal(err)
	}
	if err := f.m.reconcileCutoversOnStart(t.Context()); err != nil {
		t.Fatal(err)
	}
	views, err := f.m.ProxyCutovers(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || !views[0].RequiresRecovery || len(f.driver.calls) != 0 {
		t.Fatalf("startup replayed mutation or hid uncertainty: %+v", views)
	}
	if err := f.m.requireNoPendingCutover(t.Context()); err == nil {
		t.Fatal("recovery guard absent")
	}
}

func TestProxyCutoverRejectsBypassAndUnapprovedPorts(t *testing.T) {
	f := newCutoverFixture(t)
	for _, modify := range []func(*transport.ProxyCutoverPreviewRequest){func(in *transport.ProxyCutoverPreviewRequest) { in.PrivatePort = 18081 }, func(in *transport.ProxyCutoverPreviewRequest) {
		in.Routes[0].Listen = net.JoinHostPort("127.0.0.1", "18080")
	}, func(in *transport.ProxyCutoverPreviewRequest) { in.Routes[0].WAF.Mode = "enforce" }} {
		in := transport.ProxyCutoverPreviewRequest{ServiceID: f.s.ID, Component: "app", UpstreamPort: 8080, PrivatePort: 29080, Initiator: "admin", Routes: []transport.ProxyRouteInput{{ServiceID: f.s.ID, Component: "app", UpstreamPort: 8080, Listen: "0.0.0.0:18080", Protocol: "http1"}}}
		modify(&in)
		if _, err := f.m.ProxyCutoverPreview(t.Context(), in); err == nil {
			t.Fatal("unsafe binding/profile accepted")
		}
	}
	if len(f.driver.calls) != 0 {
		t.Fatal("rejected preview mutated containers")
	}
}

func TestProxyCutoverStaleQueuedReturnRemainsRecoverable(t *testing.T) {
	f := newCutoverFixture(t)
	active := f.confirm(t, f.preview(t))
	p, err := f.m.ProxyCutoverReturnPreview(t.Context(), transport.ProxyCutoverReturnRequest{CutoverID: active.ID, Initiator: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	f.driver.mu.Lock()
	f.driver.blockInventoryCall = f.driver.inventoryCalls + 2
	f.driver.entered = make(chan struct{})
	f.driver.releaseInventory = make(chan struct{})
	f.driver.mu.Unlock()
	if _, err = f.m.ProxyCutoverConfirm(t.Context(), transport.ProxyConfirmRequest{ProposalID: p.ProposalID, Digest: p.Digest, Initiator: "admin"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.driver.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not reach its independent freshness check")
	}
	changed := p.PreviousPolicy
	changed.Revision += 10
	if err = f.m.exportProxyPolicy(changed); err != nil {
		t.Fatal(err)
	}
	close(f.driver.releaseInventory)
	f.m.cutoverWG.Wait()
	views, err := f.m.ProxyCutovers(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || !views[0].RequiresRecovery || !views[0].CanReturn || views[0].State != "requires_recovery" {
		t.Fatalf("stale queued return orphaned the active overlay/routes: %+v", views)
	}
	if len(f.driver.calls) != 1 {
		t.Fatal("stale queued return mutated the application")
	}
}

func TestProxyCutoverOverlayStateGapRecoversWithoutLosingData(t *testing.T) {
	f := newCutoverFixture(t)
	p := f.preview(t)
	// A real SQLite trigger fails runtime-state persistence AFTER the durable
	// overlay write. Compensation is also unable to finish recording until the
	// storage fault is removed, so the transfer must remain recoverable.
	db, err := sql.Open("sqlite", filepath.Join(f.m.Config.StateDirectory, "executor.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	f.driver.afterRecreate = func() error {
		_, e := db.Exec(`CREATE TRIGGER cutover_injected_state_failure BEFORE INSERT ON records WHEN NEW.kind='runtime_state' BEGIN SELECT RAISE(ABORT,'injected runtime state failure'); END`)
		return e
	}
	v := f.confirm(t, p)
	if !v.RequiresRecovery {
		t.Fatalf("overlay/state persistence gap did not block service: %+v", v)
	}
	if _, err = db.Exec("DROP TRIGGER cutover_injected_state_failure"); err != nil {
		t.Fatal(err)
	}
	back, err := f.m.ProxyCutoverReturnPreview(t.Context(), transport.ProxyCutoverReturnRequest{CutoverID: v.ID, Initiator: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	v = f.confirm(t, back)
	if v.State != "returned" {
		t.Fatalf("known replacement ID with old runtime-state did not recover: %+v", v)
	}
	actual, _ := f.driver.Inventory(t.Context(), f.s.ComposeProject)
	if actual[0].Ports[0] != "0.0.0.0:18080->8080/tcp" || actual[0].Mounts[0].Source != "game-flags" || actual[1].ID != f.s.Containers[1].ID {
		t.Fatal("recovery changed ports/data/dependency identity")
	}
	data, _ := os.ReadFile(f.data)
	if string(data) != "competition-flag-state\x00v1" {
		t.Fatal("recovery changed persistent game data")
	}
}

func TestProxyCutoverCommittedUnappliedPolicyIsNotReplayedAndCanReturn(t *testing.T) {
	f := newCutoverFixture(t)
	preview := f.preview(t)
	var p proxyCutoverProposal
	if err := f.m.Store.Get(t.Context(), "proxy_cutover_proposal", preview.ProposalID, &p); err != nil {
		t.Fatal(err)
	}
	s, st, model, err := f.m.cutoverModel(t.Context(), p, p.ReplacementPorts)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.driver.Recreate(t.Context(), s, model, p.Component); err != nil {
		t.Fatal(err)
	}
	actual, _ := f.driver.Inventory(t.Context(), s.ComposeProject)
	refs, err := f.driver.Verify(t.Context(), s, p.Containers, actual, p.Component, model)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.m.commitCutoverOverlay(t.Context(), p, true, &st, refs); err != nil {
		t.Fatal(err)
	}
	r := proxyRevision{Policy: p.Policy, ProposalID: p.ProposalID, Digest: p.Digest, Actor: "admin", At: time.Now().UTC()}
	if err = f.m.Store.PutImmutable(t.Context(), "proxy_revision", domain.ID(fmt.Sprintf("proxy-policy-%020d", p.Policy.Revision)), "proxy", r); err != nil {
		t.Fatal(err)
	}
	record := proxyCutoverRecord{ProxyCutoverView: transport.ProxyCutoverView{ID: p.CutoverID, ProposalID: p.ProposalID, ServiceID: p.ServiceID, Component: p.Component, ProxyRevision: p.Policy.Revision, OriginalBindings: p.OriginalBindings, PrivateBindings: p.PrivateBindings}, OriginProposalID: p.ProposalID}
	if err = f.m.saveCutover(t.Context(), &record, "running", "proxy_policy_committed", ""); err != nil {
		t.Fatal(err)
	}
	if err = f.m.reconcileCutoversOnStart(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = f.m.reconcileProxyPublication(t.Context()); err == nil {
		t.Fatal("publisher replayed a policy belonging to an unresolved transfer")
	}
	file, err := proxyengine.LoadPolicyFile(filepath.Join(f.m.Config.Proxy.PolicyDirectory, "policy.json"))
	if err != nil || file.Revision != 1 {
		t.Fatal("startup changed applied/desired policy without reviewed recovery")
	}
	back, err := f.m.ProxyCutoverReturnPreview(t.Context(), transport.ProxyCutoverReturnRequest{CutoverID: p.CutoverID, Initiator: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if back.AppliedRevision != 1 || back.ProxyRevision != 2 || back.Policy.Revision != 3 {
		t.Fatalf("return confused committed and applied policies: %+v", back)
	}
	v := f.confirm(t, back)
	if v.State != "returned" {
		t.Fatalf("known prior applied policy could not be returned safely: %+v", v)
	}
}

func TestProxyCutoverReturnRejectsAnotherRouteUsingPrivateBackend(t *testing.T) {
	f := newCutoverFixture(t)
	p := f.preview(t)
	active := f.confirm(t, p)
	policy := p.Policy
	policy.Revision++
	route := policy.Routes[0]
	route.ID = "other-approved-route"
	route.Listen = "127.0.0.1:18081"
	policy.Routes = append(policy.Routes, route)
	r := proxyRevision{Policy: policy, ProposalID: "other-preview", Digest: domain.Hash([]byte("other-approved-policy")), Actor: "admin", At: time.Now().UTC()}
	if err := f.m.Store.PutImmutable(t.Context(), "proxy_revision", domain.ID(fmt.Sprintf("proxy-policy-%020d", policy.Revision)), "proxy", r); err != nil {
		t.Fatal(err)
	}
	if err := f.m.exportProxyPolicy(policy); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.ProxyCutoverReturnPreview(t.Context(), transport.ProxyCutoverReturnRequest{CutoverID: active.ID, Initiator: "admin"}); err == nil {
		t.Fatal("return would silently break another route sharing the backend")
	}
	if len(f.driver.calls) != 1 {
		t.Fatal("rejected return changed application containers")
	}
}

func TestProxyCutoverMissingApplicationRecoveryShowsActualAndBaseline(t *testing.T) {
	f := newCutoverFixture(t)
	p := f.preview(t)
	active := f.confirm(t, p)
	f.driver.mu.Lock()
	removed := f.driver.containers[0]
	f.driver.removedApplication = &removed
	f.driver.containers = f.driver.containers[1:]
	f.driver.mu.Unlock()
	records, err := f.m.cutoverRecords(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	record := records[active.ID]
	if err = f.m.saveCutover(t.Context(), &record, "requires_recovery", "partial_compose", "selected application disappeared"); err != nil {
		t.Fatal(err)
	}
	back, err := f.m.ProxyCutoverReturnPreview(t.Context(), transport.ProxyCutoverReturnRequest{CutoverID: active.ID, Initiator: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if !back.ApplicationMissing || len(back.Containers) != 1 || back.Containers[0].Component != "db" || len(back.RecoveryBaseline) != 2 {
		t.Fatalf("preview substituted old containers for actual inventory: %+v", back)
	}
	v := f.confirm(t, back)
	if v.State != "returned" {
		t.Fatalf("known absent application did not recover: %+v", v)
	}
	actual, _ := f.driver.Inventory(t.Context(), f.s.ComposeProject)
	if len(actual) != 2 {
		t.Fatal("application missing after recovery")
	}
	for _, c := range actual {
		if c.Component == "app" && (c.ImageID != string(f.s.Containers[0].ImageID) || c.Mounts[0].Source != "game-flags" || c.Ports[0] != "0.0.0.0:18080->8080/tcp") {
			t.Fatal("missing application recovered with different image/mounts/ports")
		}
	}
}

func TestProxyCutoverFailedCheckerRestoresOriginalBindings(t *testing.T) {
	f := newCutoverFixture(t)
	p := f.preview(t)
	f.driver.failHealth = true
	v := f.confirm(t, p)
	if v.State != "rolled_back" || v.RequiresRecovery || v.AppliedRevision != p.Policy.Revision+1 {
		t.Fatalf("failed post-activation checker was not safely compensated: %+v", v)
	}
	actual, _ := f.driver.Inventory(t.Context(), f.s.ComposeProject)
	if actual[0].Ports[0] != "0.0.0.0:18080->8080/tcp" || actual[1].ID != f.s.Containers[1].ID {
		t.Fatal("failed checker changed dependency or left proxy port transfer active")
	}
}

func TestProxyCutoverReadOnlyOpenDoesNotReconcileLiveJournal(t *testing.T) {
	f := newCutoverFixture(t)
	record := proxyCutoverRecord{ProxyCutoverView: transport.ProxyCutoverView{ID: "live-transfer", ServiceID: f.s.ID, ProposalID: "live-plan"}, OriginProposalID: "live-plan"}
	if err := f.m.saveCutover(t.Context(), &record, "running", "private_runtime_observed", ""); err != nil {
		t.Fatal(err)
	}
	c := config.Config{StateDirectory: f.m.Config.StateDirectory, Socket: filepath.Join(f.m.Config.StateDirectory, "executor.sock"), DockerHost: "unix:///unavailable-cutover-test.sock", DockerBinary: "/usr/bin/true", DiscoveryRoots: []string{f.s.ProjectDirectory}, WorkspaceRoots: []string{f.s.SourceDirectory}, WebUID: os.Geteuid(), Development: true}
	c.Proxy = f.m.Config.Proxy
	c.Proxy.TrafficURL = "http://127.0.0.1:9802"
	c.Proxy.TrafficTokenFile = c.Proxy.ControlTokenFile
	reader, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reader.ListServices(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = reader.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := f.m.cutoverRecords(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if records[record.ID].Sequence != record.Sequence || records[record.ID].State != "running" {
		t.Fatal("merely opening CLI metadata reconciled an active daemon operation")
	}
}

func TestProxyCutoverAdmissionAndWorkerOwnerExcludeIndependentManagers(t *testing.T) {
	f := newCutoverFixture(t)
	other := &Manager{Config: f.m.Config, Store: f.m.Store}
	unlock, err := f.m.lockCutoverAdmission()
	if err != nil {
		t.Fatal(err)
	}
	if second, e := other.lockCutoverAdmission(); e == nil {
		second()
		t.Fatal("independent Manager bypassed cross-process admission")
	}
	record := proxyCutoverRecord{ProxyCutoverView: transport.ProxyCutoverView{ID: "admitted-transfer", ServiceID: f.s.ID, ProposalID: "admitted-plan"}, OriginProposalID: "admitted-plan"}
	if err = f.m.saveCutover(t.Context(), &record, "queued", "queued", ""); err != nil {
		t.Fatal(err)
	}
	unlock()
	if _, err = other.Submit(t.Context(), transport.Principal{}, transport.SubmitRequest{ServiceID: f.s.ID, Action: domain.OperationSnapshot, Initiator: "admin", IdempotencyKey: "other-process-job"}); err == nil || !strings.Contains(err.Error(), "port transfer") {
		t.Fatalf("independent submit ignored durable cutover guard: %v", err)
	}
	if _, err = other.Approve(t.Context(), "unapproved-plan", domain.Hash([]byte("unapproved")), "admin"); err == nil || !strings.Contains(err.Error(), "port transfer") {
		t.Fatalf("independent approval ignored durable cutover guard: %v", err)
	}
	owner, err := f.m.privateExecutorLock(".worker-owner")
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err = other.Run(t.Context()); err == nil {
		t.Fatal("second worker owner reconciled a live journal")
	}
	latest, err := f.m.cutoverRecords(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if latest[record.ID].State != "queued" {
		t.Fatal("second worker changed the live journal before owning startup")
	}
}

func TestProxyCutoverConfirmWaitsForWorkerReadiness(t *testing.T) {
	f := newCutoverFixture(t)
	p := f.preview(t)
	f.m.cutoverReady = false
	if _, err := f.m.ProxyCutoverConfirm(t.Context(), transport.ProxyConfirmRequest{ProposalID: p.ProposalID, Digest: p.Digest, Initiator: "admin"}); err == nil {
		t.Fatal("confirmation was accepted before startup reconciliation")
	}
	records, err := f.m.cutoverRecords(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 || len(f.driver.calls) != 0 {
		t.Fatal("unready executor admitted a transfer")
	}
}

func TestProxyCutoverPrivateRuntimeDriftCannotHideBehindMetadataDigest(t *testing.T) {
	f := newCutoverFixture(t)
	p := f.preview(t)
	f.driver.privateRuntimeDrift = true
	actual, _ := f.driver.Inventory(t.Context(), f.s.ComposeProject)
	if cutoverRuntimeDigest(actual) != p.RuntimeDigest {
		t.Fatal("fixture accidentally changed public metadata")
	}
	if _, err := f.m.ProxyCutoverConfirm(t.Context(), transport.ProxyConfirmRequest{ProposalID: p.ProposalID, Digest: p.Digest, Initiator: "admin"}); err == nil {
		t.Fatal("resource/environment/restart inspection drift bypassed fresh verification")
	}
	if len(f.driver.calls) != 0 {
		t.Fatal("private runtime drift was overwritten by Compose")
	}
}

func TestProxyCutoverFailedMutationIntentNeverRecreatesApplication(t *testing.T) {
	f := newCutoverFixture(t)
	p := f.preview(t)
	db, err := sql.Open("sqlite", filepath.Join(f.m.Config.StateDirectory, "executor.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TRIGGER cutover_injected_intent_failure BEFORE INSERT ON records WHEN NEW.kind='proxy_cutover' AND json_extract(NEW.payload,'$.stage')='mutation_started' BEGIN SELECT RAISE(ABORT,'injected durable intent failure'); END`); err != nil {
		t.Fatal(err)
	}
	v := f.confirm(t, p)
	if v.State != "failed" || len(f.driver.calls) != 0 {
		t.Fatalf("failed intent triggered recreation/compensation: %+v calls=%v", v, f.driver.calls)
	}
	actual, _ := f.driver.Inventory(t.Context(), f.s.ComposeProject)
	if actual[0].ID != f.s.Containers[0].ID || actual[0].Ports[0] != "0.0.0.0:18080->8080/tcp" {
		t.Fatal("runtime changed despite failed durable mutation intent")
	}
}

func TestProxyCutoverDetectsDockerNATOnlyBackendReservation(t *testing.T) {
	for _, binding := range []string{"0.0.0.0:29080->80/tcp", ":::29080->80/tcp", "127.0.0.1:29080->80/tcp", ":29080->80/tcp"} {
		t.Run(binding, func(t *testing.T) {
			f := newCutoverFixture(t)
			p := f.preview(t)
			f.driver.foreignContainers = []docker.Container{{Component: "foreign-component-secret-name", ID: "foreign-id", State: "running", Ports: []string{binding}}}
			actual, _ := f.driver.Inventory(t.Context(), f.s.ComposeProject)
			if cutoverRuntimeDigest(actual) != p.RuntimeDigest {
				t.Fatal("foreign reservation changed selected project metadata")
			}
			if _, err := f.m.ProxyCutoverConfirm(t.Context(), transport.ProxyConfirmRequest{ProposalID: p.ProposalID, Digest: p.Digest, Initiator: "admin"}); err == nil || strings.Contains(err.Error(), "foreign-component-secret-name") {
				t.Fatalf("foreign reservation was accepted or disclosed private identity: %v", err)
			}
			if len(f.driver.calls) != 0 {
				t.Fatal("known Docker NAT-only collision recreated the application")
			}
		})
	}
}

func TestProxyCutoverRunKeepsWorkerOwnershipUntilCompensationStops(t *testing.T) {
	f := newCutoverFixture(t)
	f.m.cutoverReady = false
	runCtx, stop := context.WithCancel(context.Background())
	defer stop()
	done := make(chan error, 1)
	go func() { done <- f.m.Run(runCtx) }()
	deadline := time.After(3 * time.Second)
	for {
		f.m.proxyMu.Lock()
		ready := f.m.cutoverReady
		f.m.proxyMu.Unlock()
		if ready {
			break
		}
		select {
		case <-deadline:
			t.Fatal("worker did not become ready")
		case <-time.After(time.Millisecond):
		}
	}
	p := f.preview(t)
	entered, released := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseGate := func() { releaseOnce.Do(func() { close(released) }) }
	defer releaseGate()
	f.driver.afterRecreate = func() error { close(entered); <-released; return nil }
	if _, err := f.m.ProxyCutoverConfirm(t.Context(), transport.ProxyConfirmRequest{ProposalID: p.ProposalID, Digest: p.Digest, Initiator: "admin"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("recreation gate not reached")
	}
	stop()
	other := &Manager{Config: f.m.Config, Store: f.m.Store}
	if err := other.Run(t.Context()); err == nil {
		t.Fatal("replacement worker took ownership before old mutations stopped")
	}
	select {
	case err := <-done:
		t.Fatalf("Run returned while its cutover worker remained inside recreation: %v", err)
	default:
	}
	releaseGate()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not wait for bounded cutover cleanup")
	}
	owner, err := other.privateExecutorLock(".worker-owner")
	if err != nil {
		t.Fatalf("worker ownership was not released after cleanup: %v", err)
	}
	_ = owner.Close()
}
