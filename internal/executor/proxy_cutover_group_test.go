package executor

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

type groupCutoverRuntime struct {
	mu                      sync.Mutex
	containers              []docker.Container
	references              map[string]docker.Container
	calls                   []string
	failComponent, failMode string
	after                   func(string) error
	inventoryHook           func(int)
	inventoryCount          int
	privateDrift            bool
}

func (g *groupCutoverRuntime) Inventory(_ context.Context, _ string) ([]docker.Container, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.inventoryCount++
	if g.inventoryHook != nil {
		g.inventoryHook(g.inventoryCount)
	}
	raw, _ := json.Marshal(g.containers)
	var out []docker.Container
	_ = json.Unmarshal(raw, &out)
	return out, nil
}
func (g *groupCutoverRuntime) Recreate(_ context.Context, _ domain.Service, model map[string]any, component string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if component == "db" {
		return errors.New("database recreation forbidden")
	}
	g.calls = append(g.calls, component)
	fail := g.failComponent == component
	mode := g.failMode
	if fail {
		g.failComponent = ""
	}
	if fail && mode == "before" {
		return errors.New("Compose failed before selected component mutation")
	}
	found := -1
	for i, c := range g.containers {
		if c.Component == component {
			found = i
		}
	}
	if fail && mode == "remove" {
		if found >= 0 {
			g.containers = append(g.containers[:found], g.containers[found+1:]...)
		}
		return errors.New("selected application disappeared during Compose")
	}
	c := g.references[component]
	if found >= 0 {
		c = g.containers[found]
	}
	settings := model["services"].(map[string]any)[component].(map[string]any)
	ports, err := cutoverModelPorts(settings)
	if err != nil {
		return err
	}
	c.ID = fmt.Sprintf("%064x", len(g.calls)+100)
	c.ImageID = settings["image"].(string)
	c.Ports = cutoverPortStrings(ports)
	c.State = "running"
	if fail && mode == "foreignmount" {
		c.Mounts = append([]docker.Mount{}, c.Mounts...)
		c.Mounts[0].Source = "foreign-volume"
	}
	if found >= 0 {
		g.containers[found] = c
	} else {
		g.containers = append(g.containers, c)
	}
	if g.after != nil {
		if err := g.after(component); err != nil {
			return err
		}
	}
	if fail && mode == "after" {
		return errors.New("Compose returned error after selected mutation")
	}
	return nil
}
func (g *groupCutoverRuntime) Verify(_ context.Context, s domain.Service, before, after []docker.Container, component string, model map[string]any) ([]domain.ContainerRef, error) {
	g.mu.Lock()
	drift := g.privateDrift
	g.mu.Unlock()
	if drift {
		return nil, errors.New("private resource settings drift without public metadata change")
	}
	if len(before) != len(after) {
		return nil, errors.New("component count drift")
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
		if old == nil || old.ImageID != c.ImageID || !reflect.DeepEqual(old.Mounts, c.Mounts) || (c.Component != component && old.ID != c.ID) {
			return nil, errors.New("component image/mount/identity drift")
		}
		settings := model["services"].(map[string]any)[c.Component].(map[string]any)
		if settings["image"] != c.ImageID {
			return nil, errors.New("private image settings drift")
		}
		role := domain.ComponentRole("")
		for _, ref := range s.Containers {
			if ref.Component == c.Component {
				role = ref.Role
			}
		}
		if role == domain.RoleApplication {
			ports, err := cutoverModelPorts(settings)
			if err != nil {
				return nil, err
			}
			if !cutoverContainerPortsEqual(c, ports) {
				return nil, fmt.Errorf("private port settings drift in %s", c.Component)
			}
		}
		refs = append(refs, domain.ContainerRef{Component: c.Component, ID: c.ID, ImageID: domain.Digest(c.ImageID), Role: role})
	}
	return refs, nil
}
func (g *groupCutoverRuntime) Health(context.Context, domain.Service) error { return nil }

type groupCutoverFixture struct {
	*cutoverFixture
	group     *groupCutoverRuntime
	dataFiles []string
}

func newGroupCutoverFixture(t *testing.T) *groupCutoverFixture {
	t.Helper()
	base := newCutoverFixture(t)
	s := base.s
	s.PolicyRevision = 2
	s.Targets = []string{"app", "web"}
	webImage := domain.Hash([]byte("web-v1"))
	s.Containers = append(s.Containers, domain.ContainerRef{Component: "web", ID: strings.Repeat("d", 64), ImageID: webImage, Role: domain.RoleApplication})
	s.DataPaths = append(s.DataPaths, domain.DataPath{Name: "web-data", Kind: domain.StorageNamedVolume, Source: "web-data", Target: "/data", Component: "web", Significant: true})
	raw, _ := json.Marshal(base.configuration)
	var config Configuration
	_ = json.Unmarshal(raw, &config)
	services := config.Model["services"].(map[string]any)
	app := services["app"].(map[string]any)
	app["ports"] = []any{map[string]any{"target": float64(8080), "published": "18080", "host_ip": "0.0.0.0", "protocol": "tcp"}, map[string]any{"target": float64(8081), "published": "18081", "host_ip": "127.0.0.1", "protocol": "tcp"}}
	services["web"] = map[string]any{"image": string(webImage), "ports": []any{map[string]any{"target": float64(9000), "published": "18090", "host_ip": "0.0.0.0", "protocol": "tcp"}}, "volumes": []any{map[string]any{"type": "volume", "source": "web-data", "target": "/data"}}}
	config.Model["volumes"].(map[string]any)["web-data"] = map[string]any{"name": "web-data", "external": true}
	encoded, _ := json.Marshal(config)
	digest := domain.Hash(encoded)
	if err := base.m.Store.PutImmutable(t.Context(), "configuration", domain.ID(string(digest)[7:]), s.ID, config); err != nil {
		t.Fatal(err)
	}
	proposal, err := base.m.Store.CreateProposal(t.Context(), "group-registration", s, digest, "admin", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = base.m.Store.ApproveProposal(t.Context(), proposal.ID, proposal.Digest, "admin", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	base.s = s
	base.configuration = config
	base.digest = digest
	images := []domain.ImageRef{}
	for _, ref := range s.Containers {
		images = append(images, domain.ImageRef{Component: ref.Component, ImageID: ref.ImageID, RetentionTag: retentionTag(s, "group-v1", ref.Component)})
	}
	release, err := domain.NewRelease(domain.ReleaseSpec{SchemaVersion: 1, ID: "group-v1", ServiceID: s.ID, Author: "admin", CreatedAt: time.Now().UTC(), Source: domain.ReleaseImported, SnapshotID: "baseline", TreeDigest: domain.Hash([]byte("tree")), ConfigurationDigest: digest, PolicyRevision: s.PolicyRevision, FileMapRevision: s.FileMapRevision, Images: images})
	if err != nil {
		t.Fatal(err)
	}
	if err = base.m.Store.PutImmutable(t.Context(), "release", "group-v1", s.ID, release); err != nil {
		t.Fatal(err)
	}
	st := runtimeState{ServiceID: s.ID, PolicyRevision: 2, Sequence: 100, CurrentReleaseID: "group-v1", BaselineID: "baseline", ActiveSnapshotID: "baseline", Containers: s.Containers}
	if err = base.m.saveState(t.Context(), &st); err != nil {
		t.Fatal(err)
	}
	containers := append([]docker.Container{}, base.driver.containers...)
	containers[0].Ports = []string{"0.0.0.0:18080->8080/tcp", "127.0.0.1:18081->8081/tcp"}
	containers = append(containers, docker.Container{Component: "web", Project: s.ComposeProject, ID: strings.Repeat("d", 64), ImageID: string(webImage), State: "running", Health: "not_configured", Ports: []string{"0.0.0.0:18090->9000/tcp"}, Mounts: []docker.Mount{{Type: "volume", Source: "web-data", Target: "/data"}}})
	group := &groupCutoverRuntime{containers: containers, references: map[string]docker.Container{}}
	for _, c := range containers {
		group.references[c.Component] = c
	}
	base.m.cutoverRuntime = group
	data2 := filepath.Join(filepath.Dir(base.data), "web-data")
	if err = os.WriteFile(data2, []byte("web-existing-state"), 0600); err != nil {
		t.Fatal(err)
	}
	return &groupCutoverFixture{cutoverFixture: base, group: group, dataFiles: []string{base.data, data2}}
}
func (f *groupCutoverFixture) request() transport.ProxyCutoverPreviewRequest {
	return transport.ProxyCutoverPreviewRequest{ServiceID: f.s.ID, Initiator: "admin", Targets: []transport.ProxyCutoverSelection{{Component: "app", UpstreamPort: 8080, PrivatePort: 29080}, {Component: "app", UpstreamPort: 8081, PrivatePort: 29081}, {Component: "web", UpstreamPort: 9000, PrivatePort: 29090}}, Routes: []transport.ProxyRouteInput{{ServiceID: f.s.ID, Component: "app", UpstreamPort: 8080, Listen: "0.0.0.0:18080", Protocol: "http1"}, {ServiceID: f.s.ID, Component: "app", UpstreamPort: 8081, Listen: "127.0.0.1:18081", Protocol: "http1"}, {ServiceID: f.s.ID, Component: "web", UpstreamPort: 9000, Listen: "0.0.0.0:18090", Protocol: "http1"}}}
}
func (f *groupCutoverFixture) previewGroup(t *testing.T) transport.ProxyCutoverPreview {
	t.Helper()
	p, err := f.m.ProxyCutoverPreview(t.Context(), f.request())
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func (f *groupCutoverFixture) assertData(t *testing.T, expected [][]byte) {
	t.Helper()
	for i, path := range f.dataFiles {
		actual, err := os.ReadFile(path)
		if err != nil || !reflect.DeepEqual(actual, expected[i]) {
			t.Fatalf("game data changed: %s", path)
		}
	}
}
func (f *groupCutoverFixture) snapshotData(t *testing.T) [][]byte {
	t.Helper()
	out := [][]byte{}
	for _, path := range f.dataFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, data)
	}
	return out
}

func TestProxyCutoverGroupMultiPortRoundTripPreservesCurrentReleaseAndData(t *testing.T) {
	f := newGroupCutoverFixture(t)
	before := f.snapshotData(t)
	targets, err := f.m.ProxyCutoverTargets(t.Context())
	if err != nil || len(targets.Targets) != 3 {
		t.Fatalf("group discovery %+v %v", targets, err)
	}
	p := f.previewGroup(t)
	if len(p.Components) != 2 || len(p.Targets) != 3 || len(p.Policy.Routes) != 3 {
		t.Fatal("group plan incomplete")
	}
	v := f.confirm(t, p)
	if v.State != "active" {
		t.Fatalf("group transfer %+v", v)
	}
	if !reflect.DeepEqual(f.group.calls, []string{"app", "web"}) {
		t.Fatal(f.group.calls)
	}
	model, err := f.m.runtimeConfiguration(t.Context(), f.s, f.configuration)
	if err != nil {
		t.Fatal(err)
	}
	for _, component := range []string{"app", "web"} {
		ports, err := cutoverModelPorts(model["services"].(map[string]any)[component].(map[string]any))
		if err != nil {
			t.Fatal(err)
		}
		for _, port := range ports {
			if port["host_ip"] != "127.0.0.1" {
				t.Fatal("later deployment restored public backend")
			}
		}
	}
	// Simulate a later approved release and observed recreation using the same
	// overlay. Return must preserve these newer images and post-deploy data.
	st, err := f.m.state(t.Context(), f.s)
	if err != nil {
		t.Fatal(err)
	}
	images := []domain.ImageRef{}
	f.group.mu.Lock()
	for i := range f.group.containers {
		c := &f.group.containers[i]
		if c.Component != "db" {
			c.ImageID = string(domain.Hash([]byte(c.Component + "-v2")))
			c.ID = fmt.Sprintf("%064x", 500+i)
		}
		images = append(images, domain.ImageRef{Component: c.Component, ImageID: domain.Digest(c.ImageID), RetentionTag: retentionTag(f.s, "group-v2", c.Component)})
		for j := range st.Containers {
			if st.Containers[j].Component == c.Component {
				st.Containers[j].ID = c.ID
				st.Containers[j].ImageID = domain.Digest(c.ImageID)
			}
		}
	}
	f.group.mu.Unlock()
	release, err := domain.NewRelease(domain.ReleaseSpec{SchemaVersion: 1, ID: "group-v2", ServiceID: f.s.ID, Author: "admin", CreatedAt: time.Now().UTC(), Source: domain.ReleaseImported, SnapshotID: "baseline", TreeDigest: domain.Hash([]byte("new-tree")), ConfigurationDigest: f.digest, PolicyRevision: f.s.PolicyRevision, FileMapRevision: f.s.FileMapRevision, Images: images})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.m.Store.PutImmutable(t.Context(), "release", "group-v2", f.s.ID, release); err != nil {
		t.Fatal(err)
	}
	st.CurrentReleaseID = "group-v2"
	if err = f.m.saveState(t.Context(), &st); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.dataFiles[1], []byte("web-post-deploy-state"), 0600); err != nil {
		t.Fatal(err)
	}
	before[1] = []byte("web-post-deploy-state")
	back, err := f.m.ProxyCutoverReturnPreview(t.Context(), transport.ProxyCutoverReturnRequest{CutoverID: v.ID, Initiator: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	returned := f.confirm(t, back)
	if returned.State != "returned" {
		t.Fatalf("group return %+v", returned)
	}
	actual, _ := f.group.Inventory(t.Context(), f.s.ComposeProject)
	for _, c := range actual {
		if c.Component == "db" {
			if c.ID != f.s.Containers[1].ID {
				t.Fatal("database recreated")
			}
			continue
		}
		if c.ImageID != string(domain.Hash([]byte(c.Component+"-v2"))) {
			t.Fatal("return restored old image")
		}
		for _, port := range c.Ports {
			if strings.Contains(port, ":290") {
				t.Fatal("private backend retained after return")
			}
		}
	}
	f.assertData(t, before)
}

func TestProxyCutoverGroupSecondComponentFailureCompensatesKnownMixedRuntime(t *testing.T) {
	for _, mode := range []string{"before", "after", "remove"} {
		t.Run(mode, func(t *testing.T) {
			f := newGroupCutoverFixture(t)
			before := f.snapshotData(t)
			f.group.failComponent = "web"
			f.group.failMode = mode
			v := f.confirm(t, f.previewGroup(t))
			if v.State != "rolled_back" {
				t.Fatalf("partial group %+v", v)
			}
			f.assertData(t, before)
			actual, _ := f.group.Inventory(t.Context(), f.s.ComposeProject)
			for _, c := range actual {
				if c.Component == "db" {
					if c.ID != f.s.Containers[1].ID {
						t.Fatal("database changed")
					}
					continue
				}
				if strings.Contains(strings.Join(c.Ports, ","), ":290") {
					t.Fatal("component remained private")
				}
			}
		})
	}
}

func TestProxyCutoverGroupForeignMountAndPartialPortShapeRequireRecovery(t *testing.T) {
	f := newGroupCutoverFixture(t)
	f.group.failComponent = "web"
	f.group.failMode = "foreignmount"
	v := f.confirm(t, f.previewGroup(t))
	if v.State != "requires_recovery" {
		t.Fatalf("unknown group mutation %+v", v)
	}
	if _, err := f.m.ProxyCutoverReturnPreview(t.Context(), transport.ProxyCutoverReturnRequest{CutoverID: v.ID, Initiator: "admin"}); err == nil {
		t.Fatal("unknown mount accepted")
	}
}

func TestProxyCutoverGroupRejectsMissingTargetsAndDuplicateBackendsBeforeMutation(t *testing.T) {
	f := newGroupCutoverFixture(t)
	request := f.request()
	request.Targets = request.Targets[:2]
	request.Routes = request.Routes[:2]
	if _, err := f.m.ProxyCutoverPreview(t.Context(), request); err == nil {
		t.Fatal("partial service bypass accepted")
	}
	request = f.request()
	request.Targets[1].PrivatePort = request.Targets[0].PrivatePort
	if _, err := f.m.ProxyCutoverPreview(t.Context(), request); err == nil {
		t.Fatal("duplicate private backend accepted")
	}
	if len(f.group.calls) != 0 {
		t.Fatal("invalid plan recreated applications")
	}
}

func TestProxyCutoverGroupMultipleMissingApplicationsCanRecoverFromExplicitBaseline(t *testing.T) {
	f := newGroupCutoverFixture(t)
	before := f.snapshotData(t)
	view := f.previewGroup(t)
	var p proxyCutoverProposal
	if err := f.m.Store.Get(t.Context(), "proxy_cutover_proposal", view.ProposalID, &p); err != nil {
		t.Fatal(err)
	}
	f.group.mu.Lock()
	onlyDB := []docker.Container{}
	for _, c := range f.group.containers {
		if c.Component == "db" {
			onlyDB = append(onlyDB, c)
		}
	}
	f.group.containers = onlyDB
	f.group.mu.Unlock()
	record := proxyCutoverRecord{ProxyCutoverView: transport.ProxyCutoverView{ID: p.CutoverID, ProposalID: p.ProposalID, ServiceID: p.ServiceID, Components: p.Components, Targets: p.Targets, OriginalBindings: p.OriginalBindings, PrivateBindings: p.PrivateBindings}, OriginProposalID: p.ProposalID}
	if err := f.m.saveCutover(t.Context(), &record, "requires_recovery", "interrupted", ""); err != nil {
		t.Fatal(err)
	}
	back, err := f.m.ProxyCutoverReturnPreview(t.Context(), transport.ProxyCutoverReturnRequest{CutoverID: p.CutoverID, Initiator: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.MissingApplications, []string{"app", "web"}) || len(back.Containers) != 1 || len(back.RecoveryBaseline) != 3 {
		t.Fatalf("missing group evidence %+v", back)
	}
	returned := f.confirm(t, back)
	if returned.State != "returned" {
		t.Fatalf("multiple missing recovery %+v", returned)
	}
	if !reflect.DeepEqual(f.group.calls, []string{"app", "web"}) {
		t.Fatal(f.group.calls)
	}
	f.assertData(t, before)
}

func TestProxyCutoverGroupMixedPortsWithinOneComponentAreNeverRecovered(t *testing.T) {
	f := newGroupCutoverFixture(t)
	v := f.confirm(t, f.previewGroup(t))
	if v.State != "active" {
		t.Fatal(v)
	}
	f.group.mu.Lock()
	for i := range f.group.containers {
		if f.group.containers[i].Component == "app" {
			f.group.containers[i].Ports[0] = "0.0.0.0:18080->8080/tcp"
		}
	}
	f.group.mu.Unlock()
	records, err := f.m.cutoverRecords(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	record := records[v.ID]
	if err = f.m.saveCutover(t.Context(), &record, "requires_recovery", "interrupted", ""); err != nil {
		t.Fatal(err)
	}
	if _, err = f.m.ProxyCutoverReturnPreview(t.Context(), transport.ProxyCutoverReturnRequest{CutoverID: v.ID, Initiator: "admin"}); err == nil {
		t.Fatal("mixed original/private ports inside one app were accepted")
	}
	if len(f.group.calls) != 2 {
		t.Fatal("unknown shape triggered mutation")
	}
}

func TestProxyCutoverGroupSecondStateWriteFailureRecoversKnownMixedOverlay(t *testing.T) {
	f := newGroupCutoverFixture(t)
	before := f.snapshotData(t)
	db, err := sql.Open("sqlite", filepath.Join(f.m.Config.StateDirectory, "executor.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	f.group.after = func(component string) error {
		if component != "web" {
			return nil
		}
		f.group.after = nil
		_, e := db.Exec(`CREATE TRIGGER group_state_failure BEFORE INSERT ON records WHEN NEW.kind='runtime_state' BEGIN SELECT RAISE(ABORT,'group injected state failure'); END`)
		return e
	}
	v := f.confirm(t, f.previewGroup(t))
	if !v.RequiresRecovery {
		t.Fatalf("second overlay/state gap %+v", v)
	}
	if _, err = db.Exec("DROP TRIGGER group_state_failure"); err != nil {
		t.Fatal(err)
	}
	back, err := f.m.ProxyCutoverReturnPreview(t.Context(), transport.ProxyCutoverReturnRequest{CutoverID: v.ID, Initiator: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	v = f.confirm(t, back)
	if v.State != "returned" {
		t.Fatal(v)
	}
	f.assertData(t, before)
}

func TestProxyCutoverGroupInitialCheckpointRejectsAnotherSelectedIdentityChange(t *testing.T) {
	f := newGroupCutoverFixture(t)
	view := f.previewGroup(t)
	var p proxyCutoverProposal
	if err := f.m.Store.Get(t.Context(), "proxy_cutover_proposal", view.ProposalID, &p); err != nil {
		t.Fatal(err)
	}
	if err := f.m.cutoverFresh(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	f.group.mu.Lock()
	for i := range f.group.containers {
		if f.group.containers[i].Component == "web" {
			f.group.containers[i].ID = strings.Repeat("e", 64)
		}
	}
	f.group.mu.Unlock()
	record := proxyCutoverRecord{ProxyCutoverView: transport.ProxyCutoverView{ID: p.CutoverID, ProposalID: p.ProposalID, ServiceID: p.ServiceID}, OriginProposalID: p.ProposalID}
	if err := f.m.moveCutoverComponents(t.Context(), p, &record, true); err == nil {
		t.Fatal("new identity adopted after fresh CAS")
	}
	if len(f.group.calls) != 0 {
		t.Fatal("identity race changed application")
	}
}

func TestProxyCutoverGroupWarmupHealthTransitionDoesNotInvalidateIdentityCheckpoint(t *testing.T) {
	f := newGroupCutoverFixture(t)
	f.group.after = func(component string) error {
		if component == "app" {
			for i := range f.group.containers {
				if f.group.containers[i].Component == "app" {
					f.group.containers[i].Health = "starting"
				}
			}
		}
		return nil
	}
	appObservations := 0
	f.group.inventoryHook = func(_ int) {
		if len(f.group.calls) == 1 {
			appObservations++
		}
		if len(f.group.calls) == 1 && appObservations >= 2 {
			for i := range f.group.containers {
				if f.group.containers[i].Component == "app" && f.group.containers[i].Health == "starting" {
					f.group.containers[i].Health = "healthy"
					break
				}
			}
		}
	}
	v := f.confirm(t, f.previewGroup(t))
	if v.State != "active" {
		t.Fatalf("warmup health observation rejected valid group: %+v", v)
	}
}

func TestProxyCutoverLegacyProposalAndOverlayRemainReturnable(t *testing.T) {
	f := newCutoverFixture(t)
	preview := f.preview(t)
	var p proxyCutoverProposal
	if err := f.m.Store.Get(t.Context(), "proxy_cutover_proposal", preview.ProposalID, &p); err != nil {
		t.Fatal(err)
	}
	p.SchemaVersion = 0
	p.Entries = nil
	p.Components = nil
	p.Targets = nil
	p.ProposalID = "historical-single-plan"
	p.OriginProposalID = p.ProposalID
	p.Digest = ""
	encoded, _ := json.Marshal(p)
	p.Digest = domain.Hash(encoded)
	if err := f.m.Store.PutImmutable(t.Context(), "proxy_cutover_proposal", p.ProposalID, p.ServiceID, p); err != nil {
		t.Fatal(err)
	}
	v := f.confirm(t, p.ProxyCutoverPreview)
	if v.State != "active" {
		t.Fatal(v)
	}
	current, err := f.m.runtimePortOverlay(t.Context(), f.s.ID)
	if err != nil {
		t.Fatal(err)
	}
	legacy := current
	legacy.SchemaVersion = 0
	legacy.Entries = nil
	legacy.Sequence++
	if err = f.m.Store.PutImmutable(t.Context(), "runtime_port_overlay", "historical-single-overlay", f.s.ID, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err = f.m.runtimeConfiguration(t.Context(), f.s, f.configuration); err != nil {
		t.Fatal("historical overlay cannot render", err)
	}
	back, err := f.m.ProxyCutoverReturnPreview(t.Context(), transport.ProxyCutoverReturnRequest{CutoverID: v.ID, Initiator: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Components) != 1 || len(back.Targets) != 1 {
		t.Fatal("legacy public plan not normalized")
	}
	v = f.confirm(t, back)
	if v.State != "returned" {
		t.Fatal(v)
	}
	var retained proxyCutoverProposal
	if err = f.m.Store.Get(t.Context(), "proxy_cutover_proposal", p.ProposalID, &retained); err != nil || retained.Digest != p.Digest || retained.SchemaVersion != 0 || retained.Entries != nil {
		t.Fatal("historical proposal was rewritten")
	}
}

func TestProxyCutoverGroupMissingSelectedCannotHideMissingDependency(t *testing.T) {
	f := newGroupCutoverFixture(t)
	before, _ := f.group.Inventory(t.Context(), f.s.ComposeProject)
	model, err := f.m.runtimeConfiguration(t.Context(), f.s, f.configuration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.m.verifyCutoverGroup(t.Context(), f.s, before, nil, []string{"app", "web"}, model); err == nil {
		t.Fatal("missing database was treated as selected recovery")
	}
	truncated := []docker.Container{}
	service := f.s
	service.Containers = nil
	for _, ref := range f.s.Containers {
		if ref.Component != "db" {
			service.Containers = append(service.Containers, ref)
		}
	}
	for _, c := range before {
		if c.Component != "db" {
			truncated = append(truncated, c)
		}
	}
	if _, err = f.m.verifyCutoverGroup(t.Context(), f.s, truncated, nil, []string{"app", "web"}, model); err == nil {
		t.Fatal("truncated recovery baseline hid database")
	}
	if refs, err := f.m.verifyCutoverGroup(t.Context(), service, truncated, nil, []string{"app", "web"}, model); err != nil || len(refs) != 0 {
		t.Fatalf("fully missing selected-only service cannot recover: %v", err)
	}
}

func TestProxyCutoverGroupRepeatsPrivateInspectionBeforeLaterComponentMutation(t *testing.T) {
	f := newGroupCutoverFixture(t)
	afterFirst := 0
	f.group.inventoryHook = func(_ int) {
		if len(f.group.calls) == 1 {
			afterFirst++
			if afterFirst >= 2 {
				f.group.privateDrift = true
			}
		}
	}
	v := f.confirm(t, f.previewGroup(t))
	if !v.RequiresRecovery || !reflect.DeepEqual(f.group.calls, []string{"app"}) {
		t.Fatalf("private drift did not stop before later mutation: %+v calls=%v", v, f.group.calls)
	}
}

func TestProxyCutoverOverlayRecordIDsSupportWebAndMaximumServiceIDs(t *testing.T) {
	for _, id := range []domain.ID{domain.ID("service-" + strings.Repeat("a", 32)), domain.ID(strings.Repeat("b", 64))} {
		t.Run(fmt.Sprint(len(id)), func(t *testing.T) {
			f := newCutoverFixture(t)
			preview := f.preview(t)
			var p proxyCutoverProposal
			if err := f.m.Store.Get(t.Context(), "proxy_cutover_proposal", preview.ProposalID, &p); err != nil {
				t.Fatal(err)
			}
			p.ServiceID = id
			st := runtimeState{ServiceID: id, PolicyRevision: 1, CurrentReleaseID: "current", Containers: f.s.Containers}
			entries, err := cutoverProposalEntries(p)
			if err != nil {
				t.Fatal(err)
			}
			entries[0].Active = true
			if err = f.m.commitCutoverEntries(t.Context(), p, entries, &st, f.s.Containers); err != nil {
				t.Fatalf("web-sized service ID rejected after mutation: %v", err)
			}
			records, err := f.m.Store.List(t.Context(), "runtime_port_overlay", id)
			if err != nil || len(records) != 1 || len(records[0].ID) > 64 {
				t.Fatalf("bounded overlay identity: %+v %v", records, err)
			}
			observed, err := f.m.runtimePortOverlay(t.Context(), id)
			if err != nil || observed.Sequence != 1 || !observed.Active {
				t.Fatalf("overlay not readable: %+v %v", observed, err)
			}
			state, err := f.m.state(t.Context(), domain.Service{ID: id, PolicyRevision: 1, Containers: f.s.Containers})
			if err != nil || state.Sequence != 1 || state.ServiceID != id {
				t.Fatalf("runtime state not recorded: %+v %v", state, err)
			}
		})
	}
}

func TestProxyCutoverGroupPortShapeComparisonCanonicalizesAddressAliases(t *testing.T) {
	for _, test := range []struct{ frozen, actual string }{{"::ffff:127.0.0.1", "127.0.0.1"}, {"0:0:0:0:0:0:0:1", "::1"}} {
		c := docker.Container{Ports: []string{test.actual + ":18080->8080/tcp"}}
		ports := []map[string]any{{"target": float64(8080), "published": "18080", "host_ip": test.frozen, "protocol": "tcp"}}
		if !cutoverContainerPortsEqual(c, ports) {
			t.Fatalf("equivalent original binding rejected: %s vs%s", test.frozen, test.actual)
		}
	}
}
