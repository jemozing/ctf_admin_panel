package policy

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/moby/moby/client"
)

type registrationFixture struct {
	config     config.Config
	service    domain.Service
	report     docker.ComposeReport
	containers []docker.Container
}

func newFixture(t *testing.T) *registrationFixture {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(base, "projects", "flags")
	source := filepath.Join(base, "workspaces", "flags")
	for _, path := range []string{filepath.Join(active, "app"), source, filepath.Join(base, "state")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(active, "compose.yaml"), []byte("services: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f := &registrationFixture{
		config: config.Config{StateDirectory: filepath.Join(base, "state"), Socket: filepath.Join(base, "run", "executor.sock"), DockerHost: "unix:///var/run/docker.sock", DockerBinary: "/usr/local/bin/docker", DiscoveryRoots: []string{filepath.Join(base, "projects")}, WorkspaceRoots: []string{filepath.Join(base, "workspaces")}, WebUID: 12345, Development: true},
		service: domain.Service{
			SchemaVersion: domain.SchemaVersion, ID: "flags", Name: "Flag fixture", ComposeProject: "round_one", ProjectDirectory: active, SourceDirectory: source,
			ComposeFiles: []string{"compose.yaml"}, ManagedPaths: []domain.ManagedPath{{Path: "app", Kind: domain.ManagedCode}}, Targets: []string{"app"}, PolicyRevision: 1, FileMapRevision: 1,
			Containers: []domain.ContainerRef{{Component: "app", ID: strings.Repeat("a", 64), ImageID: domain.Hash([]byte("app")), Role: domain.RoleApplication}, {Component: "db", ID: strings.Repeat("b", 64), ImageID: domain.Hash([]byte("db")), Role: domain.RoleDatabase}},
			DataPaths: []domain.DataPath{
				{Name: "flags", Component: "db", Kind: domain.StorageNamedVolume, Source: "round_one_flags", Target: "/var/lib/flags", Significant: true},
				{Name: "app-layer", Component: "app", Kind: domain.StorageWritableLayer, Target: "/tmp", LossAccepted: true},
				{Name: "db-layer", Component: "db", Kind: domain.StorageWritableLayer, Target: "/tmp", LossAccepted: true},
			},
		},
	}
	input := docker.ComposeInput{ProjectDirectory: active, ProjectName: "round_one", Files: []string{"compose.yaml"}}
	f.report = docker.Analyze(input, map[string]any{
		"name": "round_one",
		"services": map[string]any{
			"app": map[string]any{"image": "fixture-app:1", "volumes": []any{map[string]any{"type": "bind", "source": filepath.Join(active, "app"), "target": "/app", "read_only": true}}},
			"db":  map[string]any{"image": "postgres:17", "volumes": []any{map[string]any{"type": "volume", "source": "flags", "target": "/var/lib/flags"}}},
		},
		"volumes": map[string]any{"flags": map[string]any{"name": "round_one_flags"}},
	})
	f.containers = []docker.Container{
		{ID: f.service.Containers[0].ID, ImageID: string(f.service.Containers[0].ImageID), Project: "round_one", Component: "app", Mounts: []docker.Mount{{Type: "bind", Source: filepath.Join(active, "app"), Target: "/app", ReadOnly: true}}},
		{ID: f.service.Containers[1].ID, ImageID: string(f.service.Containers[1].ImageID), Project: "round_one", Component: "db", Mounts: []docker.Mount{{Type: "volume", Source: "round_one_flags", Target: "/var/lib/flags"}}},
	}
	f.containers = inspectedFixture(t, f.containers)
	return f
}

// Obtain genuine executor-only evidence through the Engine adapter. Constructing
// the public inventory DTO is deliberately insufficient for policy approval.
func inspectedFixture(t *testing.T, items []docker.Container) []docker.Container {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := strings.TrimPrefix(r.URL.Path, "/v1.56")
		if path == "/volumes/round_one_flags" {
			json.NewEncoder(w).Encode(map[string]any{"Name": "round_one_flags", "Driver": "local", "Scope": "local", "Mountpoint": "/var/lib/docker/volumes/round_one_flags/_data"})
			return
		}
		if path == "/networks/round_one_default" {
			json.NewEncoder(w).Encode(map[string]any{"Name": "round_one_default", "Scope": "local", "Driver": "bridge", "IPAM": map[string]any{"Driver": "default"}, "Labels": map[string]string{"com.docker.compose.project": "round_one", "com.docker.compose.network": "default"}})
			return
		}
		if path == "/containers/json" {
			out := []map[string]any{}
			for _, c := range items {
				out = append(out, map[string]any{"Id": c.ID, "Labels": map[string]string{"com.docker.compose.project": c.Project, "com.docker.compose.service": c.Component}})
			}
			json.NewEncoder(w).Encode(out)
			return
		}
		for _, c := range items {
			if path == "/images/"+c.ImageID+"/json" {
				json.NewEncoder(w).Encode(map[string]any{"Id": c.ImageID, "Os": "linux", "Config": map[string]any{}})
				return
			}
			if path != "/containers/"+c.ID+"/json" {
				continue
			}
			name := c.Project + "-" + c.Component + "-1"
			mounts := []map[string]any{}
			for _, m := range c.Mounts {
				entry := map[string]any{"Type": m.Type, "Source": m.Source, "Destination": m.Target, "RW": !m.ReadOnly}
				if m.Type == "volume" {
					entry["Name"] = m.Source
					entry["Source"] = "/var/lib/docker/volumes/" + m.Source + "/_data"
					entry["Driver"] = "local"
				}
				mounts = append(mounts, entry)
			}
			json.NewEncoder(w).Encode(map[string]any{
				"Id": c.ID, "Name": "/" + name, "Image": c.ImageID, "Mounts": mounts,
				"Config":          map[string]any{"Hostname": c.ID[:12], "Env": []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}, "Labels": map[string]string{"com.docker.compose.project": c.Project, "com.docker.compose.service": c.Component}},
				"HostConfig":      map[string]any{"NetworkMode": c.Project + "_default", "MaskedPaths": []string{"/proc/acpi", "/proc/asound", "/proc/interrupts", "/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/sched_debug", "/proc/scsi", "/proc/timer_list", "/proc/timer_stats", "/sys/devices/virtual/powercap", "/sys/firmware"}, "ReadonlyPaths": []string{"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"}},
				"NetworkSettings": map[string]any{"Networks": map[string]any{c.Project + "_default": map[string]any{"Aliases": []string{name, c.Component}}}},
			})
			return
		}
		http.NotFound(w, r)
	})
	api, err := client.New(client.WithHost("tcp://fixture.invalid"), client.WithAPIVersion("1.56"), client.WithHTTPClient(&http.Client{Transport: fixtureTransport(func(r *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, r)
		return recorder.Result(), nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	engine := docker.Engine{Client: api}
	defer engine.Close()
	out, err := engine.Inventory(t.Context(), "round_one")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *registrationFixture) modifyDocument(t *testing.T, change func(map[string]any)) {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(f.report.Normalized, &document); err != nil {
		t.Fatal(err)
	}
	change(document)
	f.report = docker.Analyze(f.report.Input, document)
}

func assertIssue(t *testing.T, f *registrationFixture, code string) {
	t.Helper()
	err := ValidateRegistration(f.config, f.service, f.report, f.containers)
	var rejected *RegistrationError
	if !errors.As(err, &rejected) {
		t.Fatalf("expected registration diagnostics, got %v", err)
	}
	for _, issue := range rejected.Issues {
		if issue.Code == code {
			return
		}
	}
	t.Fatalf("missing issue %s: %#v", code, rejected.Issues)
}

func TestRegistrationAcceptsFullyClassifiedFreshInventory(t *testing.T) {
	f := newFixture(t)
	if err := ValidateRegistration(f.config, f.service, f.report, f.containers); err != nil {
		t.Fatalf("safe inventory rejected: %v; %#v", err, RegistrationIssues(f.config, f.service, f.report, f.containers))
	}
}

func TestRegistrationAcceptsBindDataSeparatedFromManagedCode(t *testing.T) {
	f := newFixture(t)
	data := filepath.Join(f.service.ProjectDirectory, "data")
	if err := os.Mkdir(data, 0700); err != nil {
		t.Fatal(err)
	}
	f.service.DataPaths = append(f.service.DataPaths, domain.DataPath{Name: "app-data", Component: "app", Kind: domain.StorageBind, Source: data, Target: "/data", Significant: true})
	f.containers[0].Mounts[0].ReadOnly = false
	f.containers[0].Mounts = append(f.containers[0].Mounts, docker.Mount{Type: "bind", Source: data, Target: "/data"})
	f.modifyDocument(t, func(doc map[string]any) {
		app := doc["services"].(map[string]any)["app"].(map[string]any)
		mounts := app["volumes"].([]any)
		mounts[0].(map[string]any)["read_only"] = false
		app["volumes"] = append(mounts, map[string]any{"type": "bind", "source": data, "target": "/data"})
	})
	f.containers = inspectedFixture(t, f.containers)
	if err := ValidateRegistration(f.config, f.service, f.report, f.containers); err != nil {
		t.Fatalf("separate bind data rejected: %#v", RegistrationIssues(f.config, f.service, f.report, f.containers))
	}
}

func TestRegistrationRejectsStaleOrIncompleteIdentity(t *testing.T) {
	cases := []struct {
		name, code string
		change     func(*registrationFixture)
	}{
		{"container recreated", "container_id_mismatch", func(f *registrationFixture) { f.containers[0].ID = strings.Repeat("c", 64) }},
		{"image changed", "image_id_mismatch", func(f *registrationFixture) { f.containers[0].ImageID = string(domain.Hash([]byte("new"))) }},
		{"project changed", "project_label_mismatch", func(f *registrationFixture) { f.containers[0].Project = "another-project" }},
		{"service label changed", "unregistered_runtime_component", func(f *registrationFixture) { f.containers[0].Component = "attacker" }},
		{"missing actual container", "missing_runtime_component", func(f *registrationFixture) { f.containers = f.containers[1:] }},
		{"replica", "duplicate_runtime_component", func(f *registrationFixture) { f.containers = append(f.containers, f.containers[0]) }},
		{"different file", "compose_input_mismatch", func(f *registrationFixture) { f.report.Input.Files = []string{"override.yaml"} }},
		{"different profile", "compose_input_mismatch", func(f *registrationFixture) { f.report.Input.Profiles = []string{"unapproved"} }},
		{"unregistered target", "invalid_service", func(f *registrationFixture) { f.service.Targets = []string{"outside"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { f := newFixture(t); tc.change(f); assertIssue(t, f, tc.code) })
	}
}

func TestRegistrationCannotHideNormalizationIssues(t *testing.T) {
	t.Run("all report issues block", func(t *testing.T) {
		f := newFixture(t)
		f.report.Issues = append(f.report.Issues, docker.Issue{Component: "app", Code: "needs_review", Message: "unresolved local policy"})
		assertIssue(t, f, "compose_needs_review")
	})
	t.Run("cleared public issue list", func(t *testing.T) {
		f := newFixture(t)
		f.modifyDocument(t, func(doc map[string]any) {
			doc["services"].(map[string]any)["app"].(map[string]any)["privileged"] = true
		})
		f.report.Issues = nil
		assertIssue(t, f, "compose_unsupported_privilege")
	})
	t.Run("forged projection", func(t *testing.T) {
		f := newFixture(t)
		f.report.Components[0].Mounts = nil
		assertIssue(t, f, "component_projection_mismatch")
	})
	t.Run("stale digest", func(t *testing.T) {
		f := newFixture(t)
		f.report.ConfigurationDigest = string(domain.Hash([]byte("not the config")))
		assertIssue(t, f, "configuration_digest_mismatch")
	})
	t.Run("no normalized model", func(t *testing.T) {
		f := newFixture(t)
		f.report.Normalized = nil
		assertIssue(t, f, "missing_normalization")
	})
	t.Run("missing compose component", func(t *testing.T) {
		f := newFixture(t)
		f.modifyDocument(t, func(doc map[string]any) { delete(doc["services"].(map[string]any), "db") })
		assertIssue(t, f, "missing_compose_component")
	})
}

func TestRegistrationRequiresEveryMountAndLayerClassification(t *testing.T) {
	cases := []struct {
		name, code string
		change     func(*registrationFixture)
	}{
		{"layer omitted", "unclassified_writable_layer", func(f *registrationFixture) { f.service.DataPaths = f.service.DataPaths[:2] }},
		{"significant layer", "invalid_service", func(f *registrationFixture) {
			f.service.DataPaths[1].Significant = true
			f.service.DataPaths[1].LossAccepted = false
		}},
		{"volume classification omitted", "unclassified_runtime_mount", func(f *registrationFixture) { f.service.DataPaths = f.service.DataPaths[1:] }},
		{"volume identity changed", "storage_identity_mismatch", func(f *registrationFixture) { f.service.DataPaths[0].Source = "other-data" }},
		{"runtime mount missing", "missing_runtime_mount", func(f *registrationFixture) { f.containers[1].Mounts = nil }},
		{"readonly drift", "runtime_mount_mismatch", func(f *registrationFixture) { f.containers[0].Mounts[0].ReadOnly = false }},
		{"volume name drift", "runtime_mount_mismatch", func(f *registrationFixture) { f.containers[1].Mounts[0].Source = "another_volume" }},
		{"image volume appears", "runtime_mount_not_in_compose", func(f *registrationFixture) {
			f.containers[0].Mounts = append(f.containers[0].Mounts, docker.Mount{Type: "volume", Source: "anonymous-id", Target: "/state"})
		}},
		{"unknown actual type", "unsupported_runtime_mount", func(f *registrationFixture) { f.containers[1].Mounts[0].Type = "cluster" }},
		{"duplicate target classification", "duplicate_storage_target", func(f *registrationFixture) {
			copy := f.service.DataPaths[0]
			copy.Name = "second"
			f.service.DataPaths = append(f.service.DataPaths, copy)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { f := newFixture(t); tc.change(f); assertIssue(t, f, tc.code) })
	}
}

func TestRegistrationRequiresExactManagedCodeBind(t *testing.T) {
	f := newFixture(t)
	child := filepath.Join(f.service.ProjectDirectory, "app", "unapproved-subset")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	f.containers[0].Mounts[0].Source = child
	f.modifyDocument(t, func(doc map[string]any) {
		doc["services"].(map[string]any)["app"].(map[string]any)["volumes"].([]any)[0].(map[string]any)["source"] = child
	})
	assertIssue(t, f, "unclassified_runtime_mount")
}

func TestRegistrationRejectsFilesystemAliasesAndEscapes(t *testing.T) {
	t.Run("workspace not approved", func(t *testing.T) {
		f := newFixture(t)
		outside := filepath.Join(filepath.Dir(f.config.StateDirectory), "outside")
		if err := os.Mkdir(outside, 0700); err != nil {
			t.Fatal(err)
		}
		f.service.SourceDirectory = outside
		assertIssue(t, f, "unapproved_workspace")
	})
	t.Run("workspace symlink", func(t *testing.T) {
		f := newFixture(t)
		alias := f.service.SourceDirectory + "-alias"
		if err := os.Symlink(f.service.SourceDirectory, alias); err != nil {
			t.Fatal(err)
		}
		f.service.SourceDirectory = alias
		assertIssue(t, f, "unapproved_workspace")
	})
	t.Run("managed root symlink", func(t *testing.T) {
		f := newFixture(t)
		path := filepath.Join(f.service.ProjectDirectory, "app")
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(f.service.SourceDirectory, path); err != nil {
			t.Fatal(err)
		}
		assertIssue(t, f, "unsafe_managed_path")
	})
	t.Run("compose symlink", func(t *testing.T) {
		f := newFixture(t)
		path := filepath.Join(f.service.ProjectDirectory, "compose.yaml")
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/etc/hosts", path); err != nil {
			t.Fatal(err)
		}
		assertIssue(t, f, "unsafe_compose_path")
	})
	t.Run("missing workspace file behind symlink parent", func(t *testing.T) {
		f := newFixture(t)
		f.service.ManagedPaths[0].Path = "app/missing.py"
		if err := os.WriteFile(filepath.Join(f.service.ProjectDirectory, "app", "missing.py"), []byte("pass"), 0600); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(filepath.Dir(f.service.SourceDirectory), "outside")
		if err := os.Mkdir(outside, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(f.service.SourceDirectory, "app")); err != nil {
			t.Fatal(err)
		}
		assertIssue(t, f, "unsafe_workspace_entry")
	})

	t.Run("workspace inside runtime mount", func(t *testing.T) {
		f := newFixture(t)
		parent := filepath.Dir(f.service.SourceDirectory)
		f.containers[1].Mounts = []docker.Mount{{Type: "bind", Source: parent, Target: "/data"}}
		f.service.DataPaths[0] = domain.DataPath{Name: "data", Component: "db", Kind: domain.StorageBind, Source: parent, Target: "/data", Significant: true}
		// Lexical declaration already forbids this overlap.
		assertIssue(t, f, "invalid_service")
	})
	t.Run("unclassified bind aliases workspace", func(t *testing.T) {
		f := newFixture(t)
		parent := filepath.Dir(f.service.SourceDirectory)
		f.containers[0].Mounts = append(f.containers[0].Mounts, docker.Mount{Type: "bind", Source: parent, Target: "/unclassified"})
		assertIssue(t, f, "workspace_mount_overlap")
	})
}

func TestRegistrationRejectsWritableGameParentOfAnotherBind(t *testing.T) {
	f := newFixture(t)
	parent := filepath.Join(f.config.DiscoveryRoots[0], "state")
	child := filepath.Join(parent, "nested")
	if err := os.MkdirAll(child, 0700); err != nil {
		t.Fatal(err)
	}
	f.service.DataPaths[0] = domain.DataPath{Name: "parent-state", Component: "db", Kind: domain.StorageBind, Source: parent, Target: "/parent-state", Significant: true}
	f.service.DataPaths = append(f.service.DataPaths, domain.DataPath{Name: "child-state", Component: "db", Kind: domain.StorageBind, Source: child, Target: "/child-state", Significant: true})
	f.containers[1].Mounts = []docker.Mount{{Type: "bind", Source: parent, Target: "/parent-state"}, {Type: "bind", Source: child, Target: "/child-state"}}
	f.modifyDocument(t, func(doc map[string]any) {
		doc["services"].(map[string]any)["db"].(map[string]any)["volumes"] = []any{map[string]any{"type": "bind", "source": parent, "target": "/parent-state"}, map[string]any{"type": "bind", "source": child, "target": "/child-state"}}
	})
	assertIssue(t, f, "game_writable_bind_parent")
}

func TestProductionParentAndSensitiveMountPolicy(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writable := filepath.Join(base, "game-writable")
	if err := os.Mkdir(writable, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0777); err != nil {
		t.Fatal(err)
	}
	if err := stableParents(config.Config{WebUID: 12345}, filepath.Join(writable, "data")); err == nil {
		t.Fatal("group/world writable parent accepted")
	}
	c := config.Config{StateDirectory: "/opt/ctfm/state", Socket: "/opt/ctfm/run/executor.sock", DockerBinary: "/usr/bin/docker", ComposeBinary: "/opt/ctfm-tools/compose"}
	for _, path := range []string{"/", "/etc", "/etc/ssh", "/var/lib/docker/volumes", "/opt/ctfm", "/srv/ctf/docker.sock", "/proc/1/root", "/opt/ctfm-tools"} {
		if !sensitiveHostPath(c, path) {
			t.Errorf("sensitive source %s accepted", path)
		}
	}
	if sensitiveHostPath(c, "/srv/ctf/etc-like-data") {
		t.Fatal("sibling path prefix treated as sensitive")
	}
}

func TestDiagnosticOrderIsStableAndContainsNoEnvironmentValues(t *testing.T) {
	f := newFixture(t)
	secret := "fixture_secret_value_never_display"
	f.modifyDocument(t, func(doc map[string]any) {
		doc["services"].(map[string]any)["app"].(map[string]any)["environment"] = map[string]any{"PASSWORD": secret}
		doc["services"].(map[string]any)["app"].(map[string]any)["privileged"] = true
	})
	f.containers[0].Project = "wrong"
	first, _ := json.Marshal(RegistrationIssues(f.config, f.service, f.report, f.containers))
	for range 10 {
		next, _ := json.Marshal(RegistrationIssues(f.config, f.service, f.report, f.containers))
		if string(next) != string(first) {
			t.Fatal("diagnostics depend on map iteration order")
		}
	}
	if strings.Contains(string(first), secret) {
		t.Fatal("environment value leaked into diagnostics")
	}
}

type fixtureTransport func(*http.Request) (*http.Response, error)

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRegistrationRejectsPublicInventoryDTO(t *testing.T) {
	f := newFixture(t)
	encoded, err := json.Marshal(f.containers)
	if err != nil {
		t.Fatal(err)
	}
	var public []docker.Container
	if err := json.Unmarshal(encoded, &public); err != nil {
		t.Fatal(err)
	}
	f.containers = public
	assertIssue(t, f, "runtime_inspection_missing")
}
