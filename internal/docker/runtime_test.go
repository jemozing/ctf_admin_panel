package docker

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/api/types/network"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func runtimeFixture() (Container, map[string]any) {
	id := strings.Repeat("a", 64)
	imageID := "sha256:" + strings.Repeat("b", 64)
	name := "round_one-app-1"
	health := &container.HealthConfig{Test: []string{"CMD", "check", "inherited-health-secret"}, Interval: 2 * time.Second, Timeout: 3 * time.Second, Retries: 5}
	base := &dockerspec.DockerOCIImageConfig{ImageConfig: ocispec.ImageConfig{Env: []string{"PATH=/usr/bin:/bin", "PASSWORD=inherited-env-secret"}, User: "1001:1001", WorkingDir: "/app", Cmd: []string{"app", "inherited-command-secret"}, Entrypoint: []string{"run"}, ExposedPorts: map[string]struct{}{"8080/tcp": {}}}, DockerOCIImageConfigExt: dockerspec.DockerOCIImageConfigExt{Healthcheck: health}}
	cfg := &container.Config{Hostname: id[:12], Env: append([]string{}, base.Env...), User: base.User, WorkingDir: base.WorkingDir, Cmd: append([]string{}, base.Cmd...), Entrypoint: append([]string{}, base.Entrypoint...), Healthcheck: health, Labels: map[string]string{"com.docker.compose.project": "round_one", "com.docker.compose.service": "app"}, ExposedPorts: network.PortSet{network.MustParsePort("8080/tcp"): {}}}
	hc := &container.HostConfig{NetworkMode: "round_one_default", IpcMode: "private", CgroupnsMode: "private", Runtime: "runc", MaskedPaths: append([]string{}, defaultMaskedPaths...), ReadonlyPaths: append([]string{}, defaultReadonlyPaths...)}
	info := container.InspectResponse{ID: id, Image: imageID, Name: "/" + name, Config: cfg, HostConfig: hc, NetworkSettings: &container.NetworkSettings{Networks: map[string]*network.EndpointSettings{"round_one_default": {Aliases: []string{name, "app"}}}}}
	c := Container{ID: id, ImageID: imageID, Component: "app", Project: "round_one", Name: "/" + name, runtime: &runtimeInspection{container: info, image: image.InspectResponse{ID: imageID, Os: "linux", Config: base}, networks: map[string]network.Inspect{"round_one_default": {Network: network.Network{Name: "round_one_default", Driver: "bridge", Scope: "local", IPAM: network.IPAM{Driver: "default"}, Labels: map[string]string{"com.docker.compose.project": "round_one", "com.docker.compose.network": "default"}}}}}}
	model := map[string]any{"name": "round_one", "services": map[string]any{"app": map[string]any{"image": "app:1"}}, "networks": map[string]any{"default": map[string]any{"name": "round_one_default"}}}
	return c, model
}
func runtimeService(doc map[string]any) map[string]any {
	return doc["services"].(map[string]any)["app"].(map[string]any)
}
func requireRuntimeIssue(t *testing.T, c Container, doc map[string]any, code string) {
	t.Helper()
	issues := c.RuntimeIssues(doc, "round_one")
	for _, issue := range issues {
		if issue.Code == code {
			return
		}
	}
	t.Fatalf("expected %s, got %#v", code, issues)
}
func TestRuntimeUsesImmutableImageDefaults(t *testing.T) {
	c, doc := runtimeFixture()
	if issues := c.RuntimeIssues(doc, "round_one"); len(issues) > 0 {
		t.Fatalf("image-inherited runtime rejected: %#v", issues)
	}
}
func TestRuntimeComposeOverridesAndInheritedHealthFields(t *testing.T) {
	c, doc := runtimeFixture()
	s := runtimeService(doc)
	cfg := c.runtime.container.Config
	hc := c.runtime.container.HostConfig
	s["environment"] = map[string]any{"PASSWORD": nil, "NEW_PASSWORD": "override-env-secret"}
	cfg.Env = []string{"PATH=/usr/bin:/bin", "NEW_PASSWORD=override-env-secret"}
	s["entrypoint"] = []any{"custom", "override-entry-secret"}
	cfg.Entrypoint = []string{"custom", "override-entry-secret"}
	cfg.Cmd = nil
	s["user"] = "2000:2000"
	cfg.User = "2000:2000"
	s["working_dir"] = "/work"
	cfg.WorkingDir = "/work"
	s["healthcheck"] = map[string]any{"timeout": "7s"}
	h := *cfg.Healthcheck
	h.Timeout = 7 * time.Second
	cfg.Healthcheck = &h
	s["shm_size"] = "64m"
	hc.ShmSize = 64 << 20
	s["logging"] = map[string]any{"driver": "json-file", "options": map[string]any{"max-size": "20m", "max-file": "5"}}
	hc.LogConfig = container.LogConfig{Type: "json-file", Config: map[string]string{"max-size": "20m", "max-file": "5"}}
	s["read_only"] = true
	hc.ReadonlyRootfs = true
	s["cap_drop"] = []any{"ALL"}
	hc.CapDrop = []string{"ALL"}
	s["security_opt"] = []any{"no-new-privileges:true"}
	hc.SecurityOpt = []string{"no-new-privileges"}
	s["mem_limit"] = "64m"
	hc.Memory = 64 << 20
	hc.MemorySwap = 128 << 20
	s["cpus"] = 0.5
	hc.NanoCPUs = 500000000
	s["pids_limit"] = 100
	pids := int64(100)
	hc.PidsLimit = &pids
	s["ports"] = []any{map[string]any{"target": 8080, "published": "18080", "host_ip": "127.0.0.1", "protocol": "tcp", "mode": "ingress"}}
	hc.PortBindings = network.PortMap{network.MustParsePort("8080/tcp"): []network.PortBinding{{HostIP: netip.MustParseAddr("127.0.0.1"), HostPort: "18080"}}}
	if issues := c.RuntimeIssues(doc, "round_one"); len(issues) > 0 {
		t.Fatalf("effective overrides rejected: %#v", issues)
	}
}
func TestRuntimeRejectsDriftAndUnsupportedSemantics(t *testing.T) {
	cases := []struct {
		name, code string
		mutate     func(*Container, map[string]any)
	}{
		{"environment", "runtime_environment_mismatch", func(c *Container, d map[string]any) {
			c.runtime.container.Config.Env[1] = "PASSWORD=different-env-secret"
		}},
		{"unknown environment", "runtime_environment_mismatch", func(c *Container, d map[string]any) {
			c.runtime.container.Config.Env = append(c.runtime.container.Config.Env, "INJECTED=extra-secret")
		}},
		{"command", "runtime_command_mismatch", func(c *Container, d map[string]any) {
			c.runtime.container.Config.Cmd = []string{"other", "command-secret"}
		}},
		{"entrypoint", "runtime_entrypoint_mismatch", func(c *Container, d map[string]any) {
			c.runtime.container.Config.Entrypoint = []string{"other", "entry-secret"}
		}},
		{"user", "runtime_user_mismatch", func(c *Container, d map[string]any) { c.runtime.container.Config.User = "0" }},
		{"working directory", "runtime_working_dir_mismatch", func(c *Container, d map[string]any) { c.runtime.container.Config.WorkingDir = "/other" }},
		{"health command", "runtime_healthcheck_mismatch", func(c *Container, d map[string]any) {
			h := *c.runtime.container.Config.Healthcheck
			h.Test = []string{"CMD", "bad", "health-secret"}
			c.runtime.container.Config.Healthcheck = &h
		}},
		{"health retry", "runtime_healthcheck_mismatch", func(c *Container, d map[string]any) {
			h := *c.runtime.container.Config.Healthcheck
			h.Retries++
			c.runtime.container.Config.Healthcheck = &h
		}},
		{"root readonly", "runtime_read_only_mismatch", func(c *Container, d map[string]any) { c.runtime.container.HostConfig.ReadonlyRootfs = true }},
		{"privileged", "runtime_unsupported_security", func(c *Container, d map[string]any) { c.runtime.container.HostConfig.Privileged = true }},
		{"extra capability", "runtime_unsupported_security", func(c *Container, d map[string]any) { c.runtime.container.HostConfig.CapAdd = []string{"SYS_ADMIN"} }},
		{"host namespace", "runtime_unsupported_security", func(c *Container, d map[string]any) { c.runtime.container.HostConfig.PidMode = "host" }},
		{"unconfined", "runtime_security_mismatch", func(c *Container, d map[string]any) {
			c.runtime.container.HostConfig.SecurityOpt = []string{"seccomp=unconfined"}
		}},
		{"unmask paths", "runtime_unsupported_security", func(c *Container, d map[string]any) { c.runtime.container.HostConfig.MaskedPaths = nil }},
		{"extra network", "runtime_networks_mismatch", func(c *Container, d map[string]any) {
			c.runtime.container.NetworkSettings.Networks["rogue"] = &network.EndpointSettings{}
		}},
		{"network alias", "runtime_networks_mismatch", func(c *Container, d map[string]any) {
			c.runtime.container.NetworkSettings.Networks["round_one_default"].Aliases = append(c.runtime.container.NetworkSettings.Networks["round_one_default"].Aliases, "rogue")
		}},
		{"external network", "runtime_networks_mismatch", func(c *Container, d map[string]any) {
			d["networks"].(map[string]any)["default"].(map[string]any)["external"] = true
		}},
		{"static network configuration", "runtime_networks_mismatch", func(c *Container, d map[string]any) {
			runtimeService(d)["networks"] = map[string]any{"default": map[string]any{"ipv4_address": "192.0.2.3"}}
		}},
		{"unexpected port", "runtime_ports_mismatch", func(c *Container, d map[string]any) {
			c.runtime.container.HostConfig.PortBindings = network.PortMap{network.MustParsePort("8080/tcp"): []network.PortBinding{{HostPort: "80"}}}
		}},
		{"unexpected exposure", "runtime_ports_mismatch", func(c *Container, d map[string]any) {
			c.runtime.container.Config.ExposedPorts[network.MustParsePort("9999/tcp")] = struct{}{}
		}},
		{"memory limit", "runtime_limits_mismatch", func(c *Container, d map[string]any) { c.runtime.container.HostConfig.Memory = 128 << 20 }},
		{"quota", "runtime_limits_mismatch", func(c *Container, d map[string]any) { c.runtime.container.HostConfig.CPUQuota = 1000 }},
		{"unresolved env_file", "runtime_unsupported_setting", func(c *Container, d map[string]any) { runtimeService(d)["env_file"] = []any{"outside.env"} }},
		{"invalid image exposed port", "runtime_ports_mismatch", func(c *Container, d map[string]any) {
			c.runtime.image.Config.ExposedPorts["invalid"] = struct{}{}
			c.runtime.container.Config.ExposedPorts[network.MustParsePort("9999/tcp")] = struct{}{}
		}},
		{"unknown compose semantics", "runtime_unsupported_setting", func(c *Container, d map[string]any) { runtimeService(d)["develop"] = map[string]any{"watch": []any{}} }},
		{"non normalized command", "runtime_command_mismatch", func(c *Container, d map[string]any) { runtimeService(d)["command"] = "app --password command-secret" }},
		{"forged identity", "runtime_inspection_identity", func(c *Container, d map[string]any) { c.ID = strings.Repeat("c", 64) }},
		{"image mismatch", "runtime_inspection_identity", func(c *Container, d map[string]any) { c.runtime.image.ID = "sha256:" + strings.Repeat("c", 64) }},
		{"custom shm default", "runtime_shm_size_mismatch", func(c *Container, d map[string]any) { c.runtime.container.HostConfig.ShmSize = 6 << 30 }},
		{"hidden logging options", "runtime_logging_mismatch", func(c *Container, d map[string]any) {
			c.runtime.container.HostConfig.LogConfig = container.LogConfig{Type: "json-file", Config: map[string]string{"max-file": "5"}}
		}},
		{"unknown network driver", "runtime_networks_mismatch", func(c *Container, d map[string]any) {
			n := c.runtime.networks["round_one_default"]
			n.Driver = "host"
			c.runtime.networks["round_one_default"] = n
		}},
		{"changed image shell", "runtime_shell_mismatch", func(c *Container, d map[string]any) {
			c.runtime.container.Config.Shell = []string{"sh", "-c", "shell-secret"}
		}},
		{"image platform", "runtime_platform", func(c *Container, d map[string]any) { c.runtime.image.Os = "windows" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, doc := runtimeFixture()
			tc.mutate(&c, doc)
			requireRuntimeIssue(t, c, doc, tc.code)
			raw, _ := json.Marshal(c.RuntimeIssues(doc, "round_one"))
			for _, secret := range []string{"inherited-env-secret", "inherited-command-secret", "inherited-health-secret", "different-env-secret", "extra-secret", "command-secret", "entry-secret", "health-secret"} {
				if strings.Contains(string(raw), secret) {
					t.Fatalf("secret leaked in diagnostics")
				}
			}
		})
	}
}
func TestRuntimeEvidenceNeverRoundTripsThroughPublicInventory(t *testing.T) {
	c, doc := runtimeFixture()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"inherited-env-secret", "inherited-command-secret", "inherited-health-secret"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("secret leaked in inventory")
		}
	}
	var forged Container
	if err := json.Unmarshal(raw, &forged); err != nil {
		t.Fatal(err)
	}
	requireRuntimeIssue(t, forged, doc, "runtime_inspection_missing")
}
func TestEffectiveEntrypointEmptyAndHealthDisabled(t *testing.T) {
	c, doc := runtimeFixture()
	s := runtimeService(doc)
	s["entrypoint"] = []any{}
	s["healthcheck"] = map[string]any{"disable": true}
	c.runtime.container.Config.Entrypoint = nil
	c.runtime.container.Config.Cmd = nil
	c.runtime.container.Config.Healthcheck = &container.HealthConfig{Test: []string{"NONE"}}
	if issues := c.RuntimeIssues(doc, "round_one"); len(issues) > 0 {
		t.Fatalf("explicit disabling rejected: %#v", issues)
	}
}
