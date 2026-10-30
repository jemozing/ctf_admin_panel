package docker

import (
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/volume"
)

func mountedRuntimeFixture() (Container, map[string]any) {
	c, doc := runtimeFixture()
	runtimeService(doc)["volumes"] = []any{
		map[string]any{"type": "bind", "source": "/srv/ctf/flags/code", "target": "/app", "read_only": true, "bind": map[string]any{"create_host_path": false}},
		map[string]any{"type": "volume", "source": "data", "target": "/data", "volume": map[string]any{}},
	}
	doc["volumes"] = map[string]any{"data": map[string]any{"name": "round_one_flags_data"}}
	c.runtime.volumes = map[string]volume.Volume{"round_one_flags_data": {Name: "round_one_flags_data", Driver: "local", Scope: "local", Mountpoint: "/var/lib/docker/volumes/round_one_flags_data/_data"}}
	c.runtime.container.Mounts = []container.MountPoint{
		{Type: mount.TypeBind, Source: "/srv/ctf/flags/code", Destination: "/app", RW: false, Propagation: "rprivate"},
		{Type: mount.TypeVolume, Name: "round_one_flags_data", Source: "/var/lib/docker/volumes/round_one_flags_data/_data", Destination: "/data", RW: true, Driver: "local"},
	}
	return c, doc
}
func TestRuntimeReconcilesPrivateMountIdentities(t *testing.T) {
	c, doc := mountedRuntimeFixture()
	if issues := c.RuntimeIssues(doc, "round_one"); len(issues) > 0 {
		t.Fatalf("exact mounts rejected: %#v", issues)
	}
	cases := []struct {
		name   string
		mutate func(*Container, map[string]any)
	}{
		{"extra host mount", func(c *Container, d map[string]any) {
			c.runtime.container.Mounts = append(c.runtime.container.Mounts, container.MountPoint{Type: mount.TypeBind, Source: "/", Destination: "/host", RW: true})
		}},
		{"source identity", func(c *Container, d map[string]any) {
			c.runtime.container.Mounts[0].Source = "/srv/another-service/code"
		}},
		{"read only drift", func(c *Container, d map[string]any) { c.runtime.container.Mounts[0].RW = true }},
		{"target drift", func(c *Container, d map[string]any) { c.runtime.container.Mounts[0].Destination = "/other" }},
		{"type drift", func(c *Container, d map[string]any) { c.runtime.container.Mounts[0].Type = mount.TypeVolume }},
		{"named volume drift", func(c *Container, d map[string]any) { c.runtime.container.Mounts[1].Name = "another-service-data" }},
		{"missing mount", func(c *Container, d map[string]any) { c.runtime.container.Mounts = c.runtime.container.Mounts[1:] }},
		{"duplicate target", func(c *Container, d map[string]any) { c.runtime.container.Mounts[1].Destination = "/app" }},
		{"unsupported model option", func(c *Container, d map[string]any) {
			runtimeService(d)["volumes"].([]any)[0].(map[string]any)["bind"].(map[string]any)["selinux"] = "z"
		}},
		{"anonymous model volume", func(c *Container, d map[string]any) {
			delete(runtimeService(d)["volumes"].([]any)[1].(map[string]any), "source")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, doc := mountedRuntimeFixture()
			tc.mutate(&c, doc)
			requireRuntimeIssue(t, c, doc, "runtime_mounts_mismatch")
		})
	}
}
func TestRuntimeFileBackedInputsRequireMaterializedExactPaths(t *testing.T) {
	c, doc := runtimeFixture()
	doc["secrets"] = map[string]any{"password": map[string]any{"file": "/executor/runtime-inputs/password"}}
	doc["configs"] = map[string]any{"settings": map[string]any{"file": "/executor/runtime-inputs/settings"}}
	runtimeService(doc)["secrets"] = []any{map[string]any{"source": "password"}}
	runtimeService(doc)["configs"] = []any{map[string]any{"source": "settings", "target": "/app/settings", "mode": float64(0444)}}
	c.runtime.container.Mounts = []container.MountPoint{
		{Type: mount.TypeBind, Source: "/executor/runtime-inputs/password", Destination: "/run/secrets/password", RW: false},
		{Type: mount.TypeBind, Source: "/executor/runtime-inputs/settings", Destination: "/app/settings", RW: false},
	}
	if issues := c.RuntimeIssues(doc, "round_one"); len(issues) > 0 {
		t.Fatalf("materialized file inputs rejected: %#v", issues)
	}
	if !runtimeMountsMatch(doc, "app", "round_one", c.runtime.container.Mounts) {
		t.Fatal("materialized secret/config bindings rejected")
	}
	c.runtime.container.Mounts[0].Source = "/srv/ctf/replaced/password"
	if runtimeMountsMatch(doc, "app", "round_one", c.runtime.container.Mounts) {
		t.Fatal("secret source drift accepted")
	}
	c.runtime.container.Mounts[0].Source = "/executor/runtime-inputs/password"
	doc["secrets"].(map[string]any)["password"].(map[string]any)["file"] = "ctfm-secret://password/version"
	if runtimeMountsMatch(doc, "app", "round_one", c.runtime.container.Mounts) {
		t.Fatal("unresolved frozen secret reference accepted")
	}
}

func TestRuntimeInspectsBackingVolumeIncludingExternalDeclarations(t *testing.T) {
	c, doc := mountedRuntimeFixture()
	doc["volumes"].(map[string]any)["data"].(map[string]any)["external"] = true
	if issues := c.RuntimeIssues(doc, "round_one"); len(issues) > 0 {
		t.Fatalf("plain local external volume rejected: %#v", issues)
	}
	cases := []struct {
		name   string
		mutate func(*Container)
	}{
		{"missing volume evidence", func(c *Container) { c.runtime.volumes = nil }},
		{"concealed local host bind", func(c *Container) {
			v := c.runtime.volumes["round_one_flags_data"]
			v.Options = map[string]string{"type": "none", "o": "bind", "device": "/"}
			c.runtime.volumes["round_one_flags_data"] = v
		}},
		{"remote driver", func(c *Container) {
			v := c.runtime.volumes["round_one_flags_data"]
			v.Driver = "nfs-driver"
			c.runtime.volumes["round_one_flags_data"] = v
		}},
		{"global volume", func(c *Container) {
			v := c.runtime.volumes["round_one_flags_data"]
			v.Scope = "global"
			c.runtime.volumes["round_one_flags_data"] = v
		}},
		{"changed mountpoint", func(c *Container) {
			v := c.runtime.volumes["round_one_flags_data"]
			v.Mountpoint = "/elsewhere"
			c.runtime.volumes["round_one_flags_data"] = v
		}},
		{"wrong volume identity", func(c *Container) {
			v := c.runtime.volumes["round_one_flags_data"]
			v.Name = "another-volume"
			c.runtime.volumes["round_one_flags_data"] = v
		}},
		{"cluster volume", func(c *Container) {
			v := c.runtime.volumes["round_one_flags_data"]
			v.ClusterVolume = &volume.ClusterVolume{}
			c.runtime.volumes["round_one_flags_data"] = v
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, doc := mountedRuntimeFixture()
			tc.mutate(&c)
			requireRuntimeIssue(t, c, doc, "runtime_unsupported_volume")
		})
	}
}
