package docker

import (
	"path"
	"slices"
	"strings"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/volume"
)

// runtimeMountsMatch uses private inspect mountpoints rather than the public
// inventory projection. Recreation/recovery callers need the same mount identity
// guarantees as initial registration, including file-backed Compose inputs.
func runtimeMountsMatch(document map[string]any, component, project string, actual []container.MountPoint) bool {
	services, _ := document["services"].(map[string]any)
	model, _ := services[component].(map[string]any)
	expected := map[string]Mount{}
	add := func(m Mount) bool {
		if m.Target == "/" || !path.IsAbs(m.Target) || path.Clean(m.Target) != m.Target {
			return false
		}
		if _, exists := expected[m.Target]; exists {
			return false
		}
		expected[m.Target] = m
		return true
	}
	definitions, _ := document["volumes"].(map[string]any)
	if raw, exists := model["volumes"]; exists {
		mounts, ok := raw.([]any)
		if !ok {
			return false
		}
		for _, rawMount := range mounts {
			m, ok := rawMount.(map[string]any)
			if !ok {
				return false
			}
			for k := range m {
				if !slices.Contains([]string{"type", "source", "target", "read_only", "bind", "volume", "tmpfs", "consistency"}, k) {
					return false
				}
			}
			kind, _ := m["type"].(string)
			source, _ := m["source"].(string)
			target, _ := m["target"].(string)
			ro, _ := m["read_only"].(bool)
			if consistency, _ := m["consistency"].(string); consistency != "" && consistency != "consistent" {
				return false
			}
			switch kind {
			case "bind":
				if !path.IsAbs(source) || path.Clean(source) != source {
					return false
				}
				if rawOptions, exists := m["bind"]; exists {
					opts, ok := rawOptions.(map[string]any)
					if !ok {
						return false
					}
					for key, value := range opts {
						switch key {
						case "create_host_path":
							if _, ok := value.(bool); !ok {
								return false
							}
						case "propagation":
							if value != "" && value != "rprivate" {
								return false
							}
						default:
							return false
						}
					}
				}
			case "volume":
				if source == "" {
					return false
				}
				definition, ok := definitions[source].(map[string]any)
				if !ok {
					return false
				}
				name, _ := definition["name"].(string)
				if name == "" {
					name = project + "_" + source
				}
				source = name
				if rawOptions, exists := m["volume"]; exists {
					opts, ok := rawOptions.(map[string]any)
					if !ok {
						return false
					}
					for key, value := range opts {
						if key != "nocopy" || value != false {
							return false
						}
					}
				}
			case "tmpfs":
				if source != "" {
					return false
				}
				if rawOptions, exists := m["tmpfs"]; exists {
					opts, ok := rawOptions.(map[string]any)
					if !ok || len(opts) > 0 {
						return false
					}
				}
			default:
				return false
			}
			if !add(Mount{Type: kind, Source: source, Target: target, ReadOnly: ro}) {
				return false
			}
		}
	}
	for _, section := range []string{"secrets", "configs"} {
		raw, exists := model[section]
		if !exists {
			continue
		}
		entries, ok := raw.([]any)
		if !ok {
			return false
		}
		files, _ := document[section].(map[string]any)
		for _, rawEntry := range entries {
			entry, ok := rawEntry.(map[string]any)
			if !ok {
				return false
			}
			for key := range entry {
				if !slices.Contains([]string{"source", "target", "mode", "uid", "gid"}, key) {
					return false
				}
			}
			source, _ := entry["source"].(string)
			definition, ok := files[source].(map[string]any)
			if !ok {
				return false
			}
			file, _ := definition["file"].(string)
			// Frozen references must be materialized by executor before reconciliation.
			if !path.IsAbs(file) || path.Clean(file) != file {
				return false
			}
			for _, key := range []string{"uid", "gid"} {
				if v, exists := entry[key]; exists && v != "" && v != "0" {
					return false
				}
			}
			if v, exists := entry["mode"]; exists {
				n, ok := integer(v)
				if !ok || n != 0444 {
					return false
				}
			}
			target, _ := entry["target"].(string)
			if target == "" {
				target = source
			}
			if !path.IsAbs(target) {
				if section == "secrets" {
					target = path.Join("/run/secrets", target)
				} else {
					target = "/" + target
				}
			}
			if strings.Contains(target, "\\") || !add(Mount{Type: "bind", Source: file, Target: target, ReadOnly: true}) {
				return false
			}
		}
	}
	if len(expected) != len(actual) {
		return false
	}
	seen := map[string]bool{}
	for _, m := range actual {
		planned, exists := expected[m.Destination]
		if !exists || seen[m.Destination] {
			return false
		}
		seen[m.Destination] = true
		source := m.Source
		if m.Type == "volume" {
			source = m.Name
		}
		if string(m.Type) != planned.Type || source != planned.Source || !m.RW != planned.ReadOnly {
			return false
		}
	}
	return true
}

// Named local volumes can conceal host bind options even when their Compose
// declaration is only `external: true`. Inspect the backing volume itself before
// approving registration or touching an observed replacement container.
func runtimeVolumesSafe(mounts []container.MountPoint, volumes map[string]volume.Volume) bool {
	for _, m := range mounts {
		if m.Type != "volume" {
			continue
		}
		v, ok := volumes[m.Name]
		if !ok || v.Name != m.Name || v.Driver != "local" || m.Driver != "local" || v.Scope != "local" || len(v.Options) > 0 || v.ClusterVolume != nil || !path.IsAbs(v.Mountpoint) || path.Clean(v.Mountpoint) != v.Mountpoint || m.Source != v.Mountpoint {
			return false
		}
	}
	return true
}
