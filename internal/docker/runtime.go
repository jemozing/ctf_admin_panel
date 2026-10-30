package docker

// Runtime reconciliation deliberately keeps inspect values private: command,
// healthcheck and environment may all contain credentials. Diagnostics identify
// only the setting that failed, never its expected or observed value.
import (
	"fmt"
	"net"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/docker/go-units"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/volume"
)

type runtimeInspection struct {
	container container.InspectResponse
	image     image.InspectResponse
	networks  map[string]network.Inspect
	volumes   map[string]volume.Volume
}

// RuntimeIssues reconciles the frozen normalized Compose model with fresh,
// executor-owned ContainerInspect/ImageInspect evidence. JSON inventory output
// cannot be deserialized into that evidence and therefore fails closed.
func (c Container) RuntimeIssues(document map[string]any, project string) []Issue {
	issues := []Issue{}
	add := func(code, setting string) {
		issues = append(issues, Issue{Component: c.Component, Code: code, Message: setting + " does not match the supported effective runtime profile"})
	}
	r := c.runtime
	if r == nil || r.container.Config == nil || r.container.HostConfig == nil || r.image.Config == nil {
		add("runtime_inspection_missing", "private Docker inspection evidence")
		return issues
	}
	info, image := r.container, r.image
	if info.ID != c.ID || info.Image != c.ImageID || image.ID != c.ImageID || info.Config.Labels["com.docker.compose.project"] != project || info.Config.Labels["com.docker.compose.service"] != c.Component {
		add("runtime_inspection_identity", "inspection identity")
	}
	if image.Os != "linux" {
		add("runtime_platform", "image operating system")
	}
	services, _ := document["services"].(map[string]any)
	model, ok := services[c.Component].(map[string]any)
	if !ok {
		add("runtime_component_missing", "Compose component")
		return issues
	}
	// New Compose settings must acquire explicit reconciliation before import.
	allowed := strings.Fields("image build container_name depends_on environment command entrypoint user working_dir healthcheck restart read_only cap_drop security_opt networks network_mode ports expose volumes cpus cpu_shares cpu_period cpu_quota cpuset mem_limit mem_reservation memswap_limit pids_limit init profiles labels stop_signal stop_grace_period tty stdin_open hostname domainname attach shm_size logging secrets configs")
	for setting := range model {
		if !slices.Contains(allowed, setting) && !strings.HasPrefix(setting, "x-") {
			add("runtime_unsupported_setting", setting)
		}
	}
	cfg, hc, base := info.Config, info.HostConfig, image.Config
	expectedEnv, err := mergedEnvironment(base.Env, model["environment"])
	actualEnv, envErr := environmentMap(cfg.Env)
	if err != nil || envErr != nil || !reflect.DeepEqual(expectedEnv, actualEnv) {
		add("runtime_environment_mismatch", "environment")
	}
	expectedEntry, entryOK := effectiveArgs(model, "entrypoint", base.Entrypoint)
	expectedCmd, cmdOK := effectiveArgs(model, "command", base.Cmd)
	if model["entrypoint"] != nil && model["command"] == nil {
		expectedCmd = nil
	}
	if !entryOK || !slices.Equal(expectedEntry, cfg.Entrypoint) {
		add("runtime_entrypoint_mismatch", "entrypoint")
	}
	if !slices.Equal(cfg.Shell, base.Shell) || cfg.ArgsEscaped {
		add("runtime_shell_mismatch", "image shell configuration")
	}
	if !cmdOK || !slices.Equal(expectedCmd, cfg.Cmd) {
		add("runtime_command_mismatch", "command")
	}
	labels := map[string]string{}
	for key, value := range base.Labels {
		labels[key] = value
	}
	if raw, exists := model["labels"]; exists {
		values, ok := raw.(map[string]any)
		if !ok {
			add("runtime_labels_mismatch", "labels")
		} else {
			for key, value := range values {
				text, ok := value.(string)
				if !ok {
					add("runtime_labels_mismatch", "labels")
					continue
				}
				labels[key] = text
			}
		}
	}
	actualLabels := map[string]string{}
	for key, value := range cfg.Labels {
		if !strings.HasPrefix(key, "com.docker.compose.") {
			actualLabels[key] = value
		}
	}
	for key := range labels {
		if strings.HasPrefix(key, "com.docker.compose.") {
			delete(labels, key)
		}
	}
	if !reflect.DeepEqual(labels, actualLabels) {
		add("runtime_labels_mismatch", "labels")
	}
	for _, field := range []struct{ key, fallback, actual string }{{"user", base.User, cfg.User}, {"working_dir", base.WorkingDir, cfg.WorkingDir}, {"stop_signal", base.StopSignal, cfg.StopSignal}} {
		expected := field.fallback
		if v, exists := model[field.key]; exists {
			var ok bool
			expected, ok = v.(string)
			if !ok {
				add("runtime_"+field.key+"_mismatch", field.key)
				continue
			}
		}
		if field.key == "working_dir" {
			if expected == "" {
				expected = "/"
			}
			if field.actual == "" {
				field.actual = "/"
			}
		}
		if expected != field.actual {
			add("runtime_"+field.key+"_mismatch", field.key)
		}
	}
	health, validHealth := effectiveHealth(base.Healthcheck, model["healthcheck"])
	if !validHealth || !reflect.DeepEqual(health, normalizeHealth(cfg.Healthcheck)) {
		add("runtime_healthcheck_mismatch", "healthcheck")
	}
	for _, flag := range []struct {
		key    string
		actual bool
	}{{"read_only", hc.ReadonlyRootfs}, {"tty", cfg.Tty}, {"stdin_open", cfg.OpenStdin}} {
		v, _ := model[flag.key].(bool)
		if v != flag.actual {
			add("runtime_"+flag.key+"_mismatch", flag.key)
		}
	}
	if hc.Init != nil && *hc.Init || model["init"] != nil {
		expected, _ := model["init"].(bool)
		if (hc.Init != nil && *hc.Init) != expected {
			add("runtime_init_mismatch", "init")
		}
	}
	if name, _ := model["container_name"].(string); name != "" && strings.TrimPrefix(info.Name, "/") != name {
		add("runtime_name_mismatch", "container_name")
	}
	for _, field := range []struct{ key, actual string }{{"hostname", cfg.Hostname}, {"domainname", cfg.Domainname}} {
		expected, _ := model[field.key].(string)
		// Docker assigns a generated hostname when Compose has none.
		if field.key == "hostname" && expected == "" && len(info.ID) >= 12 {
			expected = info.ID[:12]
		}
		if expected != field.actual {
			add("runtime_"+field.key+"_mismatch", field.key)
		}
	}
	if raw, exists := model["stop_grace_period"]; exists {
		d, err := duration(raw)
		if err != nil || cfg.StopTimeout == nil || int(d/time.Second) != *cfg.StopTimeout {
			add("runtime_stop_timeout_mismatch", "stop_grace_period")
		}
	} else if cfg.StopTimeout != nil && *cfg.StopTimeout != 10 {
		add("runtime_stop_timeout_mismatch", "stop_grace_period")
	}
	expectedCaps, capOK := stringList(model["cap_drop"])
	for i, v := range expectedCaps {
		expectedCaps[i] = strings.TrimPrefix(strings.ToUpper(v), "CAP_")
	}
	actualCaps := slices.Clone(hc.CapDrop)
	for i, v := range actualCaps {
		actualCaps[i] = strings.TrimPrefix(strings.ToUpper(v), "CAP_")
	}
	if !capOK || !sameSet(expectedCaps, actualCaps) {
		add("runtime_capabilities_mismatch", "cap_drop")
	}
	expectedSecurity, secOK := securityOptions(model["security_opt"])
	actualSecurity, actualSecOK := securityOptions(hc.SecurityOpt)
	if !secOK || !actualSecOK || !sameSet(expectedSecurity, actualSecurity) {
		add("runtime_security_mismatch", "security_opt")
	}
	if hc.Privileged || len(hc.CapAdd) > 0 || len(hc.Devices) > 0 || len(hc.DeviceCgroupRules) > 0 || len(hc.DeviceRequests) > 0 || len(hc.VolumesFrom) > 0 || hc.PidMode != "" || hc.UTSMode != "" || hc.UsernsMode != "" || hc.Cgroup != "" || hc.CgroupParent != "" || hc.CgroupnsMode != "" && hc.CgroupnsMode != "private" || hc.IpcMode != "" && hc.IpcMode != "private" || hc.Runtime != "" && hc.Runtime != "runc" || !hc.Isolation.IsDefault() || hc.AutoRemove || hc.PublishAllPorts || len(hc.StorageOpt) > 0 || hc.Umask != nil || len(hc.Annotations) > 0 {
		add("runtime_unsupported_security", "host security and namespaces")
	}
	if len(hc.DNS) > 0 || len(hc.DNSOptions) > 0 || len(hc.DNSSearch) > 0 || len(hc.ExtraHosts) > 0 || len(hc.GroupAdd) > 0 || len(hc.Links) > 0 || len(hc.Sysctls) > 0 || hc.OomScoreAdj != 0 || len(hc.Tmpfs) > 0 {
		add("runtime_unsupported_hostconfig", "additional host configuration")
	}
	if !loggingMatches(model["logging"], hc.LogConfig) {
		add("runtime_logging_mismatch", "logging configuration")
	}
	shm := int64(64 << 20)
	if raw, exists := model["shm_size"]; exists {
		var ok bool
		shm, ok = memory(raw)
		if !ok {
			add("runtime_shm_size_mismatch", "shared memory size")
		}
	}
	if hc.ShmSize != shm && !(hc.ShmSize == 0 && shm == 64<<20) {
		add("runtime_shm_size_mismatch", "shared memory size")
	}

	if cfg.NetworkDisabled && string(hc.NetworkMode) != "none" {
		add("runtime_networks_mismatch", "network disabled flag")
	}
	if info.AppArmorProfile != "" && info.AppArmorProfile != "docker-default" {
		add("runtime_unsupported_security", "AppArmor profile")
	}
	if !defaultPaths(hc.MaskedPaths, defaultMaskedPaths) || !defaultPaths(hc.ReadonlyPaths, defaultReadonlyPaths) {
		add("runtime_unsupported_security", "masked and read-only system paths")
	}
	for _, m := range info.Mounts {
		if m.Propagation != "" && m.Propagation != "rprivate" || m.Driver != "" && m.Driver != "local" || !slices.Contains([]string{"", "ro", "rw"}, m.Mode) {
			add("runtime_unsupported_mount", "mount options")
		}
	}
	for _, m := range hc.Mounts {
		if m.BindOptions != nil && (m.BindOptions.Propagation != "" && m.BindOptions.Propagation != "rprivate" || m.BindOptions.NonRecursive || m.BindOptions.ReadOnlyNonRecursive || m.BindOptions.ReadOnlyForceRecursive) || m.VolumeOptions != nil && (m.VolumeOptions.NoCopy || m.VolumeOptions.Subpath != "" || m.VolumeOptions.DriverConfig != nil) || m.TmpfsOptions != nil {
			add("runtime_unsupported_mount", "mount options")
		}
	}
	if !runtimeMountsMatch(document, c.Component, project, info.Mounts) {
		add("runtime_mounts_mismatch", "mount identities and read-only modes")
	}
	if !runtimeVolumesSafe(info.Mounts, r.volumes) {
		add("runtime_unsupported_volume", "volume driver, options and mountpoint evidence")
	}
	if !portsMatch(model, hc.PortBindings, cfg.ExposedPorts, base.ExposedPorts) {
		add("runtime_ports_mismatch", "published and exposed ports")
	}
	if !networksMatch(model, document, project, c) {
		add("runtime_networks_mismatch", "network attachments")
	}
	if !limitsMatch(model, hc.Resources) {
		add("runtime_limits_mismatch", "resource limits")
	}
	restart, _ := model["restart"].(string)
	if restart == "" {
		restart = "no"
	}
	actualRestart := string(hc.RestartPolicy.Name)
	if actualRestart == "" {
		actualRestart = "no"
	}
	retries := 0
	if n, ok := strings.CutPrefix(restart, "on-failure:"); ok {
		restart = "on-failure"
		retries, _ = strconv.Atoi(n)
	}
	if restart != actualRestart || retries != hc.RestartPolicy.MaximumRetryCount {
		add("runtime_restart_mismatch", "restart policy")
	}
	sort.Slice(issues, func(i, j int) bool { return issues[i].Code+issues[i].Message < issues[j].Code+issues[j].Message })
	return slices.Compact(issues)
}

func environmentMap(env []string) (map[string]string, error) {
	out := map[string]string{}
	for _, item := range env {
		key, value, ok := strings.Cut(item, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid environment")
		}
		if _, exists := out[key]; exists {
			return nil, fmt.Errorf("duplicate environment")
		}
		out[key] = value
	}
	return out, nil
}
func mergedEnvironment(base []string, raw any) (map[string]string, error) {
	out, err := environmentMap(base)
	if err != nil {
		return nil, err
	}
	// Linux daemon supplies this PATH only when the image omits it.
	if _, ok := out["PATH"]; !ok {
		out["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	if raw == nil {
		return out, nil
	}
	values, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("not normalized")
	}
	for key, value := range values {
		if value == nil {
			delete(out, key)
			continue
		}
		str, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("not normalized")
		}
		out[key] = str
	}
	return out, nil
}
func stringList(raw any) ([]string, bool) {
	if raw == nil {
		return nil, true
	}
	if values, ok := raw.([]string); ok {
		return slices.Clone(values), true
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, false
	}
	out := []string{}
	for _, v := range values {
		str, ok := v.(string)
		if !ok {
			return nil, false
		}
		out = append(out, str)
	}
	return out, true
}
func effectiveArgs(model map[string]any, key string, base []string) ([]string, bool) {
	if model[key] == nil {
		return slices.Clone(base), true
	}
	return stringList(model[key])
}
func sameSet(a, b []string) bool {
	a = slices.Clone(a)
	b = slices.Clone(b)
	sort.Strings(a)
	sort.Strings(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}
func securityOptions(raw any) ([]string, bool) {
	values, ok := stringList(raw)
	if !ok {
		return nil, false
	}
	for i, v := range values {
		if v != "no-new-privileges:true" && v != "no-new-privileges=true" && v != "no-new-privileges" {
			return nil, false
		}
		values[i] = "no-new-privileges"
	}
	return values, true
}
func duration(raw any) (time.Duration, error) {
	s, ok := raw.(string)
	if !ok {
		return 0, fmt.Errorf("invalid duration")
	}
	return time.ParseDuration(s)
}
func effectiveHealth(base *container.HealthConfig, raw any) (*container.HealthConfig, bool) {
	h := &container.HealthConfig{}
	if base != nil {
		*h = *base
		h.Test = slices.Clone(base.Test)
	}
	if raw != nil {
		model, ok := raw.(map[string]any)
		if !ok {
			return nil, false
		}
		for key := range model {
			if !slices.Contains([]string{"test", "disable", "interval", "timeout", "start_period", "start_interval", "retries"}, key) {
				return nil, false
			}
		}
		if disabled, _ := model["disable"].(bool); disabled {
			return &container.HealthConfig{Test: []string{"NONE"}}, true
		}
		if model["test"] != nil {
			test, ok := stringList(model["test"])
			if !ok {
				return nil, false
			}
			if len(test) > 0 {
				h.Test = test
			}
		}
		for _, f := range []struct {
			key    string
			target *time.Duration
		}{{"interval", &h.Interval}, {"timeout", &h.Timeout}, {"start_period", &h.StartPeriod}, {"start_interval", &h.StartInterval}} {
			if v, ok := model[f.key]; ok {
				d, err := duration(v)
				if err != nil {
					return nil, false
				}
				if d != 0 {
					*f.target = d
				}
			}
		}
		if v, ok := model["retries"]; ok {
			n, valid := integer(v)
			if !valid {
				return nil, false
			}
			if n != 0 {
				h.Retries = int(n)
			}
		}
	}
	return normalizeHealth(h), true
}
func normalizeHealth(h *container.HealthConfig) *container.HealthConfig {
	if h == nil || len(h.Test) == 0 {
		return nil
	}
	if h.Test[0] == "NONE" {
		return &container.HealthConfig{Test: []string{"NONE"}}
	}
	v := *h
	v.Test = slices.Clone(h.Test)
	return &v
}

// The daemon populates these standard Linux defaults in Inspect. Empty slices
// are rejected, because they can also mean explicit unmasking at creation.
var defaultMaskedPaths = []string{"/proc/acpi", "/proc/asound", "/proc/interrupts", "/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/sched_debug", "/proc/scsi", "/proc/timer_list", "/proc/timer_stats", "/sys/devices/virtual/powercap", "/sys/firmware"}
var defaultReadonlyPaths = []string{"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"}

func defaultPaths(actual, expected []string) bool { return sameSet(actual, expected) }

func portsMatch(model map[string]any, actual network.PortMap, exposed network.PortSet, imagePorts map[string]struct{}) bool {
	expected := map[string][]string{}
	expectedExposed := map[string]bool{}
	for p := range imagePorts {
		expectedExposed[p] = true
	}
	// Image EXPOSE metadata is retained even if not present in Compose.
	// The caller adds it separately through the image baseline below.
	if raw, exists := model["ports"]; exists {
		ports, ok := raw.([]any)
		if !ok {
			return false
		}
		for _, v := range ports {
			p, ok := v.(map[string]any)
			if !ok {
				return false
			}
			for k := range p {
				if !slices.Contains([]string{"target", "published", "host_ip", "protocol", "mode", "name", "app_protocol"}, k) {
					return false
				}
			}
			if mode, _ := p["mode"].(string); mode != "" && mode != "ingress" {
				return false
			}
			if p["name"] != nil || p["app_protocol"] != nil {
				return false
			}
			target, valid := integer(p["target"])
			if !valid || target <= 0 || target > 65535 {
				return false
			}
			protocol, _ := p["protocol"].(string)
			if protocol == "" {
				protocol = "tcp"
			}
			if protocol != "tcp" && protocol != "udp" {
				return false
			}
			port := strconv.FormatInt(target, 10) + "/" + protocol
			published, _ := p["published"].(string)
			if published != "" {
				n, err := strconv.Atoi(published)
				if err != nil || n < 1 || n > 65535 {
					return false
				}
			}
			host, _ := p["host_ip"].(string)
			if host != "" && net.ParseIP(host) == nil {
				return false
			}
			expected[port] = append(expected[port], host+"\x00"+published)
			expectedExposed[port] = true
		}
	}
	if raw, exists := model["expose"]; exists {
		values, ok := raw.([]any)
		if !ok {
			return false
		}
		for _, v := range values {
			port, ok := v.(string)
			if !ok {
				return false
			}
			if !strings.Contains(port, "/") {
				port += "/tcp"
			}
			expectedExposed[port] = true
		}
	}
	if len(expected) != len(actual) {
		return false
	}
	for port, wanted := range expected {
		parsed, err := network.ParsePort(port)
		if err != nil {
			return false
		}
		bindings, ok := actual[parsed]
		if !ok || len(bindings) != len(wanted) {
			return false
		}
		used := map[int]bool{}
		for _, entry := range wanted {
			host, published, _ := strings.Cut(entry, "\x00")
			matched := false
			for i, binding := range bindings {
				if used[i] {
					continue
				}
				if host == hostAddress(binding) && (published == binding.HostPort || published == "" && binding.HostPort == "") {
					used[i] = true
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}
	if len(expectedExposed) != len(exposed) {
		return false
	}
	for port := range expectedExposed {
		parsed, err := network.ParsePort(port)
		if err != nil {
			return false
		}
		if _, ok := exposed[parsed]; !ok {
			return false
		}
	}
	return true
}

func networksMatch(model, document map[string]any, project string, c Container) bool {
	info := c.runtime.container
	hc := info.HostConfig
	if info.NetworkSettings == nil {
		return false
	}
	mode, _ := model["network_mode"].(string)
	if mode != "" {
		if mode != "none" && mode != "bridge" {
			return false
		}
		if string(hc.NetworkMode) != mode {
			return false
		}
		metadata, ok := c.runtime.networks[mode]
		if !ok || metadata.Name != mode || metadata.Scope != "local" || metadata.Internal || metadata.Ingress || metadata.ConfigOnly {
			return false
		}
		if mode == "none" {
			return metadata.Driver == "null" && len(info.NetworkSettings.Networks) == 1 && info.NetworkSettings.Networks["none"] != nil
		}
		// The daemon bridge may contain host-specific options not reproducible
		// from this Compose model; use a project-owned network for MVP import.
		return false
	}
	planned := map[string]any{"default": nil}
	if raw, exists := model["networks"]; exists {
		var ok bool
		planned, ok = raw.(map[string]any)
		if !ok {
			return false
		}
	}
	definitions, _ := document["networks"].(map[string]any)
	if len(planned) != len(info.NetworkSettings.Networks) {
		return false
	}
	for logical, raw := range planned {
		definition, _ := definitions[logical].(map[string]any)
		name, _ := definition["name"].(string)
		if name == "" {
			name = project + "_" + logical
		}
		// Arbitrary network drivers, IPAM and external networks are outside MVP.
		for key := range definition {
			if !slices.Contains([]string{"name", "driver", "external", "labels", "ipam"}, key) {
				return false
			}
		}
		if raw, exists := definition["ipam"]; exists {
			value, ok := raw.(map[string]any)
			if !ok || len(value) > 0 {
				return false
			}
		}
		driver, _ := definition["driver"].(string)
		if driver != "" && driver != "bridge" {
			return false
		}
		if external, _ := definition["external"].(bool); external {
			return false
		}
		ep := info.NetworkSettings.Networks[name]
		if ep == nil {
			return false
		}
		metadata, ok := c.runtime.networks[name]
		if !ok || metadata.Name != name || ep.NetworkID != "" && metadata.ID != ep.NetworkID || metadata.Driver != "bridge" || metadata.Scope != "local" || metadata.Internal || metadata.Attachable || metadata.Ingress || metadata.ConfigOnly || metadata.ConfigFrom.Network != "" || len(metadata.Options) > 0 || metadata.EnableIPv6 || metadata.IPAM.Driver != "default" || len(metadata.IPAM.Options) > 0 || metadata.Labels["com.docker.compose.project"] != project || metadata.Labels["com.docker.compose.network"] != logical {
			return false
		}
		for _, subnet := range metadata.IPAM.Config {
			if subnet.IPRange.IsValid() || len(subnet.AuxAddress) > 0 {
				return false
			}
		}
		aliases := []string{strings.TrimPrefix(info.Name, "/"), c.Component}
		if raw != nil {
			settings, ok := raw.(map[string]any)
			if !ok {
				return false
			}
			for k := range settings {
				if k != "aliases" {
					return false
				}
			}
			extra, ok := stringList(settings["aliases"])
			if !ok {
				return false
			}
			aliases = append(aliases, extra...)
		}
		if !sameSet(aliases, ep.Aliases) || len(ep.Links) > 0 || len(ep.DriverOpts) > 0 || ep.GwPriority != 0 {
			return false
		}
		if ep.IPAMConfig != nil && (ep.IPAMConfig.IPv4Address.IsValid() || ep.IPAMConfig.IPv6Address.IsValid() || len(ep.IPAMConfig.LinkLocalIPs) > 0) {
			return false
		}
	}
	// NetworkMode may identify any of the explicitly attached networks.
	_, ok := info.NetworkSettings.Networks[string(hc.NetworkMode)]
	return ok
}

func integer(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), float64(int64(n)) == n
	case int:
		return int64(n), true
	case int64:
		return n, true
	case string:
		i, e := strconv.ParseInt(n, 10, 64)
		return i, e == nil
	}
	return 0, false
}
func memory(v any) (int64, bool) {
	if s, ok := v.(string); ok {
		n, e := units.RAMInBytes(s)
		return n, e == nil
	}
	return integer(v)
}
func limitsMatch(model map[string]any, r container.Resources) bool {
	for _, field := range []struct {
		key    string
		actual int64
		bytes  bool
	}{{"cpu_shares", r.CPUShares, false}, {"cpu_period", r.CPUPeriod, false}, {"cpu_quota", r.CPUQuota, false}, {"mem_limit", r.Memory, true}, {"mem_reservation", r.MemoryReservation, true}} {
		var value int64
		if raw, exists := model[field.key]; exists {
			var ok bool
			if field.bytes {
				value, ok = memory(raw)
			} else {
				value, ok = integer(raw)
			}
			if !ok {
				return false
			}
		}
		if value != field.actual {
			return false
		}
	}
	if raw, ok := model["cpus"]; ok {
		n, err := strconv.ParseFloat(fmt.Sprint(raw), 64)
		if err != nil || int64(n*1e9) != r.NanoCPUs {
			return false
		}
	} else if r.NanoCPUs != 0 {
		return false
	}
	cpuset, _ := model["cpuset"].(string)
	if cpuset != r.CpusetCpus {
		return false
	}
	swap := int64(0)
	if r.Memory > 0 {
		swap = 2 * r.Memory
	}
	if raw, exists := model["memswap_limit"]; exists {
		var ok bool
		swap, ok = memory(raw)
		if !ok {
			return false
		}
	}
	if swap != r.MemorySwap {
		return false
	}
	pids := int64(0)
	if raw, ok := model["pids_limit"]; ok {
		var valid bool
		pids, valid = integer(raw)
		if !valid {
			return false
		}
	}
	actualPids := int64(0)
	if r.PidsLimit != nil {
		actualPids = *r.PidsLimit
	}
	if pids != actualPids {
		return false
	}
	return r.CPURealtimePeriod == 0 && r.CPURealtimeRuntime == 0 && r.CpusetMems == "" && r.BlkioWeight == 0 && len(r.BlkioWeightDevice) == 0 && len(r.BlkioDeviceReadBps) == 0 && len(r.BlkioDeviceWriteBps) == 0 && len(r.BlkioDeviceReadIOps) == 0 && len(r.BlkioDeviceWriteIOps) == 0 && r.MemorySwappiness == nil && (r.OomKillDisable == nil || !*r.OomKillDisable) && len(r.Ulimits) == 0 && r.CPUCount == 0 && r.CPUPercent == 0 && r.IOMaximumIOps == 0 && r.IOMaximumBandwidth == 0
}

func hostAddress(binding network.PortBinding) string {
	if !binding.HostIP.IsValid() {
		return ""
	}
	return binding.HostIP.String()
}

func loggingMatches(raw any, actual container.LogConfig) bool {
	driver := ""
	options := map[string]string{}
	if raw != nil {
		model, ok := raw.(map[string]any)
		if !ok {
			return false
		}
		for key := range model {
			if key != "driver" && key != "options" {
				return false
			}
		}
		driver, _ = model["driver"].(string)
		if rawOptions, exists := model["options"]; exists {
			values, ok := rawOptions.(map[string]any)
			if !ok {
				return false
			}
			for key, v := range values {
				if key != "max-size" && key != "max-file" && key != "mode" && key != "max-buffer-size" {
					return false
				}
				text, ok := v.(string)
				if !ok {
					return false
				}
				options[key] = text
			}
		}
	}
	if driver == "" {
		if actual.Type != "" && actual.Type != "json-file" && actual.Type != "local" {
			return false
		}
	} else if driver != actual.Type || driver != "json-file" && driver != "local" {
		return false
	}
	if len(options) != len(actual.Config) {
		return false
	}
	for key, value := range options {
		if actual.Config[key] != value {
			return false
		}
	}
	return true
}
