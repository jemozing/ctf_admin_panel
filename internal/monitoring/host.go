package monitoring

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"golang.org/x/sys/unix"
)

const HostDirectory = "/run/ctf-manager-host"

var procFiles = []string{"stat", "meminfo", "loadavg", "uptime", "net-dev"}

type HostSampler struct {
	previous       cpuCounters
	previousAt     time.Time
	previousUptime float64
	known          bool
}

func readFixed(path string, limit int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("source must be a regular proc file")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("source exceeds read limit")
	}
	return data, nil
}

// verifiedProcMounts rejects an ordinary file, executor /proc fallback, writable
// bind, or a namespace substituted by an unapproved broad mount. Bootstrap
// authorizes the five exact host sources; mountinfo supplies runtime evidence.
func verifiedProcMounts(data string) map[string]bool {
	result := map[string]bool{}
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		separator := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				separator = i
				break
			}
		}
		if separator < 0 || separator+3 >= len(fields) || fields[separator+1] != "proc" {
			continue
		}
		ro := false
		for _, option := range strings.Split(fields[5], ",") {
			if option == "ro" {
				ro = true
			}
		}
		if !ro {
			continue
		}
		for _, name := range procFiles {
			if fields[4] == filepath.Join(HostDirectory, name) {
				// /proc/net/dev resolves to PID1's host network namespace at
				// bootstrap, while stat/meminfo/loadavg/uptime have fixed roots.
				root := fields[3]
				if name == "net-dev" {
					if root == "/1/net/dev" || root == "/1/net/dev//deleted" {
						result[name] = true
					}
				} else {
					if root == "/"+name {
						result[name] = true
					}
				}
			}
		}
	}
	return result
}

func (s *HostSampler) Collect(ctx context.Context, c config.Config, at time.Time) transport.HostMetricsSample {
	result := transport.HostMetricsSample{At: at.UTC(), Source: "unconfigured", Scope: "docker_engine_host", Filesystems: []transport.HostFilesystemMetrics{}, Errors: map[string]string{}, Sources: map[string]string{}}
	if c.Development || runtime.GOOS != "linux" {
		result.Scope = "local_executor"
	} else if !c.HostMetrics {
		result.Scope = "executor_mounts"
	}
	result.Filesystems = filesystems(ctx, c, &result)
	if !c.HostMetrics {
		result.Errors["host_source"] = "Host proc metrics require explicit administrator bootstrap"
		s.known = false
		return result
	}
	result.Source = "approved_host_proc_files"
	if runtime.GOOS != "linux" {
		result.Errors["host_source"] = "Approved Linux host proc mounts are unavailable on this platform"
		s.known = false
		return result
	}
	data, err := readFixed("/proc/self/mountinfo", 2<<20)
	if err != nil {
		result.Errors["host_source"] = "Host source mount evidence is unavailable"
		s.known = false
		return result
	}
	verified := verifiedProcMounts(string(data))
	if len(verified) > 0 {
		result.Scope = "docker_engine_host"
	}
	sources := map[string]string{}
	for _, name := range procFiles {
		if ctx.Err() != nil {
			result.Errors["collection"] = "Host collection deadline exceeded"
			break
		}
		if !verified[name] {
			result.Errors[name] = "Exact read-only host proc mount is unavailable"
			continue
		}
		content, err := readFixed(filepath.Join(HostDirectory, name), 1<<20)
		if err != nil {
			result.Errors[name] = "Host proc observation is unavailable"
			continue
		}
		sources[name] = string(content)
		result.Sources[name] = "read_only_host_proc:" + name
	}
	s.applySources(&result, sources, at)
	return result
}

func (s *HostSampler) applySources(result *transport.HostMetricsSample, sources map[string]string, at time.Time) {
	if raw, ok := sources["uptime"]; ok {
		v, err := parseUptime(raw)
		if err != nil {
			result.Errors["uptime"] = "Invalid host uptime evidence"
		} else {
			result.UptimeSeconds = &v
		}
	}
	if raw, ok := sources["stat"]; ok {
		v, err := parseCPU(raw)
		if err != nil {
			result.Errors["stat"] = "Invalid host CPU evidence"
			s.known = false
		} else {
			result.CoreCount = &v.cores
			// Counter resets/reboots/backwards or long missing intervals do not
			// produce CPU spikes or bridge gaps with an invented observation.
			validUptime := result.UptimeSeconds != nil && *result.UptimeSeconds >= s.previousUptime
			if s.known && validUptime && at.After(s.previousAt) && at.Sub(s.previousAt) <= 15*time.Second && v.total > s.previous.total && v.idle >= s.previous.idle {
				total, idle := v.total-s.previous.total, v.idle-s.previous.idle
				if idle <= total {
					percent := float64(total-idle) / float64(total) * 100
					result.CPUPercent = &percent
				}
			}
			s.previous = v
			s.previousAt = at
			s.known = result.UptimeSeconds != nil
			if result.UptimeSeconds != nil {
				s.previousUptime = *result.UptimeSeconds
			}
		}
	} else {
		s.known = false
	}
	if raw, ok := sources["meminfo"]; ok {
		v, err := parseMemory(raw)
		if err != nil {
			result.Errors["meminfo"] = "Invalid or unsupported host memory evidence"
		} else {
			total, available, swap := v["MemTotal:"], v["MemAvailable:"], v["SwapTotal:"]
			used, swapUsed := total-available, swap-v["SwapFree:"]
			result.MemoryTotalBytes = &total
			result.MemoryAvailableBytes = &available
			result.MemoryUsedBytes = &used
			result.SwapTotalBytes = &swap
			result.SwapUsedBytes = &swapUsed
		}
	}
	if raw, ok := sources["loadavg"]; ok {
		v, err := parseLoad(raw)
		if err != nil {
			result.Errors["loadavg"] = "Invalid host load evidence"
		} else {
			result.LoadAverage1 = &v[0]
			result.LoadAverage5 = &v[1]
			result.LoadAverage15 = &v[2]
		}
	}
	if raw, ok := sources["net-dev"]; ok {
		v, rx, tx, err := parseNetwork(raw)
		if err != nil {
			result.Errors["net-dev"] = "Invalid host network evidence"
		} else {
			result.NetworkInterfaces = v
			result.NetworkRxBytes = &rx
			result.NetworkTxBytes = &tx
		}
	}
}

func filesystems(ctx context.Context, c config.Config, sample *transport.HostMetricsSample) []transport.HostFilesystemMetrics {
	type root struct{ name, path, source string }
	roots := []root{{"state", c.StateDirectory, "approved_state_mount"}}
	for i, path := range c.DiscoveryRoots {
		roots = append(roots, root{fmt.Sprintf("discovery-%d", i+1), path, "approved_discovery_mount"})
	}
	for i, path := range c.WorkspaceRoots {
		roots = append(roots, root{fmt.Sprintf("workspace-%d", i+1), path, "approved_workspace_mount"})
	}
	if c.DockerStorageDirectory != "" {
		roots = append(roots, root{"docker", c.DockerStorageDirectory, "approved_docker_storage_mount"})
	}
	result := []transport.HostFilesystemMetrics{}
	seen := map[string]bool{}
	for _, root := range roots {
		if root.path == "" || seen[root.path] {
			continue
		}
		seen[root.path] = true
		if len(result) >= 16 {
			sample.Errors["filesystems"] = "Filesystem source limit exceeded (16 approved paths)"
			break
		}
		if ctx.Err() != nil {
			sample.Errors["filesystems"] = "Filesystem collection deadline exceeded"
			break
		}
		metric := transport.HostFilesystemMetrics{Name: root.name, Source: root.source}
		if err := filesystemCapacity(root.path, &metric); err != nil {
			metric.Error = "Approved filesystem capacity is unavailable"
		}
		result = append(result, metric)
	}
	return result
}
