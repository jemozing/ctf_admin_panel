package executor

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/monitoring"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

const metricsInterval = 5 * time.Second
const metricsRetention = time.Hour
const metricsHistorySamples = int(metricsRetention/metricsInterval) + 1
const metricsContainerLimit = 128

type metricsCollector struct {
	mu                sync.RWMutex
	collectMu         sync.Mutex
	running           atomic.Bool
	history           map[domain.ID][]transport.MetricsSample
	previous          map[string]container.StatsResponse
	hostSampler       monitoring.HostSampler
	hostHistory       []transport.HostMetricsSample
	hostLatest        transport.HostMetricsSample
	resetAt           time.Time
	eventsConnected   bool
	eventsConnectedAt time.Time
	eventsError       string
}

func (m *Manager) metricsCollector() *metricsCollector {
	m.metricsOnce.Do(func() {
		m.metrics = &metricsCollector{history: map[domain.ID][]transport.MetricsSample{}, previous: map[string]container.StatsResponse{}, resetAt: time.Now().UTC()}
	})
	return m.metrics
}

// RunMetrics collects independently of browsers. Both count and elapsed time
// bound RAM retention: at most 721 actual observations in the last 60 minutes.
// Restart clears history; gaps are never backfilled or interpolated here.
func (m *Manager) RunMetrics(ctx context.Context) {
	c := m.metricsCollector()
	if !c.running.CompareAndSwap(false, true) {
		return
	}
	defer c.running.Store(false)
	ticker := time.NewTicker(metricsInterval)
	defer ticker.Stop()
	for {
		cycle, cancel := context.WithTimeout(ctx, 4*time.Second)
		c.collect(cycle, m)
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (m *Manager) Metrics(ctx context.Context, id domain.ID) (transport.MetricsResponse, error) {
	return m.MetricsComponent(ctx, id, "")
}

func (m *Manager) MetricsComponent(ctx context.Context, id domain.ID, component string) (transport.MetricsResponse, error) {
	result := transport.MetricsResponse{ServiceID: id, History: []transport.MetricsSample{}, Latest: transport.MetricsSample{Containers: []transport.ContainerMetrics{}}, IntervalSeconds: 5, RetentionSeconds: 3600, Stale: true, HistoryStorage: "memory", AvailableComponents: []string{}}
	s, err := m.Store.GetService(ctx, id)
	if err != nil {
		return result, err
	}
	known := false
	for _, ref := range s.Containers {
		result.AvailableComponents = append(result.AvailableComponents, ref.Component)
		known = known || ref.Component == component
	}
	sort.Strings(result.AvailableComponents)
	if component != "" && !known {
		return result, store.ErrNotFound
	}
	if component == "" && len(result.AvailableComponents) > 0 {
		component = result.AvailableComponents[0]
	}
	result.HistoryComponent = component
	c := m.metricsCollector()
	now := time.Now().UTC()
	c.mu.RLock()
	defer c.mu.RUnlock()
	result.HistoryResetAt = c.resetAt
	history := c.history[id]
	if len(history) == 0 {
		return result, nil
	}
	result.Latest = cloneMetricsSample(history[len(history)-1])
	result.Stale = now.Sub(result.Latest.At) > 3*metricsInterval || result.Latest.At.After(now.Add(metricsInterval))
	for _, sample := range history {
		if sample.At.Before(now.Add(-metricsRetention)) || sample.At.After(now.Add(metricsInterval)) {
			continue
		}
		selected := transport.MetricsSample{At: sample.At, Containers: []transport.ContainerMetrics{}}
		for _, metric := range sample.Containers {
			if metric.Component == component {
				selected.Containers = append(selected.Containers, metric)
			}
		}
		result.History = append(result.History, selected)
	}
	for _, metric := range result.Latest.Containers {
		if metric.Error == "" && !metric.ObservedAt.IsZero() {
			result.Available = true
		}
	}
	// A registration beyond the collector budget remains explicitly unknown;
	// it does not allocate another hour-long series or fabricate zero usage.
	observed := map[string]bool{}
	for _, metric := range result.Latest.Containers {
		observed[metric.Component] = true
	}
	for _, ref := range s.Containers {
		if len(result.Latest.Containers) >= metricsContainerLimit {
			break
		}
		if !observed[ref.Component] {
			result.Latest.Containers = append(result.Latest.Containers, transport.ContainerMetrics{Component: ref.Component, ContainerID: ref.ID, State: "unknown", Error: "Metrics collection budget exceeded or component not sampled"})
		}
	}
	return result, nil
}

func (m *Manager) HostMetrics(ctx context.Context) (transport.HostMetricsResponse, error) {
	if err := ctx.Err(); err != nil {
		return transport.HostMetricsResponse{}, err
	}
	c := m.metricsCollector()
	now := time.Now().UTC()
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := transport.HostMetricsResponse{Latest: c.hostLatest, History: []transport.HostMetricsSample{}, IntervalSeconds: 5, RetentionSeconds: 3600, HistoryResetAt: c.resetAt, HistoryStorage: "memory", Stale: true}
	if result.Latest.At.IsZero() {
		result.Latest = transport.HostMetricsSample{Source: "unconfigured", Scope: "docker_engine_host", Filesystems: []transport.HostFilesystemMetrics{}}
		return result, nil
	}
	result.Stale = now.Sub(result.Latest.At) > 3*metricsInterval || result.Latest.At.After(now.Add(metricsInterval))
	// Filesystem capacity alone is not evidence for host CPU/RAM/network.
	result.Available = result.Latest.MemoryTotalBytes != nil || result.Latest.CoreCount != nil || result.Latest.UptimeSeconds != nil || result.Latest.NetworkRxBytes != nil
	for _, sample := range c.hostHistory {
		if !sample.At.Before(now.Add(-metricsRetention)) && !sample.At.After(now.Add(metricsInterval)) {
			result.History = append(result.History, sample)
		}
	}
	return result, nil
}

func cloneMetricsSample(sample transport.MetricsSample) transport.MetricsSample {
	sample.Containers = append([]transport.ContainerMetrics{}, sample.Containers...)
	return sample
}

func (c *metricsCollector) collect(ctx context.Context, m *Manager) {
	c.collectMu.Lock()
	defer c.collectMu.Unlock()
	at := time.Now().UTC()
	hostConfig := m.Config
	dockerPathVerified := hostConfig.DockerStorageDirectory == ""
	if !dockerPathVerified && m.Engine != nil && m.Engine.Client != nil {
		info, err := m.Engine.Client.Info(ctx, client.InfoOptions{})
		dockerPathVerified = err == nil && info.Info.DockerRootDir == hostConfig.DockerStorageDirectory
	}
	if !dockerPathVerified {
		hostConfig.DockerStorageDirectory = ""
	}
	hostSample := c.hostSampler.Collect(ctx, hostConfig, at)
	if !dockerPathVerified {
		hostSample.Errors["docker_filesystem"] = "Approved Docker path does not match observed daemon data root"
	}
	c.appendHost(hostSample)
	services, err := m.Store.ListServices(ctx)
	if err != nil {
		return
	}
	remaining := metricsContainerLimit
	seenServices := map[domain.ID]bool{}
	seenContainers := map[string]bool{}
	for serviceIndex, service := range services {
		if serviceIndex >= metricsContainerLimit {
			break
		}
		seenServices[service.ID] = true
		sample := transport.MetricsSample{At: at, Containers: []transport.ContainerMetrics{}}
		state, stateErr := m.state(ctx, service)
		refs := state.Containers
		// Only sampled containers occupy the ring, keeping a global128 budget.
		limit := len(refs)
		if limit > remaining {
			limit = remaining
		}
		if limit < 0 {
			limit = 0
		}
		ids := make([]string, 0, limit)
		for _, ref := range refs[:limit] {
			ids = append(ids, ref.ID)
		}
		actual, inventoryErr := m.Engine.MetricsInventory(ctx, service.ComposeProject, ids)
		for _, ref := range refs[:limit] {
			remaining--
			metric := transport.ContainerMetrics{Component: ref.Component, ContainerID: ref.ID, State: "unknown"}
			if stateErr != nil || inventoryErr != nil {
				metric.Error = "Container state is unavailable"
				sample.Containers = append(sample.Containers, metric)
				continue
			}
			found := false
			for _, item := range actual {
				if item.ID == ref.ID && item.Component == ref.Component {
					metric.State = item.State
					metric.RestartCount = item.RestartCount
					metric.OOMKilled = item.OOMKilled
					metric.CPULimitPercent = item.CPULimitPercent
					metric.PidsLimit = item.PidsLimit
					found = true
					break
				}
			}
			if !found {
				metric.Error = "Registered container was not observed"
				sample.Containers = append(sample.Containers, metric)
				continue
			}
			if metric.State != "running" {
				metric.Error = "Container is not running"
				sample.Containers = append(sample.Containers, metric)
				continue
			}
			seenContainers[ref.ID] = true
			stats, err := readContainerStats(ctx, m.Engine.Client, ref.ID)
			if err != nil {
				metric.Error = "Container statistics are unavailable"
			} else {
				previous, known := c.previous[ref.ID]
				mapped := mapContainerStats(ref.Component, ref.ID, stats, previous, known)
				mapped.RestartCount = metric.RestartCount
				mapped.OOMKilled = metric.OOMKilled
				mapped.CPULimitPercent = metric.CPULimitPercent
				if mapped.PidsLimit == nil {
					mapped.PidsLimit = metric.PidsLimit
				}
				metric = mapped
				c.previous[ref.ID] = stats
			}
			sample.Containers = append(sample.Containers, metric)
		}
		c.append(service.ID, sample)
	}
	for id := range c.previous {
		if !seenContainers[id] {
			delete(c.previous, id)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for id := range c.history {
		if !seenServices[id] {
			delete(c.history, id)
		}
	}
}

func (c *metricsCollector) append(id domain.ID, sample transport.MetricsSample) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.history == nil {
		c.history = map[domain.ID][]transport.MetricsSample{}
	}
	history := c.history[id]
	if len(history) > 0 && !sample.At.After(history[len(history)-1].At) {
		history = nil
	}
	history = append(history, sample)
	first := 0
	cutoff := sample.At.Add(-metricsRetention)
	for first < len(history) && history[first].At.Before(cutoff) {
		first++
	}
	if len(history)-first > metricsHistorySamples {
		first = len(history) - metricsHistorySamples
	}
	if first > 0 {
		copy(history, history[first:])
		history = history[:len(history)-first]
	}
	c.history[id] = history
}

func (c *metricsCollector) appendHost(sample transport.HostMetricsSample) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hostLatest = sample
	// Current metadata is not repeatedly retained with numeric observations.
	sample.NetworkInterfaces = nil
	sample.Sources = nil
	history := c.hostHistory
	if len(history) > 0 && !sample.At.After(history[len(history)-1].At) {
		history = nil
	}
	history = append(history, sample)
	first := 0
	cutoff := sample.At.Add(-metricsRetention)
	for first < len(history) && history[first].At.Before(cutoff) {
		first++
	}
	if len(history)-first > metricsHistorySamples {
		first = len(history) - metricsHistorySamples
	}
	if first > 0 {
		copy(history, history[first:])
		history = history[:len(history)-first]
	}
	c.hostHistory = history
}

func readContainerStats(ctx context.Context, api *client.Client, id string) (container.StatsResponse, error) {
	var stats container.StatsResponse
	response, err := api.ContainerStats(ctx, id, client.ContainerStatsOptions{Stream: false, IncludePreviousSample: false})
	if err != nil {
		return stats, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil {
		return stats, err
	}
	if len(data) > 1<<20 {
		return stats, io.ErrShortBuffer
	}
	err = json.Unmarshal(data, &stats)
	return stats, err
}

func mapContainerStats(component, id string, current, previous container.StatsResponse, known bool) transport.ContainerMetrics {
	result := transport.ContainerMetrics{Component: component, ContainerID: id, State: "running", ObservedAt: current.Read.UTC()}
	if current.Read.IsZero() {
		result.Error = "Statistics have no observation timestamp"
		return result
	}
	if current.OSType != "" && current.OSType != "linux" {
		result.Error = "Only Linux container statistics are supported"
		return result
	}
	if known && current.Read.After(previous.Read) && current.Read.Sub(previous.Read) <= 3*metricsInterval && current.CPUStats.SystemUsage > previous.CPUStats.SystemUsage && current.CPUStats.CPUUsage.TotalUsage >= previous.CPUStats.CPUUsage.TotalUsage {
		cpus := current.CPUStats.OnlineCPUs
		if cpus == 0 {
			cpus = uint32(len(current.CPUStats.CPUUsage.PercpuUsage))
		}
		if cpus > 0 {
			value := float64(current.CPUStats.CPUUsage.TotalUsage-previous.CPUStats.CPUUsage.TotalUsage) / float64(current.CPUStats.SystemUsage-previous.CPUStats.SystemUsage) * float64(cpus) * 100
			if !math.IsNaN(value) && !math.IsInf(value, 0) {
				result.CPUPercent = &value
			}
		}
	}
	usage := current.MemoryStats.Usage
	cache := current.MemoryStats.Stats["total_inactive_file"]
	if cache == 0 {
		cache = current.MemoryStats.Stats["inactive_file"]
	}
	if cache < usage {
		usage -= cache
	}
	limit := current.MemoryStats.Limit
	result.MemoryUsageBytes = &usage
	if limit != 0 {
		result.MemoryLimitBytes = &limit
	}
	if current.Networks != nil {
		var rx, tx uint64
		valid := true
		for _, network := range current.Networks {
			if math.MaxUint64-rx < network.RxBytes || math.MaxUint64-tx < network.TxBytes {
				valid = false
				break
			}
			rx += network.RxBytes
			tx += network.TxBytes
		}
		if valid {
			result.NetworkRxBytes = &rx
			result.NetworkTxBytes = &tx
		}
	}
	if current.PidsStats.Current > 0 {
		v := current.PidsStats.Current
		result.PidsCurrent = &v
	}
	if current.PidsStats.Limit > 0 {
		v := current.PidsStats.Limit
		result.PidsLimit = &v
	}
	if len(current.BlkioStats.IoServiceBytesRecursive) > 0 {
		var read, write uint64
		valid := true
		for _, item := range current.BlkioStats.IoServiceBytesRecursive {
			switch strings.ToLower(item.Op) {
			case "read":
				if math.MaxUint64-read < item.Value {
					valid = false
				} else {
					read += item.Value
				}
			case "write":
				if math.MaxUint64-write < item.Value {
					valid = false
				} else {
					write += item.Value
				}
			}
		}
		if valid {
			result.BlockReadBytes = &read
			result.BlockWriteBytes = &write
		}
	}
	return result
}
