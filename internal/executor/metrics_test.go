package executor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

func TestMetricsCPUAndMemoryMapping(t *testing.T) {
	previous := container.StatsResponse{Read: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), CPUStats: container.CPUStats{CPUUsage: container.CPUUsage{TotalUsage: 100}, SystemUsage: 1000}}
	current := container.StatsResponse{Read: previous.Read.Add(5 * time.Second), CPUStats: container.CPUStats{CPUUsage: container.CPUUsage{TotalUsage: 150}, SystemUsage: 2000, OnlineCPUs: 4}, MemoryStats: container.MemoryStats{Usage: 1024, Limit: 4096, Stats: map[string]uint64{"inactive_file": 256}}, Networks: map[string]container.NetworkStats{"eth0": {RxBytes: 100, TxBytes: 200}, "eth1": {RxBytes: 50, TxBytes: 25}}}
	first := mapContainerStats("app", "container-a", current, container.StatsResponse{}, false)
	if first.CPUPercent != nil {
		t.Fatal("first sample invented CPU percentage")
	}
	metric := mapContainerStats("app", "container-a", current, previous, true)
	if metric.CPUPercent == nil || *metric.CPUPercent != 20 {
		t.Fatalf("CPU delta mapping: %+v", metric.CPUPercent)
	}
	if metric.MemoryUsageBytes == nil || *metric.MemoryUsageBytes != 768 || *metric.MemoryLimitBytes != 4096 {
		t.Fatal("memory cache/limit mapping failed")
	}
	if *metric.NetworkRxBytes != 150 || *metric.NetworkTxBytes != 225 {
		t.Fatal("network counters did not sum interfaces")
	}
	current.MemoryStats.Stats = map[string]uint64{"total_inactive_file": 128, "inactive_file": 256}
	metric = mapContainerStats("app", "container-a", current, previous, true)
	if *metric.MemoryUsageBytes != 896 {
		t.Fatal("cgroup v1 cache mapping failed")
	}
	current.CPUStats.CPUUsage.TotalUsage = 1
	metric = mapContainerStats("app", "container-a", current, previous, true)
	if metric.CPUPercent != nil {
		t.Fatal("counter reset produced fake CPU")
	}
	current.Read = time.Time{}
	metric = mapContainerStats("app", "container-a", current, previous, true)
	if metric.Error == "" || metric.MemoryUsageBytes != nil {
		t.Fatal("missing observation exposed fake metrics")
	}
}

func TestMetricsHourWindowGapsAndClockRollback(t *testing.T) {
	c := metricsCollector{}
	at := time.Unix(10_000, 0)
	for i := 0; i < 1500; i++ {
		stamp := at.Add(time.Duration(i) * 5 * time.Second)
		c.append("service", transport.MetricsSample{At: stamp})
		c.appendHost(transport.HostMetricsSample{At: stamp})
	}
	if len(c.history["service"]) != 721 || len(c.hostHistory) != 721 {
		t.Fatal("hour rings not bounded")
	}
	last := at.Add(1499 * 5 * time.Second)
	if c.history["service"][0].At != last.Add(-time.Hour) {
		t.Fatal("ring cutoff is not actual60minutes")
	}
	c.append("service", transport.MetricsSample{At: last.Add(2 * time.Hour)})
	c.appendHost(transport.HostMetricsSample{At: last.Add(2 * time.Hour)})
	if len(c.history["service"]) != 1 || len(c.hostHistory) != 1 {
		t.Fatal("gap invented or retained expired observations")
	}
	c.append("service", transport.MetricsSample{At: last})
	c.appendHost(transport.HostMetricsSample{At: last})
	if len(c.history["service"]) != 1 || len(c.hostHistory) != 1 {
		t.Fatal("backwards clock left future observations")
	}
}

func TestMetricsReadsSelectedComponentAndRemainsConcurrent(t *testing.T) {
	f := newPlanningFixture(t)
	c := f.m.metricsCollector()
	now := time.Now().UTC()
	for i := 0; i < 721; i++ {
		at := now.Add(time.Duration(i-720) * 5 * time.Second)
		c.append(f.s.ID, transport.MetricsSample{At: at, Containers: []transport.ContainerMetrics{{Component: "app", ContainerID: "approved", State: "running", ObservedAt: at}, {Component: "other", ContainerID: "historical", State: "running", ObservedAt: at}}})
	}
	result, err := f.m.Metrics(t.Context(), f.s.ID)
	if err != nil || len(result.History) < 720 || result.HistoryComponent != "app" || result.RetentionSeconds != 3600 || result.HistoryStorage != "memory" || result.HistoryResetAt.IsZero() {
		t.Fatalf("history contract: %+v %v", result, err)
	}
	if len(result.Latest.Containers) != 2 || len(result.History[0].Containers) != 1 || result.History[0].Containers[0].Component != "app" {
		t.Fatal("history selectedallcomponents or latest lost data")
	}
	if _, err = f.m.MetricsComponent(t.Context(), f.s.ID, "other"); err == nil {
		t.Fatal("unregistered component history exposed")
	}
	payload, err := json.Marshal(result)
	if err != nil || len(payload) > 1<<20 {
		t.Fatalf("selected history violates boundedresponse: %d %v", len(payload), err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Go(func() {
			for j := 0; j < 20; j++ {
				if _, err := f.m.Metrics(t.Context(), f.s.ID); err != nil {
					t.Error(err)
				}
				if _, err := f.m.HostMetrics(t.Context()); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Go(func() {
		for j := 0; j < 50; j++ {
			at := now.Add(time.Duration(j+1) * time.Millisecond)
			c.append(f.s.ID, transport.MetricsSample{At: at, Containers: []transport.ContainerMetrics{}})
			c.appendHost(transport.HostMetricsSample{At: at})
		}
	})
	wg.Wait()
}

func TestMetricsRingRemainsBounded(t *testing.T) {
	c := metricsCollector{history: map[domain.ID][]transport.MetricsSample{}}
	for i := 0; i < 2000; i++ {
		c.append("service", transport.MetricsSample{At: time.Unix(int64(i)*5, 0)})
	}
	history := c.history["service"]
	if len(history) != metricsHistorySamples || history[0].At.Unix() != int64(2000-metricsHistorySamples)*5 || history[len(history)-1].At.Unix() != 1999*5 {
		t.Fatal("metric ring lost ordering or grew past limit")
	}
}

type statsRoundTripper func(*http.Request) (*http.Response, error)

func (f statsRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMetricsSDKUsesSingleBoundedObservation(t *testing.T) {
	oversized := false
	calls := 0
	httpClient := &http.Client{Transport: statsRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls++
		if !strings.HasSuffix(r.URL.Path, "/containers/approved-container/stats") || r.URL.Query().Get("stream") != "false" || r.URL.Query().Get("one-shot") != "true" {
			t.Fatalf("unbounded Docker stats request: %s", r.URL)
		}
		body := `{"read":"2026-01-01T00:00:00Z","cpu_stats":{"online_cpus":4},"memory_stats":{"usage":1024,"limit":4096}}`
		if oversized {
			body = strings.Repeat("x", (1<<20)+1)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	api, err := client.New(client.WithHost("http://docker.invalid"), client.WithHTTPClient(httpClient), client.WithAPIVersion("1.56"))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	stats, err := readContainerStats(context.Background(), api, "approved-container")
	if err != nil || stats.MemoryStats.Usage != 1024 {
		t.Fatalf("sample mapping: %+v %v", stats, err)
	}
	oversized = true
	if _, err = readContainerStats(context.Background(), api, "approved-container"); err == nil {
		t.Fatal("oversized daemon response accepted")
	}
	if calls != 2 {
		t.Fatal("unexpected streaming/background calls")
	}
	payload, err := json.Marshal(transport.ContainerMetrics{Component: "app"})
	if err != nil || !strings.Contains(string(payload), `"cpu_percent":null`) {
		t.Fatal("unknown metrics serialized as fake zero")
	}
}

func TestHostHourPayloadRemainsBelowIPCResponseLimit(t *testing.T) {
	value := uint64(1 << 63)
	percent := 99.99
	sample := transport.HostMetricsSample{At: time.Now().UTC(), Source: "approved_host_proc_files", Scope: "docker_engine_host", CPUPercent: &percent, CoreCount: &value, MemoryTotalBytes: &value, MemoryAvailableBytes: &value, MemoryUsedBytes: &value, SwapTotalBytes: &value, SwapUsedBytes: &value, NetworkRxBytes: &value, NetworkTxBytes: &value, Filesystems: []transport.HostFilesystemMetrics{}}
	for i := 0; i < 16; i++ {
		sample.Filesystems = append(sample.Filesystems, transport.HostFilesystemMetrics{Name: "discovery-16", Source: "approved_discovery_mount", AvailableBytes: &value, TotalBytes: &value, AvailableInodes: &value, TotalInodes: &value})
	}
	response := transport.HostMetricsResponse{Latest: sample, History: make([]transport.HostMetricsSample, 721), IntervalSeconds: 5, RetentionSeconds: 3600}
	for i := range response.History {
		response.History[i] = sample
	}
	data, err := json.Marshal(response)
	if err != nil || len(data) >= 4*1024*1024 {
		t.Fatalf("bounded host history payload: %d %v", len(data), err)
	}
}

func TestContainerAdditionalCountersAndUnavailableEvidence(t *testing.T) {
	stats := container.StatsResponse{Read: time.Now().UTC(), PidsStats: container.PidsStats{Current: 7, Limit: 32}, BlkioStats: container.BlkioStats{IoServiceBytesRecursive: []container.BlkioStatEntry{{Op: "Read", Value: 10}, {Op: "Write", Value: 20}, {Op: "Total", Value: 30}}}}
	metric := mapContainerStats("app", "id", stats, container.StatsResponse{}, false)
	if metric.PidsCurrent == nil || *metric.PidsCurrent != 7 || metric.PidsLimit == nil || *metric.PidsLimit != 32 || metric.BlockReadBytes == nil || *metric.BlockReadBytes != 10 || metric.BlockWriteBytes == nil || *metric.BlockWriteBytes != 20 {
		t.Fatalf("extra counters: %+v", metric)
	}
	stats.PidsStats = container.PidsStats{}
	stats.BlkioStats = container.BlkioStats{}
	metric = mapContainerStats("app", "id", stats, container.StatsResponse{}, false)
	if metric.PidsCurrent != nil || metric.PidsLimit != nil || metric.BlockReadBytes != nil || metric.BlockWriteBytes != nil || metric.RestartCount != nil || metric.OOMKilled != nil {
		t.Fatal("missing evidence became fakezero")
	}
}
