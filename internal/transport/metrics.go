package transport

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

// ContainerMetrics uses nullable measurements: missing evidence is never a zero.
type ContainerMetrics struct {
	Component        string    `json:"component"`
	ContainerID      string    `json:"container_id,omitempty"`
	State            string    `json:"state"`
	ObservedAt       time.Time `json:"observed_at,omitzero"`
	CPUPercent       *float64  `json:"cpu_percent"`
	MemoryUsageBytes *uint64   `json:"memory_usage_bytes"`
	MemoryLimitBytes *uint64   `json:"memory_limit_bytes"`
	NetworkRxBytes   *uint64   `json:"network_rx_bytes"`
	NetworkTxBytes   *uint64   `json:"network_tx_bytes"`
	BlockReadBytes   *uint64   `json:"block_read_bytes"`
	BlockWriteBytes  *uint64   `json:"block_write_bytes"`
	PidsCurrent      *uint64   `json:"pids_current"`
	PidsLimit        *uint64   `json:"pids_limit"`
	RestartCount     *uint64   `json:"restart_count"`
	OOMKilled        *bool     `json:"oom_killed"`
	CPULimitPercent  *float64  `json:"cpu_limit_percent"`
	Error            string    `json:"error,omitempty"`
}
type MetricsSample struct {
	At         time.Time          `json:"at"`
	Containers []ContainerMetrics `json:"containers"`
}
type MetricsResponse struct {
	ServiceID           domain.ID       `json:"service_id"`
	Available           bool            `json:"available"`
	Stale               bool            `json:"stale"`
	Latest              MetricsSample   `json:"latest"`
	History             []MetricsSample `json:"history"`
	IntervalSeconds     int             `json:"interval_seconds"`
	RetentionSeconds    int             `json:"retention_seconds"`
	HistoryComponent    string          `json:"history_component"`
	AvailableComponents []string        `json:"available_components"`
	HistoryResetAt      time.Time       `json:"history_reset_at"`
	HistoryStorage      string          `json:"history_storage"`
}

type HostFilesystemMetrics struct {
	Name            string  `json:"name"`
	Source          string  `json:"source"`
	AvailableBytes  *uint64 `json:"available_bytes"`
	TotalBytes      *uint64 `json:"total_bytes"`
	AvailableInodes *uint64 `json:"available_inodes"`
	TotalInodes     *uint64 `json:"total_inodes"`
	Error           string  `json:"error,omitempty"`
}
type HostNetworkMetrics struct {
	Name    string `json:"name"`
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
}
type HostMetricsSample struct {
	At                   time.Time               `json:"at"`
	Source               string                  `json:"source"`
	Scope                string                  `json:"scope"`
	CPUPercent           *float64                `json:"cpu_percent"`
	CoreCount            *uint64                 `json:"core_count"`
	MemoryTotalBytes     *uint64                 `json:"memory_total_bytes"`
	MemoryAvailableBytes *uint64                 `json:"memory_available_bytes"`
	MemoryUsedBytes      *uint64                 `json:"memory_used_bytes"`
	SwapTotalBytes       *uint64                 `json:"swap_total_bytes"`
	SwapUsedBytes        *uint64                 `json:"swap_used_bytes"`
	LoadAverage1         *float64                `json:"load_average_1"`
	LoadAverage5         *float64                `json:"load_average_5"`
	LoadAverage15        *float64                `json:"load_average_15"`
	UptimeSeconds        *float64                `json:"uptime_seconds"`
	NetworkRxBytes       *uint64                 `json:"network_rx_bytes"`
	NetworkTxBytes       *uint64                 `json:"network_tx_bytes"`
	NetworkInterfaces    []HostNetworkMetrics    `json:"network_interfaces,omitempty"`
	Filesystems          []HostFilesystemMetrics `json:"filesystems"`
	Sources              map[string]string       `json:"sources,omitempty"`
	Errors               map[string]string       `json:"errors,omitempty"`
}
type HostMetricsResponse struct {
	Available        bool                `json:"available"`
	Stale            bool                `json:"stale"`
	Latest           HostMetricsSample   `json:"latest"`
	History          []HostMetricsSample `json:"history"`
	IntervalSeconds  int                 `json:"interval_seconds"`
	RetentionSeconds int                 `json:"retention_seconds"`
	HistoryResetAt   time.Time           `json:"history_reset_at"`
	HistoryStorage   string              `json:"history_storage"`
}

type MetricsBackend interface {
	Metrics(context.Context, domain.ID) (MetricsResponse, error)
}
type ComponentMetricsBackend interface {
	MetricsComponent(context.Context, domain.ID, string) (MetricsResponse, error)
}
type HostMetricsBackend interface {
	HostMetrics(context.Context) (HostMetricsResponse, error)
}

var metricsComponentPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

// MetricsComponentQuery accepts a single fixed selector, never arbitrary daemon options.
func MetricsComponentQuery(raw string) (string, bool) {
	if raw == "" {
		return "", true
	}
	q, err := url.ParseQuery(raw)
	if err != nil || len(q) != 1 || len(q["component"]) != 1 || !metricsComponentPattern.MatchString(q.Get("component")) {
		return "", false
	}
	return q.Get("component"), true
}

func (s *Server) metricsEndpoint(w http.ResponseWriter, r *http.Request, id domain.ID) {
	component, valid := MetricsComponentQuery(r.URL.RawQuery)
	if !valid {
		writeError(w, 400, "invalid_query", "only one approved component selector is supported")
		return
	}
	backend, ok := s.options.Backend.(MetricsBackend)
	if !ok {
		writeError(w, 501, "not_implemented", "metrics collection unavailable")
		return
	}
	var result MetricsResponse
	var err error
	if component == "" {
		result, err = backend.Metrics(r.Context(), id)
	} else {
		selected, ok := s.options.Backend.(ComponentMetricsBackend)
		if !ok {
			writeError(w, 501, "not_implemented", "component history unavailable")
			return
		}
		result, err = selected.MetricsComponent(r.Context(), id, component)
	}
	if err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, 200, result)
}

func (s *Server) hostMetricsEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	backend, ok := s.options.Backend.(HostMetricsBackend)
	if !ok {
		writeError(w, 501, "not_implemented", "host metrics unavailable")
		return
	}
	result, err := backend.HostMetrics(r.Context())
	if err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, 200, result)
}

func (c *Client) HostMetrics(ctx context.Context) (HostMetricsResponse, error) {
	var result HostMetricsResponse
	err := c.request(ctx, http.MethodGet, "/v1/metrics/host", nil, &result)
	return result, err
}

func (c *Client) Metrics(ctx context.Context, id domain.ID) (MetricsResponse, error) {
	return c.MetricsComponent(ctx, id, "")
}
func (c *Client) MetricsComponent(ctx context.Context, id domain.ID, component string) (MetricsResponse, error) {
	var result MetricsResponse
	if err := id.Validate(); err != nil {
		return result, err
	}
	path := "/v1/services/" + string(id) + "/metrics"
	if component != "" {
		if !metricsComponentPattern.MatchString(component) {
			return result, &ProtocolError{Status: 400, Code: "invalid_component", Message: "invalid component selector"}
		}
		path += "?" + url.Values{"component": []string{component}}.Encode()
	}
	err := c.request(ctx, http.MethodGet, path, nil, &result)
	return result, err
}
