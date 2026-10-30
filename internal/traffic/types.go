// Package traffic is the bounded, separately authenticated HTTP traffic recorder.
// It has no Docker, executor IPC, panel state or game filesystem access.
package traffic

import (
	"net/http"
	"time"
)

// Metadata is the only shape returned by list queries. It deliberately has no
// request/response headers or payload, including when the caller is an Admin.
type Metadata struct {
	Sequence            int64      `json:"sequence"`
	RequestID           string     `json:"request_id"`
	CollectorEpoch      string     `json:"collector_epoch"`
	ServiceID           string     `json:"service_id"`
	RouteID             string     `json:"route_id"`
	PolicyRevision      uint64     `json:"policy_revision"`
	At                  time.Time  `json:"at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	EndAt               *time.Time `json:"end_at,omitempty"`
	State               string     `json:"state"`
	PeerIP              string     `json:"peer_ip"`
	ClientIP            string     `json:"client_ip"`
	ClientIPSource      string     `json:"client_ip_source"`
	HTTPProtocol        string     `json:"http_protocol,omitempty"`
	Method              string     `json:"method"`
	URL                 string     `json:"url"`
	Upstream            string     `json:"upstream"`
	Status              int        `json:"status"`
	ResponseSource      string     `json:"response_source"`
	DurationMS          float64    `json:"duration_ms"`
	RequestBytes        int64      `json:"request_bytes"`
	ResponseBytes       int64      `json:"response_bytes"`
	WAFDecision         string     `json:"waf_decision"`
	WAFReason           string     `json:"waf_reason,omitempty"`
	Truncated           bool       `json:"truncated"`
	Dropped             bool       `json:"dropped"`
	RecorderUnavailable bool       `json:"recorder_unavailable"`
}

// Body.Data is redacted text unless SensitiveRaw explicitly marks bounded
// opaque gRPC bytes from H2 termination. Such bytes have no automatic secret
// redaction. Other unredactable bodies have empty Data and NotCapturedReason.
type Body struct {
	SensitiveRaw      bool   `json:"sensitive_raw,omitempty"`
	Encoding          string `json:"encoding,omitempty"`
	Data              string `json:"data,omitempty"`
	ObservedBytes     int64  `json:"observed_bytes"`
	CapturedBytes     int64  `json:"captured_bytes"`
	Truncated         bool   `json:"truncated"`
	NotCapturedReason string `json:"not_captured_reason,omitempty"`
	ContentType       string `json:"content_type,omitempty"`
	ContentEncoding   string `json:"content_encoding,omitempty"`
}

// Exchange is an initial/intermediate/final observation of one request. Updates
// use the same RequestID, CollectorEpoch, ServiceID, RouteID and At values.
type Exchange struct {
	Metadata
	RequestHeaders   http.Header `json:"request_headers,omitempty"`
	ResponseHeaders  http.Header `json:"response_headers,omitempty"`
	RequestTrailers  http.Header `json:"request_trailers,omitempty"`
	ResponseTrailers http.Header `json:"response_trailers,omitempty"`
	RequestBody      Body        `json:"request_body"`
	ResponseBody     Body        `json:"response_body"`
}

type Query struct {
	ServiceIDs []string `json:"service_ids,omitempty"`
	RouteID    string   `json:"route_id,omitempty"`
	From       string   `json:"from,omitempty"`
	Until      string   `json:"until,omitempty"`
	IP         string   `json:"ip,omitempty"`
	Method     string   `json:"method,omitempty"`
	Status     string   `json:"status,omitempty"`
	URL        string   `json:"url,omitempty"`
	WAF        string   `json:"waf,omitempty"`
	Cursor     string   `json:"cursor,omitempty"`
	Limit      int      `json:"limit,omitempty"`
}

type Counters struct {
	Ingested       uint64 `json:"ingested"`
	Updated        uint64 `json:"updated"`
	Rejected       uint64 `json:"rejected"`
	WriteErrors    uint64 `json:"write_errors"`
	Rotated        uint64 `json:"rotated"`
	Completed      uint64 `json:"completed"`
	Aborted        uint64 `json:"aborted"`
	WAFDenied      uint64 `json:"waf_denied"`
	UpstreamErrors uint64 `json:"upstream_errors"`
}

type Status struct {
	Available                    bool      `json:"available"`
	Epoch                        string    `json:"epoch"`
	StartedAt                    time.Time `json:"started_at"`
	CountersScope                string    `json:"counters_scope"`
	PreviousEpochCountersUnknown bool      `json:"previous_epoch_counters_unknown"`
	Counters                     Counters  `json:"counters"`
	StoredRecords                int64     `json:"stored_records"`
	StoredBytes                  int64     `json:"stored_bytes"`
	DiskBytes                    int64     `json:"disk_bytes"`
	QuotaBytes                   int64     `json:"quota_bytes"`
	PayloadBudgetBytes           int64     `json:"payload_budget_bytes"`
	PerServiceBytes              int64     `json:"per_service_bytes"`
	RetentionSeconds             int64     `json:"retention_seconds"`
	MaxRecords                   int       `json:"max_records"`
	RetiredSequence              int64     `json:"retired_sequence"`
	LastError                    string    `json:"last_error,omitempty"`
}

type Page struct {
	Records    []Metadata `json:"records"`
	NextCursor string     `json:"next_cursor,omitempty"`
	LiveCursor string     `json:"live_cursor"`
	HasMore    bool       `json:"has_more"`
	Gap        bool       `json:"gap"`
	Epoch      string     `json:"epoch"`
	Counters   Status     `json:"counters"`
}
