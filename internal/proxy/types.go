// Package proxy implements the opt-in HTTP data plane. It has no Docker,
// executor IPC or application filesystem access.
package proxy

import (
	"context"
	"net"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/traffic"
)

type Policy struct {
	SchemaVersion int     `json:"schema_version"`
	Revision      uint64  `json:"revision"`
	Routes        []Route `json:"routes"`
}

type Route struct {
	ID                string          `json:"id"`
	ServiceID         string          `json:"service_id"`
	Component         string          `json:"component"`
	Listen            string          `json:"listen"`
	Host              string          `json:"host,omitempty"`
	Upstream          string          `json:"upstream"`
	Protocol          string          `json:"protocol"`
	TLS               *TLSRoutePolicy `json:"tls,omitempty"`
	TrustedProxyCIDRs []string        `json:"trusted_proxy_cidrs,omitempty"`
	Capture           CapturePolicy   `json:"capture"`
	WAF               WAFPolicy       `json:"waf"`
	Limits            RouteLimits     `json:"limits"`
}

// TLSRoutePolicy references a private, immutable local profile. PEM material
// and filesystem paths are never accepted in a policy or control request.
type TLSRoutePolicy struct {
	CertificateID string `json:"certificate_id"`
}

type TLSCertificateMetadata struct {
	ID                string    `json:"id"`
	DNSNames          []string  `json:"dns_names"`
	IPAddresses       []string  `json:"ip_addresses"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	Valid             bool      `json:"valid"`
	ErrorCode         string    `json:"error_code,omitempty"`
}

type TLSCertificatePage struct {
	Certificates []TLSCertificateMetadata `json:"certificates"`
	Total        int                      `json:"total"`
	Truncated    bool                     `json:"truncated"`
}

const MaxCutoverListeners = 32
const MaxCutoverUpstreams = 16

type CutoverPreflightRequest struct {
	Policy            Policy   `json:"policy"`
	ReleasedListeners []string `json:"released_listeners"`
	PendingUpstreams  []string `json:"pending_upstreams"`
}

type CapturePolicy struct {
	Mode              string   `json:"mode"`
	MaxBodyBytes      int      `json:"max_body_bytes"`
	RedactHeaders     []string `json:"redact_headers,omitempty"`
	RedactQueryFields []string `json:"redact_query_fields,omitempty"`
	RedactBodyFields  []string `json:"redact_body_fields,omitempty"`
	BodyPatterns      []string `json:"body_patterns,omitempty"`
}

type WAFPolicy struct {
	Mode                   string         `json:"mode"`
	RatePerSecond          float64        `json:"rate_per_second"`
	Burst                  int            `json:"burst"`
	ViolationThreshold     int            `json:"violation_threshold"`
	ViolationWindowSeconds int            `json:"violation_window_seconds"`
	BanTTLSeconds          int            `json:"ban_ttl_seconds"`
	MaxIPStates            int            `json:"max_ip_states"`
	StateTTLSeconds        int            `json:"state_ttl_seconds"`
	OverflowMode           string         `json:"overflow_mode"`
	RouteSpecific          bool           `json:"route_specific,omitempty"`
	Exceptions             []WAFException `json:"exceptions,omitempty"`
}

type WAFException struct {
	CIDR       string `json:"cidr"`
	BypassRate bool   `json:"bypass_rate"`
	BypassBan  bool   `json:"bypass_ban"`
	Comment    string `json:"comment,omitempty"`
}

type RouteLimits struct {
	MaxConcurrent                        int   `json:"max_concurrent"`
	MaxHeaderBytes                       int   `json:"max_header_bytes"`
	ReadHeaderTimeoutSeconds             int   `json:"read_header_timeout_seconds"`
	UpstreamResponseHeaderTimeoutSeconds int   `json:"upstream_response_header_timeout_seconds"`
	IdleTimeoutSeconds                   int   `json:"idle_timeout_seconds"`
	MaxConnectionSeconds                 int   `json:"max_connection_seconds"`
	MaxBodyBytes                         int64 `json:"max_body_bytes,omitempty"`
}

type Ban struct {
	ServiceID string    `json:"service_id"`
	RouteID   string    `json:"route_id,omitempty"`
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type BanRequest struct {
	ServiceID  string `json:"service_id"`
	RouteID    string `json:"route_id,omitempty"`
	IP         string `json:"ip"`
	TTLSeconds int    `json:"ttl_seconds"`
	Comment    string `json:"comment"`
}

type UnbanRequest struct {
	ServiceID string `json:"service_id"`
	RouteID   string `json:"route_id,omitempty"`
	IP        string `json:"ip"`
	Comment   string `json:"comment"`
}

type Counters struct {
	Accepted       uint64 `json:"accepted"`
	Forwarded      uint64 `json:"forwarded"`
	Rejected       uint64 `json:"rejected"`
	WouldReject    uint64 `json:"would_reject"`
	UpstreamErrors uint64 `json:"upstream_errors"`
	CaptureDropped uint64 `json:"capture_dropped"`
	RequestBytes   uint64 `json:"request_bytes"`
	ResponseBytes  uint64 `json:"response_bytes"`
}

type Status struct {
	Available         bool      `json:"available"`
	CollectorEpoch    string    `json:"collector_epoch"`
	StartedAt         time.Time `json:"started_at"`
	DesiredRevision   uint64    `json:"desired_revision"`
	AppliedRevision   uint64    `json:"applied_revision"`
	PolicyDigest      string    `json:"policy_digest"`
	Routes            int       `json:"routes"`
	WAFDegraded       bool      `json:"waf_degraded"`
	LastError         string    `json:"last_error,omitempty"`
	Counters          Counters  `json:"counters"`
	CountersReset     bool      `json:"counters_reset"`
	SupportedProfiles []string  `json:"supported_profiles"`
}

// Sink runs in one bounded background worker; forwarding never waits for it.
// Implementations must provide their own finite I/O timeout.
type Sink interface{ Submit(traffic.Exchange) bool }

type Options struct {
	StateDirectory    string
	TLSDirectory      string
	Sink              Sink
	Now               func() time.Time
	Listen            func(network, address string) (net.Listener, error)
	GlobalMaxIPStates int
}

// Runner owns listeners and last-known-good policy independently of the panel.
type Runner interface {
	Apply(Policy) error
	Status() Status
	ListBans(serviceID string) []Ban
	AddBan(BanRequest) (Ban, error)
	RemoveBan(UnbanRequest) error
	Close(context.Context) error
}
