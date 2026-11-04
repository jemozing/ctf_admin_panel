package transport

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	proxyengine "github.com/ctf-service-manager/ctf-service-manager/internal/proxy"
)

const (
	MaxProxyCutoverComponents = 8
	MaxProxyCutoverTargets    = 16
	MaxProxyCutoverListeners  = 32
)

type ProxyCutoverSelection struct {
	Component    string `json:"component"`
	UpstreamPort int    `json:"upstream_port"`
	PrivatePort  int    `json:"private_port"`
}

type ProxyCutoverTargetPlan struct {
	Component        string   `json:"component"`
	UpstreamPort     int      `json:"upstream_port"`
	PrivatePort      int      `json:"private_port"`
	OriginalBindings []string `json:"original_bindings"`
	PrivateBinding   string   `json:"private_binding"`
}

type ProxyCutoverTarget struct {
	ServiceID        domain.ID `json:"service_id"`
	ServiceName      string    `json:"service_name"`
	Component        string    `json:"component"`
	UpstreamPort     int       `json:"upstream_port"`
	OriginalBindings []string  `json:"original_bindings"`
}
type ProxyCutoverTargets struct {
	Targets                []ProxyCutoverTarget     `json:"targets"`
	Unavailable            []ProxyUnavailableTarget `json:"unavailable"`
	AllowedListenIPs       []string                 `json:"allowed_listen_ips"`
	AllowedListenEndpoints []string                 `json:"allowed_listen_endpoints,omitempty"`
	ListenPortMin          int                      `json:"listen_port_min"`
	ListenPortMax          int                      `json:"listen_port_max"`
	BackendPortMin         int                      `json:"backend_port_min"`
	BackendPortMax         int                      `json:"backend_port_max"`
	MaxComponents          int                      `json:"max_components"`
	MaxTargets             int                      `json:"max_targets"`
	MaxListeners           int                      `json:"max_listeners"`
}
type ProxyCutoverPreviewRequest struct {
	ServiceID    domain.ID               `json:"service_id"`
	Component    string                  `json:"component,omitempty"`
	UpstreamPort int                     `json:"upstream_port,omitempty"`
	PrivatePort  int                     `json:"private_port,omitempty"`
	Targets      []ProxyCutoverSelection `json:"targets,omitempty"`
	Routes       []ProxyRouteInput       `json:"routes"`
	Initiator    domain.ID               `json:"initiator,omitempty"`
}
type ProxyCutoverReturnRequest struct {
	CutoverID domain.ID `json:"cutover_id"`
	Initiator domain.ID `json:"initiator,omitempty"`
}
type ProxyCutoverPreview struct {
	ProposalID          domain.ID                `json:"proposal_id"`
	Digest              domain.Digest            `json:"digest"`
	ExpiresAt           time.Time                `json:"expires_at"`
	Mode                string                   `json:"mode"`
	CutoverID           domain.ID                `json:"cutover_id"`
	ServiceID           domain.ID                `json:"service_id"`
	Component           string                   `json:"component"`
	UpstreamPort        int                      `json:"upstream_port"`
	PrivatePort         int                      `json:"private_port"`
	Targets             []ProxyCutoverTargetPlan `json:"targets,omitempty"`
	Components          []string                 `json:"components,omitempty"`
	MissingApplications []string                 `json:"missing_applications,omitempty"`
	PolicyRevision      uint64                   `json:"policy_revision"`
	StateSequence       uint64                   `json:"state_sequence"`
	ConfigurationDigest domain.Digest            `json:"configuration_digest"`
	RuntimeDigest       domain.Digest            `json:"runtime_digest"`
	ProxyRevision       uint64                   `json:"proxy_revision"`
	AppliedRevision     uint64                   `json:"applied_revision"`
	OriginalBindings    []string                 `json:"original_bindings"`
	PrivateBindings     []string                 `json:"private_bindings"`
	Containers          []docker.Container       `json:"containers"`
	RecoveryBaseline    []docker.Container       `json:"recovery_baseline,omitempty"`
	ApplicationMissing  bool                     `json:"application_missing,omitempty"`
	Policy              proxyengine.Policy       `json:"policy"`
	PreviousPolicy      proxyengine.Policy       `json:"previous_policy"`
	Changes             []string                 `json:"changes"`
	Warnings            []string                 `json:"warnings"`
}
type ProxyCutoverView struct {
	ID                  domain.ID                `json:"id"`
	ProposalID          domain.ID                `json:"proposal_id"`
	Mode                string                   `json:"mode"`
	ServiceID           domain.ID                `json:"service_id"`
	Component           string                   `json:"component"`
	Components          []string                 `json:"components,omitempty"`
	Targets             []ProxyCutoverTargetPlan `json:"targets,omitempty"`
	ActiveComponent     string                   `json:"active_component,omitempty"`
	CompletedComponents []string                 `json:"completed_components,omitempty"`
	State               string                   `json:"state"`
	Stage               string                   `json:"stage"`
	Digest              domain.Digest            `json:"digest"`
	Sequence            uint64                   `json:"sequence"`
	UpdatedAt           time.Time                `json:"updated_at"`
	Error               string                   `json:"error,omitempty"`
	Recoverable         bool                     `json:"recoverable"`
	CanReturn           bool                     `json:"can_return"`
	RequiresRecovery    bool                     `json:"requires_recovery"`
	OriginalBindings    []string                 `json:"original_bindings"`
	PrivateBindings     []string                 `json:"private_bindings"`
	ProxyRevision       uint64                   `json:"proxy_revision"`
	AppliedRevision     uint64                   `json:"applied_revision"`
}

// Optional capability interfaces preserve compatibility with basic backends.
type ProxyCutoverBackend interface {
	ProxyCutoverTargets(context.Context) (ProxyCutoverTargets, error)
	ProxyCutovers(context.Context) ([]ProxyCutoverView, error)
	ProxyCutoverPreview(context.Context, ProxyCutoverPreviewRequest) (ProxyCutoverPreview, error)
	ProxyCutoverReturnPreview(context.Context, ProxyCutoverReturnRequest) (ProxyCutoverPreview, error)
	ProxyCutoverConfirm(context.Context, ProxyConfirmRequest) (ProxyCutoverView, error)
}

func (s *Server) proxyCutoverEndpoint(w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.Path
	if path != "/v1/proxy/cutover/targets" && path != "/v1/proxy/cutovers" && path != "/v1/proxy/cutover/preview" && path != "/v1/proxy/cutover/return-preview" && path != "/v1/proxy/cutover/confirm" {
		return false
	}
	b, ok := s.options.Backend.(ProxyCutoverBackend)
	if !ok {
		writeError(w, 501, "not_implemented", "proxy port transfer unavailable")
		return true
	}
	var value any
	var err error
	switch {
	case path == "/v1/proxy/cutover/targets" && r.Method == http.MethodGet:
		value, err = b.ProxyCutoverTargets(r.Context())
	case path == "/v1/proxy/cutovers" && r.Method == http.MethodGet:
		value, err = b.ProxyCutovers(r.Context())
	case path == "/v1/proxy/cutover/preview" && r.Method == http.MethodPost:
		var in ProxyCutoverPreviewRequest
		if !decodeProxyInput(w, r, &in) {
			return true
		}
		if in.Initiator.Validate() != nil || in.ServiceID.Validate() != nil || ValidateProxyCutoverSelection(in) != nil || len(in.Routes) == 0 || len(in.Routes) > MaxProxyCutoverListeners {
			writeError(w, 400, "invalid_request", "bounded routes, service and authenticated actor required")
			return true
		}
		value, err = b.ProxyCutoverPreview(r.Context(), in)
	case path == "/v1/proxy/cutover/return-preview" && r.Method == http.MethodPost:
		var in ProxyCutoverReturnRequest
		if !decodeProxyInput(w, r, &in) {
			return true
		}
		if in.Initiator.Validate() != nil || in.CutoverID.Validate() != nil {
			writeError(w, 400, "invalid_request", "cutover and authenticated actor required")
			return true
		}
		value, err = b.ProxyCutoverReturnPreview(r.Context(), in)
	case path == "/v1/proxy/cutover/confirm" && r.Method == http.MethodPost:
		var in ProxyConfirmRequest
		if !decodeProxyInput(w, r, &in) {
			return true
		}
		if in.Initiator.Validate() != nil || in.ProposalID.Validate() != nil || in.Digest.Validate() != nil {
			writeError(w, 400, "invalid_request", "proposal, digest and authenticated actor required")
			return true
		}
		value, err = b.ProxyCutoverConfirm(r.Context(), in)
	default:
		writeError(w, 405, "method_not_allowed", "unsupported cutover method")
		return true
	}
	if err != nil {
		proxyBackendError(w, err)
		return true
	}
	writeJSON(w, 200, value)
	return true
}

// ValidateProxyCutoverSelection validates only the public request boundary.
// Executor still derives the complete frozen publication set and compares it
// with fresh Docker inspection before allowing any container mutation.
func ValidateProxyCutoverSelection(in ProxyCutoverPreviewRequest) error {
	if in.Targets != nil {
		if in.Component != "" || in.UpstreamPort != 0 || in.PrivatePort != 0 || len(in.Targets) == 0 || len(in.Targets) > MaxProxyCutoverTargets {
			return &ProxyInputError{Message: "Use either bounded grouped targets or the legacy single target"}
		}
		pairs, ports, components := map[string]bool{}, map[int]bool{}, map[string]bool{}
		for _, target := range in.Targets {
			if domain.ValidateComponent(target.Component) != nil || target.UpstreamPort < 1 || target.UpstreamPort > 65535 || target.PrivatePort < 1024 || target.PrivatePort > 65535 {
				return &ProxyInputError{Message: "Each target requires an application component, TCP port and private backend port"}
			}
			key := target.Component + ":" + fmt.Sprint(target.UpstreamPort)
			if pairs[key] || ports[target.PrivatePort] {
				return &ProxyInputError{Message: "Duplicate component ports or private backend ports are forbidden"}
			}
			pairs[key], ports[target.PrivatePort], components[target.Component] = true, true, true
		}
		if len(components) > MaxProxyCutoverComponents {
			return &ProxyInputError{Message: "Too many application components in one transfer"}
		}
		return nil
	}
	if domain.ValidateComponent(in.Component) != nil || in.UpstreamPort < 1 || in.UpstreamPort > 65535 || in.PrivatePort < 1024 || in.PrivatePort > 65535 {
		return &ProxyInputError{Message: "A registered application, TCP port and private backend port are required"}
	}
	return nil
}
func (c *Client) ProxyCutoverTargets(ctx context.Context) (v ProxyCutoverTargets, err error) {
	err = c.request(ctx, "GET", "/v1/proxy/cutover/targets", nil, &v)
	return
}
func (c *Client) ProxyCutovers(ctx context.Context) (v []ProxyCutoverView, err error) {
	err = c.request(ctx, "GET", "/v1/proxy/cutovers", nil, &v)
	return
}
func (c *Client) ProxyCutoverPreview(ctx context.Context, in ProxyCutoverPreviewRequest) (v ProxyCutoverPreview, err error) {
	err = c.request(ctx, "POST", "/v1/proxy/cutover/preview", in, &v)
	return
}
func (c *Client) ProxyCutoverReturnPreview(ctx context.Context, in ProxyCutoverReturnRequest) (v ProxyCutoverPreview, err error) {
	err = c.request(ctx, "POST", "/v1/proxy/cutover/return-preview", in, &v)
	return
}
func (c *Client) ProxyCutoverConfirm(ctx context.Context, in ProxyConfirmRequest) (v ProxyCutoverView, err error) {
	err = c.request(ctx, "POST", "/v1/proxy/cutover/confirm", in, &v)
	return
}
