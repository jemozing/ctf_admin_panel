package transport

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	proxyengine "github.com/ctf-service-manager/ctf-service-manager/internal/proxy"
	"github.com/ctf-service-manager/ctf-service-manager/internal/traffic"
)

type ProxyRouteInput struct {
	ID                string                      `json:"id"`
	ServiceID         domain.ID                   `json:"service_id"`
	Component         string                      `json:"component"`
	Listen            string                      `json:"listen"`
	Host              string                      `json:"host,omitempty"`
	UpstreamPort      int                         `json:"upstream_port"`
	Protocol          string                      `json:"protocol"`
	TLS               *proxyengine.TLSRoutePolicy `json:"tls,omitempty"`
	TrustedProxyCIDRs []string                    `json:"trusted_proxy_cidrs,omitempty"`
	Capture           proxyengine.CapturePolicy   `json:"capture"`
	WAF               proxyengine.WAFPolicy       `json:"waf"`
	Limits            proxyengine.RouteLimits     `json:"limits"`
}
type ProxyPreviewRequest struct {
	ExpectedRevision uint64            `json:"expected_revision"`
	Routes           []ProxyRouteInput `json:"routes"`
	ConfirmChecker   bool              `json:"confirm_checker"`
	Initiator        domain.ID         `json:"initiator,omitempty"`
}
type ProxyConfirmRequest struct {
	ProposalID domain.ID     `json:"proposal_id"`
	Digest     domain.Digest `json:"digest"`
	Initiator  domain.ID     `json:"initiator,omitempty"`
}
type ProxyPreview struct {
	ProposalID              domain.ID          `json:"proposal_id"`
	Digest                  domain.Digest      `json:"digest"`
	Policy                  proxyengine.Policy `json:"policy"`
	Warnings                []string           `json:"warnings"`
	ExpiresAt               time.Time          `json:"expires_at"`
	PreviousPolicy          proxyengine.Policy `json:"previous_policy"`
	ObservedAppliedRevision uint64             `json:"observed_applied_revision"`
}
type ProxyPolicyView struct {
	Configured       bool               `json:"configured"`
	Policy           proxyengine.Policy `json:"policy"`
	DesiredRevision  uint64             `json:"desired_revision"`
	AppliedRevision  uint64             `json:"applied_revision"`
	Activation       string             `json:"activation"`
	Error            string             `json:"error,omitempty"`
	ExternalRevision bool               `json:"external_revision"`
}
type ProxyBansPage struct {
	Bans      []proxyengine.Ban `json:"bans"`
	Truncated bool              `json:"truncated"`
	Total     int               `json:"total"`
}
type ProxyStatus struct {
	Configured      bool               `json:"configured"`
	DesiredRevision uint64             `json:"desired_revision"`
	AppliedRevision uint64             `json:"applied_revision"`
	Proxy           proxyengine.Status `json:"proxy"`
	Recorder        traffic.Status     `json:"recorder"`
	Error           string             `json:"error,omitempty"`
}
type ProxyTarget struct {
	ServiceID       domain.ID `json:"service_id"`
	ServiceName     string    `json:"service_name"`
	Component       string    `json:"component"`
	UpstreamPort    int       `json:"upstream_port"`
	UpstreamAddress string    `json:"upstream_address"`
	PrivateBinding  bool      `json:"private_binding"`
}
type ProxyUnavailableTarget struct {
	ServiceID domain.ID `json:"service_id"`
	Component string    `json:"component"`
	Reason    string    `json:"reason"`
}
type ProxyTargets struct {
	Targets                []ProxyTarget            `json:"targets"`
	Unavailable            []ProxyUnavailableTarget `json:"unavailable"`
	AllowedListenIPs       []string                 `json:"allowed_listen_ips"`
	AllowedListenEndpoints []string                 `json:"allowed_listen_endpoints,omitempty"`
	ListenPortMin          int                      `json:"listen_port_min"`
	ListenPortMax          int                      `json:"listen_port_max"`
}
type ProxyBanRequest struct {
	proxyengine.BanRequest
	Initiator domain.ID `json:"initiator"`
}
type ProxyUnbanRequest struct {
	proxyengine.UnbanRequest
	Initiator domain.ID `json:"initiator"`
}
type ProxyBackend interface {
	ProxyStatus(context.Context) (ProxyStatus, error)
	ProxyPolicy(context.Context) (ProxyPolicyView, error)
	ProxyTargets(context.Context) (ProxyTargets, error)
	ProxyPreview(context.Context, ProxyPreviewRequest) (ProxyPreview, error)
	ProxyConfirm(context.Context, ProxyConfirmRequest) (ProxyPolicyView, error)
	ProxyBans(context.Context) (ProxyBansPage, error)
	ProxyBan(context.Context, ProxyBanRequest) (proxyengine.Ban, error)
	ProxyUnban(context.Context, ProxyUnbanRequest) error
	TrafficList(context.Context, traffic.Query) (traffic.Page, error)
	TrafficDetail(context.Context, string) (traffic.Exchange, error)
}
type ProxyInputError struct{ Message string }

func (e *ProxyInputError) Error() string { return e.Message }

func decodeProxyInput(w http.ResponseWriter, r *http.Request, out any) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		writeError(w, 415, "invalid_content_type", "JSON required")
		return false
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256*1024))
	if err != nil || DecodeRegistrationJSON(data, out) != nil {
		writeError(w, 400, "invalid_request", "one bounded typed JSON object is required")
		return false
	}
	return true
}
func proxyBackendError(w http.ResponseWriter, err error) {
	var input *ProxyInputError
	if errors.As(err, &input) {
		writeError(w, 400, "invalid_proxy_configuration", input.Message)
		return
	}
	backendError(w, err)
}
func (s *Server) proxyControlEndpoint(w http.ResponseWriter, r *http.Request) {
	if s.proxyTLSEndpoint(w, r) {
		return
	}
	if s.proxyCutoverEndpoint(w, r) {
		return
	}
	b, ok := s.options.Backend.(ProxyBackend)
	if !ok {
		writeError(w, 501, "not_implemented", "proxy module unavailable")
		return
	}
	var value any
	var err error
	if r.Method == http.MethodGet {
		switch r.URL.Path {
		case "/v1/proxy/status":
			value, err = b.ProxyStatus(r.Context())
		case "/v1/proxy/policy":
			value, err = b.ProxyPolicy(r.Context())
		case "/v1/proxy/targets":
			value, err = b.ProxyTargets(r.Context())
		case "/v1/proxy/bans":
			value, err = b.ProxyBans(r.Context())
		case "/v1/traffic":
			var query traffic.Query
			query, err = traffic.ParseRawQuery(r.URL.RawQuery)
			if err != nil {
				writeError(w, 400, "invalid_query", "Invalid traffic filters")
				return
			}
			if err == nil {
				value, err = b.TrafficList(r.Context(), query)
			}
		default:
			if strings.HasPrefix(r.URL.Path, "/v1/traffic/") {
				id := strings.TrimPrefix(r.URL.Path, "/v1/traffic/")
				if strings.Contains(id, "/") || len(id) > 128 || id == "" {
					writeError(w, 400, "invalid_id", "invalid request ID")
					return
				}
				value, err = b.TrafficDetail(r.Context(), id)
			} else {
				writeError(w, 404, "not_found", "unknown proxy endpoint")
				return
			}
		}
	} else if r.Method == http.MethodPost {
		switch r.URL.Path {
		case "/v1/proxy/preview":
			var input ProxyPreviewRequest
			if !decodeProxyInput(w, r, &input) {
				return
			}
			if input.Initiator.Validate() != nil {
				writeError(w, 400, "invalid_actor", "authenticated actor required")
				return
			}
			value, err = b.ProxyPreview(r.Context(), input)
		case "/v1/proxy/confirm":
			var input ProxyConfirmRequest
			if !decodeProxyInput(w, r, &input) {
				return
			}
			if input.Initiator.Validate() != nil || input.ProposalID.Validate() != nil || input.Digest.Validate() != nil {
				writeError(w, 400, "invalid_request", "valid proposal, digest and actor required")
				return
			}
			value, err = b.ProxyConfirm(r.Context(), input)
		case "/v1/proxy/bans":
			var input ProxyBanRequest
			if !decodeProxyInput(w, r, &input) {
				return
			}
			if input.Initiator.Validate() != nil {
				writeError(w, 400, "invalid_actor", "authenticated actor required")
				return
			}
			value, err = b.ProxyBan(r.Context(), input)
		case "/v1/proxy/unban":
			var input ProxyUnbanRequest
			if !decodeProxyInput(w, r, &input) {
				return
			}
			if input.Initiator.Validate() != nil {
				writeError(w, 400, "invalid_actor", "authenticated actor required")
				return
			}
			err = b.ProxyUnban(r.Context(), input)
			value = map[string]bool{"ok": err == nil}
		default:
			writeError(w, 404, "not_found", "unknown proxy endpoint")
			return
		}
	} else {
		methodNotAllowed(w, "GET, POST")
		return
	}
	if err != nil {
		proxyBackendError(w, err)
		return
	}
	writeJSON(w, 200, value)
}

func (c *Client) ProxyStatus(ctx context.Context) (v ProxyStatus, err error) {
	err = c.request(ctx, "GET", "/v1/proxy/status", nil, &v)
	return
}
func (c *Client) ProxyPolicy(ctx context.Context) (v ProxyPolicyView, err error) {
	err = c.request(ctx, "GET", "/v1/proxy/policy", nil, &v)
	return
}
func (c *Client) ProxyTargets(ctx context.Context) (v ProxyTargets, err error) {
	err = c.request(ctx, "GET", "/v1/proxy/targets", nil, &v)
	return
}
func (c *Client) ProxyPreview(ctx context.Context, in ProxyPreviewRequest) (v ProxyPreview, err error) {
	err = c.request(ctx, "POST", "/v1/proxy/preview", in, &v)
	return
}
func (c *Client) ProxyConfirm(ctx context.Context, in ProxyConfirmRequest) (v ProxyPolicyView, err error) {
	err = c.request(ctx, "POST", "/v1/proxy/confirm", in, &v)
	return
}
func (c *Client) ProxyBans(ctx context.Context) (v ProxyBansPage, err error) {
	err = c.request(ctx, "GET", "/v1/proxy/bans", nil, &v)
	return
}
func (c *Client) ProxyBan(ctx context.Context, in ProxyBanRequest) (v proxyengine.Ban, err error) {
	err = c.request(ctx, "POST", "/v1/proxy/bans", in, &v)
	return
}
func (c *Client) ProxyUnban(ctx context.Context, in ProxyUnbanRequest) error {
	var out any
	return c.request(ctx, "POST", "/v1/proxy/unban", in, &out)
}
func (c *Client) TrafficList(ctx context.Context, q traffic.Query) (v traffic.Page, err error) {
	err = c.request(ctx, "GET", "/v1/traffic?"+traffic.QueryValues(q).Encode(), nil, &v)
	return
}
func (c *Client) TrafficDetail(ctx context.Context, id string) (v traffic.Exchange, err error) {
	if id == "" || len(id) > 128 || strings.ContainsAny(id, "/?#%\\\x00") {
		return v, errors.New("invalid request ID")
	}
	err = c.request(ctx, "GET", "/v1/traffic/"+id, nil, &v)
	return
}
