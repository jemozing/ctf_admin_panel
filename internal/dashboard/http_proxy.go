package dashboard

import (
	"context"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	proxyengine "github.com/ctf-service-manager/ctf-service-manager/internal/proxy"
	"github.com/ctf-service-manager/ctf-service-manager/internal/traffic"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

// Browser inputs deliberately do not expose executor actor fields. In
// particular, a valid JSON "initiator" is still an unknown browser field.
type webProxyPreview struct {
	ExpectedRevision uint64                      `json:"expected_revision"`
	Routes           []transport.ProxyRouteInput `json:"routes"`
	ConfirmChecker   bool                        `json:"confirm_checker"`
}
type webProxyConfirm struct {
	ProposalID domain.ID     `json:"proposal_id"`
	Digest     domain.Digest `json:"digest"`
}
type webProxyBan struct {
	ServiceID  string `json:"service_id"`
	RouteID    string `json:"route_id,omitempty"`
	IP         string `json:"ip"`
	TTLSeconds int    `json:"ttl_seconds"`
	Comment    string `json:"comment"`
}
type webProxyUnban struct {
	ServiceID string `json:"service_id"`
	RouteID   string `json:"route_id,omitempty"`
	IP        string `json:"ip"`
	Comment   string `json:"comment"`
}

func decodeWebProxy(w http.ResponseWriter, r *http.Request, out any) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		apiError(w, 415, "invalid_content_type", "Content-Type must be application/json")
		return false
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256*1024))
	if err != nil {
		apiError(w, 413, "body_too_large", "Proxy policy exceeds request limit")
		return false
	}
	if transport.DecodeRegistrationJSON(data, out) != nil {
		apiError(w, 400, "invalid_request", "Proxy request contains invalid, duplicate or unknown fields")
		return false
	}
	return true
}

func (s *Server) httpProxyRoutes(w http.ResponseWriter, r *http.Request, current session) {
	if r.URL.RawQuery != "" {
		apiError(w, 400, "invalid_query", "No query is supported for proxy control")
		return
	}
	if s.httpProxyCutoverRoutes(w, r, current) {
		return
	}
	admin := current.User.Role == RoleAdmin
	switch r.URL.Path {
	case "/api/proxy/status":
		if !method(w, r, http.MethodGet) {
			return
		}
		s.proxyCall(w, r, current, "", "", false, false, func(ctx context.Context) (any, error) { return s.executor.ProxyStatus(ctx) })
	case "/api/proxy/bans":
		if r.Method == http.MethodGet {
			s.proxyCall(w, r, current, "", "", false, false, func(ctx context.Context) (any, error) {
				return s.executor.ProxyBans(ctx)
			})
			return
		}
		if !admin {
			s.deny(w, r, current.User.ID)
			return
		}
		if !method(w, r, http.MethodPost) {
			return
		}
		var in webProxyBan
		if !decodeWebProxy(w, r, &in) {
			return
		}
		ip, valid := validWebBan(in.ServiceID, in.RouteID, in.IP, in.Comment)
		if !valid || in.TTLSeconds < 1 || in.TTLSeconds > 3600 {
			apiError(w, 400, "invalid_request", "Known service scope, valid IP, bounded TTL and comment are required")
			return
		}
		request := transport.ProxyBanRequest{BanRequest: proxyengine.BanRequest{ServiceID: in.ServiceID, RouteID: in.RouteID, IP: ip, TTLSeconds: in.TTLSeconds, Comment: in.Comment}, Initiator: domain.ID(current.User.ID)}
		s.proxyCall(w, r, current, "proxy.ban", in.ServiceID, true, false, func(ctx context.Context) (any, error) { return s.executor.ProxyBan(ctx, request) })
	case "/api/proxy/unban":
		if current.User.Role != RoleAdmin && current.User.Role != RoleDefender {
			s.deny(w, r, current.User.ID)
			return
		}
		if !method(w, r, http.MethodPost) {
			return
		}
		var in webProxyUnban
		if !decodeWebProxy(w, r, &in) {
			return
		}
		ip, valid := validWebBan(in.ServiceID, in.RouteID, in.IP, in.Comment)
		if !valid {
			apiError(w, 400, "invalid_request", "Known service scope, valid IP and comment are required")
			return
		}
		request := transport.ProxyUnbanRequest{UnbanRequest: proxyengine.UnbanRequest{ServiceID: in.ServiceID, RouteID: in.RouteID, IP: ip, Comment: in.Comment}, Initiator: domain.ID(current.User.ID)}
		s.proxyCall(w, r, current, "proxy.unban", in.ServiceID, false, false, func(ctx context.Context) (any, error) {
			err := s.executor.ProxyUnban(ctx, request)
			return map[string]bool{"ok": err == nil}, err
		})
	case "/api/proxy/policy", "/api/proxy/targets":
		if !admin {
			s.deny(w, r, current.User.ID)
			return
		}
		if !method(w, r, http.MethodGet) {
			return
		}
		s.proxyCall(w, r, current, "proxy.configuration.read", "policy", true, false, func(ctx context.Context) (any, error) {
			if r.URL.Path == "/api/proxy/policy" {
				return s.executor.ProxyPolicy(ctx)
			}
			return s.executor.ProxyTargets(ctx)
		})
	case "/api/proxy/preview":
		if !admin {
			s.deny(w, r, current.User.ID)
			return
		}
		if !method(w, r, http.MethodPost) {
			return
		}
		var in webProxyPreview
		if !decodeWebProxy(w, r, &in) {
			return
		}
		request := transport.ProxyPreviewRequest{ExpectedRevision: in.ExpectedRevision, Routes: in.Routes, ConfirmChecker: in.ConfirmChecker, Initiator: domain.ID(current.User.ID)}
		s.proxyCall(w, r, current, "proxy.policy.preview", "policy", true, false, func(ctx context.Context) (any, error) { return s.executor.ProxyPreview(ctx, request) })
	case "/api/proxy/confirm":
		if !admin {
			s.deny(w, r, current.User.ID)
			return
		}
		if !method(w, r, http.MethodPost) {
			return
		}
		var in webProxyConfirm
		if !decodeWebProxy(w, r, &in) {
			return
		}
		if in.ProposalID.Validate() != nil || in.Digest.Validate() != nil {
			apiError(w, 400, "invalid_request", "Valid proposal and digest are required")
			return
		}
		request := transport.ProxyConfirmRequest{ProposalID: in.ProposalID, Digest: in.Digest, Initiator: domain.ID(current.User.ID)}
		s.proxyCall(w, r, current, "proxy.policy.confirm", string(in.ProposalID), true, false, func(ctx context.Context) (any, error) { return s.executor.ProxyConfirm(ctx, request) })
	default:
		apiError(w, 404, "not_found", "Unknown proxy endpoint")
	}
}

func validWebBan(serviceID, routeID, rawIP, comment string) (string, bool) {
	ip, err := netip.ParseAddr(rawIP)
	if err != nil || ip.Zone() != "" || domain.ID(serviceID).Validate() != nil || routeID != "" && domain.ID(routeID).Validate() != nil || len(strings.TrimSpace(comment)) < 3 || len(comment) > 500 || !utf8.ValidString(comment) {
		return "", false
	}
	for _, c := range comment {
		if unicode.IsControl(c) && c != '\n' && c != '\t' {
			return "", false
		}
	}
	return ip.Unmap().String(), true
}

func (s *Server) trafficRoutes(w http.ResponseWriter, r *http.Request, current session) {
	if !method(w, r, http.MethodGet) {
		return
	}
	if r.URL.Path == "/api/traffic" {
		query, err := traffic.ParseRawQuery(r.URL.RawQuery)
		if err != nil {
			apiError(w, 400, "invalid_query", "Traffic filters are invalid or duplicated")
			return
		}
		s.proxyCall(w, r, current, "", "", false, false, func(ctx context.Context) (any, error) { return s.executor.TrafficList(ctx, query) })
		return
	}
	if !current.User.SensitiveAccess {
		s.deny(w, r, current.User.ID)
		return
	}
	if r.URL.RawQuery != "" {
		apiError(w, 400, "invalid_query", "No query is supported for a traffic detail")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/traffic/")
	if id == r.URL.Path || !validTrafficRequestID(id) {
		apiError(w, 400, "invalid_id", "Invalid traffic request ID")
		return
	}
	s.proxyCall(w, r, current, "traffic.detail.read", id, false, true, func(ctx context.Context) (any, error) { return s.executor.TrafficDetail(ctx, id) })
}

func validTrafficRequestID(id string) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.:-", c) {
			continue
		}
		return false
	}
	return true
}

// Authorize both before a downstream call and before publication. A revocation
// during that call must not release private capture or configuration bytes.
func (s *Server) freshProxySession(w http.ResponseWriter, r *http.Request, current session, admin, sensitive bool) bool {
	cookie, err := r.Cookie(s.cookieName())
	if err != nil {
		apiError(w, 401, "unauthenticated", "Session has expired")
		return false
	}
	fresh, err := s.getSession(r.Context(), cookie.Value)
	if err != nil || fresh.User.ID != current.User.ID || fresh.Hash != current.Hash {
		apiError(w, 401, "unauthenticated", "Session has expired")
		return false
	}
	if admin && fresh.User.Role != RoleAdmin || sensitive && (!fresh.User.SensitiveAccess || fresh.User.Role != current.User.Role) || r.URL.Path == "/api/proxy/unban" && fresh.User.Role != RoleAdmin && fresh.User.Role != RoleDefender {
		s.deny(w, r, current.User.ID)
		return false
	}
	return true
}

func (s *Server) proxyCall(w http.ResponseWriter, r *http.Request, current session, action, target string, admin, sensitive bool, call func(context.Context) (any, error)) {
	if !s.freshProxySession(w, r, current, admin, sensitive) {
		return
	}
	if action != "" {
		if err := s.audit(r.Context(), current.User.ID, action, target, "requested", ""); err != nil {
			internalError(w)
			return
		}
	}
	value, err := call(r.Context())
	if !s.freshProxySession(w, r, current, admin, sensitive) {
		if action != "" {
			_ = s.audit(r.Context(), current.User.ID, action, target, "withheld", "")
		}
		return
	}
	if err != nil {
		if action != "" {
			_ = s.audit(r.Context(), current.User.ID, action, target, "rejected", "")
		}
		executorError(w, err)
		return
	}
	if action != "" {
		if err := s.audit(r.Context(), current.User.ID, action, target, "succeeded", ""); err != nil {
			apiError(w, 502, "audit_incomplete", "Result was withheld because its audit could not be completed; refresh the state")
			return
		}
	}
	if !s.freshProxySession(w, r, current, admin, sensitive) {
		return
	}
	writeJSON(w, 200, value)
}
