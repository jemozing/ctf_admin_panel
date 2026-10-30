package dashboard

import (
	"context"
	"net/http"
	"strings"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

type webProxyCutoverPreview struct {
	ServiceID    domain.ID                         `json:"service_id"`
	Component    string                            `json:"component"`
	UpstreamPort int                               `json:"upstream_port"`
	PrivatePort  int                               `json:"private_port"`
	Targets      []transport.ProxyCutoverSelection `json:"targets,omitempty"`
	Routes       []transport.ProxyRouteInput       `json:"routes"`
}
type webProxyCutoverReturn struct {
	CutoverID domain.ID `json:"cutover_id"`
}

// Port moves and their recovery are separate from code Deploy/Rollback. They
// always require a fresh Admin plan; the browser never supplies an actor or URL.
func (s *Server) httpProxyCutoverRoutes(w http.ResponseWriter, r *http.Request, current session) bool {
	if !strings.HasPrefix(r.URL.Path, "/api/proxy/cutover") && r.URL.Path != "/api/proxy/tls/certificates" {
		return false
	}
	if current.User.Role != RoleAdmin {
		s.deny(w, r, current.User.ID)
		return true
	}
	var action, target string
	var call func(context.Context) (any, error)
	switch r.URL.Path {
	case "/api/proxy/tls/certificates":
		if !method(w, r, http.MethodGet) {
			return true
		}
		action, target = "proxy.tls.metadata.read", "certificates"
		call = func(ctx context.Context) (any, error) { return s.executor.ProxyTLSCertificates(ctx) }
	case "/api/proxy/cutover/targets":
		if !method(w, r, http.MethodGet) {
			return true
		}
		action, target = "proxy.cutover.targets.read", "targets"
		call = func(ctx context.Context) (any, error) { return s.executor.ProxyCutoverTargets(ctx) }
	case "/api/proxy/cutovers":
		if !method(w, r, http.MethodGet) {
			return true
		}
		action, target = "proxy.cutover.history.read", "cutovers"
		call = func(ctx context.Context) (any, error) { return s.executor.ProxyCutovers(ctx) }
	case "/api/proxy/cutover/preview":
		if !method(w, r, http.MethodPost) {
			return true
		}
		var in webProxyCutoverPreview
		if !decodeWebProxy(w, r, &in) {
			return true
		}
		request := transport.ProxyCutoverPreviewRequest{ServiceID: in.ServiceID, Component: in.Component, UpstreamPort: in.UpstreamPort, PrivatePort: in.PrivatePort, Targets: in.Targets, Routes: in.Routes, Initiator: domain.ID(current.User.ID)}
		if in.ServiceID.Validate() != nil || transport.ValidateProxyCutoverSelection(request) != nil || len(in.Routes) == 0 || len(in.Routes) > transport.MaxProxyCutoverListeners {
			apiError(w, 400, "invalid_request", "Choose a registered application, bounded TCP ports and all existing bindings")
			return true
		}
		action, target = "proxy.cutover.preview", string(in.ServiceID)
		call = func(ctx context.Context) (any, error) { return s.executor.ProxyCutoverPreview(ctx, request) }
	case "/api/proxy/cutover/return-preview":
		if !method(w, r, http.MethodPost) {
			return true
		}
		var in webProxyCutoverReturn
		if !decodeWebProxy(w, r, &in) {
			return true
		}
		if in.CutoverID.Validate() != nil {
			apiError(w, 400, "invalid_request", "Known cutover required")
			return true
		}
		request := transport.ProxyCutoverReturnRequest{CutoverID: in.CutoverID, Initiator: domain.ID(current.User.ID)}
		action, target = "proxy.cutover.return.preview", string(in.CutoverID)
		call = func(ctx context.Context) (any, error) { return s.executor.ProxyCutoverReturnPreview(ctx, request) }
	case "/api/proxy/cutover/confirm":
		if !method(w, r, http.MethodPost) {
			return true
		}
		var in webProxyConfirm
		if !decodeWebProxy(w, r, &in) {
			return true
		}
		if in.ProposalID.Validate() != nil || in.Digest.Validate() != nil {
			apiError(w, 400, "invalid_request", "Reviewed cutover proposal and digest required")
			return true
		}
		request := transport.ProxyConfirmRequest{ProposalID: in.ProposalID, Digest: in.Digest, Initiator: domain.ID(current.User.ID)}
		action, target = "proxy.cutover.confirm", string(in.ProposalID)
		call = func(ctx context.Context) (any, error) { return s.executor.ProxyCutoverConfirm(ctx, request) }
	default:
		apiError(w, 404, "not_found", "Unknown proxy control endpoint")
		return true
	}
	s.proxyCall(w, r, current, action, target, true, false, call)
	return true
}
