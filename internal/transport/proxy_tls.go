package transport

import (
	"context"
	"net/http"

	proxyengine "github.com/ctf-service-manager/ctf-service-manager/internal/proxy"
)

type ProxyTLSBackend interface {
	ProxyTLSCertificates(context.Context) (proxyengine.TLSCertificatePage, error)
}

func (s *Server) proxyTLSEndpoint(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/v1/proxy/tls/certificates" {
		return false
	}
	if r.Method != http.MethodGet {
		writeError(w, 405, "method_not_allowed", "certificate metadata is read only")
		return true
	}
	b, ok := s.options.Backend.(ProxyTLSBackend)
	if !ok {
		writeError(w, 501, "not_implemented", "TLS certificate metadata unavailable")
		return true
	}
	value, err := b.ProxyTLSCertificates(r.Context())
	if err != nil {
		proxyBackendError(w, err)
		return true
	}
	writeJSON(w, 200, value)
	return true
}
func (c *Client) ProxyTLSCertificates(ctx context.Context) (v proxyengine.TLSCertificatePage, err error) {
	err = c.request(ctx, "GET", "/v1/proxy/tls/certificates", nil, &v)
	return
}
