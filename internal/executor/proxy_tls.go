package executor

import (
	"context"

	proxyengine "github.com/ctf-service-manager/ctf-service-manager/internal/proxy"
)

func (m *Manager) ProxyTLSCertificates(ctx context.Context) (value proxyengine.TLSCertificatePage, err error) {
	err = m.proxyRPC(ctx, "GET", "/v1/tls/certificates", nil, &value)
	return
}
