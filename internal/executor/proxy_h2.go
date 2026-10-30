package executor

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strconv"

	proxyengine "github.com/ctf-service-manager/ctf-service-manager/internal/proxy"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

// Probe only approved CURRENT publications, before a pending private port is
// created. No application request is sent. The proxy process verifies each
// non-loopback literal is an exact address of its own host network namespace.
func (m *Manager) preflightCutoverHTTP2(ctx context.Context, policy proxyengine.Policy, targets []transport.ProxyCutoverTargetPlan) error {
	origins := []string{}
	seen := map[string]bool{}
	for _, target := range targets {
		needs := false
		for _, route := range policy.Routes {
			if route.Protocol == "https2" && route.Component == target.Component && route.Upstream == "http://"+target.PrivateBinding {
				needs = true
				break
			}
		}
		if !needs {
			continue
		}
		bindings := append([]string{}, target.OriginalBindings...)
		sort.Strings(bindings)
		chosen := ""
		for _, binding := range bindings {
			host, port, e := net.SplitHostPort(binding)
			if e != nil {
				return proxyInput("Invalid frozen HTTP/2 publication")
			}
			ip, e := netip.ParseAddr(host)
			if e != nil {
				return proxyInput("HTTP/2 preflight requires a literal host publication")
			}
			n, e := strconv.Atoi(port)
			if e != nil || n < 1 || n > 65535 {
				return proxyInput("Invalid frozen HTTP/2 port")
			}
			if ip.IsUnspecified() {
				if ip.Is4() {
					ip = netip.MustParseAddr("127.0.0.1")
				} else {
					ip = netip.IPv6Loopback()
				}
			}
			origin := "http://" + net.JoinHostPort(ip.Unmap().String(), port)
			if chosen == "" || ip.IsLoopback() {
				chosen = origin
			}
			if ip.IsLoopback() {
				break
			}
		}
		if chosen == "" {
			return proxyInput("HTTP/2 transfer requires a probeable current publication")
		}
		if !seen[chosen] {
			origins = append(origins, chosen)
			seen[chosen] = true
		}
	}
	if len(origins) == 0 {
		return nil
	}
	var out any
	return m.proxyRPC(ctx, "POST", "/v1/h2-preflight", proxyengine.HTTP2ProbeRequest{Upstreams: origins, AllowHostAddresses: true}, &out)
}
