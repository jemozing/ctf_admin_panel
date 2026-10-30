package proxy

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

func normalizedIP(raw string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() {
		return netip.Addr{}, errors.New("invalid client IP")
	}
	return a.Unmap(), nil
}

func normalizedPrefix(raw string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, errors.New("ambiguous mapped IPv4 prefix")
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), nil
}

// ClientIP uses XFF only behind an explicitly trusted immediate TCP peer. It
// walks right-to-left, stopping at the first untrusted hop. Forwarded is never
// a second competing source; malformed/ambiguous trusted chains are rejected.
func ClientIP(request *http.Request, trusted []string) (peer, effective, source string, err error) {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return "", "", "", errors.New("invalid TCP peer")
	}
	ip, err := normalizedIP(host)
	if err != nil {
		return "", "", "", err
	}
	peer, effective, source = ip.String(), ip.String(), "tcp_peer"
	prefixes := make([]netip.Prefix, 0, len(trusted))
	for _, cidr := range trusted {
		p, e := normalizedPrefix(cidr)
		if e != nil {
			return "", "", "", errors.New("invalid trusted proxy configuration")
		}
		prefixes = append(prefixes, p)
	}
	isTrusted := func(a netip.Addr) bool {
		for _, p := range prefixes {
			if p.Contains(a) || p.Contains(a.Unmap()) {
				return true
			}
		}
		return false
	}
	if !isTrusted(ip) {
		return peer, effective, source, nil
	}
	xff := request.Header.Values("X-Forwarded-For")
	if len(xff) == 0 {
		return peer, effective, source, nil
	}
	if len(xff) != 1 || len(xff[0]) > 4096 || request.Header.Get("Forwarded") != "" {
		return "", "", "", errors.New("ambiguous trusted forwarding chain")
	}
	parts := strings.Split(xff[0], ",")
	if len(parts) > 32 {
		return "", "", "", errors.New("forwarding chain exceeds hop budget")
	}
	chain := make([]netip.Addr, len(parts))
	for i, value := range parts {
		a, e := normalizedIP(value)
		if e != nil {
			return "", "", "", errors.New("invalid trusted forwarding chain")
		}
		chain[i] = a
	}
	current := ip
	for i := len(chain) - 1; i >= 0 && isTrusted(current); i-- {
		current = chain[i]
	}
	return peer, current.String(), "trusted_x_forwarded_for", nil
}
