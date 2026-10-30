package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const MaxPolicyBytes = 256 << 10

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

func DefaultRoute() Route {
	return Route{Protocol: "http1", Capture: CapturePolicy{Mode: "metadata", MaxBodyBytes: 65536},
		WAF: WAFPolicy{Mode: "observe_only", RatePerSecond: 20, Burst: 40, ViolationThreshold: 10,
			ViolationWindowSeconds: 60, BanTTLSeconds: 60, MaxIPStates: 4096, StateTTLSeconds: 300, OverflowMode: "reject_new"},
		Limits: RouteLimits{MaxConcurrent: 128, MaxHeaderBytes: 65536, ReadHeaderTimeoutSeconds: 5,
			UpstreamResponseHeaderTimeoutSeconds: 30, IdleTimeoutSeconds: 60, MaxConnectionSeconds: 300}}
}

// NormalizePolicy supplies conservative defaults, without changing explicit modes.
func policyDefaults(p Policy) Policy {
	if p.SchemaVersion == 0 {
		p.SchemaVersion = 1
	}
	p.Routes = append(make([]Route, 0, len(p.Routes)), p.Routes...)
	for i := range p.Routes {
		r, d := &p.Routes[i], DefaultRoute()
		if r.Protocol == "" {
			r.Protocol = d.Protocol
		}
		if r.Capture.Mode == "" {
			r.Capture.Mode = d.Capture.Mode
		}
		if r.Capture.MaxBodyBytes == 0 {
			r.Capture.MaxBodyBytes = d.Capture.MaxBodyBytes
		}
		if r.WAF.Mode == "" {
			r.WAF.Mode = d.WAF.Mode
		}
		if r.WAF.RatePerSecond == 0 {
			r.WAF.RatePerSecond = d.WAF.RatePerSecond
		}
		if r.WAF.Burst == 0 {
			r.WAF.Burst = d.WAF.Burst
		}
		if r.WAF.ViolationThreshold == 0 {
			r.WAF.ViolationThreshold = d.WAF.ViolationThreshold
		}
		if r.WAF.ViolationWindowSeconds == 0 {
			r.WAF.ViolationWindowSeconds = d.WAF.ViolationWindowSeconds
		}
		if r.WAF.BanTTLSeconds == 0 {
			r.WAF.BanTTLSeconds = d.WAF.BanTTLSeconds
		}
		if r.WAF.MaxIPStates == 0 {
			r.WAF.MaxIPStates = d.WAF.MaxIPStates
		}
		if r.WAF.StateTTLSeconds == 0 {
			r.WAF.StateTTLSeconds = d.WAF.StateTTLSeconds
		}
		if r.WAF.OverflowMode == "" {
			r.WAF.OverflowMode = d.WAF.OverflowMode
		}
		if r.Limits.MaxConcurrent == 0 {
			r.Limits.MaxConcurrent = d.Limits.MaxConcurrent
		}
		if r.Limits.MaxHeaderBytes == 0 {
			r.Limits.MaxHeaderBytes = d.Limits.MaxHeaderBytes
		}
		if r.Limits.ReadHeaderTimeoutSeconds == 0 {
			r.Limits.ReadHeaderTimeoutSeconds = d.Limits.ReadHeaderTimeoutSeconds
		}
		if r.Limits.UpstreamResponseHeaderTimeoutSeconds == 0 {
			r.Limits.UpstreamResponseHeaderTimeoutSeconds = d.Limits.UpstreamResponseHeaderTimeoutSeconds
		}
		if r.Limits.IdleTimeoutSeconds == 0 {
			r.Limits.IdleTimeoutSeconds = d.Limits.IdleTimeoutSeconds
		}
		if r.Limits.MaxConnectionSeconds == 0 {
			r.Limits.MaxConnectionSeconds = d.Limits.MaxConnectionSeconds
		}
	}
	return p
}

func NormalizePolicy(p Policy) (Policy, error) {
	p = policyDefaults(p)
	return p, ValidatePolicy(p)
}

func PolicyDigest(p Policy) string {
	b, _ := json.Marshal(policyDefaults(p))
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func ValidatePolicy(p Policy) error {
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > MaxPolicyBytes {
		return errors.New("proxy policy exceeds 256 KiB serialized budget")
	}
	if p.SchemaVersion != 1 || (p.Revision == 0 && len(p.Routes) > 0) || len(p.Routes) > 64 {
		return errors.New("invalid policy schema, revision or route budget")
	}
	ids, listeners, scopes := map[string]bool{}, map[string]bool{}, map[string]string{}
	binds := map[string][]netip.Addr{}
	for _, r := range p.Routes {
		if !identifier.MatchString(r.ID) || !identifier.MatchString(r.ServiceID) || !identifier.MatchString(r.Component) || ids[r.ID] {
			return errors.New("invalid or duplicate route identity")
		}
		ids[r.ID] = true
		ip, port, err := splitListen(r.Listen)
		if err != nil {
			return err
		}
		canonical := net.JoinHostPort(ip.String(), strconv.Itoa(port))
		if listeners[canonical] {
			return errors.New("one route per external listener is required")
		}
		listeners[canonical] = true
		// Released cutover listeners cannot be bind-probed until Docker lets
		// them go. Reject an impossible same-family wildcard overlap now.
		familyPort := fmt.Sprintf("%t:%d", ip.Unmap().Is4(), port)
		for _, old := range binds[familyPort] {
			if old.IsUnspecified() || ip.IsUnspecified() || old == ip {
				return errors.New("proxy listeners overlap within one IP family")
			}
		}
		binds[familyPort] = append(binds[familyPort], ip.Unmap())
		if r.Protocol != "http1" && !isTLSProfile(r.Protocol) {
			return errors.New("only explicit HTTP/1.1, HTTPS/1.1 and HTTPS/2-to-h2c profiles are supported")
		}
		if (isTLSProfile(r.Protocol) && (r.TLS == nil || !identifier.MatchString(r.TLS.CertificateID) || r.Host == "")) || (r.Protocol == "http1" && r.TLS != nil) {
			return errors.New("HTTPS requires an immutable certificate ID and exact host; HTTP forbids TLS options")
		}
		if r.Host != "" {
			if len(r.Host) > 253 || strings.ContainsAny(r.Host, " /\\\t\r\n@?#*") {
				return errors.New("route host must be an exact HTTP Host")
			}
			u, e := url.Parse("http://" + r.Host)
			if e != nil || u.Host != r.Host || u.Hostname() == "" {
				return errors.New("invalid exact route host")
			}
		}
		u, e := url.Parse(r.Upstream)
		if e != nil || u.Scheme != "http" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "" || strings.ContainsAny(u.Host, "\\\r\n\t ") {
			return errors.New("upstream must be a frozen HTTP origin without credentials, path or query")
		}
		upstreamIP, parseErr := netip.ParseAddr(u.Hostname())
		if parseErr != nil || !upstreamIP.Unmap().IsLoopback() || len(r.Upstream) > 2048 {
			return errors.New("first HTTP profile requires a frozen literal loopback upstream")
		}
		up := 80
		if u.Port() != "" {
			up, e = strconv.Atoi(u.Port())
			if e != nil || up < 1 || up > 65535 {
				return errors.New("invalid upstream port")
			}
		}
		if up == port && ((u.Hostname() == "localhost") || (func() bool {
			a, e := netip.ParseAddr(u.Hostname())
			return e == nil && (a.IsLoopback() || a.IsUnspecified() || a.Unmap() == ip.Unmap())
		})()) {
			return errors.New("upstream loops into the proxy listener")
		}
		if len(r.TrustedProxyCIDRs) > 32 || len(r.WAF.Exceptions) > 128 {
			return errors.New("trusted proxy or exception budget exceeded")
		}
		for _, raw := range r.TrustedProxyCIDRs {
			if _, e := normalizedPrefix(raw); e != nil {
				return errors.New("invalid trusted proxy CIDR")
			}
		}
		if r.Capture.Mode != "metadata" && r.Capture.Mode != "bounded_body" && r.Capture.Mode != "grpc_body" {
			return errors.New("unsupported capture mode")
		}
		if r.Capture.Mode == "grpc_body" && r.Protocol != "https2" {
			return errors.New("explicit opaque gRPC capture requires HTTPS/2 termination")
		}
		if r.Protocol == "https2" && r.Limits.MaxConcurrent > 128 {
			return errors.New("HTTPS/2 profile supports at most 128 concurrent RPC streams per route")
		}
		if r.Capture.MaxBodyBytes < 1 || r.Capture.MaxBodyBytes > 65536 {
			return errors.New("capture prefix must be 1..65536 bytes per direction")
		}
		if len(r.Capture.BodyPatterns) > 8 || len(r.Capture.RedactHeaders) > 32 || len(r.Capture.RedactQueryFields) > 32 || len(r.Capture.RedactBodyFields) > 32 {
			return errors.New("redaction configuration budget exceeded")
		}
		for _, s := range append(append(append([]string{}, r.Capture.RedactHeaders...), r.Capture.RedactQueryFields...), r.Capture.RedactBodyFields...) {
			if s == "" || len(s) > 128 || strings.ContainsAny(s, "\r\n\x00") {
				return errors.New("invalid redaction field")
			}
		}
		for _, s := range r.Capture.BodyPatterns {
			if len(s) > 1024 {
				return errors.New("redaction expression exceeds limit")
			}
			if _, err := regexp.Compile(s); err != nil {
				return errors.New("invalid RE2 redaction expression")
			}
		}
		w := r.WAF
		if w.Mode != "off" && w.Mode != "observe_only" && w.Mode != "enforce" {
			return errors.New("invalid WAF mode")
		}
		if math.IsNaN(w.RatePerSecond) || math.IsInf(w.RatePerSecond, 0) || w.RatePerSecond <= 0 || w.RatePerSecond > 100000 || w.Burst < 1 || w.Burst > 100000 || w.ViolationThreshold < 1 || w.ViolationThreshold > 10000 || w.ViolationWindowSeconds < 1 || w.ViolationWindowSeconds > 3600 || w.BanTTLSeconds < 1 || w.BanTTLSeconds > 3600 || w.MaxIPStates < 1 || w.MaxIPStates > 65536 || w.StateTTLSeconds < 1 || w.StateTTLSeconds > 3600 || w.OverflowMode != "reject_new" {
			return errors.New("WAF limits outside supported bounds; explicit reject_new overflow required")
		}
		if float64(w.StateTTLSeconds) < float64(w.Burst)/w.RatePerSecond || w.StateTTLSeconds < w.ViolationWindowSeconds {
			return errors.New("IP state TTL must cover bucket refill and violation window")
		}
		for _, ex := range w.Exceptions {
			if _, err := normalizedPrefix(ex.CIDR); err != nil || (!ex.BypassRate && !ex.BypassBan) || len(ex.Comment) > 500 {
				return errors.New("invalid checker exception")
			}
		}
		if !w.RouteSpecific {
			b, _ := json.Marshal(w)
			if previous, ok := scopes[r.ServiceID]; ok && previous != string(b) {
				return errors.New("service-scoped routes must share one WAF policy")
			}
			scopes[r.ServiceID] = string(b)
		}
		l := r.Limits
		if l.MaxConcurrent < 1 || l.MaxConcurrent > 1024 || l.MaxHeaderBytes < 1024 || l.MaxHeaderBytes > 262144 || l.ReadHeaderTimeoutSeconds < 1 || l.ReadHeaderTimeoutSeconds > 60 || l.UpstreamResponseHeaderTimeoutSeconds < 1 || l.UpstreamResponseHeaderTimeoutSeconds > 300 || l.IdleTimeoutSeconds < 1 || l.IdleTimeoutSeconds > 300 || l.MaxConnectionSeconds < 1 || l.MaxConnectionSeconds > 3600 || l.MaxBodyBytes < 0 {
			return fmt.Errorf("route connection/header/body/time limits outside supported bounds")
		}
	}
	for _, r := range p.Routes {
		u, _ := url.Parse(r.Upstream)
		up := u.Port()
		if up == "" {
			up = "80"
		}
		a, err := netip.ParseAddr(u.Hostname())
		local := u.Hostname() == "localhost" || (err == nil && a.IsLoopback())
		if !local {
			continue
		}
		for _, other := range p.Routes {
			ip, port, _ := splitListen(other.Listen)
			if strconv.Itoa(port) == up && (ip.IsLoopback() || ip.IsUnspecified()) {
				return errors.New("cross-route upstream loop into a proxy listener")
			}
		}
	}

	return nil
}

func splitListen(raw string) (netip.Addr, int, error) {
	host, port, e := net.SplitHostPort(raw)
	if e != nil {
		return netip.Addr{}, 0, errors.New("listener must be a literal IP:port")
	}
	ip, e := netip.ParseAddr(host)
	if e != nil || ip.Zone() != "" || ip.IsMulticast() {
		return netip.Addr{}, 0, errors.New("listener must use a literal unicast/wildcard IP")
	}
	p, e := strconv.Atoi(port)
	if e != nil || p < 1 || p > 65535 {
		return netip.Addr{}, 0, errors.New("listener port must be 1..65535")
	}
	return ip.Unmap(), p, nil
}

// Explicit families make [::]:port IPv6-only. A Docker service may publish
// separate IPv4 and IPv6 wildcard bindings on the same numeric port.
func listenNetwork(address string) string {
	host, _, _ := net.SplitHostPort(address)
	ip, err := netip.ParseAddr(host)
	if err == nil && ip.Unmap().Is4() {
		return "tcp4"
	}
	return "tcp6"
}
