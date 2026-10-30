package config

import (
	"errors"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

// ProxyPolicy is an opt-in, administrator-owned installation boundary. Browser
// input never selects control URLs, credentials, output files or listen ranges.
type ProxyPolicy struct {
	Enabled          bool     `json:"enabled"`
	PolicyDirectory  string   `json:"policy_directory"`
	ControlURL       string   `json:"control_url"`
	ControlTokenFile string   `json:"control_token_file"`
	TrafficURL       string   `json:"traffic_url"`
	TrafficTokenFile string   `json:"traffic_token_file"`
	AllowedListenIPs []string `json:"allowed_listen_ips"`
	ListenPortMin    int      `json:"listen_port_min"`
	ListenPortMax    int      `json:"listen_port_max"`
	BackendPortMin   int      `json:"backend_port_min,omitempty"`
	BackendPortMax   int      `json:"backend_port_max,omitempty"`
	ProxyGID         int      `json:"proxy_gid"`
}

// BackendPorts is a separate host-loopback allocation boundary. Older opt-in
// installations receive the conservative default without widening listeners.
func (p ProxyPolicy) BackendPorts() (int, int) {
	if p.BackendPortMin == 0 && p.BackendPortMax == 0 {
		for _, first := range []int{29080, 39080, 49080} {
			if first+31 < p.ListenPortMin || p.ListenPortMax < first {
				return first, first + 31
			}
		}
	}
	return p.BackendPortMin, p.BackendPortMax
}

func (p ProxyPolicy) Validate(c Config) error {
	if !p.Enabled {
		return nil
	}
	for _, origin := range []string{p.ControlURL, p.TrafficURL} {
		u, err := url.Parse(origin)
		if err == nil && u.Scheme == "unix" && u.Host == "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.RawPath == "" && u.Fragment == "" && u.Opaque == "" && !strings.ContainsAny(u.Path, "\x00\r\n") && filepath.IsAbs(u.Path) && filepath.Clean(u.Path) == u.Path && u.Path != "/" && u.Path != c.Socket {
			continue
		}
		if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.Port() == "" {
			return errors.New("proxy control and recorder must use explicit loopback HTTP origins with ports")
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return errors.New("proxy control and recorder ports must be 1..65535")
		}
		ip, err := netip.ParseAddr(u.Hostname())
		if err != nil || !ip.Unmap().IsLoopback() {
			return errors.New("proxy control and recorder require literal loopback addresses")
		}
	}
	if p.ControlURL == p.TrafficURL {
		return errors.New("proxy and recorder must have separate control origins")
	}
	for _, path := range []string{p.PolicyDirectory, p.ControlTokenFile, p.TrafficTokenFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsRune(path, 0) {
			return errors.New("proxy paths must be explicit canonical absolute paths")
		}
	}
	if overlap(p.PolicyDirectory, c.StateDirectory) {
		return errors.New("proxy policy output must be separate from executor state")
	}
	for _, root := range append(append([]string{}, c.DiscoveryRoots...), c.WorkspaceRoots...) {
		if overlap(p.PolicyDirectory, root) {
			return errors.New("proxy policy output cannot overlap managed game or workspace roots")
		}
	}
	if len(p.AllowedListenIPs) == 0 || len(p.AllowedListenIPs) > 16 || p.ListenPortMin < 1024 || p.ListenPortMax > 65535 || p.ListenPortMin > p.ListenPortMax || p.ListenPortMax-p.ListenPortMin > 1023 {
		return errors.New("proxy requires approved listen IPs and a bounded unprivileged port range")
	}
	backendMin, backendMax := p.BackendPorts()
	if backendMin < 1024 || backendMax > 65535 || backendMin > backendMax || backendMax-backendMin > 1023 || (backendMin <= p.ListenPortMax && p.ListenPortMin <= backendMax) {
		return errors.New("proxy backend ports must use a separate bounded unprivileged range")
	}
	seen := map[netip.Addr]bool{}
	for _, raw := range p.AllowedListenIPs {
		ip, err := netip.ParseAddr(raw)
		if err != nil || ip.Zone() != "" || ip.IsMulticast() || seen[ip.Unmap()] {
			return errors.New("proxy listen addresses must be unique literal IPs")
		}
		seen[ip.Unmap()] = true
	}
	if p.ProxyGID <= 0 || p.ProxyGID == c.WebUID {
		return errors.New("proxy policy reader group must be non-root and distinct from dashboard UID")
	}
	return nil
}
