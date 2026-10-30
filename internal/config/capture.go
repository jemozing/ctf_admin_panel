package config

import (
	"errors"
	"path/filepath"
	"strings"
)

// CapturePolicy is an installation boundary. The browser may only select
// executor-derived endpoints on these exact, administrator-approved interfaces.
type CapturePolicy struct {
	Enabled            bool     `json:"enabled"`
	PolicyDirectory    string   `json:"policy_directory"`
	ControlURL         string   `json:"control_url"`
	ControlTokenFile   string   `json:"control_token_file"`
	PacketsURL         string   `json:"packets_url"`
	PacketsTokenFile   string   `json:"packets_token_file"`
	AllowedInterfaces  []string `json:"allowed_interfaces"`
	ProtectedHostPorts []int    `json:"protected_host_ports,omitempty"`
}

func (p CapturePolicy) Validate(c Config) error {
	if !p.Enabled {
		return nil
	}
	// Reuse the same strictly local origins/private-output path boundary as the
	// existing HTTP data plane; no HTTP proxy installation is required.
	q := ProxyPolicy{Enabled: true, PolicyDirectory: p.PolicyDirectory, ControlURL: p.ControlURL, ControlTokenFile: p.ControlTokenFile, TrafficURL: p.PacketsURL, TrafficTokenFile: p.PacketsTokenFile, AllowedListenIPs: []string{"127.0.0.1"}, ListenPortMin: 18080, ListenPortMax: 18080, ProxyGID: 10004}
	if c.WebUID == 10004 {
		q.ProxyGID = 10005
	}
	if err := q.Validate(c); err != nil {
		return err
	}
	if !strings.HasPrefix(p.ControlURL, "unix:///") || !strings.HasPrefix(p.PacketsURL, "unix:///") {
		return errors.New("capture control and packet reads require private Unix sockets")
	}
	if len(p.AllowedInterfaces) == 0 || len(p.AllowedInterfaces) > 8 {
		return errors.New("capture requires 1..8 exact approved observation interfaces")
	}
	seen := map[string]bool{}
	for _, name := range p.AllowedInterfaces {
		if name == "" || len(name) > 15 || strings.ContainsAny(name, "/\\ \t\r\n\x00*?[]") || seen[name] {
			return errors.New("capture interface must be a unique exact approved name")
		}
		seen[name] = true
	}
	seenPorts := map[int]bool{}
	if len(p.ProtectedHostPorts) > 256 {
		return errors.New("too many protected host ports")
	}
	for _, port := range p.ProtectedHostPorts {
		if port < 1 || port > 65535 || seenPorts[port] {
			return errors.New("protected host ports must be unique valid ports")
		}
		seenPorts[port] = true
	}
	paths := []string{p.PolicyDirectory, p.ControlTokenFile, p.PacketsTokenFile, strings.TrimPrefix(p.ControlURL, "unix://"), strings.TrimPrefix(p.PacketsURL, "unix://")}
	for i, a := range paths {
		for j, b := range paths {
			if i < j && (a == b || overlap(a, b)) {
				return errors.New("capture policy, sockets and credentials must be separate paths")
			}
		}
	}
	if p.ControlTokenFile == p.PacketsTokenFile {
		return errors.New("capture read and control credentials must be distinct")
	}
	for _, a := range paths {
		for _, b := range append(append([]string{c.StateDirectory, c.Socket, strings.TrimPrefix(c.DockerHost, "unix://")}, c.DiscoveryRoots...), c.WorkspaceRoots...) {
			if b != "" && overlap(a, b) {
				return errors.New("capture IPC, credentials and policy must be separate from state and game roots")
			}
		}
		if c.Proxy.Enabled {
			proxyPaths := []string{c.Proxy.PolicyDirectory, c.Proxy.ControlTokenFile, c.Proxy.TrafficTokenFile}
			for _, url := range []string{c.Proxy.ControlURL, c.Proxy.TrafficURL} {
				if strings.HasPrefix(url, "unix:///") {
					proxyPaths = append(proxyPaths, strings.TrimPrefix(url, "unix://"))
				}
			}
			for _, b := range proxyPaths {
				if b != "" && overlap(a, b) {
					return errors.New("capture paths must be separate from all HTTP proxy policies, credentials and IPC")
				}
			}
		}
		if !filepath.IsAbs(a) {
			return errors.New("capture paths must be absolute")
		}
	}
	return nil
}

// HostPortProtected is additive: installation config cannot remove defaults.
func (p CapturePolicy) HostPortProtected(port int) bool {
	for _, v := range append([]int{22, 2222, 2375, 2376, 8765, 18765, 9801, 9802, 9803, 9804}, p.ProtectedHostPorts...) {
		if port == v {
			return true
		}
	}
	return false
}
