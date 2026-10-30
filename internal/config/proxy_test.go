package config

import (
	"encoding/json"
	"testing"
)

func proxyBootstrapFixture() Config {
	return Config{Development: true, StateDirectory: "/srv/ctf/state", Socket: "/run/ctf/executor.sock", DockerHost: "unix:///var/run/docker.sock", DockerBinary: "/usr/bin/docker", DiscoveryRoots: []string{"/srv/ctf/services"}, WorkspaceRoots: []string{"/srv/ctf/workspaces"}, WebUID: 11001, Proxy: ProxyPolicy{Enabled: true, PolicyDirectory: "/srv/ctf/proxy-policy", ControlURL: "unix:///run/ctf/proxy-control.sock", TrafficURL: "unix:///run/ctf/traffic.sock", ControlTokenFile: "/etc/ctf/proxy-token", TrafficTokenFile: "/etc/ctf/traffic-token", AllowedListenIPs: []string{"127.0.0.1", "::1"}, ListenPortMin: 18000, ListenPortMax: 18100, ProxyGID: 11004}}
}

func TestProxyBootstrapDisabledRemainsBackwardCompatible(t *testing.T) {
	c := proxyBootstrapFixture()
	c.Proxy = ProxyPolicy{}
	if err := c.Validate(); err != nil {
		t.Fatalf("legacy bootstrap without proxy is no longer accepted: %v", err)
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Config
	if err = json.Unmarshal(raw, &decoded); err != nil || decoded.Proxy.Enabled {
		t.Fatalf("proxy became enabled implicitly: %+v %v", decoded.Proxy, err)
	}
}

func TestProxyBootstrapAcceptsOnlyExplicitLocalControlBoundaries(t *testing.T) {
	for _, endpoints := range [][2]string{
		{"unix:///run/ctf/proxy-control.sock", "unix:///run/ctf/traffic.sock"},
		{"http://127.0.0.1:9801", "http://[::1]:9802"},
	} {
		c := proxyBootstrapFixture()
		c.Proxy.ControlURL, c.Proxy.TrafficURL = endpoints[0], endpoints[1]
		if err := c.Validate(); err != nil {
			t.Fatalf("valid explicit local control endpoints rejected: %v", err)
		}
	}
	for _, endpoint := range []string{
		"http://192.0.2.10:9801", "https://127.0.0.1:9801", "http://localhost:9801", "http://0.0.0.0:9801", "http://127.0.0.1", "http://user:pass@127.0.0.1:9801", "http://127.0.0.1:9801/v1", "http://127.0.0.1:9801?key=x", "http://127.0.0.1:9801#fragment", "http://127.0.0.1:9801?", "http://127.0.0.1:0", "http://127.0.0.1:65536",
		"unix://remote/run/ctf/proxy.sock", "unix:relative.sock", "unix:///run/ctf/../proxy.sock", "unix:///run/ctf//proxy.sock", "unix:///run/ctf/%70roxy.sock", "unix:///run/ctf/proxy.sock?", "unix:///run/ctf/proxy.sock?x=1", "unix:///run/ctf/proxy.sock#fragment", "unix:///run/ctf/executor.sock",
	} {
		for _, field := range []string{"control", "recorder"} {
			t.Run(field+"/"+endpoint, func(t *testing.T) {
				c := proxyBootstrapFixture()
				if field == "control" {
					c.Proxy.ControlURL = endpoint
				} else {
					c.Proxy.TrafficURL = endpoint
				}
				if err := c.Validate(); err == nil {
					t.Fatal("accepted a remote, aliased, multiplexed, or noncanonical control endpoint")
				}
			})
		}
	}
	c := proxyBootstrapFixture()
	c.Proxy.TrafficURL = c.Proxy.ControlURL
	if err := c.Validate(); err == nil {
		t.Fatal("proxy and recorder share a control endpoint")
	}
}

func TestProxyBootstrapRejectsUnsafeListenerAndPathAuthority(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Config)
	}{
		{"missing IPs", func(c *Config) { c.Proxy.AllowedListenIPs = nil }},
		{"hostname IP", func(c *Config) { c.Proxy.AllowedListenIPs = []string{"localhost"} }},
		{"multicast IP", func(c *Config) { c.Proxy.AllowedListenIPs = []string{"224.0.0.1"} }},
		{"zoned IP", func(c *Config) { c.Proxy.AllowedListenIPs = []string{"fe80::1%eth0"} }},
		{"IPv4 mapped duplicate", func(c *Config) { c.Proxy.AllowedListenIPs = []string{"127.0.0.1", "::ffff:127.0.0.1"} }},
		{"too many IPs", func(c *Config) { c.Proxy.AllowedListenIPs = make([]string, 17) }},
		{"privileged port", func(c *Config) { c.Proxy.ListenPortMin = 80 }},
		{"port overflow", func(c *Config) { c.Proxy.ListenPortMax = 65536 }},
		{"reversed range", func(c *Config) { c.Proxy.ListenPortMin = 19000 }},
		{"unbounded range", func(c *Config) { c.Proxy.ListenPortMax = 19024 }},
		{"state child", func(c *Config) { c.Proxy.PolicyDirectory = c.StateDirectory + "/proxy" }},
		{"state parent", func(c *Config) { c.Proxy.PolicyDirectory = "/srv/ctf" }},
		{"discovery child", func(c *Config) { c.Proxy.PolicyDirectory = c.DiscoveryRoots[0] + "/proxy" }},
		{"workspace child", func(c *Config) { c.Proxy.PolicyDirectory = c.WorkspaceRoots[0] + "/proxy" }},
		{"root policy directory", func(c *Config) { c.Proxy.PolicyDirectory = "/" }},
		{"relative policy directory", func(c *Config) { c.Proxy.PolicyDirectory = "proxy-policy" }},
		{"noncanonical policy directory", func(c *Config) { c.Proxy.PolicyDirectory = "/srv/ctf/../proxy-policy" }},
		{"relative proxy credential", func(c *Config) { c.Proxy.ControlTokenFile = "proxy-token" }},
		{"noncanonical recorder credential", func(c *Config) { c.Proxy.TrafficTokenFile = "/etc/ctf/../traffic-token" }},
		{"root group", func(c *Config) { c.Proxy.ProxyGID = 0 }},
		{"dashboard group", func(c *Config) { c.Proxy.ProxyGID = c.WebUID }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := proxyBootstrapFixture()
			tc.edit(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("unsafe proxy installation boundary accepted")
			}
		})
	}
}
