package config

import "testing"

func captureBootstrapFixture() Config {
	c := proxyBootstrapFixture()
	c.Proxy = ProxyPolicy{}
	c.Capture = CapturePolicy{Enabled: true, PolicyDirectory: "/srv/capture/policy", ControlURL: "unix:///srv/capture/control/capture.sock", ControlTokenFile: "/srv/capture/secrets/control", PacketsURL: "unix:///srv/capture/read/packets.sock", PacketsTokenFile: "/srv/capture/secrets/read", AllowedInterfaces: []string{"br-0123456789ab", "docker0"}}
	return c
}
func TestCaptureBootstrapBoundary(t *testing.T) {
	c := captureBootstrapFixture()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Capture = CapturePolicy{}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*Config)
	}{
		{"HTTPcontrol", func(c *Config) { c.Capture.ControlURL = "http://127.0.0.1:9803" }},
		{"HTTPread", func(c *Config) { c.Capture.PacketsURL = "http://127.0.0.1:9804" }},
		{"remote", func(c *Config) { c.Capture.ControlURL = "unix://remote/run/capture.sock" }},
		{"coreIPC", func(c *Config) { c.Capture.ControlURL = "unix://" + c.Socket }},
		{"sameIPC", func(c *Config) { c.Capture.PacketsURL = c.Capture.ControlURL }},
		{"samecredential", func(c *Config) { c.Capture.PacketsTokenFile = c.Capture.ControlTokenFile }},
		{"policycredential", func(c *Config) { c.Capture.ControlTokenFile = c.Capture.PolicyDirectory + "/control" }},
		{"statesocket", func(c *Config) { c.Capture.ControlURL = "unix://" + c.StateDirectory + "/capture.sock" }},
		{"gamerootcredential", func(c *Config) { c.Capture.PacketsTokenFile = c.DiscoveryRoots[0] + "/token" }},
		{"workspacepolicy", func(c *Config) { c.Capture.PolicyDirectory = c.WorkspaceRoots[0] + "/capture" }},
		{"canonical", func(c *Config) { c.Capture.PolicyDirectory = "/srv/../capture/policy" }},
		{"wildcard", func(c *Config) { c.Capture.AllowedInterfaces = []string{"br-*"} }},
		{"duplicate", func(c *Config) { c.Capture.AllowedInterfaces = []string{"docker0", "docker0"} }},
		{"nointerfaces", func(c *Config) { c.Capture.AllowedInterfaces = nil }},
		{"longinterface", func(c *Config) { c.Capture.AllowedInterfaces = []string{"abcdefghijklmnop"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := captureBootstrapFixture()
			tc.edit(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("unsafe capture boundary accepted")
			}
		})
	}
}

func TestCaptureBootstrapSeparateFromHTTPDataPlane(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Config)
	}{
		{"policy", func(c *Config) { c.Capture.PolicyDirectory = c.Proxy.PolicyDirectory }},
		{"control", func(c *Config) { c.Capture.ControlURL = c.Proxy.ControlURL }},
		{"recorder", func(c *Config) { c.Capture.PacketsURL = c.Proxy.TrafficURL }},
		{"controlcredential", func(c *Config) { c.Capture.ControlTokenFile = c.Proxy.ControlTokenFile }},
		{"readcredential", func(c *Config) { c.Capture.PacketsTokenFile = c.Proxy.TrafficTokenFile }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := captureBootstrapFixture()
			c.Proxy = proxyBootstrapFixture().Proxy
			tc.edit(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("capture shared HTTP data-plane authority")
			}
		})
	}
}

func TestCaptureObservationInterfacesAndProtectedPortsAreExplicit(t *testing.T) {
	c := captureBootstrapFixture()
	c.Capture.AllowedInterfaces = []string{"lo", "eth0", "veth-a", "br-games"}
	c.Capture.ProtectedHostPorts = []int{8443, 9090}
	if err := c.Validate(); err != nil {
		t.Fatalf("explicit observation points rejected: %v", err)
	}
	for _, port := range []int{22, 2222, 2375, 2376, 8765, 18765, 9801, 9802, 9803, 9804, 8443, 9090} {
		if !c.Capture.HostPortProtected(port) {
			t.Fatalf("protected port %d was removed", port)
		}
	}
	for _, port := range []int{1, 23, 5000, 65535} {
		if c.Capture.HostPortProtected(port) {
			t.Fatalf("unconfigured game publication %d blocked", port)
		}
	}
	c.Capture.ProtectedHostPorts = nil
	if !c.Capture.HostPortProtected(22) {
		t.Fatal("empty custom list removed defaults")
	}
	for _, ports := range [][]int{{0}, {65536}, {-1}, {9000, 9000}, make([]int, 257)} {
		c.Capture.ProtectedHostPorts = ports
		if err := c.Validate(); err == nil {
			t.Fatalf("invalid protected host port list accepted: %+v", ports)
		}
	}
}

func TestCaptureProtectedHostPortListAcceptsExactMaximum(t *testing.T) {
	c := captureBootstrapFixture()
	for n := 0; n < 256; n++ {
		c.Capture.ProtectedHostPorts = append(c.Capture.ProtectedHostPorts, 20000+n)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if !c.Capture.HostPortProtected(20255) || !c.Capture.HostPortProtected(9804) || c.Capture.HostPortProtected(20256) {
		t.Fatal("maximum custom port list altered immutable defaults or boundary")
	}
}
