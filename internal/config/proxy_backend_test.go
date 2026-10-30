package config

import "testing"

func TestProxyBackendPortsKeepAuthorityBoundedAndSeparate(t *testing.T) {
	c := proxyBootstrapFixture()
	min, max := c.Proxy.BackendPorts()
	if min != 29080 || max != 29111 {
		t.Fatal("unexpected conservative backend range")
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Proxy.ListenPortMin, c.Proxy.ListenPortMax = 29080, 29111
	min, max = c.Proxy.BackendPorts()
	if min <= 29111 && max >= 29080 {
		t.Fatal("legacy listen range collides with implicit backend range")
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("legacy approved listener range became invalid: %v", err)
	}
	for _, span := range [][2]int{{0, 29111}, {29080, 0}, {80, 443}, {30000, 29999}, {29000, 31000}, {65535, 65536}, {29080, 29111}} {
		c.Proxy.BackendPortMin, c.Proxy.BackendPortMax = span[0], span[1]
		if err := c.Validate(); err == nil {
			t.Fatalf("unsafe backend range accepted: %v", span)
		}
	}
	c.Proxy.BackendPortMin, c.Proxy.BackendPortMax = 39080, 39111
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}
