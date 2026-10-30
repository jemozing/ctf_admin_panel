package docker

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/network"
)

func captureRuntimeFixture() Container {
	c, _ := runtimeFixture()
	c.State = "running"
	n := c.runtime.networks["round_one_default"]
	n.ID = strings.Repeat("c", 64)
	c.runtime.networks["round_one_default"] = n
	e := c.runtime.container.NetworkSettings.Networks["round_one_default"]
	e.NetworkID = n.ID
	e.IPAddress = netip.MustParseAddr("172.20.0.2")
	e.GlobalIPv6Address = netip.MustParseAddr("fd00::2")
	c.runtime.container.Config.ExposedPorts[network.MustParsePort("53/udp")] = struct{}{}
	c.runtime.container.Config.ExposedPorts[network.MustParsePort("9000/sctp")] = struct{}{}
	return c
}
func TestCapturePointsOnlyPrivateRuntimeBridgeAndTCPUDP(t *testing.T) {
	c := captureRuntimeFixture()
	points, err := c.CapturePoints()
	if err != nil || len(points) != 2 {
		t.Fatalf("points: %+v %v", points, err)
	}
	for _, p := range points {
		if p.Interface != "br-cccccccccccc" || len(p.Addresses) != 2 || p.Addresses[0] != "172.20.0.2" || p.Addresses[1] != "fd00::2" || p.NetworkID != strings.Repeat("c", 64) || (p.Protocol != "tcp" && p.Protocol != "udp") {
			t.Fatalf("unsafe point: %+v", p)
		}
	}
	raw, _ := json.Marshal(c)
	var forged Container
	if json.Unmarshal(raw, &forged) != nil {
		t.Fatal("fixture")
	}
	if _, err := forged.CapturePoints(); err == nil {
		t.Fatal("public inventory became runtime authority")
	}
}
func TestCapturePointsRejectChangedIdentityOrNonPrivateScope(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Container)
	}{
		{"stopped", func(c *Container) { c.State = "exited" }},
		{"forgedID", func(c *Container) { c.ID = strings.Repeat("d", 64) }},
		{"unknownnetwork", func(c *Container) { delete(c.runtime.networks, "round_one_default") }},
		{"mismatchednetwork", func(c *Container) {
			c.runtime.container.NetworkSettings.Networks["round_one_default"].NetworkID = strings.Repeat("e", 64)
		}},
		{"uninspected-second-network", func(c *Container) {
			c.runtime.container.NetworkSettings.Networks["other"] = &network.EndpointSettings{}
		}},
		{"publicip", func(c *Container) {
			c.runtime.container.NetworkSettings.Networks["round_one_default"].IPAddress = netip.MustParseAddr("8.8.8.8")
		}},
		{"loopback", func(c *Container) {
			c.runtime.container.NetworkSettings.Networks["round_one_default"].IPAddress = netip.MustParseAddr("127.0.0.1")
		}},
		{"unspecified", func(c *Container) {
			c.runtime.container.NetworkSettings.Networks["round_one_default"].IPAddress = netip.MustParseAddr("0.0.0.0")
		}},
		{"linklocal", func(c *Container) {
			c.runtime.container.NetworkSettings.Networks["round_one_default"].GlobalIPv6Address = netip.MustParseAddr("fe80::1")
		}},
		{"zoned", func(c *Container) {
			c.runtime.container.NetworkSettings.Networks["round_one_default"].GlobalIPv6Address = netip.MustParseAddr("fd00::1%eth0")
		}},
		{"driver", func(c *Container) {
			n := c.runtime.networks["round_one_default"]
			n.Driver = "overlay"
			c.runtime.networks["round_one_default"] = n
		}},
		{"ingress", func(c *Container) {
			n := c.runtime.networks["round_one_default"]
			n.Ingress = true
			c.runtime.networks["round_one_default"] = n
		}},
		{"loopbackinterface", func(c *Container) {
			n := c.runtime.networks["round_one_default"]
			n.Options = map[string]string{"com.docker.network.bridge.name": "lo"}
			c.runtime.networks["round_one_default"] = n
		}},
		{"custominvalidID", func(c *Container) {
			n := c.runtime.networks["round_one_default"]
			n.ID = "forged"
			n.Options = map[string]string{"com.docker.network.bridge.name": "gamebr0"}
			c.runtime.networks["round_one_default"] = n
			c.runtime.container.NetworkSettings.Networks["round_one_default"].NetworkID = n.ID
		}},
		{"defaultinvalidID", func(c *Container) {
			n := c.runtime.networks["round_one_default"]
			n.ID = "forged"
			c.runtime.networks = map[string]network.Inspect{"bridge": n}
			e := c.runtime.container.NetworkSettings.Networks["round_one_default"]
			e.NetworkID = n.ID
			c.runtime.container.NetworkSettings.Networks = map[string]*network.EndpointSettings{"bridge": e}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := captureRuntimeFixture()
			tc.edit(&c)
			if _, err := c.CapturePoints(); err == nil {
				t.Fatal("unverified scope accepted")
			}
		})
	}
}

func addCaptureNetwork(c *Container, name, id, iface, ip string) {
	info := c.runtime.networks["round_one_default"]
	info.ID = id
	info.Driver = "bridge"
	info.Ingress = false
	info.Options = map[string]string{"com.docker.network.bridge.name": iface}
	c.runtime.networks[name] = info
	c.runtime.container.NetworkSettings.Networks[name] = &network.EndpointSettings{NetworkID: id, IPAddress: netip.MustParseAddr(ip), GlobalIPv6Address: netip.MustParseAddr("fd01::2")}
}
func TestCapturePointsSupportMultipleInspectedNetworksAndStayBounded(t *testing.T) {
	c := captureRuntimeFixture()
	addCaptureNetwork(&c, "extra", strings.Repeat("d", 64), "gamebr-extra", "10.41.0.2")
	points, err := c.CapturePoints()
	if err != nil || len(points) != 4 {
		t.Fatalf("multiple verified bridges rejected: %+v %v", points, err)
	}
	byNetwork := map[string]int{}
	for _, p := range points {
		byNetwork[p.NetworkID]++
		if p.NetworkID == strings.Repeat("d", 64) && (p.Interface != "gamebr-extra" || p.Addresses[0] != "10.41.0.2" || p.Addresses[1] != "fd01::2") {
			t.Fatalf("second network lost its own addresses: %+v", p)
		}
	}
	if len(byNetwork) != 2 || byNetwork[strings.Repeat("c", 64)] != 2 || byNetwork[strings.Repeat("d", 64)] != 2 {
		t.Fatal("network mappings overlapped")
	}
	for n := 2; n < 8; n++ {
		addCaptureNetwork(&c, fmt.Sprintf("network%d", n), fmt.Sprintf("%064x", n), fmt.Sprintf("gamebr%d", n), fmt.Sprintf("10.%d.0.2", n))
	}
	if p, e := c.CapturePoints(); e != nil || len(p) != 16 {
		t.Fatalf("eight network boundary rejected: %d %v", len(p), e)
	}
	addCaptureNetwork(&c, "ninth", strings.Repeat("e", 64), "gamebr9", "10.90.0.2")
	if _, e := c.CapturePoints(); e == nil {
		t.Fatal("unbounded network inventory accepted")
	}
}
func TestCapturePointsSecondNetworkIsNeverAcceptedOnPartialEvidence(t *testing.T) {
	for _, edit := range []func(*Container){
		func(c *Container) { delete(c.runtime.networks, "extra") },
		func(c *Container) { c.runtime.container.NetworkSettings.Networks["extra"] = nil },
		func(c *Container) {
			n := c.runtime.networks["extra"]
			n.Driver = "overlay"
			c.runtime.networks["extra"] = n
		},
		func(c *Container) {
			n := c.runtime.networks["extra"]
			n.Ingress = true
			c.runtime.networks["extra"] = n
		},
		func(c *Container) {
			c.runtime.container.NetworkSettings.Networks["extra"].IPAddress = netip.MustParseAddr("192.0.2.1")
		},
	} {
		c := captureRuntimeFixture()
		addCaptureNetwork(&c, "extra", strings.Repeat("d", 64), "gamebr-extra", "10.41.0.2")
		edit(&c)
		if _, err := c.CapturePoints(); err == nil {
			t.Fatal("partially verified network set was offered")
		}
	}
}
