package executor

import (
	"context"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/packetcapture"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func TestCapturePublicationParsesExactTCPUDPAndRejectsUnsafeBindings(t *testing.T) {
	for _, tc := range []struct {
		raw, host, proto  string
		published, target int
	}{
		{"127.0.0.1:18000->7000/tcp", "127.0.0.1", "tcp", 18000, 7000},
		{"0.0.0.0:19000->53/udp", "0.0.0.0", "udp", 19000, 53},
		{"::1:18001->7000/tcp", "::1", "tcp", 18001, 7000},
		{"[::1]:18001->7000/tcp", "::1", "tcp", 18001, 7000},
		{"[::]:18002->8000/udp", "::", "udp", 18002, 8000},
		{"::ffff:127.0.0.1:18003->7000/tcp", "127.0.0.1", "tcp", 18003, 7000},
	} {
		host, published, target, protocol, ok := capturePublication(tc.raw)
		if !ok || host.String() != tc.host || published != tc.published || target != tc.target || protocol != tc.proto {
			t.Fatalf("publication changed: %q -> %v %d %d %q %v", tc.raw, host, published, target, protocol, ok)
		}
	}
	for _, raw := range []string{"127.0.0.1:0->7000/tcp", "127.0.0.1:65536->7000/tcp", "127.0.0.1:18000->0/tcp", "127.0.0.1:18000->65536/tcp", "127.0.0.1:18000->7000/sctp", "localhost:18000->7000/tcp", "127.0.0.1:18000->7000/tcp?extra=1", "fe80::1%eth0:18000->7000/tcp", "224.0.0.1:18000->7000/udp", "127.0.0.1:18000", "127.0.0.1:18000->7000/tcp/extra"} {
		if _, _, _, _, ok := capturePublication(raw); ok {
			t.Fatalf("unsafe binding offered: %q", raw)
		}
	}
}
func TestCaptureHostPublicationMatchesOnlyOwnAddressesAndApprovedFamily(t *testing.T) {
	physical := packetcapture.Interface{Name: "eth0", Index: 2, Up: true, Supported: true, Addresses: []string{"192.0.2.10/24", "10.0.0.1/24", "2001:db8::1/64", "fd00::1/64", "fe80::1/64", "224.0.0.1/4", "0.0.0.0/0", "bad-prefix", "192.0.2.10/24"}}
	for _, tc := range []struct {
		host string
		want []string
	}{
		{"0.0.0.0", []string{"10.0.0.1", "192.0.2.10"}},
		{"::", []string{"2001:db8::1", "fd00::1"}},
		{"192.0.2.10", []string{"192.0.2.10"}},
		{"192.0.2.11", []string{}},
		{"127.0.0.1", []string{}},
	} {
		got := capturePublicationAddresses(netip.MustParseAddr(tc.host), physical)
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("host %s expanded beyond own addresses: got%v want%v", tc.host, got, tc.want)
		}
	}
	loopback := packetcapture.Interface{Name: "lo", Index: 1, Up: true, Supported: true, Loopback: true, Addresses: []string{"127.0.0.1/8", "::1/128"}}
	if got := capturePublicationAddresses(netip.MustParseAddr("127.0.0.8"), loopback); !reflect.DeepEqual(got, []string{"127.0.0.8"}) {
		t.Fatal("explicit loopback alias was lost")
	}
	for _, host := range []string{"0.0.0.0", "::", "192.0.2.10"} {
		if got := capturePublicationAddresses(netip.MustParseAddr(host), loopback); len(got) != 0 {
			t.Fatal("wildcard/public binding expanded onto loopback")
		}
	}
	m := &Manager{Config: config.Config{Capture: config.CapturePolicy{AllowedInterfaces: []string{"eth0", "lo"}}}}
	if !m.captureInterfaceApproved("lo") || !m.captureInterfaceApproved("eth0") || m.captureInterfaceApproved("eth1") || m.captureInterfaceApproved("ETH0") {
		t.Fatal("interface installation boundary widened")
	}
}
func networkTargetsFixture() transport.CaptureTargets {
	base := transport.CaptureTarget{ServiceID: "game", Component: "app", Protocol: "tcp", TargetPort: 7000, PointGroup: "canonical-a", ReleaseID: "release-1", SourceDigest: "sha256:" + strings.Repeat("a", 64)}
	bridge := base
	bridge.ID = "bridge"
	bridge.Point = "container_bridge"
	bridge.Interface = "br-games"
	bridge.IfIndex = 7
	bridge.Addresses = []string{"172.20.0.5"}
	veth := bridge
	veth.ID = "veth"
	veth.Point = "container_veth"
	veth.Interface = "veth-game"
	veth.IfIndex = 8
	host := base
	host.ID = "host4"
	host.Point = "host_publication"
	host.Interface = "eth0"
	host.IfIndex = 2
	host.Addresses = []string{"192.0.2.10"}
	host.ObservedPort = 18000
	host6 := host
	host6.ID = "host6"
	host6.Interface = "lo"
	host6.IfIndex = 1
	host6.Addresses = []string{"::1"}
	host6.ObservedPort = 18001
	other := bridge
	other.ID = "other-network"
	other.PointGroup = "canonical-b"
	other.Interface = "br-extra"
	other.IfIndex = 9
	other.Addresses = []string{"10.0.0.5"}
	return transport.CaptureTargets{Targets: []transport.CaptureTarget{bridge, veth, host, host6, other}}
}
func TestCaptureCanonicalSelectionSeparatesObservationLegsButKeepsPublications(t *testing.T) {
	targets := networkTargetsFixture()
	for _, ids := range [][]string{{"bridge", "veth"}, {"bridge", "host4"}, {"veth", "host4"}, {"host4", "bridge"}, {"bridge", "bridge"}, {"unknown"}} {
		if _, err := captureSelection(targets, ids); err == nil {
			t.Fatalf("mixed/repeated/unapproved canonical leg accepted: %v", ids)
		}
	}
	for _, ids := range [][]string{{"bridge"}, {"veth"}, {"host4", "host6"}, {"bridge", "other-network"}} {
		if selected, err := captureSelection(targets, ids); err != nil || len(selected) != len(ids) {
			t.Fatalf("valid canonical selection rejected: %v %v", ids, err)
		}
	}
	selected, err := captureSelection(targets, []string{"host6", "host4"})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := capturePolicyFor(3, transport.CapturePreviewRequest{Enabled: true, Snaplen: 64, MaxPacketsPerSecond: 1000}, selected)
	if err != nil {
		t.Fatal(err)
	}
	ports := map[string]int{}
	for _, iface := range policy.Interfaces {
		for _, ep := range iface.Endpoints {
			ports[iface.Name] = ep.Port
			if ep.ServiceID != "game" || ep.Component != "app" || ep.ReleaseID != "release-1" || ep.SourceDigest != "sha256:"+strings.Repeat("a", 64) {
				t.Fatalf("version/source association lost: %+v", ep)
			}
		}
	}
	if ports["eth0"] != 18000 || ports["lo"] != 18001 {
		t.Fatalf("host port was confused with container port7000: %+v", ports)
	}
	if _, err = capturePolicyFor(4, transport.CapturePreviewRequest{Enabled: false, Snaplen: 64, MaxPacketsPerSecond: 1000}, selected); err == nil {
		t.Fatal("disabled capture retained selected endpoints")
	}
}
func TestLegacyCaptureTargetStillMapsToItsContainerPort(t *testing.T) {
	target := transport.CaptureTarget{ID: "legacy", ServiceID: "game", Component: "app", Protocol: "udp", TargetPort: 53, Interface: "br-game", IfIndex: 7, Addresses: []string{"172.20.0.5"}}
	selected, err := captureSelection(transport.CaptureTargets{Targets: []transport.CaptureTarget{target}}, []string{"legacy"})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := capturePolicyFor(2, transport.CapturePreviewRequest{Enabled: true, Snaplen: 0, MaxPacketsPerSecond: 1000}, selected)
	if err != nil || len(policy.Interfaces) != 1 || policy.Interfaces[0].Endpoints[0].Port != 53 || policy.Interfaces[0].Endpoints[0].ReleaseID != "" {
		t.Fatalf("legacy target changed semantics: %+v %v", policy, err)
	}
}

func TestCaptureProtectedHostPortAuthorityChangeInvalidatesPreview(t *testing.T) {
	m, _ := captureControlFixture(t)
	preview := captureEmptyPreview(t, m, 1)
	m.Config.Capture.ProtectedHostPorts = []int{19000}
	if _, err := m.CaptureConfirm(context.Background(), captureConfirmInput(preview)); err == nil {
		t.Fatal("new protected host port boundary accepted old confirmation")
	}
	if captureRevisionCount(t, m) != 0 || capturePublished(t, m).Revision != 1 {
		t.Fatal("stale host-port approval mutated policy history or output")
	}
}
