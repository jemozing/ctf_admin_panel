package executor

import (
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

func TestPrivateProxyPublicationParsesIPv4IPv6AndRejectsInvalidBindings(t *testing.T) {
	for _, raw := range []string{"127.0.0.1:18011->4444/tcp", "::1:18011->4444/tcp", "[::1]:18011->4444/tcp", "::ffff:127.0.0.1:18011->4444/tcp"} {
		_, host, container, private, ok := privatePublication(raw)
		if !ok || !private || host != 18011 || container != 4444 {
			t.Fatalf("lost private publication %q", raw)
		}
	}
	for _, raw := range []string{"127.0.0.1:0->4444/tcp", "127.0.0.1:18011->0/tcp", "127.0.0.1:18011->4444/udp", "localhost:18011->4444/tcp", "127.0.0.1:18011->4444/tcp?x=y", "127.0.0.1:18011"} {
		if _, _, _, _, ok := privatePublication(raw); ok {
			t.Fatalf("accepted malformed publication %q", raw)
		}
	}
	if _, _, _, private, ok := privatePublication("0.0.0.0:18011->4444/tcp"); !ok || private {
		t.Fatal("public binding confused with private")
	}
}

func TestProxyCandidatesUseOnlyApprovedPrivateApplicationPorts(t *testing.T) {
	s := domain.Service{ID: "game", Name: "Test", Containers: []domain.ContainerRef{{Component: "web", Role: domain.RoleApplication}, {Component: "db", Role: domain.RoleDatabase}, {Component: "stopped", Role: domain.RoleApplication}, {Component: "public", Role: domain.RoleApplication}}}
	actual := []docker.Container{
		{Component: "web", State: "running", Ports: []string{"::1:18011->4444/tcp", "127.0.0.1:18011->4444/tcp"}},
		{Component: "db", State: "running", Ports: []string{"127.0.0.1:5432->5432/tcp"}},
		{Component: "stopped", State: "exited", Ports: []string{"127.0.0.1:18012->80/tcp"}},
		{Component: "unknown", State: "running", Ports: []string{"127.0.0.1:18013->80/tcp"}},
		{Component: "public", State: "running", Ports: []string{"127.0.0.1:18014->80/tcp", "0.0.0.0:18015->80/tcp"}},
	}
	v := proxyCandidateTargets(s, actual)
	if len(v) != 1 || v[0].Component != "web" || v[0].UpstreamPort != 4444 || v[0].UpstreamAddress != "http://127.0.0.1:18011" || !v[0].PrivateBinding {
		t.Fatalf("unapproved, public or ambiguous target offered: %#v", v)
	}
}
