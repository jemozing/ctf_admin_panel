package executor

import (
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

func TestProxyObservationTargetsFromVerifiedTCPPublications(t *testing.T) {
	service := domain.Service{
		ID: "game", Name: "Game",
		Containers: []domain.ContainerRef{{Component: "app", Role: domain.RoleApplication}},
	}
	for _, tt := range []struct {
		name       string
		ports      []string
		allow      bool
		binding    map[string]any
		upstream   string
		targetPort int
		private    bool
	}{
		{
			name:  "disabled wildcard",
			ports: []string{"0.0.0.0:8087->8080/tcp"},
		},
		{
			name:  "observed dual-stack wildcard",
			ports: []string{"0.0.0.0:8087->8080/tcp", ":::8087->8080/tcp"},
			allow: true, binding: map[string]any{"published": "8087", "target": 8080},
			upstream: "http://127.0.0.1:8087", targetPort: 8080,
		},
		{
			name:  "automatic wildcard assignment is not saved",
			ports: []string{"0.0.0.0:8087->8080/tcp"},
			allow: true, binding: map[string]any{"target": 8080},
		},
		{
			name:  "observed wildcard port must match the approved model",
			ports: []string{"0.0.0.0:8087->8080/tcp"},
			allow: true, binding: map[string]any{"published": "8086", "target": 8080},
		},
		{
			name:  "IPv6-only wildcard",
			ports: []string{":::8087->8080/tcp"},
			allow: true, binding: map[string]any{"host_ip": "::", "published": "8087", "target": 8080},
		},
		{
			name:  "specific non-loopback address",
			ports: []string{"192.0.2.15:8087->8080/tcp"},
			allow: true, binding: map[string]any{"host_ip": "192.0.2.15", "published": "8087", "target": 8080},
		},
		{
			name:  "public UDP does not create HTTP target",
			ports: []string{"0.0.0.0:8087->8080/udp"},
			allow: true, binding: map[string]any{"protocol": "udp", "published": "8087", "target": 8080},
		},
		{
			name:  "private listener with an alternate public TCP listener",
			ports: []string{"127.0.0.1:5000->8000/tcp", "192.0.2.15:5000->8000/tcp"},
			allow: true, binding: map[string]any{"host_ip": "127.0.0.1", "published": "5000", "target": 8000},
			upstream: "http://127.0.0.1:5000", targetPort: 8000,
		},
		{
			name:  "private listener remains private when enabled",
			ports: []string{"127.0.0.1:4444->4444/tcp"},
			allow: true, upstream: "http://127.0.0.1:4444", targetPort: 4444, private: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			actual := []docker.Container{{Component: "app", State: "running", Ports: tt.ports}}
			model := map[string]any{"services": map[string]any{"app": map[string]any{"ports": []any{tt.binding}}}}
			got := proxyCandidateTargets(service, actual, tt.allow, model)
			if tt.upstream == "" {
				if len(got) != 0 {
					t.Fatalf("unsafe target offered: %#v", got)
				}
				return
			}
			if len(got) != 1 || got[0].UpstreamAddress != tt.upstream ||
				got[0].UpstreamPort != tt.targetPort || got[0].PrivateBinding != tt.private {
				t.Fatalf("unexpected target: %#v", got)
			}
		})
	}
}
