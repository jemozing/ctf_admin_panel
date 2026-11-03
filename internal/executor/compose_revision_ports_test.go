package executor

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"github.com/moby/moby/client"
)

func TestComposePortPreflightUsesHostPublicationsAndOnlyReleasesExactTargets(t *testing.T) {
	service := domain.Service{Targets: []string{"app"}}
	before := composePortModel("127.0.0.1", "18021")
	after := composePortModel("", "8070")
	for _, tc := range []struct {
		name, inventory, replaced string
		conflict                  bool
	}{
		{"another service on IPv4 loopback", `{"Id":"foreign","State":"running","Ports":[{"IP":"127.0.0.1","PublicPort":8070,"PrivatePort":81,"Type":"tcp"}]}`, "current", true},
		{"another service on IPv6 wildcard", `{"Id":"foreign","State":"paused","Ports":[{"IP":"::","PublicPort":8070,"PrivatePort":81,"Type":"tcp"}]}`, "current", true},
		{"only exact target is about to stop", `{"Id":"current","State":"running","Ports":[{"IP":"127.0.0.1","PublicPort":8070,"PrivatePort":81,"Type":"tcp"}]}`, "current", false},
		{"stopped container and another protocol", `{"Id":"old","State":"exited","Ports":[{"IP":"0.0.0.0","PublicPort":8070,"PrivatePort":81,"Type":"tcp"}]},{"Id":"udp","State":"running","Ports":[{"IP":"0.0.0.0","PublicPort":8070,"PrivatePort":81,"Type":"udp"}]}`, "current", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api, err := client.New(client.WithHost("http://docker.invalid"), client.WithAPIVersion("1.56"), client.WithHTTPClient(&http.Client{Transport: statsRoundTripper(func(r *http.Request) (*http.Response, error) {
				if !strings.HasSuffix(r.URL.Path, "/containers/json") {
					t.Fatalf("unexpected Docker request: %s", r.URL.Path)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("[" + tc.inventory + "]"))}, nil
			})}))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = api.Close() })
			manager := &Manager{Engine: &docker.Engine{Client: api}}
			err = manager.checkComposePorts(t.Context(), service, before, after, []string{tc.replaced})
			if !tc.conflict {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var conflict *transport.ComposePortConflict
			if !errors.As(err, &conflict) || conflict.Binding != "*:8070/tcp" || strings.Contains(conflict.Error(), "foreign") {
				t.Fatalf("expected safe destination conflict, got %v", err)
			}
		})
	}
}

func TestPrepareComposeProtectsNewAdministrativePort(t *testing.T) {
	manager := &Manager{}
	service := domain.Service{Targets: []string{"app"}}
	err := manager.validateNewComposePorts(service, composePortModel("127.0.0.1", "18021"), composePortModel("", "8765"))
	var conflict *transport.ComposePortConflict
	if !errors.As(err, &conflict) || conflict.Binding != "*:8765/tcp" {
		t.Fatalf("expected administrative port conflict, got %v", err)
	}
}

func composePortModel(host, published string) map[string]any {
	return map[string]any{"services": map[string]any{"app": map[string]any{
		"ports": []any{map[string]any{"host_ip": host, "published": published, "target": float64(8070), "protocol": "tcp"}},
	}}}
}
