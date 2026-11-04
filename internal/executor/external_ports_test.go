package executor

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func TestServiceExternalPorts(t *testing.T) {
	const token = "test-status-control-token-0000000000000"
	tokenFile := filepath.Join(t.TempDir(), "control-token")
	if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/status" || r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unexpected control request", http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, `{"available":true,"desired_revision":3,"applied_revision":2,"public_ports_by_service":{"bimba":[8070,8070],"other":[5000]}}`)
	}))
	defer status.Close()
	m := Manager{Config: config.Config{Proxy: config.ProxyPolicy{Enabled: true, ControlURL: status.URL, ControlTokenFile: tokenFile}}}
	containers := []docker.Container{
		{State: "running", Ports: []string{
			"127.0.0.1:29080->80/tcp", "::1:29080->80/tcp", "[::ffff:127.0.0.2]:29080->80/tcp",
			"0.0.0.0:8070->80/udp", ":::8070->80/udp", "192.0.2.10:7000->80/sctp",
		}},
		{State: "running", Ports: []string{"0.0.0.0:9000->80/tcp", ":::9000->80/tcp"}},
		{State: "exited", Ports: []string{"0.0.0.0:6000->80/tcp"}},
	}
	wantDirect := []transport.ExternalPort{{Port: 7000, Protocol: "sctp"}, {Port: 8070, Protocol: "udp"}, {Port: 9000, Protocol: "tcp"}}
	wantAll := []transport.ExternalPort{wantDirect[0], {Port: 8070, Protocol: "tcp"}, wantDirect[1], wantDirect[2]}
	if got := m.serviceExternalPorts(t.Context(), "bimba", containers); !reflect.DeepEqual(got, wantAll) {
		t.Errorf("external ports = %+v, want %+v", got, wantAll)
	}
	if got := m.serviceExternalPorts(t.Context(), "unpublished", nil); got == nil || len(got) != 0 {
		t.Errorf("known empty external ports = %#v, want non-nil empty slice", got)
	}

	oldStatus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"available":true}`)
	}))
	defer oldStatus.Close()
	m.Config.Proxy.ControlURL = oldStatus.URL
	if got := m.serviceExternalPorts(t.Context(), "bimba", containers); !reflect.DeepEqual(got, wantDirect) {
		t.Errorf("external ports with older proxy = %+v, want %+v", got, wantDirect)
	}
	if got := m.serviceExternalPorts(t.Context(), "unpublished", nil); got != nil {
		t.Errorf("unknown external ports = %#v, want nil", got)
	}

	oldStatus.Close()
	if got := m.serviceExternalPorts(t.Context(), "bimba", containers); !reflect.DeepEqual(got, wantDirect) {
		t.Errorf("external ports with unavailable proxy = %+v, want %+v", got, wantDirect)
	}
	if got := m.serviceExternalPorts(t.Context(), "unpublished", nil); got != nil {
		t.Errorf("unknown external ports with unavailable proxy = %#v, want nil", got)
	}
	m.Config.Proxy.Enabled = false
	if got := m.serviceExternalPorts(t.Context(), "unpublished", nil); got == nil || len(got) != 0 {
		t.Errorf("known empty external ports with proxy disabled = %#v, want non-nil empty slice", got)
	}
}
