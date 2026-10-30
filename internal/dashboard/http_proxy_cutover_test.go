package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func TestProxyCutoverAndTLSRequireAdminAndTrustedActor(t *testing.T) {
	s, _ := testServer(t)
	admin, csrf, adminUser := loginAs(t, s, "admin")
	createAccount(t, s, admin, csrf, "portviewer", RoleViewer)
	createAccount(t, s, admin, csrf, "portdefender", RoleDefender)
	viewer, vcsrf, _ := loginAs(t, s, "portviewer")
	defender, dcsrf, _ := loginAs(t, s, "portdefender")
	var calls atomic.Int32
	var actor atomic.Value
	isolatedStreamExecutor(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/v1/proxy/cutover/confirm" {
			t.Errorf("unexpected call %s", r.URL.Path)
		}
		var in transport.ProxyConfirmRequest
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			t.Error("invalid downstream confirmation")
		}
		actor.Store(in.Initiator)
		_ = json.NewEncoder(w).Encode(transport.ProxyCutoverView{ID: "move-1", State: "queued", Stage: "prepared"})
	}))
	endpoints := []struct{ method, path string }{
		{"GET", "/api/proxy/cutover/targets"}, {"GET", "/api/proxy/cutovers"}, {"GET", "/api/proxy/tls/certificates"},
		{"POST", "/api/proxy/cutover/preview"}, {"POST", "/api/proxy/cutover/return-preview"}, {"POST", "/api/proxy/cutover/confirm"},
	}
	for _, account := range []struct {
		cookie *http.Cookie
		csrf   string
	}{{viewer, vcsrf}, {defender, dcsrf}} {
		for _, endpoint := range endpoints {
			response := request(t, s, endpoint.method, endpoint.path, map[string]any{}, account.cookie, account.csrf)
			if response.Code != 403 {
				t.Fatalf("role bypass %s %d", endpoint.path, response.Code)
			}
		}
	}
	confirmation := map[string]any{"proposal_id": "move-plan-1", "digest": domain.Hash([]byte("reviewed"))}
	if response := request(t, s, "POST", "/api/proxy/cutover/confirm", confirmation, admin, ""); response.Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	confirmation["initiator"] = "forged"
	if response := request(t, s, "POST", "/api/proxy/cutover/confirm", confirmation, admin, csrf); response.Code != 400 {
		t.Fatal("browser actor accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("forbidden call reached privileged backend")
	}
	delete(confirmation, "initiator")
	response := request(t, s, "POST", "/api/proxy/cutover/confirm", confirmation, admin, csrf)
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"state":"queued"`) {
		t.Fatalf("async response %d %s", response.Code, response.Body.String())
	}
	if actor.Load() != domain.ID(adminUser.ID) || calls.Load() != 1 {
		t.Fatal("actor was not injected from authenticated Admin")
	}
}

func TestProxyCutoverRejectsUnsafeBrowserFieldsAndQueries(t *testing.T) {
	s, _ := testServer(t)
	admin, csrf, _ := loginAs(t, s, "admin")
	var calls atomic.Int32
	isolatedStreamExecutor(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = w.Write([]byte(`{}`)) }))
	for _, path := range []string{"/api/proxy/cutover/targets?raw=true", "/api/proxy/cutovers?limit=999999", "/api/proxy/tls/certificates?private_key=true"} {
		if response := request(t, s, "GET", path, nil, admin, ""); response.Code != 400 {
			t.Fatalf("query accepted %s %d", path, response.Code)
		}
	}
	for _, body := range []string{
		`{"service_id":"game","component":"app","upstream_port":80,"private_port":29080,"routes":[{"upstream":"http://evil/"}]}`,
		`{"service_id":"game","component":"app","upstream_port":80,"private_port":29080,"routes":[{"tls":{"certificate_id":"safe","private_key":"SECRET"}}]}`,
		`{"service_id":"game","service_id":"other","routes":[]}`,
		`{"initiator":"forged","routes":[]}`,
		`{"service_id":"game","component":"app","upstream_port":80,"private_port":443,"routes":[{}]}`,
	} {
		req := httptest.NewRequest("POST", "http://panel.test/api/proxy/cutover/preview", strings.NewReader(body))
		req.Header.Set("Origin", "http://panel.test")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		req.AddCookie(admin)
		response := httptest.NewRecorder()
		s.handle(response, req)
		if response.Code != 400 {
			t.Fatalf("unsafe body accepted %d", response.Code)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request reached executor")
	}
}

func TestProxyTLSMetadataRevokedDuringReadIsWithheld(t *testing.T) {
	s, _ := testServer(t)
	admin, csrf, _ := loginAs(t, s, "admin")
	created := createAccount(t, s, admin, csrf, "tlsadmin", RoleAdmin)
	cookie, _, _ := loginAs(t, s, "tlsadmin")
	isolatedStreamExecutor(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := s.db.ExecContext(context.Background(), "UPDATE users SET role='viewer' WHERE id=?", created.ID)
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"certificates":[{"id":"secret-profile-marker"}]}`))
	}))
	response := request(t, s, "GET", "/api/proxy/tls/certificates", nil, cookie, "")
	if response.Code != 403 || strings.Contains(response.Body.String(), "secret-profile-marker") {
		t.Fatalf("revoked metadata released: %d %s", response.Code, response.Body.String())
	}
}
