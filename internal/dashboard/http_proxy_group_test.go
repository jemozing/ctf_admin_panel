package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func TestGroupedCutoverHTTPInjectsActorAndPreservesAllMappings(t *testing.T) {
	s, _ := testServer(t)
	admin, csrf, user := loginAs(t, s, "admin")
	var calls atomic.Int32
	isolatedStreamExecutor(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/v1/proxy/cutover/preview" {
			t.Errorf("unexpected %s", r.URL.Path)
		}
		var in transport.ProxyCutoverPreviewRequest
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			t.Error("bad downstream request")
		}
		if in.Initiator != domain.ID(user.ID) || in.ServiceID != "game" || len(in.Targets) != 3 || len(in.Routes) != 3 || in.Component != "" || in.PrivatePort != 0 {
			t.Error("group or actor changed")
		}
		if in.Targets[0].Component != "api" || in.Targets[1].UpstreamPort != 9090 || in.Targets[2].PrivatePort != 29082 {
			t.Error("target routing lost")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(transport.ProxyCutoverPreview{ProposalID: "group-plan", Components: []string{"api", "front"}, Digest: domain.Hash([]byte("group"))})
	}))
	input := map[string]any{"service_id": "game", "targets": []map[string]any{{"component": "api", "upstream_port": 8080, "private_port": 29080}, {"component": "api", "upstream_port": 9090, "private_port": 29081}, {"component": "front", "upstream_port": 3000, "private_port": 29082}}, "routes": []map[string]any{{"component": "api", "upstream_port": 8080}, {"component": "api", "upstream_port": 9090}, {"component": "front", "upstream_port": 3000}}}
	response := request(t, s, "POST", "/api/proxy/cutover/preview", input, admin, csrf)
	if response.Code != 200 || calls.Load() != 1 {
		t.Fatalf("group rejected %d %s", response.Code, response.Body.String())
	}
	input["initiator"] = "forged"
	if response := request(t, s, "POST", "/api/proxy/cutover/preview", input, admin, csrf); response.Code != 400 || calls.Load() != 1 {
		t.Fatal("browser actor crossed boundary")
	}
}

func TestGroupedCutoverHTTPRejectsAmbiguousOrUnboundedSelectionBeforeRPC(t *testing.T) {
	s, _ := testServer(t)
	admin, csrf, _ := loginAs(t, s, "admin")
	var calls atomic.Int32
	isolatedStreamExecutor(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = w.Write([]byte(`{}`)) }))
	for _, body := range []string{
		`{"service_id":"game","component":"api","targets":[{"component":"api","upstream_port":80,"private_port":29080}],"routes":[{}]}`,
		`{"service_id":"game","targets":[],"routes":[{}]}`,
		`{"service_id":"game","targets":[{"component":"api","upstream_port":80,"private_port":29080},{"component":"front","upstream_port":3000,"private_port":29080}],"routes":[{}]}`,
		`{"service_id":"game","targets":[{"component":"api","upstream_port":80,"private_port":29080},{"component":"api","upstream_port":80,"private_port":29081}],"routes":[{}]}`,
		`{"service_id":"game","targets":[{"component":"api","upstream_port":80,"private_port":29080.5}],"routes":[{}]}`,
		`{"service_id":"game","targets":[{"component":"api","upstream_port":80,"private_port":29080,"upstream":"http://evil/"}],"routes":[{}]}`,
		`{"service_id":"game","targets":[{"component":"api","component":"front","upstream_port":80,"private_port":29080}],"routes":[{}]}`,
	} {
		req := httptest.NewRequest("POST", "http://panel.test/api/proxy/cutover/preview", strings.NewReader(body))
		req.Header.Set("Origin", "http://panel.test")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		req.AddCookie(admin)
		out := httptest.NewRecorder()
		s.handle(out, req)
		if out.Code != 400 {
			t.Fatalf("unsafe group accepted %d", out.Code)
		}
	}
	routes := make([]map[string]any, transport.MaxProxyCutoverListeners+1)
	for i := range routes {
		routes[i] = map[string]any{}
	}
	oversized := map[string]any{"service_id": "game", "targets": []map[string]any{{"component": "api", "upstream_port": 80, "private_port": 29080}}, "routes": routes}
	if response := request(t, s, "POST", "/api/proxy/cutover/preview", oversized, admin, csrf); response.Code != 400 {
		t.Fatal("listener budget accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("invalid selection reached privileged executor")
	}
}
