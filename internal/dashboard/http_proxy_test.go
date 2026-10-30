package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	proxyengine "github.com/ctf-service-manager/ctf-service-manager/internal/proxy"
	"github.com/ctf-service-manager/ctf-service-manager/internal/traffic"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func TestHTTPProxyRBACActorAndCSRF(t *testing.T) {
	s, _ := testServer(t)
	admin, acsrf, adminUser := loginAs(t, s, "admin")
	vuser := createAccount(t, s, admin, acsrf, "proxyviewer", RoleViewer)
	if r := request(t, s, "PATCH", "/api/users/"+vuser.ID, map[string]bool{"sensitive_access": true}, admin, acsrf); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	viewer, vcsrf, _ := loginAs(t, s, "proxyviewer")
	createAccount(t, s, admin, acsrf, "proxydefender", RoleDefender)
	defender, dcsrf, defenderUser := loginAs(t, s, "proxydefender")
	var calls atomic.Int32
	var actor atomic.Value
	isolatedStreamExecutor(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/proxy/preview" {
			var value transport.ProxyPreviewRequest
			if err := json.NewDecoder(r.Body).Decode(&value); err != nil {
				t.Error(err)
			}
			actor.Store(value.Initiator)
			_ = json.NewEncoder(w).Encode(transport.ProxyPreview{ProposalID: "proxy-plan", Digest: domain.Hash([]byte("plan"))})
			return
		}
		if r.URL.Path == "/v1/proxy/unban" {
			var value transport.ProxyUnbanRequest
			if err := json.NewDecoder(r.Body).Decode(&value); err != nil {
				t.Error(err)
			}
			actor.Store(value.Initiator)
			if value.IP != "192.0.2.10" || value.Comment != "Checker recovered" {
				t.Error("unban scope/comment changed")
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		t.Errorf("unexpected downstream call %s", r.URL.Path)
		_, _ = w.Write([]byte(`{}`))
	}))
	for _, test := range []struct{ method, path string }{
		{"GET", "/api/proxy/policy"}, {"GET", "/api/proxy/targets"}, {"POST", "/api/proxy/preview"},
		{"POST", "/api/proxy/confirm"}, {"POST", "/api/proxy/bans"}, {"POST", "/api/proxy/unban"},
	} {
		if r := request(t, s, test.method, test.path, map[string]any{}, viewer, vcsrf); r.Code != 403 {
			t.Fatalf("viewer %s %s: %d", test.method, test.path, r.Code)
		}
	}
	for _, path := range []string{"/api/proxy/policy", "/api/proxy/targets", "/api/proxy/preview", "/api/proxy/confirm", "/api/proxy/bans"} {
		method := "POST"
		if path == "/api/proxy/policy" || path == "/api/proxy/targets" {
			method = "GET"
		}
		if r := request(t, s, method, path, map[string]any{}, defender, dcsrf); r.Code != 403 {
			t.Fatalf("defender %s: %d", path, r.Code)
		}
	}
	if r := request(t, s, "POST", "/api/proxy/preview", map[string]any{"routes": []any{}}, admin, ""); r.Code != 403 {
		t.Fatal("CSRF bypass")
	}
	if calls.Load() != 0 {
		t.Fatal("forbidden request reached executor")
	}
	if r := request(t, s, "POST", "/api/proxy/preview", map[string]any{"expected_revision": 0, "routes": []any{}, "confirm_checker": false, "initiator": "forged-admin"}, admin, acsrf); r.Code != 400 {
		t.Fatal("browser actor field accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("forged actor reached executor")
	}
	if r := request(t, s, "POST", "/api/proxy/preview", map[string]any{"expected_revision": 0, "routes": []any{}, "confirm_checker": false}, admin, acsrf); r.Code != 200 {
		t.Fatalf("preview: %d %s", r.Code, r.Body.String())
	}
	if actor.Load() != domain.ID(adminUser.ID) {
		t.Fatal("preview actor not authenticated Admin")
	}
	if r := request(t, s, "POST", "/api/proxy/unban", map[string]any{"service_id": "game", "ip": "::ffff:192.0.2.10", "comment": "Checker recovered"}, defender, dcsrf); r.Code != 200 {
		t.Fatalf("unban: %d %s", r.Code, r.Body.String())
	}
	if actor.Load() != domain.ID(defenderUser.ID) || calls.Load() != 2 {
		t.Fatal("Defender actor not assigned by server")
	}
}

func TestHTTPProxyStrictQueriesAndInputsNeverReachExecutor(t *testing.T) {
	s, _ := testServer(t)
	admin, csrf, _ := loginAs(t, s, "admin")
	var calls atomic.Int32
	isolatedStreamExecutor(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = w.Write([]byte(`{}`)) }))
	for _, path := range []string{"/api/proxy/status?upstream=http://evil/", "/api/traffic?method=GET&method=POST", "/api/traffic?limit=0", "/api/traffic?url=%zz", "/api/traffic?url=a;b", "/api/traffic?unknown=1", "/api/traffic/request-test?raw=true", "/api/traffic/request%2Fother"} {
		if r := request(t, s, "GET", path, nil, admin, ""); r.Code != 400 {
			t.Fatalf("query/path %s: %d", path, r.Code)
		}
	}
	for _, body := range []string{`{"routes":[],"routes":[]}`, `{"routes":[{"id":"r","capture":{"mode":"metadata","mode":"bounded_body"}}]}`, `{"routes":[],"initiator":"forged"}`, `{"routes":[],"upstream":"http://evil/"}`, `null`, `{} {}`} {
		r := httptest.NewRequest("POST", "http://panel.test/api/proxy/preview", strings.NewReader(body))
		r.Header.Set("Origin", "http://panel.test")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		r.AddCookie(admin)
		w := httptest.NewRecorder()
		s.handle(w, r)
		if w.Code != 400 {
			t.Fatalf("invalid JSON accepted: %d %s", w.Code, body)
		}
	}
	r := httptest.NewRequest("POST", "http://panel.test/api/proxy/preview", strings.NewReader(`{"routes":[],"padding":"`+strings.Repeat("x", 256*1024)+`"}`))
	r.Header.Set("Origin", "http://panel.test")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	r.AddCookie(admin)
	w := httptest.NewRecorder()
	s.handle(w, r)
	if w.Code != 413 {
		t.Fatalf("unbounded policy body: %d", w.Code)
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request reached executor")
	}
}

func TestTrafficMetadataAndSensitiveAccessBoundary(t *testing.T) {
	s, _ := testServer(t)
	admin, csrf, _ := loginAs(t, s, "admin")
	createAccount(t, s, admin, csrf, "trafficviewer", RoleViewer)
	viewer, _, _ := loginAs(t, s, "trafficviewer")
	var calls atomic.Int32
	isolatedStreamExecutor(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/v1/traffic" {
			t.Error("payload requested by Viewer")
		}
		q, err := traffic.ParseRawQuery(r.URL.RawQuery)
		if err != nil || len(q.ServiceIDs) != 2 || q.Status != "4xx" {
			t.Error("typed metadata filters lost")
		}
		_ = json.NewEncoder(w).Encode(traffic.Page{Records: []traffic.Metadata{{RequestID: "record-1", State: "completed", Method: "GET", URL: "/safe", WAFDecision: "allowed"}}})
	}))
	if r := request(t, s, "GET", "/api/traffic?service_id=game-a&service_id=game-b&status=4xx", nil, viewer, ""); r.Code != 200 || !strings.Contains(r.Body.String(), "record-1") {
		t.Fatalf("metadata unavailable: %d %s", r.Code, r.Body.String())
	}
	if r := request(t, s, "GET", "/api/traffic/record-1", nil, viewer, ""); r.Code != 403 {
		t.Fatal("sensitive detail granted to ordinary Viewer")
	}
	if calls.Load() != 1 {
		t.Fatal("forbidden payload reached executor")
	}
}

func TestTrafficDetailRevokedDuringRoundTripIsDiscarded(t *testing.T) {
	for _, scenario := range []string{"sensitive", "role", "disabled", "session"} {
		t.Run(scenario, func(t *testing.T) {
			s, _ := testServer(t)
			admin, csrf, _ := loginAs(t, s, "admin")
			user := createAccount(t, s, admin, csrf, "captureuser", RoleDefender)
			if r := request(t, s, "PATCH", "/api/users/"+user.ID, map[string]bool{"sensitive_access": true}, admin, csrf); r.Code != 200 {
				t.Fatal(r.Body.String())
			}
			cookie, _, _ := loginAs(t, s, "captureuser")
			entered, release := make(chan struct{}), make(chan struct{})
			const secret = "PRIVATE-CAPTURE-MUST-NOT-BE-PUBLISHED"
			isolatedStreamExecutor(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/traffic/record-1" {
					t.Error("unexpected private endpoint")
				}
				close(entered)
				<-release
				_ = json.NewEncoder(w).Encode(traffic.Exchange{Metadata: traffic.Metadata{RequestID: "record-1", State: "completed"}, RequestHeaders: http.Header{"Authorization": {secret}}, RequestBody: traffic.Body{Encoding: "utf8", Data: secret}})
			}))
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- request(t, s, "GET", "/api/traffic/record-1", nil, cookie, "") }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("private RPC not reached")
			}
			switch scenario {
			case "sensitive":
				if _, err := s.db.Exec("UPDATE users SET sensitive_access=0 WHERE id=?", user.ID); err != nil {
					t.Fatal(err)
				}
			case "role":
				if _, err := s.db.Exec("UPDATE users SET role=? WHERE id=?", RoleViewer, user.ID); err != nil {
					t.Fatal(err)
				}
			case "disabled":
				if _, err := s.db.Exec("UPDATE users SET disabled=1 WHERE id=?", user.ID); err != nil {
					t.Fatal(err)
				}
			case "session":
				if _, err := s.db.Exec("DELETE FROM sessions WHERE user_id=?", user.ID); err != nil {
					t.Fatal(err)
				}
			}
			close(release)
			select {
			case result := <-done:
				if result.Code != 401 && result.Code != 403 {
					t.Fatalf("revocation ignored: %d", result.Code)
				}
				if strings.Contains(result.Body.String(), secret) {
					t.Fatal("pending private data escaped after revocation")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("revoked request did not finish")
			}
			rows, err := s.db.Query("SELECT action,target,result FROM audit")
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			for rows.Next() {
				var action, target, result string
				if err := rows.Scan(&action, &target, &result); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(action+target+result, secret) {
					t.Fatal("capture bytes entered audit")
				}
			}
		})
	}
}

func TestProxyMutationRequiresAuditBeforeRPC(t *testing.T) {
	s, _ := testServer(t)
	admin, csrf, _ := loginAs(t, s, "admin")
	var calls atomic.Int32
	isolatedStreamExecutor(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}))
	if _, err := s.db.ExecContext(context.Background(), "DROP TABLE audit"); err != nil {
		t.Fatal(err)
	}
	if r := request(t, s, "POST", "/api/proxy/preview", map[string]any{"routes": []any{}}, admin, csrf); r.Code != 500 {
		t.Fatal("missing audit did not fail closed")
	}
	if calls.Load() != 0 {
		t.Fatal("unaudited policy operation reached executor")
	}
}

func TestProxyPrivatePolicyRoleRevokedDuringReadIsDiscarded(t *testing.T) {
	s, _ := testServer(t)
	admin, csrf, _ := loginAs(t, s, "admin")
	user := createAccount(t, s, admin, csrf, "policyreader", RoleAdmin)
	cookie, _, _ := loginAs(t, s, "policyreader")
	entered, release := make(chan struct{}), make(chan struct{})
	const privatePattern = "PRIVATE-POLICY-REDACTION-PATTERN"
	isolatedStreamExecutor(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_ = json.NewEncoder(w).Encode(transport.ProxyPolicyView{Policy: proxyengine.Policy{Routes: []proxyengine.Route{{Capture: proxyengine.CapturePolicy{BodyPatterns: []string{privatePattern}}}}}})
	}))
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- request(t, s, "GET", "/api/proxy/policy", nil, cookie, "") }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("policy RPC not reached")
	}
	if _, err := s.db.Exec("UPDATE users SET role=? WHERE id=?", RoleViewer, user.ID); err != nil {
		t.Fatal(err)
	}
	close(release)
	select {
	case result := <-done:
		if result.Code != 403 || strings.Contains(result.Body.String(), privatePattern) {
			t.Fatal("pending private policy escaped after Admin demotion")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("revoked policy read did not finish")
	}
}

func TestTrafficPrivateBytesWithheldWhenCompletionAuditFails(t *testing.T) {
	s, _ := testServer(t)
	admin, _, _ := loginAs(t, s, "admin")
	const privateBody = "PRIVATE-BODY-AUDIT-FAILURE"
	isolatedStreamExecutor(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := s.db.Exec("DROP TABLE audit"); err != nil {
			t.Error(err)
		}
		_ = json.NewEncoder(w).Encode(traffic.Exchange{Metadata: traffic.Metadata{RequestID: "record-1"}, ResponseBody: traffic.Body{Encoding: "utf8", Data: privateBody}})
	}))
	result := request(t, s, "GET", "/api/traffic/record-1", nil, admin, "")
	if result.Code != 502 || strings.Contains(result.Body.String(), privateBody) {
		t.Fatal("capture published without its completion audit")
	}
}
