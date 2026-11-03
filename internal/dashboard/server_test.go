package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

const testPassword = "a-correct-test-password-123"

func testServer(t *testing.T) (*Server, *atomic.Int32) {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "ctf-web-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	socket := filepath.Join(directory, "executor.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var submits atomic.Int32
	executor := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/health":
			w.Write([]byte(`{"status":"ok","schema_version":1}`))
		case "/v1/services", "/v1/operations":
			if r.Method == http.MethodPost {
				submits.Add(1)
				w.WriteHeader(501)
				w.Write([]byte(`{"code":"not_implemented","message":"disabled"}`))
			} else {
				w.Write([]byte(`[]`))
			}
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{"code":"not_found","message":"missing"}`))
		}
	})}
	go executor.Serve(listener)
	t.Cleanup(func() { executor.Close() })
	s, err := Open(Config{StateDirectory: filepath.Join(directory, "state"), ExecutorSocket: socket, AllowedHosts: []string{"panel.test"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err = s.CreateAdmin(context.Background(), "admin", testPassword); err != nil {
		t.Fatal(err)
	}
	return s, &submits
}

func request(t *testing.T, s *Server, method, path string, body any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, "http://panel.test"+path, bytes.NewReader(payload))
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Origin", "http://panel.test")
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	w := httptest.NewRecorder()
	s.handle(w, r)
	return w
}

func loginAs(t *testing.T, s *Server, username string) (*http.Cookie, string, User) {
	t.Helper()
	response := request(t, s, "POST", "/api/auth/login", map[string]string{"username": username, "password": testPassword}, nil, "")
	if response.Code != 200 {
		t.Fatalf("login: %d %s", response.Code, response.Body.String())
	}
	var result struct {
		User User   `json:"user"`
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("missing session cookie")
	}
	return cookies[0], result.CSRF, result.User
}

func createAccount(t *testing.T, s *Server, admin *http.Cookie, csrf, username string, role Role) User {
	t.Helper()
	response := request(t, s, "POST", "/api/users", map[string]any{"username": username, "password": testPassword, "role": role, "sensitive_access": false}, admin, csrf)
	if response.Code != 201 {
		t.Fatalf("create user: %d %s", response.Code, response.Body.String())
	}
	var u User
	if err := json.Unmarshal(response.Body.Bytes(), &u); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestBootstrapPasswordsAndSessionStorage(t *testing.T) {
	s, _ := testServer(t)
	if err := s.CreateAdmin(context.Background(), "other", testPassword); err == nil {
		t.Fatal("bootstrap replaced existing account")
	}
	cookie, csrf, user := loginAs(t, s, "admin")
	if err := domain.ID(user.ID).Validate(); err != nil {
		t.Fatal(err)
	}
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.MaxAge < 28000 {
		t.Fatalf("unsafe cookie: %+v", cookie)
	}
	if len(csrf) != 43 || cookie.Value == csrf {
		t.Fatal("CSRF is missing or equals authentication token")
	}
	var passwordHash, storedToken string
	if err := s.db.QueryRow("SELECT password_hash FROM users").Scan(&passwordHash); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(passwordHash, "$argon2id$") || strings.Contains(passwordHash, testPassword) {
		t.Fatal("password not hashed")
	}
	if err := s.db.QueryRow("SELECT token_hash FROM sessions").Scan(&storedToken); err != nil {
		t.Fatal(err)
	}
	if storedToken == cookie.Value || storedToken != tokenHash(cookie.Value) {
		t.Fatal("raw session token persisted")
	}
	// Metadata access by bootstrap/maintenance helpers leaves live sessions valid.
	other, err := Open(s.config)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if response := request(t, s, "GET", "/api/auth/session", nil, cookie, ""); response.Code != 200 {
		t.Fatal("opening metadata revoked a live session")
	}
	response := request(t, s, "POST", "/api/auth/logout", map[string]any{}, cookie, csrf)
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	if response = request(t, s, "GET", "/api/auth/session", nil, cookie, ""); response.Code != 401 {
		t.Fatal("logout did not revoke session")
	}
}

func TestOriginHostCSRFAndViewerCannotSubmit(t *testing.T) {
	s, submits := testServer(t)
	admin, csrf, _ := loginAs(t, s, "admin")
	createAccount(t, s, admin, csrf, "viewer", RoleViewer)
	viewer, vcsrf, _ := loginAs(t, s, "viewer")
	input := map[string]any{"service_id": "example", "action": "start", "idempotency_key": "test-start"}
	if response := request(t, s, "POST", "/api/operations", input, viewer, vcsrf); response.Code != 403 {
		t.Fatalf("Viewer submitted operation: %d", response.Code)
	}
	if response := request(t, s, "POST", "/api/operations", input, admin, ""); response.Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	if response := request(t, s, "GET", "/api/users", nil, viewer, ""); response.Code != 403 {
		t.Fatal("Viewer read users")
	}
	for _, test := range []struct{ host, origin string }{{"evil.test", "http://evil.test"}, {"panel.test", "http://evil.test"}, {"panel.test", "https://panel.test"}, {"panel.test", "null"}, {"panel.test", ""}} {
		r := httptest.NewRequest("POST", "http://"+test.host+"/api/auth/login", strings.NewReader(`{"username":"admin","password":"`+testPassword+`"}`))
		r.Header.Set("Content-Type", "application/json")
		if test.origin != "" {
			r.Header.Set("Origin", test.origin)
		}
		w := httptest.NewRecorder()
		s.handle(w, r)
		if w.Code != 403 {
			t.Fatalf("host=%q origin=%q accepted: %d", test.host, test.origin, w.Code)
		}
	}
	if submits.Load() != 0 {
		t.Fatal("forbidden request reached executor")
	}
	if response := request(t, s, "GET", "/api/services/example/logs?component=app&tail=10", nil, viewer, ""); response.Code != 403 {
		t.Fatal("Viewer accessed sensitive logs")
	}
	if response := request(t, s, "POST", "/api/operations", input, admin, csrf); response.Code != 501 || submits.Load() != 1 {
		t.Fatalf("authorized request did not reach fixed executor endpoint: %d %s", response.Code, response.Body.String())
	}
}

func TestUserRoleChangeRevokesSessionsAndProtectsLastAdmin(t *testing.T) {
	s, _ := testServer(t)
	admin, csrf, adminUser := loginAs(t, s, "admin")
	response := request(t, s, "PATCH", "/api/users/"+adminUser.ID, map[string]any{"disabled": true}, admin, csrf)
	if response.Code != 409 {
		t.Fatalf("last admin disabled: %d", response.Code)
	}
	u := createAccount(t, s, admin, csrf, "defender", RoleDefender)
	defender, _, _ := loginAs(t, s, "defender")
	response = request(t, s, "PATCH", "/api/users/"+u.ID, map[string]any{"role": "viewer"}, admin, csrf)
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	if response = request(t, s, "GET", "/api/auth/session", nil, defender, ""); response.Code != 401 {
		t.Fatal("role change did not revoke session")
	}
	defender, _, _ = loginAs(t, s, "defender")
	response = request(t, s, "POST", "/api/users/"+u.ID+"/revoke-sessions", map[string]any{}, admin, csrf)
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	if response = request(t, s, "GET", "/api/auth/session", nil, defender, ""); response.Code != 401 {
		t.Fatal("explicit revocation failed")
	}
	if response = request(t, s, "GET", "/api/audit", nil, admin, ""); strings.Contains(response.Body.String(), testPassword) || strings.Contains(response.Body.String(), cookieToken(admin)) {
		t.Fatal("secret leaked to audit")
	}
}

func cookieToken(cookie *http.Cookie) string { return cookie.Value }

func TestLoginRateLimit(t *testing.T) {
	s, _ := testServer(t)
	for attempt := 0; attempt < 6; attempt++ {
		response := request(t, s, "POST", "/api/auth/login", map[string]string{"username": "missing", "password": "wrong-password"}, nil, "")
		want := 401
		if attempt == 5 {
			want = 429
		}
		if response.Code != want {
			t.Fatalf("attempt %d: got %d expected %d", attempt, response.Code, want)
		}
	}
}

func TestWebSocketOriginAndLiveSessionRevocation(t *testing.T) {
	s, _ := testServer(t)
	admin, csrf, _ := loginAs(t, s, "admin")
	u := createAccount(t, s, admin, csrf, "watcher", RoleViewer)
	cookie, _, _ := loginAs(t, s, "watcher")
	server := httptest.NewUnstartedServer(http.HandlerFunc(s.handle))
	host := server.Listener.Addr().String()
	s.hosts[host] = true
	server.Start()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	url := "ws://" + host + "/api/stream"
	headers := http.Header{"Origin": []string{"http://evil.test"}, "Cookie": []string{cookie.String()}}
	if connection, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: headers}); err == nil {
		connection.CloseNow()
		t.Fatal("cross-origin WebSocket accepted")
	}
	headers.Set("Origin", "http://"+host)
	connection, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	if _, _, err = connection.Read(ctx); err != nil {
		t.Fatal(err)
	}
	response := request(t, s, "PATCH", "/api/users/"+u.ID, map[string]bool{"disabled": true}, admin, csrf)
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	if _, _, err = connection.Read(ctx); err == nil {
		t.Fatal("revoked session still received live data")
	}
	if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("unexpected close after revocation: %v", err)
	}
}

func TestServeRestartInvalidatesSessions(t *testing.T) {
	s, _ := testServer(t)
	cookie, _, _ := loginAs(t, s, "admin")
	s.config.Listen = "127.0.0.1:0"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- s.Serve(ctx) }()
	for deadline := time.Now().Add(2 * time.Second); ; {
		var count int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Serve did not invalidate sessions")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if _, err := s.getSession(context.Background(), cookie.Value); err == nil {
		t.Fatal("serving a restarted process retained old session")
	}
}

func TestComposeRevisionPreparationAndSwitchRequireAdmin(t *testing.T) {
	s, _ := testServer(t)
	admin, csrf, _ := loginAs(t, s, "admin")
	createAccount(t, s, admin, csrf, "compose-defender", RoleDefender)
	defender, token, _ := loginAs(t, s, "compose-defender")
	for _, endpoint := range []string{"/api/preview", "/api/operations"} {
		for _, body := range []map[string]any{
			{"action": "prepare_compose", "compose_from_git": true},
			{"action": "deploy", "release_id": "release-new", "confirm_compose_change": true},
			{"action": "rollback", "release_id": "release-old", "confirm_compose_change": true},
		} {
			body["service_id"] = "service-test"
			body["idempotency_key"] = "compose-admin-only"
			res := request(t, s, "POST", endpoint, body, defender, token)
			if res.Code != http.StatusForbidden {
				t.Fatalf("%s accepted %s for Defender: %d %s", endpoint, body["action"], res.Code, res.Body)
			}
		}
	}
}
