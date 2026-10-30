package dashboard

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func isolatedStreamExecutor(t *testing.T, s *Server, handler http.Handler) {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "ctfm-stream-api-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	socket := filepath.Join(root, "executor.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	backend := &http.Server{Handler: handler}
	go backend.Serve(listener)
	t.Cleanup(func() { backend.Close() })
	client, err := transport.NewClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	s.executor.Close()
	s.executor = client
}
func streamHTTPServer(t *testing.T, s *Server, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	s.hosts[server.Listener.Addr().String()] = true
	server.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateNew {
			if tcp, ok := conn.(*net.TCPConn); ok {
				_ = tcp.SetWriteBuffer(1024)
			}
		}
	}
	server.Start()
	t.Cleanup(server.Close)
	return server
}
func dialLogStream(t *testing.T, server *httptest.Server, cookie *http.Cookie, query string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/api/stream?format=records&service_id=game&component=app&"+query, &websocket.DialOptions{HTTPHeader: http.Header{"Origin": []string{server.URL}, "Cookie": []string{cookie.String()}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.CloseNow() })
	return conn
}

func TestViewerAllMutationsBlockedAndDefenderIdentityCannotBeSpoofed(t *testing.T) {
	s, _ := testServer(t)
	admin, csrf, _ := loginAs(t, s, "admin")
	viewerUser := createAccount(t, s, admin, csrf, "matrixviewer", RoleViewer)
	if r := request(t, s, "PATCH", "/api/users/"+viewerUser.ID, map[string]bool{"sensitive_access": true}, admin, csrf); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	viewer, vcsrf, _ := loginAs(t, s, "matrixviewer")
	createAccount(t, s, admin, csrf, "matrixdefender", RoleDefender)
	defender, dcsrf, defenderUser := loginAs(t, s, "matrixdefender")
	var mutations atomic.Int32
	var actor atomic.Value
	isolatedStreamExecutor(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected RPC %s", r.URL.Path)
		}
		mutations.Add(1)
		var input transport.SubmitRequest
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Error(err)
		}
		actor.Store(input.Initiator)
		json.NewEncoder(w).Encode(domain.Operation{Spec: domain.OperationSpec{ID: "op-accepted"}})
	}))
	for _, action := range []string{"start", "stop", "restart", "prepare", "fetch_source", "build", "deploy", "snapshot", "restore_snapshot", "rollback", "recover"} {
		input := map[string]any{"service_id": "game", "action": action, "idempotency_key": "viewer-" + action, "release_id": "release-test", "snapshot_id": "snapshot-test", "recovery_operation_id": "op-previous"}
		for _, endpoint := range []string{"/api/operations", "/api/preview"} {
			if r := request(t, s, "POST", endpoint, input, viewer, vcsrf); r.Code != 403 {
				t.Fatalf("Viewer action %s through %s accepted: %d", action, endpoint, r.Code)
			}
		}
	}
	if r := request(t, s, "POST", "/api/operations/op-other/cancel", map[string]any{}, viewer, vcsrf); r.Code != 403 {
		t.Fatal("Viewer cancelled operation")
	}
	if mutations.Load() != 0 {
		t.Fatal("forbidden Viewer request reached executor")
	}
	input := map[string]any{"service_id": "game", "action": "start", "idempotency_key": "defender-start", "initiator": "forged-admin", "plan_digest": domain.Hash([]byte("reviewed"))}
	if r := request(t, s, "POST", "/api/operations", input, defender, dcsrf); r.Code != 202 {
		t.Fatalf("Defender authorized action denied: %d %s", r.Code, r.Body.String())
	}
	if actor.Load() != domain.ID(defenderUser.ID) || mutations.Load() != 1 {
		t.Fatal("browser spoofed privileged initiator")
	}
	input["action"] = "deploy"
	input["release_id"] = "release-test"
	input["accept_file_drift"] = true
	if r := request(t, s, "POST", "/api/operations", input, defender, dcsrf); r.Code != 403 || mutations.Load() != 1 {
		t.Fatal("Defender without file access accepted hidden drift")
	}
}

func TestLiveLogRevocationDuringExecutorRoundTripDiscardsPendingPrivateFrame(t *testing.T) {
	s, _ := testServer(t)
	admin, csrf, _ := loginAs(t, s, "admin")
	user := createAccount(t, s, admin, csrf, "livereader", RoleDefender)
	var mu sync.Mutex
	var entered, release chan struct{}
	var calls atomic.Int32
	isolatedStreamExecutor(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/operations" {
			w.Write([]byte(`[]`))
			return
		}
		if r.URL.Path != "/v1/services/game/log-records" {
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		mu.Lock()
		in, proceed := entered, release
		mu.Unlock()
		in <- struct{}{}
		select {
		case <-proceed:
		case <-r.Context().Done():
			return
		}
		json.NewEncoder(w).Encode(transport.LogPage{Records: []transport.LogRecord{{ID: "private-record", Text: "MUST-NOT-LEAK-AFTER-REVOCATION"}}, Sources: []transport.LogSource{}})
	}))
	server := streamHTTPServer(t, s, http.HandlerFunc(s.handle))
	for _, test := range []struct {
		name     string
		patch    map[string]any
		explicit bool
	}{{"sensitive permission removed", map[string]any{"sensitive_access": false}, false}, {"role reduced", map[string]any{"role": "viewer"}, false}, {"account disabled", map[string]any{"disabled": true}, false}, {"sessions revoked", nil, true}} {
		t.Run(test.name, func(t *testing.T) {
			if r := request(t, s, "PATCH", "/api/users/"+user.ID, map[string]any{"role": "defender", "disabled": false, "sensitive_access": true}, admin, csrf); r.Code != 200 {
				t.Fatal(r.Body.String())
			}
			cookie, _, _ := loginAs(t, s, "livereader")
			mu.Lock()
			entered, release = make(chan struct{}, 1), make(chan struct{})
			in, proceed := entered, release
			mu.Unlock()
			conn := dialLogStream(t, server, cookie, "tail=1")
			select {
			case <-in:
			case <-time.After(5 * time.Second):
				t.Fatal("log RPC did not start")
			}
			var response *httptest.ResponseRecorder
			if test.explicit {
				response = request(t, s, "POST", "/api/users/"+user.ID+"/revoke-sessions", map[string]any{}, admin, csrf)
			} else {
				response = request(t, s, "PATCH", "/api/users/"+user.ID, test.patch, admin, csrf)
			}
			if response.Code != 200 {
				t.Fatal(response.Body.String())
			}
			close(proceed)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			_, body, err := conn.Read(ctx)
			if err == nil || strings.Contains(string(body), "MUST-NOT-LEAK") {
				t.Fatalf("revoked stream received pending private data: %s %v", body, err)
			}
			if response = request(t, s, "GET", "/api/auth/session", nil, cookie, ""); response.Code != 401 {
				t.Fatal("old session survived permission mutation")
			}
			conn.CloseNow()
		})
	}
	if calls.Load() != 4 {
		t.Fatalf("unexpected stream read count %d", calls.Load())
	}
}

func TestSlowLogClientIsDisconnectedWithoutBlockingOtherViewers(t *testing.T) {
	s, _ := testServer(t)
	admin, _, _ := loginAs(t, s, "admin")
	entered := make(chan struct{}, 1)
	finished := make(chan struct{})
	var slowReads atomic.Int32
	isolatedStreamExecutor(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/operations":
			w.Write([]byte(`[]`))
		case "/v1/health":
			w.Write([]byte(`{"status":"ok","schema_version":1}`))
		case "/v1/services/game/log-records":
			text := "fast-observation"
			if r.URL.Query().Get("tail") == "500" {
				slowReads.Add(1)
				select {
				case entered <- struct{}{}:
				default:
				}
				text = strings.Repeat("x", 512<<10)
			}
			json.NewEncoder(w).Encode(transport.LogPage{Records: []transport.LogRecord{{ID: "record", Text: text}}, Sources: []transport.LogSource{}})
		default:
			http.NotFound(w, r)
		}
	}))
	server := streamHTTPServer(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/stream" && r.URL.Query().Get("tail") == "500" {
			defer close(finished)
		}
		s.handle(w, r)
	}))
	// A tiny receiver window makes the test exercise the server's write timeout,
	// independent of the host's default TCP buffers. The client never reads data.
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err == nil {
			if tcp, ok := conn.(*net.TCPConn); ok {
				_ = tcp.SetReadBuffer(1024)
			}
		}
		return conn, err
	}}}
	slow, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/api/stream?format=records&service_id=game&component=app&tail=500", &websocket.DialOptions{HTTPClient: client, HTTPHeader: http.Header{"Origin": []string{server.URL}, "Cookie": []string{admin.String()}}})
	if err != nil {
		t.Fatal(err)
	}
	defer slow.CloseNow()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("slow reader did not enter bounded log request")
	}
	fast := dialLogStream(t, server, admin, "tail=1")
	readCtx, readCancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer readCancel()
	_, body, err := fast.Read(readCtx)
	if err != nil || !strings.Contains(string(body), "fast-observation") {
		t.Fatalf("slow client blocked independent viewer: %v", err)
	}
	fast.CloseNow()
	select {
	case <-finished:
	case <-time.After(8 * time.Second):
		t.Fatal("slow WebSocket did not release handler after bounded write deadline")
	}
	if slowReads.Load() != 1 {
		t.Fatalf("backpressure repeatedly queried executor: %d", slowReads.Load())
	}
}
