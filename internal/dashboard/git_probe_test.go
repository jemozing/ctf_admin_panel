package dashboard

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/sourcegit"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func gitProbeAPIFixture(t *testing.T, handler http.HandlerFunc) *Server {
	t.Helper()
	s, _ := testServer(t)
	directory, err := os.MkdirTemp("/tmp", "ctfm-probe-api-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	socket := filepath.Join(directory, "executor.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	executor := &http.Server{Handler: handler}
	go executor.Serve(listener)
	t.Cleanup(func() { executor.Close() })
	client, err := transport.NewClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	s.executor.Close()
	s.executor = client
	return s
}

func TestGitProbeAdminCSRFStrictInputAndNoCredentialAudit(t *testing.T) {
	var calls atomic.Int32
	const secret = "fixture-probe-token-never-return"
	s := gitProbeAPIFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/git/probe" || r.Method != "POST" {
			t.Error("wrong executor endpoint")
		}
		var input transport.GitProbeRequest
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.Source.Token != secret || input.ServiceID != "" {
			t.Error("draft probe credentials lost or service ID invented")
		}
		calls.Add(1)
		json.NewEncoder(w).Encode(transport.GitProbeResult{Branches: []sourcegit.RemoteRef{{Name: "main", Ref: "refs/heads/main", Commit: strings.Repeat("a", 40)}}, SelectedRef: "HEAD", RefStatus: "available"})
	})
	admin, csrf, _ := loginAs(t, s, "admin")
	input := map[string]any{"source": map[string]string{"url": "https://github.com/example/service.git", "ref": "HEAD", "token": secret}}
	for _, role := range []Role{RoleViewer, RoleDefender} {
		createAccount(t, s, admin, csrf, string(role), role)
		cookie, token, _ := loginAs(t, s, string(role))
		if response := request(t, s, "POST", "/api/git/probe", input, cookie, token); response.Code != 403 {
			t.Fatalf("%s may probe private refs: %d", role, response.Code)
		}
	}
	for _, tc := range []struct {
		method, path string
		body         any
		cookie       *http.Cookie
		token        string
		status       int
	}{
		{"POST", "/api/git/probe", input, nil, "", 401},
		{"POST", "/api/git/probe", input, admin, "", 403},
		{"GET", "/api/git/probe", nil, admin, csrf, 405},
		{"POST", "/api/git/probe?url=/etc", input, admin, csrf, 400},
		{"POST", "/api/git/probe", map[string]any{"source": input["source"], "initiator": "forged"}, admin, csrf, 400},
		{"POST", "/api/git/probe", map[string]any{"Source": input["source"]}, admin, csrf, 400},
	} {
		if response := request(t, s, tc.method, tc.path, tc.body, tc.cookie, tc.token); response.Code != tc.status {
			t.Errorf("%s %s: got %d want %d", tc.method, tc.path, response.Code, tc.status)
		}
	}
	response := request(t, s, "POST", "/api/git/probe", input, admin, csrf)
	if response.Code != 200 || strings.Contains(response.Body.String(), secret) || !strings.Contains(response.Body.String(), "refs/heads/main") {
		t.Fatalf("Admin probe: %d %s", response.Code, response.Body.String())
	}
	if calls.Load() != 1 {
		t.Fatal("denied probe reached executor")
	}
	var audit string
	if err := s.db.QueryRow("SELECT COALESCE(group_concat(action || target || result || operation_id), '') FROM audit").Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(audit, secret) || strings.Contains(audit, "https://github.com/example/service.git") || !strings.Contains(audit, "source.probe") {
		t.Fatal("audit absent or contains credentials / submitted URL")
	}
}

func TestGitProbeAccessOrAuditFailureDuringRPCWithholdsPrivateBranches(t *testing.T) {
	for _, mode := range []string{"logout", "demote", "audit-failure"} {
		t.Run(mode, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			s := gitProbeAPIFixture(t, func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				<-release
				json.NewEncoder(w).Encode(transport.GitProbeResult{Branches: []sourcegit.RemoteRef{{Name: "private-branch"}}, RefStatus: "available"})
			})
			admin, csrf, user := loginAs(t, s, "admin")
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				done <- request(t, s, "POST", "/api/git/probe", map[string]any{"source": map[string]string{"url": "https://github.com/example/service.git", "ref": "HEAD"}}, admin, csrf)
			}()
			<-entered
			var err error
			if mode == "logout" {
				_, err = s.db.Exec("DELETE FROM sessions WHERE user_id=?", user.ID)
			} else if mode == "demote" {
				_, err = s.db.Exec("UPDATE users SET role='viewer' WHERE id=?", user.ID)
			} else {
				_, err = s.db.Exec("DROP TABLE audit")
			}
			close(release)
			if err != nil {
				t.Fatal(err)
			}
			response := <-done
			want := 401
			if mode == "demote" {
				want = 403
			} else if mode == "audit-failure" {
				want = 500
			}
			if response.Code != want || strings.Contains(response.Body.String(), "private-branch") {
				t.Fatalf("private refs released after %s: %d %s", mode, response.Code, response.Body.String())
			}
		})
	}
}
