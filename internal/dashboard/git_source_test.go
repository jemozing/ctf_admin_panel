package dashboard

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func TestGitSourceAdminOnlyCSRFAndNoCredentialAudit(t *testing.T) {
	s, _ := testServer(t)
	directory, err := os.MkdirTemp("/tmp", "ctfm-git-api-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	socket := filepath.Join(directory, "executor.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var writes atomic.Int32
	const privateToken = "SECRET_GIT_TOKEN_57db4f"
	executor := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/services/game/source" {
			http.NotFound(w, r)
			return
		}
		if r.Method == "POST" {
			var input transport.GitSourceRequest
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			if input.Token != privateToken {
				t.Error("write-only token lost before executor")
			}
			writes.Add(1)
		}
		json.NewEncoder(w).Encode(transport.GitSourceView{Configured: true, URL: "https://github.com/SibirCTF/ncdex.git", Ref: "HEAD", Revision: 1, HasCredentials: true})
	})}
	go executor.Serve(listener)
	t.Cleanup(func() { executor.Close() })
	client, err := transport.NewClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	s.executor.Close()
	s.executor = client
	admin, csrf, _ := loginAs(t, s, "admin")
	input := map[string]string{"url": "https://github.com/SibirCTF/ncdex.git", "ref": "HEAD", "token": privateToken}
	for _, role := range []Role{RoleViewer, RoleDefender} {
		createAccount(t, s, admin, csrf, string(role), role)
		cookie, token, _ := loginAs(t, s, string(role))
		if response := request(t, s, "POST", "/api/services/game/source", input, cookie, token); response.Code != 403 {
			t.Fatalf("%s saved Git config: %d", role, response.Code)
		}
		if response := request(t, s, "GET", "/api/services/game/source", nil, cookie, ""); response.Code != 200 || strings.Contains(response.Body.String(), privateToken) {
			t.Fatalf("source view: %d %s", response.Code, response.Body.String())
		}
	}
	if response := request(t, s, "POST", "/api/services/game/source", input, admin, ""); response.Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	if response := request(t, s, "POST", "/api/services/game/source", input, admin, csrf); response.Code != 200 || strings.Contains(response.Body.String(), privateToken) {
		t.Fatalf("admin source save: %d %s", response.Code, response.Body.String())
	}
	if writes.Load() != 1 {
		t.Fatal("unauthorized request reached executor")
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
		if strings.Contains(action+target+result, privateToken) {
			t.Fatal("token leaked to audit")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}
