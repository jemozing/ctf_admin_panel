package dashboard

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func TestRegistrationAdminOnlyCSRFAndServerAssignedActor(t *testing.T) {
	s, _ := testServer(t)
	directory, err := os.MkdirTemp("/tmp", "ctfm-registration-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	socket := filepath.Join(directory, "executor.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	actors := make(chan domain.ID, 4)
	executor := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/registration/options":
			json.NewEncoder(w).Encode(transport.RegistrationOptions{DiscoveryRoots: []string{"/srv/game"}, WorkspaceRoots: []string{"/srv/workspaces"}})
		case "/v1/registration/proposals":
			var input transport.RegistrationProposalRequest
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			actors <- input.Initiator
			w.Write([]byte(`{"id":"proposal-test","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","service":{"id":"draft-test"}}`))
		case "/v1/registration/approve":
			var input transport.RegistrationApproveRequest
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			actors <- input.Initiator
			w.Write([]byte(`{"service":{"id":"draft-test"},"initialized":true}`))
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{"code":"not_found","message":"missing"}`))
		}
	})}
	go executor.Serve(listener)
	t.Cleanup(func() { executor.Close() })
	client, err := transport.NewClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	s.executor.Close()
	s.executor = client
	admin, csrf, adminUser := loginAs(t, s, "admin")
	for _, role := range []Role{RoleViewer, RoleDefender} {
		username := string(role)
		createAccount(t, s, admin, csrf, username, role)
		cookie, token, _ := loginAs(t, s, username)
		for _, path := range []string{"options", "inspect", "proposals", "approve"} {
			method := "POST"
			var body any = map[string]any{}
			if path == "options" {
				method = "GET"
				body = nil
			}
			response := request(t, s, method, "/api/registration/"+path, body, cookie, token)
			if response.Code != 403 {
				t.Fatalf("%s can access %s: %d %s", role, path, response.Code, response.Body.String())
			}
		}
	}
	if response := request(t, s, "GET", "/api/registration/options", nil, nil, ""); response.Code != 401 {
		t.Fatalf("anonymous discovery: %d", response.Code)
	}
	if response := request(t, s, "GET", "/api/registration/options", nil, admin, ""); response.Code != 200 {
		t.Fatalf("admin discovery: %d %s", response.Code, response.Body.String())
	}
	input := map[string]any{"service": map[string]string{"id": "draft-test"}}
	if response := request(t, s, "POST", "/api/registration/proposals", input, admin, ""); response.Code != 403 {
		t.Fatalf("missing CSRF accepted: %d", response.Code)
	}
	input["initiator"] = "forged-admin"
	if response := request(t, s, "POST", "/api/registration/proposals", input, admin, csrf); response.Code != 400 {
		t.Fatalf("browser actor accepted: %d", response.Code)
	}
	delete(input, "initiator")
	if response := request(t, s, "POST", "/api/registration/proposals", input, admin, csrf); response.Code != 200 {
		t.Fatalf("admin proposal: %d %s", response.Code, response.Body.String())
	}
	if actor := <-actors; actor != domain.ID(adminUser.ID) {
		t.Fatalf("proposal actor %s", actor)
	}
	approval := map[string]string{"proposal_id": "proposal-test", "digest": string(domain.Hash([]byte("reviewed")))}
	if response := request(t, s, "POST", "/api/registration/approve", approval, admin, csrf); response.Code != 200 {
		t.Fatalf("admin approve: %d %s", response.Code, response.Body.String())
	}
	if actor := <-actors; actor != domain.ID(adminUser.ID) {
		t.Fatalf("approval actor %s", actor)
	}
	if response := request(t, s, "GET", "/api/registration/options?root=/etc", nil, admin, ""); response.Code != 400 {
		t.Fatalf("arbitrary roots query accepted: %d", response.Code)
	}
}
