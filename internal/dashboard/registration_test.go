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
		case "/v1/registration/directories":
			var input transport.RegistrationBrowseRequest
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			if input.Directory != "/srv/game" {
				w.WriteHeader(400)
				w.Write([]byte(`{"code":"invalid_registration","message":"Directory outside approved roots"}`))
				return
			}
			json.NewEncoder(w).Encode(transport.RegistrationDirectoryListing{Directory: input.Directory, Directories: []transport.RegistrationDirectoryEntry{{Name: "game", Path: "/srv/game/game"}}, ComposeFiles: []string{}})
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
		for _, path := range []string{"options", "directories", "inspect", "proposals", "approve"} {
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
	browse := map[string]string{"directory": "/srv/game"}
	if response := request(t, s, "POST", "/api/registration/directories", browse, nil, ""); response.Code != 401 {
		t.Fatalf("anonymous directory listing: %d", response.Code)
	}
	if response := request(t, s, "POST", "/api/registration/directories", browse, admin, ""); response.Code != 403 {
		t.Fatalf("directory listing without CSRF: %d", response.Code)
	}
	response := request(t, s, "POST", "/api/registration/directories", browse, admin, csrf)
	var listing transport.RegistrationDirectoryListing
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &listing) != nil || listing.Directory != "/srv/game" || len(listing.Directories) != 1 || listing.Directories[0].Path != "/srv/game/game" {
		t.Fatalf("admin directory listing: %d %s", response.Code, response.Body.String())
	}
	for _, tc := range []struct {
		method, suffix string
		body           any
		status         int
	}{
		{"GET", "", nil, 405},
		{"POST", "?root=/etc", browse, 400},
		{"POST", "", map[string]string{"directory": "/etc"}, 400},
		{"POST", "", map[string]string{"directory": "/srv/game", "root": "/etc"}, 400},
		{"POST", "", map[string]string{"Directory": "/srv/game"}, 400},
	} {
		if response := request(t, s, tc.method, "/api/registration/directories"+tc.suffix, tc.body, admin, csrf); response.Code != tc.status {
			t.Errorf("directory request %s %s: got %d want %d: %s", tc.method, tc.suffix, response.Code, tc.status, response.Body.String())
		}
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
