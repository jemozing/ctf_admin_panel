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

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func TestHealthAdminConfigurationDefenderManualCSRFAndPrivateAudit(t *testing.T) {
	s, _ := testServer(t)
	directory, err := os.MkdirTemp("/tmp", "ctfm-health-api-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	listener, err := net.Listen("unix", filepath.Join(directory, "executor.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var configs, manuals atomic.Int32
	actors := make(chan domain.ID, 3)
	const privateInput = "private-health-check-input"
	executor := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/services/game/checks":
			if r.Method == "POST" {
				var input transport.HealthChecksRequest
				if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
					t.Error(err)
				}
				if input.Policy.Checks[0].BodyContains != privateInput {
					t.Error("write-only input lost")
				}
				actors <- input.Actor
				configs.Add(1)
			}
			json.NewEncoder(w).Encode(transport.HealthChecksView{Revision: 1})
		case "/v1/services/game/checks/manual":
			var input transport.ManualHealthRequest
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			actors <- input.Actor
			manuals.Add(1)
			json.NewEncoder(w).Encode(transport.ManualHealthView{Actor: input.Actor})
		default:
			http.NotFound(w, r)
		}
	})}
	go executor.Serve(listener)
	t.Cleanup(func() { executor.Close() })
	client, err := transport.NewClient(filepath.Join(directory, "executor.sock"))
	if err != nil {
		t.Fatal(err)
	}
	s.executor.Close()
	s.executor = client
	admin, csrf, adminUser := loginAs(t, s, "admin")
	config := transport.HealthChecksRequest{Confirmed: true, Actor: "forged-root", Policy: domain.HealthCheckPolicy{Checks: []domain.HTTPCheck{{ID: "ready", Source: domain.HealthReadiness, URL: "http://service/", ExpectedStatus: 200, BodyContains: privateInput, TimeoutSeconds: 1}}}}
	manual := transport.ManualHealthRequest{ExpectedReleaseID: "release-a", ExpectedStateSequence: 1, ExpectedRuntimeDigest: domain.Hash([]byte("observed")), TTLSeconds: 30, Healthy: true, Comment: "Synthetic app proof", Actor: "forged-root"}
	for _, role := range []Role{RoleViewer, RoleDefender} {
		createAccount(t, s, admin, csrf, string(role), role)
		cookie, token, user := loginAs(t, s, string(role))
		if response := request(t, s, "POST", "/api/services/game/checks", config, cookie, token); response.Code != 403 {
			t.Fatal("non-admin changed checks", role, response.Code)
		}
		if response := request(t, s, "GET", "/api/services/game/checks", nil, cookie, ""); response.Code != 200 || strings.Contains(response.Body.String(), privateInput) {
			t.Fatal("summary denied or leaked", response.Code)
		}
		response := request(t, s, "POST", "/api/services/game/checks/manual", manual, cookie, token)
		if role == RoleViewer {
			if response.Code != 403 {
				t.Fatal("viewer submitted manual proof")
			}
		} else {
			if response.Code != 200 {
				t.Fatal(response.Code, response.Body.String())
			}
			if actor := <-actors; actor != domain.ID(user.ID) {
				t.Fatal("manual actor forged", actor)
			}
		}
	}
	if response := request(t, s, "POST", "/api/services/game/checks", config, admin, ""); response.Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	response := request(t, s, "POST", "/api/services/game/checks", config, admin, csrf)
	if response.Code != 200 || strings.Contains(response.Body.String(), privateInput) {
		t.Fatal(response.Code, response.Body.String())
	}
	if actor := <-actors; actor != domain.ID(adminUser.ID) {
		t.Fatal("configuration actor forged", actor)
	}
	if configs.Load() != 1 || manuals.Load() != 1 {
		t.Fatal("unauthorized write reached executor")
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
		if strings.Contains(action+target+result, privateInput) {
			t.Fatal("private check input leaked to audit")
		}
	}
}
