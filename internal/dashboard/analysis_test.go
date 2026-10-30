package dashboard

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/flows"
	"github.com/ctf-service-manager/ctf-service-manager/internal/packets"
	"github.com/ctf-service-manager/ctf-service-manager/internal/protocols"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func TestAnalysisMetadataSensitiveAccessAndDescriptorAdminBoundary(t *testing.T) {
	s, _ := testServer(t)
	admin, csrf, adminUser := loginAs(t, s, "admin")
	createAccount(t, s, admin, csrf, "flowviewer", RoleViewer)
	viewer, vcsrf, viewerUser := loginAs(t, s, "flowviewer")
	var calls atomic.Int32
	previewActor := make(chan transport.DescriptorPreviewRequest, 1)
	isolatedStreamExecutor(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/v1/flows":
			q, e := packets.ParseRawQuery(r.URL.RawQuery)
			if e != nil || len(q.ServiceIDs) != 2 || q.Protocol != "tcp" {
				t.Errorf("flow query altered: %+v %v", q, e)
			}
			_ = json.NewEncoder(w).Encode(packets.FlowPage{Flows: []flows.Metadata{{ID: "flow-one", Protocol: "tcp", Candidates: []flows.Candidate{{ServiceID: "one", Component: "app"}, {ServiceID: "two", Component: "api"}}}}})
		case "/v1/flows/detail":
			_ = json.NewEncoder(w).Encode(flows.Detail{Metadata: flows.Metadata{ID: "flow-one"}, Directions: []flows.Direction{{From: "a", Chunks: []flows.Chunk{{Data: []byte("private-flow")}}}}})
		case "/v1/descriptors":
			_ = json.NewEncoder(w).Encode([]packets.DescriptorView{})
		case "/v1/descriptors/preview":
			var in transport.DescriptorPreviewRequest
			if e := json.NewDecoder(r.Body).Decode(&in); e != nil {
				t.Error(e)
			}
			previewActor <- in
			_ = json.NewEncoder(w).Encode(packets.DescriptorPreview{ProposalID: "descriptor-preview", Digest: string(domain.Hash(in.Data))})
		default:
			t.Errorf("forbidden analysis RPC reached executor %s", r.URL.Path)
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		}
	}))
	response := request(t, s, "GET", "/api/flows?service_id=one&service_id=two&protocol=tcp", nil, viewer, "")
	if response.Code != 200 || strings.Contains(response.Body.String(), "private-flow") || strings.Contains(response.Body.String(), "chunks") {
		t.Fatalf("metadata list leaked bytes: %d %s", response.Code, response.Body.String())
	}
	for _, endpoint := range []struct{ method, path string }{{"POST", "/api/flows/detail"}, {"POST", "/api/flows/decode"}, {"POST", "/api/traffic/request-one/decode"}, {"GET", "/api/descriptors"}, {"POST", "/api/descriptors/preview"}, {"POST", "/api/descriptors/confirm"}, {"DELETE", "/api/descriptors/descriptor-one"}} {
		if r := request(t, s, endpoint.method, endpoint.path, map[string]any{"flow_id": "flow-one"}, viewer, vcsrf); r.Code != 403 {
			t.Fatalf("viewer analysis boundary %s: %d", endpoint.path, r.Code)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("forbidden analysis reached executor")
	}
	if _, e := s.db.Exec("UPDATE users SET sensitive_access=1 WHERE id=?", viewerUser.ID); e != nil {
		t.Fatal(e)
	}
	viewer, vcsrf, _ = loginAs(t, s, "flowviewer")
	if r := request(t, s, "POST", "/api/flows/detail", packets.FlowDetailRequest{FlowID: "flow-one"}, viewer, vcsrf); r.Code != 200 || !strings.Contains(r.Body.String(), base64.StdEncoding.EncodeToString([]byte("private-flow"))) {
		t.Fatal("sensitive viewer cannot read bounded stream")
	}
	if r := request(t, s, "GET", "/api/descriptors", nil, viewer, ""); r.Code != 200 {
		t.Fatal("sensitive reader cannot list descriptor metadata")
	}
	for _, endpoint := range []struct{ method, path string }{{"POST", "/api/descriptors/preview"}, {"POST", "/api/descriptors/confirm"}, {"DELETE", "/api/descriptors/descriptor-one"}} {
		if r := request(t, s, endpoint.method, endpoint.path, map[string]any{}, viewer, vcsrf); r.Code != 403 {
			t.Fatal("sensitive viewer gained descriptor mutation rights")
		}
	}
	data := make([]byte, protocols.MaxDescriptorBytes)
	data[len(data)-1] = 0xff
	r := request(t, s, "POST", "/api/descriptors/preview", map[string]any{"service_id": "game", "release_id": "release-one", "data": data}, admin, csrf)
	if r.Code != 200 {
		t.Fatalf("maximum descriptor upload cannot pass web/IPC: %d %s", r.Code, r.Body.String())
	}
	actor := <-previewActor
	if actor.Initiator != domain.ID(adminUser.ID) || actor.ReleaseID != "release-one" || !bytes.Equal(actor.Data, data) {
		t.Fatal("browser descriptor actor/scope or maximum bytes altered")
	}
}

func TestAnalysisStrictInputAndCSRFOrigin(t *testing.T) {
	s, _ := testServer(t)
	admin, csrf, _ := loginAs(t, s, "admin")
	var calls atomic.Int32
	isolatedStreamExecutor(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	for _, path := range []string{"/api/flows?protocol=tcp&protocol=udp", "/api/flows?limit=0", "/api/flows?ip=%zz", "/api/flows?unknown=1", "/api/descriptors?service_id=one", "/api/flows/detail?query=all"} {
		if r := request(t, s, "GET", path, nil, admin, ""); r.Code != 400 {
			t.Fatalf("invalid analysis query accepted: %s %d", path, r.Code)
		}
	}
	for _, endpoint := range []string{"/api/flows/detail", "/api/flows/decode", "/api/traffic/request-one/decode"} {
		for _, body := range []string{`null`, `[]`, `{"query":{},"query":{}}`, `{"flow_id":"../other"}`, `{"flow_id":"flow-one","data":"injected"}`, `{"flow_id":"flow-one","initiator":"forged"}`} {
			if r := packetWebJSON(t, s, endpoint, body, admin, csrf, "http://panel.test"); r.Code != 400 {
				t.Fatalf("invalid analysis body accepted %s %d %s", endpoint, r.Code, body)
			}
		}
	}
	for _, body := range []string{`{"service_id":"game","data":"AA==","initiator":"forged"}`, `{"service_id":"game","data":"AA==","data":"AQ=="}`, `{"service_id":"../host","data":"AA=="}`, `{"service_id":"game","data":"not base64"}`, `{"service_id":"game","data":"AA==","path":"/tmp/file"}`, `{"service_id":"game","release_id":"../bad","data":"AA=="}`, `{"service_id":"game","data":""}`} {
		if r := packetWebJSON(t, s, "/api/descriptors/preview", body, admin, csrf, "http://panel.test"); r.Code != 400 {
			t.Fatalf("invalid descriptor body accepted %d", r.Code)
		}
	}
	for _, endpoint := range []string{"/api/flows/detail", "/api/flows/decode", "/api/traffic/request-one/decode", "/api/descriptors/preview", "/api/descriptors/confirm"} {
		for _, guard := range []struct{ csrf, origin string }{{"", "http://panel.test"}, {csrf, "http://untrusted.test"}, {csrf, ""}} {
			if r := packetWebJSON(t, s, endpoint, `{}`, admin, guard.csrf, guard.origin); r.Code != 403 {
				t.Fatalf("missing Origin/CSRF accepted %s %d", endpoint, r.Code)
			}
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid input reached analysis executor")
	}
}

func TestAnalysisSensitiveResultsWithheldAfterRevocationAndAuditFailure(t *testing.T) {
	for _, kind := range []string{"flow-detail", "flow-decode", "exchange-decode", "descriptor-list", "descriptor-preview", "audit-failure"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := testServer(t)
			admin, csrf, user := loginAs(t, s, "admin")
			secret := []byte("PRIVATE-ANALYSIS-BYTES-MUST-BE-WITHHELD")
			entered, release := make(chan struct{}), make(chan struct{})
			isolatedStreamExecutor(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				<-release
				if kind == "audit-failure" {
					if _, e := s.db.Exec("DROP TABLE audit"); e != nil {
						t.Error(e)
					}
				}
				switch kind {
				case "flow-detail":
					_ = json.NewEncoder(w).Encode(flows.Detail{Metadata: flows.Metadata{ID: "flow-one"}, Directions: []flows.Direction{{Chunks: []flows.Chunk{{Data: secret}}}}})
				case "descriptor-list":
					_ = json.NewEncoder(w).Encode([]packets.DescriptorView{{ID: string(secret)}})
				case "descriptor-preview":
					_ = json.NewEncoder(w).Encode(packets.DescriptorPreview{ProposalID: string(secret)})
				default:
					_ = json.NewEncoder(w).Encode(protocols.Result{Protocol: "grpc", RPCs: []protocols.RPC{{RequestMessages: []protocols.Message{{Data: secret}}}}})
				}
			}))
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				var result *httptest.ResponseRecorder
				switch kind {
				case "flow-detail":
					result = request(t, s, "POST", "/api/flows/detail", packets.FlowDetailRequest{FlowID: "flow-one"}, admin, csrf)
				case "descriptor-list":
					result = request(t, s, "GET", "/api/descriptors", nil, admin, "")
				case "descriptor-preview":
					result = request(t, s, "POST", "/api/descriptors/preview", map[string]any{"service_id": "game", "data": []byte{0}}, admin, csrf)
				case "exchange-decode":
					result = request(t, s, "POST", "/api/traffic/request-one/decode", map[string]any{}, admin, csrf)
				default:
					result = request(t, s, "POST", "/api/flows/decode", packets.FlowDecodeRequest{FlowID: "flow-one"}, admin, csrf)
				}
				done <- result
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("analysis RPC not reached")
			}
			if kind != "audit-failure" {
				if _, e := s.db.Exec("DELETE FROM sessions WHERE user_id=?", user.ID); e != nil {
					t.Fatal(e)
				}
			}
			close(release)
			select {
			case result := <-done:
				if kind == "audit-failure" {
					if result.Code != 502 {
						t.Fatalf("audit failure released result %d", result.Code)
					}
				} else if result.Code != 401 && result.Code != 403 {
					t.Fatalf("revocation ignored %d", result.Code)
				}
				if bytes.Contains(result.Body.Bytes(), secret) || strings.Contains(result.Body.String(), base64.StdEncoding.EncodeToString(secret)) {
					t.Fatal("private analysis result leaked after revocation/audit failure")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("revoked analysis request stalled")
			}
		})
	}
}
