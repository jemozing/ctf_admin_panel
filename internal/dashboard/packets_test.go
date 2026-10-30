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
	"github.com/ctf-service-manager/ctf-service-manager/internal/packets"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func packetWebJSON(t *testing.T, s *Server, path, body string, cookie *http.Cookie, csrf, origin string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "http://panel.test"+path, strings.NewReader(body))
	r.Header.Set("Origin", origin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.handle(w, r)
	return w
}

func TestPacketsMetadataSensitiveBoundaryAndAdminCaptureActor(t *testing.T) {
	s, _ := testServer(t)
	admin, csrf, adminUser := loginAs(t, s, "admin")
	createAccount(t, s, admin, csrf, "packetviewer", RoleViewer)
	viewer, vcsrf, _ := loginAs(t, s, "packetviewer")
	var calls atomic.Int32
	actor := make(chan domain.ID, 1)
	isolatedStreamExecutor(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/v1/packets":
			q, err := packets.ParseRawQuery(r.URL.RawQuery)
			if err != nil || len(q.ServiceIDs) != 2 || q.Protocol != "udp" || q.DestinationPort != 9000 {
				t.Errorf("packet filters changed: %#v %v", q, err)
			}
			_ = json.NewEncoder(w).Encode(packets.Page{Records: []packets.Metadata{{PacketID: "packet-1", Protocol: "udp"}}})
		case "/v1/packets/status":
			_ = json.NewEncoder(w).Encode(transport.PacketStatus{Configured: true})
		case "/v1/capture/preview":
			var value transport.CapturePreviewRequest
			if err := json.NewDecoder(r.Body).Decode(&value); err != nil {
				t.Error(err)
			}
			actor <- value.Initiator
			_ = json.NewEncoder(w).Encode(transport.CapturePreview{ProposalID: "capture-plan", Digest: domain.Hash([]byte("plan"))})
		default:
			t.Errorf("forbidden packet RPC reached executor: %s", r.URL.Path)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	for _, path := range []string{"/api/packets?service_id=a&service_id=b&protocol=udp&destination_port=9000", "/api/packets/status"} {
		if r := request(t, s, "GET", path, nil, viewer, ""); r.Code != 200 {
			t.Fatalf("metadata %s: %d %s", path, r.Code, r.Body.String())
		}
	}
	for _, endpoint := range []struct{ method, path string }{{"GET", "/api/packets/packet-1"}, {"POST", "/api/packets/export"}, {"GET", "/api/capture/policy"}, {"GET", "/api/capture/targets"}, {"POST", "/api/capture/preview"}, {"POST", "/api/capture/confirm"}} {
		if r := request(t, s, endpoint.method, endpoint.path, map[string]any{}, viewer, vcsrf); r.Code != 403 {
			t.Fatalf("viewer boundary %s: %d", endpoint.path, r.Code)
		}
	}
	if calls.Load() != 2 {
		t.Fatal("forbidden packet request reached executor")
	}
	if r := request(t, s, "POST", "/api/capture/preview", map[string]any{"expected_revision": 0, "enabled": true, "target_ids": []string{"frozen-target"}, "snaplen": 0, "max_packets_per_second": 1000}, admin, csrf); r.Code != 200 {
		t.Fatalf("preview: %d %s", r.Code, r.Body.String())
	}
	if value := <-actor; value != domain.ID(adminUser.ID) {
		t.Fatal("browser controlled capture initiator")
	}
}

func TestPacketsStrictInputsAndExportOriginCSRF(t *testing.T) {
	s, _ := testServer(t)
	admin, csrf, _ := loginAs(t, s, "admin")
	var calls atomic.Int32
	isolatedStreamExecutor(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = w.Write([]byte(`{}`)) }))
	for _, path := range []string{"/api/packets?protocol=tcp&protocol=udp", "/api/packets?source_port=0", "/api/packets?limit=0", "/api/packets?unknown=1", "/api/packets?ip=%zz", "/api/packets/status?raw=1", "/api/capture/targets?interface=any", "/api/packets/packet%2Fother"} {
		if r := request(t, s, "GET", path, nil, admin, ""); r.Code != 400 {
			t.Fatalf("invalid packet query %s: %d", path, r.Code)
		}
	}
	for _, body := range []string{`{"enabled":false,"initiator":"forged"}`, `{"enabled":false,"enabled":true}`, `{"target_ids":[],"interface":"any"}`, `{"target_ids":[],"bpf":"tcp"}`, `null`, `{} {}`} {
		if r := packetWebJSON(t, s, "/api/capture/preview", body, admin, csrf, "http://panel.test"); r.Code != 400 {
			t.Fatalf("capture body accepted: %d %s", r.Code, body)
		}
	}
	for _, body := range []string{`{"query":{"limit":50,"limit":1}}`, `{"query":{},"max_bytes":1000,"initiator":"forged"}`, `{"query":{"data":"secret"}}`} {
		if r := packetWebJSON(t, s, "/api/packets/export", body, admin, csrf, "http://panel.test"); r.Code != 400 {
			t.Fatalf("export body accepted: %d %s", r.Code, body)
		}
	}
	for _, check := range []struct{ csrf, origin string }{{"", "http://panel.test"}, {csrf, "http://evil.test"}, {csrf, ""}} {
		if r := packetWebJSON(t, s, "/api/packets/export", `{"query":{}}`, admin, check.csrf, check.origin); r.Code != 403 {
			t.Fatal("packet export accepted without Origin and CSRF")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid packet request reached executor")
	}
}

func TestPacketRawAndExportWithholdBytesAfterSessionRevocation(t *testing.T) {
	for _, endpoint := range []string{"raw", "export"} {
		t.Run(endpoint, func(t *testing.T) {
			s, _ := testServer(t)
			admin, csrf, _ := loginAs(t, s, "admin")
			user := createAccount(t, s, admin, csrf, "packetreader", RoleDefender)
			if r := request(t, s, "PATCH", "/api/users/"+user.ID, map[string]bool{"sensitive_access": true}, admin, csrf); r.Code != 200 {
				t.Fatal(r.Body.String())
			}
			cookie, readCSRF, _ := loginAs(t, s, "packetreader")
			entered, release := make(chan struct{}), make(chan struct{})
			secret := []byte("PRIVATE-PACKET-MUST-BE-WITHHELD")
			isolatedStreamExecutor(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				<-release
				if endpoint == "raw" {
					_ = json.NewEncoder(w).Encode(packets.Record{Metadata: packets.Metadata{PacketID: "packet-1"}, Data: secret})
				} else {
					_ = json.NewEncoder(w).Encode(packets.Export{Data: secret, Packets: 1, Epoch: "epoch-1"})
				}
			}))
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				if endpoint == "raw" {
					done <- request(t, s, "GET", "/api/packets/packet-1", nil, cookie, "")
				} else {
					done <- request(t, s, "POST", "/api/packets/export", packets.ExportRequest{}, cookie, readCSRF)
				}
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("private packet RPC not reached")
			}
			if _, err := s.db.Exec("DELETE FROM sessions WHERE user_id=?", user.ID); err != nil {
				t.Fatal(err)
			}
			close(release)
			select {
			case result := <-done:
				if result.Code != 401 && result.Code != 403 {
					t.Fatalf("revocation ignored: %d", result.Code)
				}
				if bytes.Contains(result.Body.Bytes(), secret) || strings.Contains(result.Body.String(), base64.StdEncoding.EncodeToString(secret)) {
					t.Fatal("revoked packet bytes published")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("revoked packet request stalled")
			}
		})
	}
}

func TestPacketExportAuditedBinaryHeadersAndBoundedOutput(t *testing.T) {
	for _, scenario := range []string{"valid", "oversized", "requested-byte-overflow", "requested-count-overflow", "audit-failure"} {
		t.Run(scenario, func(t *testing.T) {
			s, _ := testServer(t)
			admin, csrf, _ := loginAs(t, s, "admin")
			data := append([]byte{0xd4, 0xc3, 0xb2, 0xa1}, bytes.Repeat([]byte{0}, 20)...)
			isolatedStreamExecutor(t, s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/packets/export" {
					t.Errorf("wrong export path %s", r.URL.Path)
				}
				var requested int
				if err := s.db.QueryRow("SELECT count(*) FROM audit WHERE action='packets.export' AND result='requested'").Scan(&requested); err != nil || requested != 1 {
					t.Errorf("export RPC ran before audit: %d %v", requested, err)
				}
				out := packets.Export{Data: data, Packets: 0, Truncated: true, Gap: true, Epoch: "store-epoch"}
				if scenario == "oversized" {
					out.Data = make([]byte, packets.MaxExportBytes+1)
				}
				if scenario == "requested-byte-overflow" {
					out.Data = make([]byte, 1025)
				}
				if scenario == "requested-count-overflow" {
					out.Packets = 101
				}
				if scenario == "audit-failure" {
					if _, err := s.db.Exec("DROP TABLE audit"); err != nil {
						t.Error(err)
					}
				}
				_ = json.NewEncoder(w).Encode(out)
			}))
			result := request(t, s, "POST", "/api/packets/export", packets.ExportRequest{MaxPackets: 100, MaxBytes: 1024}, admin, csrf)
			if scenario != "valid" {
				if result.Code != 502 {
					t.Fatalf("unsafe export status %d, returned %d bytes", result.Code, result.Body.Len())
				}
				if bytes.Equal(result.Body.Bytes(), data) {
					t.Fatal("unsafe export published")
				}
				return
			}
			if result.Code != 200 || !bytes.Equal(result.Body.Bytes(), data) {
				t.Fatalf("binary PCAP changed: %d %q", result.Code, result.Body.Bytes())
			}
			for key, want := range map[string]string{"Content-Type": "application/vnd.tcpdump.pcap", "Content-Length": "24", "X-Packet-Count": "0", "X-Packets-Truncated": "true", "X-Packets-Gap": "true", "X-Collector-Epoch": "store-epoch"} {
				if got := result.Header().Get(key); got != want {
					t.Errorf("%s=%q want %q", key, got, want)
				}
			}
			var count int
			if err := s.db.QueryRow("SELECT count(*) FROM audit WHERE action='packets.export' AND result='succeeded'").Scan(&count); err != nil || count != 1 {
				t.Fatalf("export completion audit missing: %d %v", count, err)
			}
		})
	}
}
