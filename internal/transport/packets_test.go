package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/packets"
)

type packetTestBackend struct {
	testBackend
	calls    atomic.Int32
	queries  chan packets.Query
	previews chan CapturePreviewRequest
}

func (b *packetTestBackend) PacketStatus(context.Context) (PacketStatus, error) {
	b.calls.Add(1)
	return PacketStatus{Configured: true}, nil
}
func (b *packetTestBackend) PacketList(_ context.Context, q packets.Query) (packets.Page, error) {
	b.calls.Add(1)
	if b.queries != nil {
		b.queries <- q
	}
	return packets.Page{Records: []packets.Metadata{{PacketID: "packet-1", Protocol: "udp"}}}, nil
}
func (b *packetTestBackend) PacketRaw(context.Context, string) (packets.Record, error) {
	b.calls.Add(1)
	return packets.Record{Metadata: packets.Metadata{PacketID: "packet-1"}, Data: []byte{0, 0xff, 1}}, nil
}
func (b *packetTestBackend) PacketExport(context.Context, packets.ExportRequest) (packets.Export, error) {
	b.calls.Add(1)
	return packets.Export{Data: make([]byte, 24), Epoch: "epoch"}, nil
}
func (b *packetTestBackend) CapturePolicy(context.Context) (CapturePolicyView, error) {
	b.calls.Add(1)
	return CapturePolicyView{}, nil
}
func (b *packetTestBackend) CaptureTargets(context.Context) (CaptureTargets, error) {
	b.calls.Add(1)
	return CaptureTargets{}, nil
}
func (b *packetTestBackend) CapturePreview(_ context.Context, q CapturePreviewRequest) (CapturePreview, error) {
	b.calls.Add(1)
	if b.previews != nil {
		b.previews <- q
	}
	return CapturePreview{}, nil
}
func (b *packetTestBackend) CaptureConfirm(context.Context, ProxyConfirmRequest) (CapturePolicyView, error) {
	b.calls.Add(1)
	return CapturePolicyView{}, nil
}

func packetIPCRequest(t *testing.T, s *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "http://executor"+path, strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), principalKey{}, Principal{UID: uint32(os.Geteuid())}))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	s.handle(w, r)
	return w
}

func TestPacketIPCStrictQueriesAndActorInputs(t *testing.T) {
	b := &packetTestBackend{queries: make(chan packets.Query, 1), previews: make(chan CapturePreviewRequest, 1)}
	s := &Server{options: Options{Backend: b, AllowedUIDs: []uint32{uint32(os.Geteuid())}}}
	for _, path := range []string{"/v1/packets?protocol=tcp&protocol=udp", "/v1/packets?source_port=0", "/v1/packets?direction=outgoing", "/v1/packets?limit=0", "/v1/packets?unknown=1", "/v1/packets/status?raw=1", "/v1/capture/targets?interface=any", "/v1/packets/a%2Fb"} {
		if r := packetIPCRequest(t, s, "GET", path, ""); r.Code != 400 {
			t.Fatalf("invalid packet query %s accepted: %d", path, r.Code)
		}
	}
	for _, body := range []string{`{"enabled":false}`, `{"initiator":"../root","enabled":true}`, `{"initiator":"actor","enabled":false,"enabled":true}`, `{"initiator":"actor","bpf":"tcp"}`, `{"initiator":"actor","target_ids":[],"interface":"any"}`, `null`, `{} {}`} {
		if r := packetIPCRequest(t, s, "POST", "/v1/capture/preview", body); r.Code != 400 {
			t.Fatalf("invalid capture request accepted: %d %s", r.Code, body)
		}
	}
	for _, body := range []string{`{"query":{"limit":50,"limit":1}}`, `{"query":{},"unknown":1}`, `null`, `[]`} {
		if r := packetIPCRequest(t, s, "POST", "/v1/packets/export", body); r.Code != 400 {
			t.Fatalf("invalid export request accepted: %d %s", r.Code, body)
		}
	}
	if r := packetIPCRequest(t, s, "POST", "/v1/capture/confirm", `{"proposal_id":"plan","digest":"`+strings.Repeat("a", 64)+`"}`); r.Code != 400 {
		t.Fatal("capture confirm accepted without initiator")
	}
	if b.calls.Load() != 0 {
		t.Fatal("invalid packet request reached backend")
	}
	if r := packetIPCRequest(t, s, "GET", "/v1/packets?service_id=a&service_id=b&protocol=udp&source_port=53&destination_port=9000&direction=ingress&limit=50", ""); r.Code != 200 {
		t.Fatalf("typed packet query: %d %s", r.Code, r.Body.String())
	}
	q := <-b.queries
	if len(q.ServiceIDs) != 2 || q.SourcePort != 53 || q.DestinationPort != 9000 || q.Direction != "ingress" {
		t.Fatalf("query scope changed: %#v", q)
	}
	if r := packetIPCRequest(t, s, "POST", "/v1/capture/preview", `{"initiator":"authenticated-actor","enabled":true,"target_ids":["target-1"],"snaplen":0,"max_packets_per_second":1000}`); r.Code != 200 {
		t.Fatalf("valid capture preview: %d %s", r.Code, r.Body.String())
	}
	if preview := <-b.previews; preview.Initiator != "authenticated-actor" || len(preview.TargetIDs) != 1 || preview.Snaplen != 0 {
		t.Fatal("typed capture preview changed")
	}
}

type packetRoundTripper func(*http.Request) (*http.Response, error)

func (f packetRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPacketIPCClientPreservesRawBytesAndLargerBoundedPCAP(t *testing.T) {
	b := &packetTestBackend{}
	_, client := runServer(t, Options{Backend: b})
	raw, err := client.PacketRaw(context.Background(), "packet-1")
	if err != nil || !bytes.Equal(raw.Data, []byte{0, 0xff, 1}) {
		t.Fatalf("binary packet altered: %#v %v", raw, err)
	}
	if _, err := client.PacketRaw(context.Background(), "packet/escape"); err == nil {
		t.Fatal("client accepted packet path injection")
	}
	large := packets.Export{Data: make([]byte, packets.MaxExportBytes), Packets: 1, Epoch: "epoch"}
	encoded, err := json.Marshal(large)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) <= 8<<20 || len(encoded) >= 12<<20 {
		t.Fatal("fixture does not exercise increased bounded export response")
	}
	largeClient := &Client{http: &http.Client{Transport: packetRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.Method != "POST" || r.URL.Path != "/v1/packets/export" {
			t.Errorf("unexpected packet client route: %s %s", r.Method, r.URL.Path)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(encoded)), Header: make(http.Header)}, nil
	})}}
	result, err := largeClient.PacketExport(context.Background(), packets.ExportRequest{MaxBytes: packets.MaxExportBytes})
	if err != nil || len(result.Data) != packets.MaxExportBytes {
		t.Fatalf("bounded full PCAP cannot pass IPC: %d %v", len(result.Data), err)
	}
}

type packetCountingReader struct {
	remaining int
	read      int
	closed    bool
}

func (r *packetCountingReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := min(len(p), r.remaining)
	for i := range p[:n] {
		p[i] = ' '
	}
	r.remaining -= n
	r.read += n
	return n, nil
}
func (r *packetCountingReader) Close() error { r.closed = true; return nil }

func TestPacketIPCExportResponseStopsAtTwelveMiBBudget(t *testing.T) {
	body := &packetCountingReader{remaining: 20 << 20}
	client := &Client{http: &http.Client{Transport: packetRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: body}, nil
	})}}
	if _, err := client.PacketExport(context.Background(), packets.ExportRequest{}); err == nil || !strings.Contains(err.Error(), "exceeds body limit") {
		t.Fatalf("oversized packet export response accepted: %v", err)
	}
	if body.read != (12<<20)+1 || !body.closed {
		t.Fatalf("response was not bounded/closed: read=%d closed=%v", body.read, body.closed)
	}
}
