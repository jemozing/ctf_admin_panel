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

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/flows"
	"github.com/ctf-service-manager/ctf-service-manager/internal/packets"
	"github.com/ctf-service-manager/ctf-service-manager/internal/protocols"
)

type analysisTestBackend struct {
	testBackend
	calls    atomic.Int32
	previews chan DescriptorPreviewRequest
	queries  chan packets.Query
}

func (b *analysisTestBackend) FlowList(_ context.Context, q packets.Query) (packets.FlowPage, error) {
	b.calls.Add(1)
	if b.queries != nil {
		b.queries <- q
	}
	return packets.FlowPage{Flows: []flows.Metadata{{ID: "flow-one", Protocol: "tcp"}}}, nil
}
func (b *analysisTestBackend) FlowDetail(context.Context, packets.FlowDetailRequest) (flows.Detail, error) {
	b.calls.Add(1)
	return flows.Detail{Metadata: flows.Metadata{ID: "flow-one"}, Directions: []flows.Direction{{From: "a", Chunks: []flows.Chunk{{Data: []byte("private-stream")}}}}}, nil
}
func (b *analysisTestBackend) FlowDecode(context.Context, packets.FlowDecodeRequest) (protocols.Result, error) {
	b.calls.Add(1)
	return protocols.Result{Protocol: "grpc", RPCs: []protocols.RPC{{Path: "/test.Service/Method"}}}, nil
}
func (b *analysisTestBackend) ExchangeDecode(context.Context, ExchangeDecodeRequest) (protocols.Result, error) {
	b.calls.Add(1)
	return protocols.Result{Protocol: "grpc"}, nil
}
func (b *analysisTestBackend) DescriptorList(context.Context) ([]packets.DescriptorView, error) {
	b.calls.Add(1)
	return []packets.DescriptorView{}, nil
}
func (b *analysisTestBackend) DescriptorPreview(_ context.Context, in DescriptorPreviewRequest) (packets.DescriptorPreview, error) {
	b.calls.Add(1)
	if b.previews != nil {
		b.previews <- in
	}
	return packets.DescriptorPreview{ProposalID: "descriptor-preview", Digest: string(domain.Hash(in.Data))}, nil
}
func (b *analysisTestBackend) DescriptorConfirm(context.Context, DescriptorConfirmRequest) (packets.DescriptorView, error) {
	b.calls.Add(1)
	return packets.DescriptorView{ID: "descriptor-one", Confirmed: true}, nil
}
func (b *analysisTestBackend) DescriptorDelete(context.Context, DescriptorDeleteRequest) error {
	b.calls.Add(1)
	return nil
}

func TestAnalysisIPCStrictQueriesAndDescriptorActors(t *testing.T) {
	b := &analysisTestBackend{queries: make(chan packets.Query, 1), previews: make(chan DescriptorPreviewRequest, 1)}
	s := &Server{options: Options{Backend: b, AllowedUIDs: []uint32{uint32(os.Geteuid())}}}
	for _, path := range []string{"/v1/flows?protocol=tcp&protocol=udp", "/v1/flows?unknown=1", "/v1/flows?limit=0", "/v1/flows?ip=%zz", "/v1/descriptors?service_id=game", "/v1/flows/detail?source=any", "/v1/flows/a%2Fb"} {
		if r := packetIPCRequest(t, s, "GET", path, ""); r.Code != 400 {
			t.Fatalf("invalid analysis path accepted: %s %d", path, r.Code)
		}
	}
	for _, path := range []string{"/v1/flows/detail", "/v1/flows/decode", "/v1/exchange/decode"} {
		for _, body := range []string{`null`, `[]`, `{"query":{},"query":{}}`, `{"request_id":"one","body":"injected"}`} {
			if r := packetIPCRequest(t, s, "POST", path, body); r.Code != 400 {
				t.Fatalf("unknown or duplicate analysis input accepted %s: %d", path, r.Code)
			}
		}
	}
	for _, body := range []string{`{"service_id":"game","data":"AA=="}`, `{"service_id":"../host","initiator":"actor","data":"AA=="}`, `{"service_id":"game","initiator":"actor","data":"AA==","data":"AQ=="}`, `{"service_id":"game","initiator":"actor","data":"AA==","url":"https://remote/descriptor"}`, `{"service_id":"game","initiator":"actor","release_id":"../bad","data":"AA=="}`, `{"service_id":"game","initiator":"actor","data":""}`} {
		if r := packetIPCRequest(t, s, "POST", "/v1/descriptors/preview", body); r.Code != 400 {
			t.Fatalf("descriptor input accepted: %d", r.Code)
		}
	}
	for _, endpoint := range []string{"confirm", "delete"} {
		if r := packetIPCRequest(t, s, "POST", "/v1/descriptors/"+endpoint, `{}`); r.Code != 400 {
			t.Fatalf("descriptor %s actor absent accepted", endpoint)
		}
	}
	if b.calls.Load() != 0 {
		t.Fatal("invalid analysis input reached backend")
	}
	if r := packetIPCRequest(t, s, "GET", "/v1/flows?service_id=one&service_id=two&protocol=tcp&direction=ambiguous&limit=50", ""); r.Code != 200 {
		t.Fatalf("metadata scope: %d %s", r.Code, r.Body.String())
	}
	q := <-b.queries
	if len(q.ServiceIDs) != 2 || q.Direction != "ambiguous" {
		t.Fatal("analysis filter scope altered")
	}
	body := `{"service_id":"game","initiator":"actor","data":"AA=="}`
	request := httptest.NewRequest("POST", "http://executor/v1/descriptors/preview", strings.NewReader(body))
	request = request.WithContext(context.WithValue(request.Context(), principalKey{}, Principal{UID: uint32(os.Geteuid())}))
	request.Header.Set("Content-Type", "application/jsonjunk")
	response := httptest.NewRecorder()
	s.handle(response, request)
	if response.Code != 415 {
		t.Fatalf("descriptor accepted invalid media type: %d", response.Code)
	}
}

func TestAnalysisDescriptorIPCAllowsMaximumFileWithoutWideningOtherRequests(t *testing.T) {
	b := &analysisTestBackend{previews: make(chan DescriptorPreviewRequest, 1)}
	_, c := runServer(t, Options{Backend: b})
	data := make([]byte, protocols.MaxDescriptorBytes)
	data[len(data)-1] = 0xff
	_, err := c.DescriptorPreview(context.Background(), DescriptorPreviewRequest{ServiceID: "game", ReleaseID: "release-one", Initiator: "authenticated", Data: data})
	if err != nil {
		t.Fatal(err)
	}
	seen := <-b.previews
	if seen.Initiator != "authenticated" || seen.ReleaseID != "release-one" || !bytes.Equal(seen.Data, data) {
		t.Fatal("large descriptor scope/bytes changed")
	}
	tooLarge := DescriptorPreviewRequest{ServiceID: "game", Initiator: "authenticated", Data: make([]byte, protocols.MaxDescriptorBytes+1)}
	if _, err := c.DescriptorPreview(context.Background(), tooLarge); err == nil {
		t.Fatal("descriptor raw2MiB bound ignored")
	}
	if b.calls.Load() != 1 {
		t.Fatal("oversized file reached backend")
	}
	if err := c.request(context.Background(), "POST", "/v1/flows/detail", map[string]string{"flow_id": strings.Repeat("x", MaxBodyBytes+1)}, new(any)); err == nil || !strings.Contains(err.Error(), "body limit") {
		t.Fatal("descriptor allowance widened generic IPC request bound")
	}
}

func TestAnalysisIPCResponsesBoundDecodedPayloadMemory(t *testing.T) {
	raw := flows.Detail{Metadata: flows.Metadata{ID: "flow-one"}, Directions: []flows.Direction{{From: "a", Chunks: []flows.Chunk{{Data: []byte{0, 0xff, 1}}}}}}
	encoded, _ := json.Marshal(raw)
	c := &Client{http: &http.Client{Transport: packetRoundTripper(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(encoded))}, nil
	})}}
	detail, err := c.FlowDetail(context.Background(), packets.FlowDetailRequest{FlowID: "flow-one"})
	if err != nil || !bytes.Equal(detail.Directions[0].Chunks[0].Data, []byte{0, 0xff, 1}) {
		t.Fatal("flow raw bytes altered across IPC")
	}
	reader := &packetCountingReader{remaining: 12 << 20}
	c.http.Transport = packetRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: reader}, nil
	})
	if _, err := c.FlowDecode(context.Background(), packets.FlowDecodeRequest{FlowID: "flow-one"}); err == nil || !strings.Contains(err.Error(), "body limit") {
		t.Fatal("unbounded protocol analysis response accepted")
	}
	if reader.read != (8<<20)+1 || !reader.closed {
		t.Fatalf("analysis response not bounded and closed: %d/%t", reader.read, reader.closed)
	}
}
