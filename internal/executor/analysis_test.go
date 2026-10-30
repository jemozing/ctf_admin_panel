package executor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/packets"
	"github.com/ctf-service-manager/ctf-service-manager/internal/traffic"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func executorAnalysisDescriptor(t *testing.T) []byte {
	t.Helper()
	str := descriptorpb.FieldDescriptorProto_TYPE_STRING
	optional := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	set := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{Name: proto.String("executor.proto"), Package: proto.String("game"), Syntax: proto.String("proto3"), MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Request"), Field: []*descriptorpb.FieldDescriptorProto{{Name: proto.String("value"), Number: proto.Int32(1), Label: &optional, Type: &str}}}, {Name: proto.String("Response")}}, Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("Service"), Method: []*descriptorpb.MethodDescriptorProto{{Name: proto.String("Check"), InputType: proto.String(".game.Request"), OutputType: proto.String(".game.Response")}}}}}}}
	raw, err := proto.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func analysisArchive(t *testing.T, m *Manager) (*packets.Store, string) {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "ctfm-analysis-")
	if err != nil {
		t.Fatal(err)
	}
	base, err = filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	archive, err := packets.Open(packets.Config{StateDirectory: filepath.Join(base, "archive"), QuotaBytes: 8 << 20, PerServiceBytes: 1 << 20, MinimumFreeBytes: 1, Retention: time.Hour, MaxRecords: 100})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = archive.Close() })
	tokens := packets.Tokens{Ingest: strings.Repeat("i", 40), Read: strings.Repeat("r", 40)}
	handler, err := packets.Handler(archive, tokens)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "control"), 0700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(base, "control", "packets.sock")
	listener, cleanup, err := traffic.ListenPrivateUnix(socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: packets.ReadOnly(handler), ReadHeaderTimeout: time.Second}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); <-done; cleanup() })
	token := filepath.Join(base, "read-token")
	if err = os.WriteFile(token, []byte(tokens.Read), 0600); err != nil {
		t.Fatal(err)
	}
	m.Config.Capture = config.CapturePolicy{Enabled: true, PacketsURL: "unix://" + socket, PacketsTokenFile: token}
	return archive, base
}
func TestExecutorDescriptorBindingUsesApprovedCurrentOrSelectedServiceRelease(t *testing.T) {
	f := newPlanningFixture(t)
	archive, _ := analysisArchive(t, f.m)
	ctx := context.Background()
	input := transport.DescriptorPreviewRequest{ServiceID: f.s.ID, Initiator: "admin-one", Data: executorAnalysisDescriptor(t)}
	p, err := f.m.DescriptorPreview(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	binding := p.Info.Binding
	if binding.ServiceID != string(f.s.ID) || binding.ReleaseID != string(f.release.Spec().ID) || binding.SourceDigest != string(f.release.Spec().TreeDigest) {
		t.Fatalf("current release binding invented: %+v", binding)
	}
	if _, err := f.m.DescriptorConfirm(ctx, transport.DescriptorConfirmRequest{ProposalID: domain.ID(p.ProposalID), Digest: domain.Digest(p.Digest), Initiator: "other-admin"}); err == nil {
		t.Fatal("other actor confirmed descriptor")
	}
	confirmed, err := f.m.DescriptorConfirm(ctx, transport.DescriptorConfirmRequest{ProposalID: domain.ID(p.ProposalID), Digest: domain.Digest(p.Digest), Initiator: input.Initiator})
	if err != nil || !confirmed.Confirmed {
		t.Fatal(err)
	}
	second := planningRelease(t, f.m, f.s, f.baseline, "release-selected")
	input.ReleaseID = second.Spec().ID
	p2, err := f.m.DescriptorPreview(ctx, input)
	if err != nil || p2.Info.Binding.ReleaseID != string(second.Spec().ID) {
		t.Fatal("selected local release ignored", err)
	}
	foreignSpec := f.release.Spec()
	foreignSpec.ID = "foreign-release"
	foreignSpec.ServiceID = "foreign-game"
	foreignSpec.Images[0].RetentionTag = retentionTag(domain.Service{ID: foreignSpec.ServiceID}, foreignSpec.ID, "app")
	foreign, err := domain.NewRelease(foreignSpec)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.m.Store.PutImmutable(ctx, "release", foreignSpec.ID, foreignSpec.ServiceID, foreign); err != nil {
		t.Fatal(err)
	}
	input.ReleaseID = foreignSpec.ID
	if _, err = f.m.DescriptorPreview(ctx, input); err == nil {
		t.Fatal("descriptor bound to another service's release")
	}
	input.ReleaseID = "missing-release"
	if _, err = f.m.DescriptorPreview(ctx, input); err == nil {
		t.Fatal("missing release accepted")
	}
	input.ReleaseID = ""
	input.Initiator = "../bad"
	if _, err = f.m.DescriptorPreview(ctx, input); err == nil {
		t.Fatal("invalid actor accepted")
	}
	if list, err := archive.Descriptors(ctx); err != nil || len(list) != 1 {
		t.Fatal("rejected previews changed confirmed inventory", err)
	}
	if err = f.m.DescriptorDelete(ctx, transport.DescriptorDeleteRequest{ID: confirmed.ID, Initiator: "admin-one"}); err != nil {
		t.Fatal(err)
	}
	if list, err := f.m.DescriptorList(ctx); err != nil || len(list) != 0 {
		t.Fatal("executor delete did not reach private archive", err)
	}
}
func TestExecutorDescriptorIPCRejectsCallerBindingOverrides(t *testing.T) {
	f := newPlanningFixture(t)
	archive, base := analysisArchive(t, f.m)
	socket := filepath.Join(base, "executor.sock")
	server, err := transport.NewServer(transport.Options{SocketPath: socket, AllowedUIDs: []uint32{uint32(os.Geteuid())}, Backend: f.m, Development: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(ctx) }()
	t.Cleanup(func() { cancel(); _ = server.Close(); <-done })
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
	defer client.CloseIdleConnections()
	for _, field := range []string{`"binding":{"service_id":"forged","release_id":"foreign"}`, `"source_digest":"sha256:` + strings.Repeat("b", 64) + `"`, `"service_id":"different"`} {
		body := `{"service_id":"` + string(f.s.ID) + `","initiator":"admin","data":"` + base64.StdEncoding.EncodeToString(executorAnalysisDescriptor(t)) + `",` + field + `}`
		r, err := http.NewRequest("POST", "http://executor/v1/descriptors/preview", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != 400 {
			t.Fatalf("caller binding override accepted: %d", response.StatusCode)
		}
	}
	list, err := archive.Descriptors(context.Background())
	if err != nil || len(list) != 0 {
		t.Fatal("invalid IPC mutated archive", err)
	}
}
func TestExecutorH2TerminationDecodeDoesNotGuessHistoricalReleaseBinding(t *testing.T) {
	f := newPlanningFixture(t)
	_, base := analysisArchive(t, f.m)
	frame := func(value []byte) []byte {
		data := make([]byte, 5)
		binary.BigEndian.PutUint32(data[1:], uint32(len(value)))
		return append(data, value...)
	}
	requestBody := frame([]byte{10, 1, 'x'})
	exchange := traffic.Exchange{Metadata: traffic.Metadata{RequestID: "http2-rpc", ServiceID: string(f.s.ID), HTTPProtocol: "h2", Method: "POST", URL: "https://game.local/game.Service/Check", Status: 200, State: "completed"}, RequestHeaders: http.Header{"Content-Type": []string{"application/grpc"}}, ResponseHeaders: http.Header{"Content-Type": []string{"application/grpc"}}, ResponseTrailers: http.Header{"Grpc-Status": []string{"0"}}, RequestBody: traffic.Body{Encoding: "base64", Data: base64.StdEncoding.EncodeToString(requestBody), SensitiveRaw: true}, ResponseBody: traffic.Body{Encoding: "base64", Data: "", SensitiveRaw: true}}
	recorder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("t", 40) || r.URL.Path != "/v1/exchanges/http2-rpc" {
			t.Error("wrong recorder request")
		}
		_ = json.NewEncoder(w).Encode(exchange)
	}))
	defer recorder.Close()
	token := filepath.Join(base, "traffic-token")
	if err := os.WriteFile(token, []byte(strings.Repeat("t", 40)), 0600); err != nil {
		t.Fatal(err)
	}
	f.m.Config.Proxy = config.ProxyPolicy{Enabled: true, TrafficURL: recorder.URL, TrafficTokenFile: token}
	result, err := f.m.ExchangeDecode(context.Background(), transport.ExchangeDecodeRequest{RequestID: exchange.RequestID})
	if err != nil || result.Protocol != "grpc" || len(result.RPCs) != 1 || !bytes.Equal(result.RPCs[0].RequestMessages[0].Data, []byte{10, 1, 'x'}) || len(result.RPCs[0].RequestMessages[0].JSON) > 0 || result.RPCs[0].HTTPStatus != 200 || result.RPCs[0].Path != "/game.Service/Check" {
		t.Fatalf("terminated H2 framing: %+v %v", result, err)
	}
	if _, err = f.m.ExchangeDecode(context.Background(), transport.ExchangeDecodeRequest{RequestID: exchange.RequestID, DescriptorID: "descriptor-current"}); err == nil {
		t.Fatal("current release substituted for historical HTTP2 exchange")
	}
	exchange.HTTPProtocol = "http/1.1"
	if _, err = f.m.ExchangeDecode(context.Background(), transport.ExchangeDecodeRequest{RequestID: exchange.RequestID}); err == nil {
		t.Fatal("HTTP1 body passed to H2 termination decoder")
	}
	exchange.HTTPProtocol = "h2"
	exchange.RequestBody.NotCapturedReason = "metadata_only"
	result, err = f.m.ExchangeDecode(context.Background(), transport.ExchangeDecodeRequest{RequestID: exchange.RequestID})
	if err != nil || !result.Incomplete || !result.Truncated || len(result.RPCs[0].RequestMessages) != 0 {
		t.Fatalf("omitted body appeared complete: %+v %v", result, err)
	}
}
