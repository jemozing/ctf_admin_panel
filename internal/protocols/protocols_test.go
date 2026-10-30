package protocols

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/anypb"
)

type wire struct {
	buf     bytes.Buffer
	block   bytes.Buffer
	framer  *http2.Framer
	encoder *hpack.Encoder
}

func newWire(client bool) *wire {
	w := new(wire)
	if client {
		w.buf.WriteString(clientPreface)
	}
	w.framer = http2.NewFramer(&w.buf, nil)
	w.encoder = hpack.NewEncoder(&w.block)
	_ = w.framer.WriteSettings()
	return w
}
func (w *wire) headers(t *testing.T, id uint32, end bool, headers []Header, split bool) {
	t.Helper()
	w.block.Reset()
	for _, h := range headers {
		if err := w.encoder.WriteField(hpack.HeaderField{Name: h.Name, Value: h.Value}); err != nil {
			t.Fatal(err)
		}
	}
	block := w.block.Bytes()
	if split && len(block) > 1 {
		n := len(block) / 2
		if err := w.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:n], EndStream: end}); err != nil {
			t.Fatal(err)
		}
		if err := w.framer.WriteContinuation(id, true, block[n:]); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := w.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block, EndStream: end, EndHeaders: true}); err != nil {
			t.Fatal(err)
		}
	}
}
func (w *wire) data(t *testing.T, id uint32, end bool, data []byte) {
	t.Helper()
	if err := w.framer.WriteData(id, end, data); err != nil {
		t.Fatal(err)
	}
}
func grpcFrame(data []byte, compressed byte) []byte {
	out := make([]byte, 5)
	out[0] = compressed
	binary.BigEndian.PutUint32(out[1:], uint32(len(data)))
	return append(out, data...)
}
func requestHeaders(path string) []Header {
	return []Header{{":method", "POST"}, {":scheme", "http"}, {":path", path}, {":authority", "game.local"}, {"content-type", "application/grpc+proto"}, {"te", "trailers"}, {"x-sample", "dynamic context repeats"}}
}
func responseHeaders() []Header {
	return []Header{{":status", "200"}, {"content-type", "application/grpc"}}
}
func decodeWire(t *testing.T, client, server *wire, opts Options) Result {
	t.Helper()
	result, err := Decode(context.Background(), Input{AToB: DirectionInput{Data: client.buf.Bytes()}, BToA: DirectionInput{Data: server.buf.Bytes()}}, opts)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func testDescriptor(t *testing.T, binding Binding) *Descriptor {
	t.Helper()
	raw := descriptorBytes(t)
	d, err := NewDescriptor(raw, binding)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func descriptorBytes(t *testing.T) []byte {
	t.Helper()
	optional := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	str := descriptorpb.FieldDescriptorProto_TYPE_STRING
	boolean := descriptorpb.FieldDescriptorProto_TYPE_BOOL
	set := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{Name: proto.String("demo.proto"), Package: proto.String("demo"), Syntax: proto.String("proto3"), MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Request"), Field: []*descriptorpb.FieldDescriptorProto{{Name: proto.String("name"), Number: proto.Int32(1), Label: &optional, Type: &str}}}, {Name: proto.String("Response"), Field: []*descriptorpb.FieldDescriptorProto{{Name: proto.String("ok"), Number: proto.Int32(1), Label: &optional, Type: &boolean}}}}, Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("Echo"), Method: []*descriptorpb.MethodDescriptorProto{{Name: proto.String("Chat"), InputType: proto.String(".demo.Request"), OutputType: proto.String(".demo.Response"), ClientStreaming: proto.Bool(true), ServerStreaming: proto.Bool(true)}}}}}}}
	raw, err := proto.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func has(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func TestHTTP2MultiplexedStreamingContinuationAndDynamicHPACK(t *testing.T) {
	client, server := newWire(true), newWire(false)
	client.headers(t, 1, false, requestHeaders("/demo.Echo/Chat"), true)
	client.headers(t, 3, false, requestHeaders("/demo.Echo/Chat"), false)
	first := grpcFrame([]byte{10, 5, 'a', 'l', 'i', 'c', 'e'}, 0)
	second := grpcFrame([]byte{10, 3, 'b', 'o', 'b'}, 0)
	client.data(t, 1, false, first[:3])
	client.data(t, 3, true, second)
	client.data(t, 1, true, append(first[3:], second...))
	server.headers(t, 3, false, responseHeaders(), false)
	server.headers(t, 1, false, responseHeaders(), true)
	server.data(t, 1, false, append(grpcFrame([]byte{8, 1}, 0), grpcFrame([]byte{8, 0}, 0)...))
	server.data(t, 3, false, grpcFrame([]byte{8, 1}, 0))
	server.headers(t, 1, true, []Header{{"grpc-status", "0"}, {"grpc-message", "all%20done"}}, false)
	server.headers(t, 3, true, []Header{{"grpc-status", "0"}}, false)
	binding := Binding{ServiceID: "game", ReleaseID: "rel-one"}
	result := decodeWire(t, client, server, Options{Descriptor: testDescriptor(t, binding), Binding: binding})
	if result.Protocol != "grpc" || result.Status != "decoded" || result.Incomplete || len(result.RPCs) != 2 {
		t.Fatalf("multiplexed decode: %+v", result)
	}
	rpc := result.RPCs[0]
	if rpc.StreamID != 1 || len(rpc.RequestMessages) != 2 || len(rpc.ResponseMessages) != 2 || rpc.GRPCStatus == nil || *rpc.GRPCStatus != 0 || rpc.GRPCMessage != "all done" || rpc.ClientStreaming == nil || !*rpc.ClientStreaming || rpc.ServerStreaming == nil || !*rpc.ServerStreaming {
		t.Fatalf("RPC boundaries/status lost: %+v", rpc)
	}
	var payload map[string]any
	if json.Unmarshal(rpc.RequestMessages[0].JSON, &payload) != nil || payload["name"] != "alice" || rpc.RequestMessages[0].Type != "demo.Request" {
		t.Fatalf("protobuf names not resolved: %+v", rpc.RequestMessages[0])
	}
	if !bytes.Equal(rpc.RequestMessages[0].Data, []byte{10, 5, 'a', 'l', 'i', 'c', 'e'}) || rpc.ResponseMessages[0].Type != "demo.Response" {
		t.Fatal("request/response type or bytes altered")
	}
}
func TestClientDirectionAndOpaqueFallbackWithoutDescriptors(t *testing.T) {
	client, server := newWire(true), newWire(false)
	client.headers(t, 1, false, requestHeaders("/unknown.Service/Method"), false)
	payload := []byte{0, 255, '<', 's', 'c', 'r', 'i', 'p', 't', '>'}
	client.data(t, 1, true, grpcFrame(payload, 0))
	server.headers(t, 1, true, append(responseHeaders(), Header{"grpc-status", "7"}), false)
	result, err := Decode(context.Background(), Input{BToA: DirectionInput{Data: client.buf.Bytes()}, AToB: DirectionInput{Data: server.buf.Bytes()}}, Options{})
	if err != nil || result.ClientDirection != "b_to_a" || result.Protocol != "grpc" || len(result.RPCs) != 1 {
		t.Fatalf("reverse orientation: %+v %v", result, err)
	}
	msg := result.RPCs[0].RequestMessages[0]
	if !bytes.Equal(msg.Data, payload) || len(msg.JSON) > 0 || msg.Type != "" || *result.RPCs[0].GRPCStatus != 7 {
		t.Fatal("protobuf fields invented without descriptors or raw bytes altered")
	}
}
func TestDescriptorClosedImportsBindingAndImmutableInventory(t *testing.T) {
	binding := Binding{ServiceID: "game", SourceDigest: "sha256:" + strings.Repeat("a", 64)}
	d := testDescriptor(t, binding)
	info := d.Info()
	if len(info.Methods) != 1 || info.Methods[0].Path != "/demo.Echo/Chat" || info.Files != 1 || info.Bytes < 1 || !strings.HasPrefix(info.Digest, "sha256:") {
		t.Fatalf("descriptor inventory: %+v", info)
	}
	info.Methods[0].Path = "forged"
	if d.Info().Methods[0].Path == "forged" {
		t.Fatal("inventory mutable")
	}
	if !d.matches(Binding{ServiceID: "game", ReleaseID: "another-release", SourceDigest: binding.SourceDigest}) || d.matches(Binding{ServiceID: "other", SourceDigest: binding.SourceDigest}) || d.matches(Binding{ServiceID: "game", SourceDigest: "sha256:" + strings.Repeat("b", 64)}) {
		t.Fatal("descriptor binding widened or irrelevant captured pin rejected")
	}
	for _, bad := range []Binding{{}, {ServiceID: "game"}, {ServiceID: "../root", ReleaseID: "release"}, {ServiceID: "game", SourceDigest: "not-a-digest"}} {
		if _, err := NewDescriptor(descriptorBytes(t), bad); err == nil {
			t.Fatal("unbound descriptor accepted")
		}
	}
	set := new(descriptorpb.FileDescriptorSet)
	if proto.Unmarshal(descriptorBytes(t), set) != nil {
		t.Fatal("fixture")
	}
	set.File[0].Dependency = []string{"missing.proto"}
	raw, _ := proto.Marshal(set)
	if _, err := NewDescriptor(raw, binding); err == nil {
		t.Fatal("missing import caused implicit global/disk lookup")
	}
	if _, err := NewDescriptor(make([]byte, MaxDescriptorBytes+1), binding); err == nil {
		t.Fatal("oversized descriptor")
	}
}
func TestDescriptorMismatchNeverAppliesFieldNames(t *testing.T) {
	binding := Binding{ServiceID: "game", ReleaseID: "release"}
	d := testDescriptor(t, binding)
	exchange := Exchange{RequestHeaders: requestHeaders("/demo.Echo/Chat"), ResponseHeaders: responseHeaders(), ResponseTrailers: []Header{{"grpc-status", "0"}}, RequestBody: grpcFrame([]byte{10, 1, 'x'}, 0), RequestComplete: true, ResponseComplete: true}
	result, err := DecodeExchange(context.Background(), exchange, Options{Descriptor: d, Binding: Binding{ServiceID: "game", ReleaseID: "different"}})
	if err != nil || !has(result.RPCs[0].Errors, "descriptor_binding_mismatch") || len(result.RPCs[0].RequestMessages[0].JSON) > 0 {
		t.Fatalf("wrong release received field names: %+v %v", result, err)
	}
	exchange.RequestHeaders = requestHeaders("/other.Service/Unknown")
	result, err = DecodeExchange(context.Background(), exchange, Options{Descriptor: d, Binding: binding})
	if err != nil || result.RPCs[0].RequestMessages[0].Error != "descriptor_method_not_found" {
		t.Fatal("method guessed")
	}
}
func TestGzipMessageAndBombUnknownOrInvalidEncoding(t *testing.T) {
	gzipBytes := func(payload []byte) []byte {
		var out bytes.Buffer
		z := gzip.NewWriter(&out)
		_, _ = z.Write(payload)
		_ = z.Close()
		return out.Bytes()
	}
	exchange := Exchange{RequestHeaders: append(requestHeaders("/x.S/M"), Header{"grpc-encoding", "gzip"}), ResponseHeaders: responseHeaders(), ResponseTrailers: []Header{{"grpc-status", "0"}}, RequestComplete: true, ResponseComplete: true}
	payload := []byte("binary message\x00\xff")
	exchange.RequestBody = grpcFrame(gzipBytes(payload), 1)
	result, err := DecodeExchange(context.Background(), exchange, Options{})
	if err != nil || result.Status != "decoded" || !bytes.Equal(result.RPCs[0].RequestMessages[0].Data, payload) || !result.RPCs[0].RequestMessages[0].Compressed {
		t.Fatalf("gzip decode: %+v %v", result, err)
	}
	for _, scenario := range []string{"bomb", "invalid", "unknown", "trailing"} {
		t.Run(scenario, func(t *testing.T) {
			copy := exchange
			switch scenario {
			case "bomb":
				copy.RequestBody = grpcFrame(gzipBytes(bytes.Repeat([]byte{0}, MaxMessageBytes)), 1)
			case "invalid":
				copy.RequestBody = grpcFrame([]byte("not gzip"), 1)
			case "unknown":
				copy.RequestHeaders = append(requestHeaders("/x.S/M"), Header{"grpc-encoding", "snappy"})
			case "trailing":
				copy.RequestBody = grpcFrame(append(gzipBytes(payload), 0), 1)
			}
			r, err := DecodeExchange(context.Background(), copy, Options{})
			if err != nil || len(r.RPCs[0].RequestMessages) != 1 || r.RPCs[0].RequestMessages[0].Error == "" || !r.Incomplete {
				t.Fatalf("unsafe compressed message decoded: %+v %v", r, err)
			}
		})
	}
}
func TestMalformedGRPCFramingAndTotalMessageBudget(t *testing.T) {
	base := Exchange{RequestHeaders: requestHeaders("/x.S/M"), ResponseHeaders: responseHeaders(), ResponseTrailers: []Header{{"grpc-status", "0"}}, RequestComplete: true, ResponseComplete: true}
	for _, body := range [][]byte{{1, 2}, grpcFrame([]byte{1}, 2), {0, 0, 0, 0, 9, 1}, {0, 0, 16, 0, 1}} {
		copy := base
		copy.RequestBody = body
		result, err := DecodeExchange(context.Background(), copy, Options{})
		if err != nil || !result.Incomplete || len(result.RPCs[0].Errors) == 0 {
			t.Fatalf("malformed framing accepted: %+v %v", result, err)
		}
	}
	base.RequestBody = bytes.Repeat(grpcFrame(nil, 0), MaxMessages)
	base.ResponseBody = grpcFrame(nil, 0)
	result, err := DecodeExchange(context.Background(), base, Options{})
	if err != nil || len(result.RPCs[0].RequestMessages) != MaxMessages || len(result.RPCs[0].ResponseMessages) != 0 || !result.Truncated || !has(result.RPCs[0].Errors, "grpc_message_count_limit") {
		t.Fatalf("aggregate RPC message budget bypassed: %+v %v", result, err)
	}
}
func TestGapsTruncationTLSAndMissingPrefaceExplicit(t *testing.T) {
	for _, input := range []Input{{AToB: DirectionInput{Data: []byte{22, 3, 3, 0, 10}}}, {AToB: DirectionInput{Data: []byte("PRI * HTTP/2.0")}}, {AToB: DirectionInput{Data: []byte("opaque"), PrefixMissing: true}}} {
		r, err := Decode(context.Background(), input, Options{})
		if err != nil || r.Protocol == "grpc" || len(r.RPCs) > 0 || len(r.Reasons) == 0 {
			t.Fatalf("unsupported stream guessed: %+v %v", r, err)
		}
	}
	client, server := newWire(true), newWire(false)
	client.headers(t, 1, false, requestHeaders("/x.S/M"), false)
	client.data(t, 1, true, grpcFrame([]byte("captured prefix"), 0))
	server.headers(t, 1, true, append(responseHeaders(), Header{"grpc-status", "0"}), false)
	r, err := Decode(context.Background(), Input{AToB: DirectionInput{Data: client.buf.Bytes(), Gap: true, Truncated: true}, BToA: DirectionInput{Data: server.buf.Bytes()}}, Options{})
	if err != nil || !r.Incomplete || !r.Truncated || !has(r.Reasons, "tcp_gap_stopped_decode") {
		t.Fatalf("capture holes hidden: %+v %v", r, err)
	}
}
func TestIncompleteOneRPCDoesNotTaintCompleteMultiplexedRPC(t *testing.T) {
	client, server := newWire(true), newWire(false)
	for _, id := range []uint32{1, 3} {
		client.headers(t, id, true, requestHeaders("/x.S/M"), false)
		server.headers(t, id, id == 3, append(responseHeaders(), Header{"grpc-status", "0"}), false)
	}
	r := decodeWire(t, client, server, Options{})
	if len(r.RPCs) != 2 || !r.RPCs[0].Incomplete || r.RPCs[1].Incomplete {
		t.Fatalf("independent RPC completeness merged: %+v", r)
	}
}
func TestHTTP2BoundsInvalidContinuationAndContexts(t *testing.T) {
	for _, scenario := range []string{"streamlimit", "headerlimit", "frameoversize", "continuation", "uppercase"} {
		t.Run(scenario, func(t *testing.T) {
			client, server := newWire(true), newWire(false)
			switch scenario {
			case "streamlimit":
				for i := 0; i < MaxStreams+1; i++ {
					client.headers(t, uint32(i*2+1), true, requestHeaders("/x.S/M"), false)
				}
			case "headerlimit":
				headers := requestHeaders("/x.S/M")
				headers = append(headers, Header{"x-large", strings.Repeat("x", MaxHeaderBytes)})
				client.headers(t, 1, true, headers, false)
			case "frameoversize":
				client.buf.Write([]byte{0x10, 0, 1, 0, 0, 0, 0, 0, 1})
			case "continuation":
				_ = client.framer.WriteContinuation(1, true, []byte{1, 2})
			case "uppercase":
				client.headers(t, 1, true, append(requestHeaders("/x.S/M"), Header{"X-Bad", "value"}), false)
			}
			r := decodeWire(t, client, server, Options{})
			if r.Status != "invalid" && r.Status != "limit" {
				t.Fatalf("invalid HTTP2 accepted: %+v", r)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client, server := newWire(true), newWire(false)
	client.headers(t, 1, true, requestHeaders("/x.S/M"), false)
	if _, err := Decode(ctx, Input{AToB: DirectionInput{Data: client.buf.Bytes()}, BToA: DirectionInput{Data: server.buf.Bytes()}}, Options{}); err == nil {
		t.Fatal("cancelled decode ignored")
	}
	if r, err := Decode(context.Background(), Input{AToB: DirectionInput{Data: make([]byte, MaxInputBytes+1)}}, Options{}); err != nil || r.Status != "limit" {
		t.Fatal("input budget ignored")
	}
}
func FuzzBoundedHTTP2AndGRPC(f *testing.F) {
	f.Add([]byte(clientPreface), []byte{})
	f.Add([]byte{22, 3, 3}, []byte{0, 0, 0, 0, 0})
	f.Add([]byte("opaque"), []byte{})
	f.Fuzz(func(t *testing.T, a, b []byte) {
		if len(a)+len(b) > 32<<10 {
			t.Skip()
		}
		r, err := Decode(context.Background(), Input{AToB: DirectionInput{Data: a}, BToA: DirectionInput{Data: b}}, Options{})
		if err != nil && len(r.RPCs) > MaxStreams {
			t.Fatal("stream cap")
		}
		if len(r.RPCs) > MaxStreams || r.DecodedBytes > MaxDecodedBytes {
			t.Fatal("output cap")
		}
		_, _ = DecodeExchange(context.Background(), Exchange{RequestHeaders: requestHeaders("/fuzz.S/M"), RequestBody: a, ResponseBody: b}, Options{})
	})
}

func TestProtoJSONExpansionIsBoundedBeforeMarshalling(t *testing.T) {
	binding := Binding{ServiceID: "game", ReleaseID: "release"}
	descriptor := testDescriptor(t, binding)
	// One valid protobuf string would become six JSON bytes per control byte.
	data := []byte{10}
	length := uint64(MaxMessageBytes / 3)
	for length >= 128 {
		data = append(data, byte(length)|128)
		length >>= 7
	}
	data = append(data, byte(length))
	data = append(data, bytes.Repeat([]byte{1}, MaxMessageBytes/3)...)
	_, decoded, reason := descriptor.decode(data, "/demo.Echo/Chat", false, binding)
	if len(decoded) != 0 || reason != "protobuf_json_resource_limit_or_opaque_any" {
		t.Fatalf("JSON amplification allowed: length=%d reason=%q", len(decoded), reason)
	}
}
func TestAggregateHeaderOutputBudgetAndJSONResponseBound(t *testing.T) {
	client, server := newWire(true), newWire(false)
	for i := 0; i < MaxStreams; i++ {
		client.headers(t, uint32(i*2+1), true, append(requestHeaders("/x.S/M"), Header{"x-many", strings.Repeat("x", 4000)}), false)
	}
	result := decodeWire(t, client, server, Options{})
	encoded, err := json.Marshal(result)
	if err != nil || result.Status != "limit" || result.DecodedBytes > MaxDecodedBytes || len(encoded) > 8<<20 || !has(result.Reasons, "header_output_limit") {
		t.Fatalf("header output escaped budget: bytes=%d decoded=%d status=%s err=%v", len(encoded), result.DecodedBytes, result.Status, err)
	}
}

func TestDuplicateReservedGRPCMetadataDoesNotInventStatusOrEncoding(t *testing.T) {
	exchange := Exchange{RequestHeaders: append(requestHeaders("/x.S/M"), Header{"grpc-encoding", "gzip"}, Header{"grpc-encoding", "snappy"}), ResponseHeaders: append(responseHeaders(), Header{"grpc-status", "0"}), ResponseTrailers: []Header{{"grpc-status", "7"}}, RequestComplete: true, ResponseComplete: true, RequestBody: grpcFrame([]byte("ambiguous compressed bytes"), 1)}
	result, err := DecodeExchange(context.Background(), exchange, Options{})
	if err != nil || result.RPCs[0].GRPCStatus != nil || !has(result.RPCs[0].Errors, "grpc_status_ambiguous") || !has(result.RPCs[0].Errors, "grpc_encoding_ambiguous") || result.RPCs[0].RequestMessages[0].Error != "unsupported_grpc_encoding" {
		t.Fatalf("reserved metadata assigned an arbitrary value: %+v %v", result, err)
	}
}

func TestAnyJSONExpansionRemainsOpaque(t *testing.T) {
	message := (&anypb.Any{TypeUrl: "type.googleapis.com/google.protobuf.Any", Value: []byte{1, 2, 3}}).ProtoReflect()
	nodes, left := 10000, MaxMessageBytes
	if estimateJSON(message, 0, &nodes, &left) {
		t.Fatal("Any recursively expands embedded bytes outside wire preflight")
	}
}

func TestDescriptorWireObjectBudgetBeforeUnmarshal(t *testing.T) {
	set := new(descriptorpb.FileDescriptorSet)
	if err := proto.Unmarshal(descriptorBytes(t), set); err != nil {
		t.Fatal(err)
	}
	set.File[0].SourceCodeInfo = new(descriptorpb.SourceCodeInfo)
	for i := 0; i < 10001; i++ {
		set.File[0].SourceCodeInfo.Location = append(set.File[0].SourceCodeInfo.Location, &descriptorpb.SourceCodeInfo_Location{Path: []int32{4, 0}, Span: []int32{0, 0, 1}})
	}
	raw, err := proto.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > MaxDescriptorBytes {
		t.Fatal("fixture does not exercise object count independently of byte cap")
	}
	if _, err = NewDescriptor(raw, Binding{ServiceID: "game", ReleaseID: "release"}); err == nil || !strings.Contains(err.Error(), "wire/object budget") {
		t.Fatalf("descriptor tiny repeated messages bypassed pre-allocation budget: %v", err)
	}
	// A large opaque source comment uses bytes, not a hidden message count.
	set.File[0].SourceCodeInfo.Location = []*descriptorpb.SourceCodeInfo_Location{{Path: []int32{4, 0}, Span: []int32{0, 0, 1}, LeadingComments: proto.String(strings.Repeat("x", 1<<20))}}
	raw, err = proto.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewDescriptor(raw, Binding{ServiceID: "game", ReleaseID: "release"}); err != nil {
		t.Fatalf("opaque text incorrectly recursed as descriptor objects: %v", err)
	}
}
