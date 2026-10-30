package traffic

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
)

func TestOpaqueGRPCCaptureNeedsExplicitH2ProvenanceAndStaysOutOfLists(t *testing.T) {
	s, clock := recorder(t, nil)
	raw := []byte{0, 0, 0, 0, 9, 0, 0xff, 's', 'e', 'c', 'r', 'e', 't', '!'}
	e := observation(clock, "grpc-capture", "game")
	e.HTTPProtocol = "h2"
	e.Method = "POST"
	e.URL = "/test.Service/Method"
	e.RequestBytes = int64(len(raw))
	e.ResponseBytes = int64(len(raw))
	e.RequestHeaders = http.Header{"Content-Type": {"application/grpc+proto"}, "Authorization": {"private-header"}}
	e.RequestTrailers = http.Header{"X-Client-Metadata": {"visible"}, "X-Api-Key": {"private-trailer"}}
	e.ResponseTrailers = http.Header{"Grpc-Status": {"0"}, "Grpc-Message": {"ok"}, "Cookie": {"private-cookie"}}
	e.RequestBody = Body{SensitiveRaw: true, Encoding: "base64", Data: base64.StdEncoding.EncodeToString(raw), ObservedBytes: int64(len(raw)), CapturedBytes: int64(len(raw)), ContentType: "application/grpc+proto"}
	e.ResponseBody = e.RequestBody
	if _, err := s.Ingest(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	page, err := s.List(context.Background(), Query{})
	if err != nil {
		t.Fatal(err)
	}
	serialized, _ := json.Marshal(page)
	for _, private := range [][]byte{[]byte(e.RequestBody.Data), []byte("request_trailers"), []byte("response_body"), []byte("private-trailer")} {
		if bytes.Contains(serialized, private) {
			t.Fatal("metadata API leaked sensitive gRPC bytes/trailers")
		}
	}
	detail, err := s.Detail(context.Background(), e.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(detail.RequestBody.Data)
	if err != nil || !bytes.Equal(decoded, raw) || !detail.RequestBody.SensitiveRaw || detail.RequestTrailers.Get("X-Api-Key") != "[REDACTED]" || detail.ResponseTrailers.Get("Cookie") != "[REDACTED]" || detail.ResponseTrailers.Get("Grpc-Status") != "0" {
		t.Fatalf("opaque capture/independent trailer redaction incorrect: %v", err)
	}
	bad := e
	bad.RequestID = "grpc-without-raw"
	bad.RequestBody.SensitiveRaw = false
	bad.ResponseBody.SensitiveRaw = false
	if _, err := s.Ingest(context.Background(), bad); err != nil {
		t.Fatal(err)
	}
	omitted, err := s.Detail(context.Background(), bad.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if omitted.RequestBody.Data != "" || omitted.RequestBody.NotCapturedReason != "unsupported_body_format" {
		t.Fatal("old redacted profile silently enabled opaque binary retention")
	}
	for _, change := range []func(*Exchange){func(e *Exchange) { e.HTTPProtocol = "http/1.1" }, func(e *Exchange) { e.HTTPProtocol = "HTTP/3" }, func(e *Exchange) { e.RequestBody.ContentType = "application/grpcevil" }, func(e *Exchange) { e.RequestBody.CapturedBytes-- }, func(e *Exchange) { e.RequestBody.Encoding = "utf8" }} {
		bad := e
		bad.RequestID = "invalid-grpc"
		change(&bad)
		if _, err := s.Ingest(context.Background(), bad); err == nil {
			t.Fatal("invalid sensitive raw body accepted")
		}
	}
}

func TestGRPCObservationCannotChangeItsHTTPProtocolProvenance(t *testing.T) {
	s, clock := recorder(t, nil)
	e := observation(clock, "grpc-progress", "game")
	e.HTTPProtocol = "h2"
	e.State = "in_progress"
	e.EndAt = nil
	if _, err := s.Ingest(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	e.HTTPProtocol = "http/1.1"
	if _, err := s.Ingest(context.Background(), e); err != ErrConflict {
		t.Fatalf("protocol identity changed: %v", err)
	}
}
