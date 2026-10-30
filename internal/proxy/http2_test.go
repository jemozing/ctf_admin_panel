package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func grpcTestFrame(payload string) []byte {
	b := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(b[1:5], uint32(len(payload)))
	copy(b[5:], payload)
	return b
}
func h2Fixture(t *testing.T, handler http.Handler) (*Engine, Route, *http.Client, *collected) {
	t.Helper()
	up := httptest.NewServer(h2c.NewHandler(handler, &http2.Server{MaxConcurrentStreams: 128, MaxReadFrameSize: 16384}))
	t.Cleanup(up.Close)
	dir := t.TempDir()
	now := time.Now()
	roots, _ := testCertificate(t, dir, "h2-cert", []string{"game.test"}, now.Add(-time.Hour), now.Add(time.Hour))
	e, r := testTLSEngine(t, up.URL, dir)
	sink := &collected{}
	e.options.Sink = sink
	r.Protocol, r.Host, r.TLS = "https2", "game.test", &TLSRoutePolicy{CertificateID: "h2-cert"}
	r.Capture.Mode = "grpc_body"
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 2, Routes: []Route{r}}); err != nil {
		t.Fatal(err)
	}
	client := trustedH2Client(t, r, roots)
	return e, r, client, sink
}
func trustedH2Client(t *testing.T, r Route, roots *x509.CertPool) *http.Client {
	t.Helper()
	tr := &http2.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "game.test"}, DialTLSContext: func(ctx context.Context, network, _ string, cfg *tls.Config) (net.Conn, error) {
		return (&tls.Dialer{Config: cfg, NetDialer: &net.Dialer{Timeout: time.Second}}).DialContext(ctx, network, r.Listen)
	}}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 4 * time.Second}
}
func doGRPC(t *testing.T, client *http.Client, path string, body io.Reader) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest("POST", "https://game.test"+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc+proto")
	req.Header.Set("Te", "trailers")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return response, data
}

func TestHTTP2TLSGRPCUnaryPreservesBytesAndBothTrailers(t *testing.T) {
	requestBody := grpcTestFrame("\x00binary\xffpayload")
	var gotRequestTrailer string
	_, _, client, sink := h2Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("upstream not H2: %s", r.Proto)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		gotRequestTrailer = r.Trailer.Get("X-Client-Trailer")
		w.Header().Set("Content-Type", "application/grpc+proto")
		w.Header().Add("Trailer", "Grpc-Status, Grpc-Message, X-Custom-Trailer, X-Api-Key")
		w.WriteHeader(200)
		_, _ = w.Write(body)
		w.Header().Set("Grpc-Status", "0")
		w.Header().Set("Grpc-Message", "done")
		w.Header().Set("X-Custom-Trailer", "visible")
		w.Header().Set("X-Api-Key", "secret-trailer")
	}))
	req, _ := http.NewRequest("POST", "https://game.test/test.Echo/Unary", bytes.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/grpc+proto")
	req.Header.Set("Authorization", "Bearer private")
	req.Header.Set("Te", "trailers")
	req.Trailer = http.Header{"X-Client-Trailer": {"client-value"}}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.ProtoMajor != 2 || !bytes.Equal(body, requestBody) || response.Trailer.Get("Grpc-Status") != "0" || response.Trailer.Get("X-Api-Key") != "secret-trailer" || gotRequestTrailer != "client-value" {
		t.Fatalf("wire bytes/trailers changed: H2=%d trailer=%v req=%q", response.ProtoMajor, response.Trailer, gotRequestTrailer)
	}
	record := waitFinal(t, sink)
	captured, err := base64.StdEncoding.DecodeString(record.ResponseBody.Data)
	if err != nil {
		t.Fatal(err)
	}
	if record.HTTPProtocol != "h2" || !record.RequestBody.SensitiveRaw || !record.ResponseBody.SensitiveRaw || !bytes.Equal(captured, requestBody) || record.ResponseTrailers.Get("Grpc-Status") != "0" || record.ResponseTrailers.Get("X-Api-Key") != "[REDACTED]" || record.RequestTrailers.Get("X-Client-Trailer") != "client-value" || record.RequestHeaders.Get("Authorization") != "[REDACTED]" {
		t.Fatalf("capture provenance/bodies/trailers incorrect: %+v", record)
	}
}

func TestHTTP2TLSBidirectionalStreamingDoesNotWaitForRequestEOF(t *testing.T) {
	first, second := grpcTestFrame("one"), grpcTestFrame("two")
	_, _, client, _ := h2Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		for range 2 {
			chunk := make([]byte, len(first))
			if _, err := io.ReadFull(r.Body, chunk); err != nil {
				return
			}
			_, _ = w.Write(chunk)
			w.(http.Flusher).Flush()
		}
		w.Header().Set("Grpc-Status", "0")
	}))
	reader, writer := io.Pipe()
	t.Cleanup(func() { reader.Close(); writer.Close() })
	req, _ := http.NewRequest("POST", "https://game.test/test.Echo/Bidi", reader)
	req.Header.Set("Content-Type", "application/grpc")
	done := make(chan error, 1)
	go func() { _, err := writer.Write(first); done <- err }()
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	chunk := make([]byte, len(first))
	if _, err := io.ReadFull(response.Body, chunk); err != nil || !bytes.Equal(chunk, first) {
		t.Fatalf("first response delayed until request EOF: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	go func() {
		_, err := writer.Write(second)
		if err == nil {
			err = writer.Close()
		}
		done <- err
	}()
	rest, err := io.ReadAll(response.Body)
	if err != nil || !bytes.Equal(rest, second) || response.Trailer.Get("Grpc-Status") != "0" {
		t.Fatalf("stream remainder/trailers: %q %v %v", rest, response.Trailer, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestHTTP2TLSMultiplexAndCancellationArePerStream(t *testing.T) {
	cancelled := make(chan struct{}, 1)
	var active, peak atomic.Int32
	_, _, client, _ := h2Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cancel" {
			<-r.Context().Done()
			cancelled <- struct{}{}
			return
		}
		n := active.Add(1)
		defer active.Add(-1)
		for {
			old := peak.Load()
			if n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		_, _ = w.Write(body)
		w.Header().Set("Grpc-Status", "0")
	}))
	doGRPC(t, client, "/warmup", bytes.NewReader(grpcTestFrame("warmup")))
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for n := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := grpcTestFrame(fmt.Sprintf("message-%d", n))
			req, _ := http.NewRequest("POST", "https://game.test/test.Echo/Unary", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/grpc")
			res, err := client.Do(req)
			if err == nil {
				var b []byte
				b, err = io.ReadAll(res.Body)
				res.Body.Close()
				if !bytes.Equal(b, payload) || res.Trailer.Get("Grpc-Status") != "0" {
					err = fmt.Errorf("stream mixed")
				}
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if peak.Load() < 2 {
		t.Fatal("requests were serialized instead of multiplexed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://game.test/cancel", bytes.NewReader(grpcTestFrame("cancel")))
	req.Header.Set("Content-Type", "application/grpc")
	done := make(chan error, 1)
	go func() { _, err := client.Do(req); done <- err }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancelled stream succeeded")
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("upstream stream context not cancelled")
	}
	res, _ := doGRPC(t, client, "/still-working", bytes.NewReader(grpcTestFrame("alive")))
	if res.StatusCode != 200 {
		t.Fatal("one cancelled stream poisoned sibling requests")
	}
}

func TestHTTP2TLSProfileIsExplicitAndWAFCountsRPCStarts(t *testing.T) {
	var upstream atomic.Int32
	e, r, client, _ := h2Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream.Add(1)
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(200)
		w.Header().Set("Grpc-Status", "0")
	}))
	r.WAF.Mode = "enforce"
	r.WAF.RatePerSecond = 1
	r.WAF.Burst = 1
	r.WAF.ViolationThreshold = 10
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 3, Routes: []Route{r}}); err != nil {
		t.Fatal(err)
	}
	first, _ := doGRPC(t, client, "/one", bytes.NewReader(append(grpcTestFrame("a"), grpcTestFrame("b")...)))
	second, _ := doGRPC(t, client, "/two", bytes.NewReader(grpcTestFrame("c")))
	if first.StatusCode != 200 || second.StatusCode != 429 || second.Header.Get("Retry-After") == "" || upstream.Load() != 1 {
		t.Fatalf("RPC start WAF semantics incorrect: %d %d upstream%d", first.StatusCode, second.StatusCode, upstream.Load())
	}
	untrusted := trustedH2Client(t, r, x509.NewCertPool())
	req, _ := http.NewRequest("POST", "https://game.test/no-trust", nil)
	if response, err := untrusted.Do(req); err == nil {
		response.Body.Close()
		t.Fatal("TLS accepted untrusted certificate")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: client.Transport.(*http2.Transport).TLSClientConfig.RootCAs, ServerName: "game.test"}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, r.Listen)
	}}
	defer tr.CloseIdleConnections()
	h1 := &http.Client{Transport: tr, Timeout: time.Second}
	if response, err := h1.Get("https://game.test/not-h2"); err == nil {
		response.Body.Close()
		if response.StatusCode == 200 {
			t.Fatal("HTTPS/2 profile silently served HTTP1")
		}
	}
	bad := r
	bad.Protocol = "https1"
	if _, err := NormalizePolicy(Policy{SchemaVersion: 1, Revision: 4, Routes: []Route{bad}}); err == nil {
		t.Fatal("opaque gRPC capture enabled on HTTP1")
	}
	bad = r
	bad.Upstream = "http://203.0.113.2:1234"
	if _, err := NormalizePolicy(Policy{SchemaVersion: 1, Revision: 4, Routes: []Route{bad}}); err == nil {
		t.Fatal("non-loopback H2 origin accepted")
	}
}

func TestOpaqueGRPCCaptureIsExplicitBoundedAndNeverClaimsRedaction(t *testing.T) {
	raw := grpcTestFrame(strings.Repeat("secret", 20))
	policy := DefaultRoute().Capture
	policy.Mode = "grpc_body"
	policy.MaxBodyBytes = 16
	c := newBodyCapture(policy, http.Header{"Content-Type": {"application/grpc+proto"}}, newRedactor(policy))
	c.write(raw)
	c.mu.Lock()
	c.complete = true
	c.mu.Unlock()
	b := c.snapshot()
	data, _ := base64.StdEncoding.DecodeString(b.Data)
	if !b.SensitiveRaw || !b.Truncated || len(data) != 16 || !bytes.Equal(data, raw[:16]) {
		t.Fatalf("opaque prefix not explicitly bounded: %+v", b)
	}
	policy.BodyPatterns = []string{"secret"}
	c = newBodyCapture(policy, http.Header{"Content-Type": {"application/grpc"}}, newRedactor(policy))
	c.write(raw)
	c.mu.Lock()
	c.complete = true
	c.mu.Unlock()
	b = c.snapshot()
	if b.Data != "" || b.NotCapturedReason != "opaque_grpc_redaction_unavailable" {
		t.Fatal("opaque bytes bypassed configured body redaction")
	}
	policy.BodyPatterns = nil
	policy.RedactHeaders = []string{"content-type"}
	c = newBodyCapture(policy, http.Header{"Content-Type": {"application/grpc"}}, newRedactor(policy))
	c.write(raw)
	c.mu.Lock()
	c.complete = true
	c.mu.Unlock()
	b = c.snapshot()
	if b.Data != "" || b.SensitiveRaw || b.NotCapturedReason != "grpc_content_metadata_redacted" {
		t.Fatal("hidden content metadata caused unsafe raw capture")
	}

}

func TestHTTP2CertificateFailureKeepsLKGAndRestoresProtocolAfterRestart(t *testing.T) {
	e, r, client, _ := h2Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(200)
		w.Header().Set("Grpc-Status", "0")
	}))
	bad := r
	bad.TLS = &TLSRoutePolicy{CertificateID: "missing-profile"}
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 3, Routes: []Route{bad}}); err == nil {
		t.Fatal("missing H2 TLS profile accepted")
	}
	res, _ := doGRPC(t, client, "/still-lkg", bytes.NewReader(grpcTestFrame("safe")))
	if res.StatusCode != 200 || e.Status().AppliedRevision != 2 || e.Status().LastError == "" {
		t.Fatal("TLS failure replaced active H2 policy")
	}
	options := e.options
	options.Listen = net.Listen
	shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := e.Close(shutdown); err != nil {
		t.Fatal(err)
	}
	restored, err := NewEngine(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = restored.Close(ctx)
	})
	if err := restored.Restore(); err != nil {
		t.Fatal(err)
	}
	fresh := trustedH2Client(t, r, client.Transport.(*http2.Transport).TLSClientConfig.RootCAs)
	res, _ = doGRPC(t, fresh, "/restored", bytes.NewReader(grpcTestFrame("again")))
	if res.ProtoMajor != 2 || res.Trailer.Get("Grpc-Status") != "0" || restored.Status().AppliedRevision != 2 {
		t.Fatal("restart lost H2 policy or original TLS pins")
	}
}

func TestHTTP2UpstreamHeaderTimeoutIsBoundedAndCancelsRPC(t *testing.T) {
	cancelled := make(chan struct{}, 1)
	e, r, client, _ := h2Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done(); cancelled <- struct{}{} }))
	r.Limits.UpstreamResponseHeaderTimeoutSeconds = 1
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 3, Routes: []Route{r}}); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	response, _ := doGRPC(t, client, "/never-headers", bytes.NewReader(grpcTestFrame("wait")))
	if response.StatusCode != 502 || time.Since(started) > 3*time.Second {
		t.Fatal("upstream headers were not bounded")
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("timed out upstream RPC not cancelled")
	}
}

func TestHTTP2PreflightVerifiesProtocolWithoutCallingAnApplication(t *testing.T) {
	var calls atomic.Int32
	h2 := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }), &http2.Server{}))
	defer h2.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := ProbeHTTP2Origins(ctx, []string{h2.URL, h2.URL}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("HTTP/2 protocol preflight invoked an application RPC")
	}
	h1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(400) }))
	defer h1.Close()
	if err := ProbeHTTP2Origins(context.Background(), []string{h1.URL}); err == nil {
		t.Fatal("HTTP1-only backend accepted for H2 termination")
	}
	for _, origin := range []string{"http://localhost:1234", "http://203.0.113.2:1234", "https://127.0.0.1:1234", "http://127.0.0.1:1234/other", "http://a@127.0.0.1:1234", "http://127.0.0.1", "http://127.0.0.1:1234?x=y"} {
		if err := ProbeHTTP2Origins(context.Background(), []string{origin}); err == nil {
			t.Fatalf("arbitrary probe allowed: %s", origin)
		}
	}
	if err := ProbeHTTP2Origins(context.Background(), nil); err == nil {
		t.Fatal("empty probe accepted")
	}
}

func TestHTTP2HostProbeBoundaryUsesExactCurrentAddresses(t *testing.T) {
	local := []netip.Addr{netip.MustParseAddr("192.168.50.202"), netip.MustParseAddr("2001:db8:1::2")}
	for _, tc := range []struct {
		ip          string
		allow, want bool
	}{{"192.168.50.202", true, true}, {"::ffff:192.168.50.202", true, true}, {"192.168.50.202", false, false}, {"192.168.50.201", true, false}, {"2001:db8:1::2", true, true}, {"2001:db8:1::3", true, false}, {"127.0.0.1", false, true}, {"0.0.0.0", true, false}, {"::", true, false}, {"fe80::1", true, false}, {"224.0.0.1", true, false}} {
		if got := approvedH2ProbeIP(netip.MustParseAddr(tc.ip), tc.allow, local); got != tc.want {
			t.Fatalf("probe boundary widened %s allow%t got%t", tc.ip, tc.allow, got)
		}
	}
}
