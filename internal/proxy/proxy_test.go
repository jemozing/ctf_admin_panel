package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/ctf-service-manager/ctf-service-manager/internal/traffic"
)

type collected struct {
	mu     sync.Mutex
	events []traffic.Exchange
	gate   <-chan struct{}
}

func (c *collected) Submit(e traffic.Exchange) bool {
	if c.gate != nil {
		<-c.gate
	}
	c.mu.Lock()
	c.events = append(c.events, e)
	c.mu.Unlock()
	return true
}
func (c *collected) all() []traffic.Exchange {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]traffic.Exchange(nil), c.events...)
}
func waitFinal(t *testing.T, c *collected) traffic.Exchange {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, e := range c.all() {
			if e.State != "in_progress" {
				return e
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("final exchange missing")
	return traffic.Exchange{}
}

func testEngine(t *testing.T, upstream string, c Sink) (*Engine, Route) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	used := false
	e, err := NewEngine(Options{StateDirectory: filepath.Join(t.TempDir(), "state"), Sink: c, Listen: func(network, addr string) (net.Listener, error) {
		if addr == address && !used {
			used = true
			return listener, nil
		}
		return net.Listen(network, addr)
	}})
	if err != nil {
		t.Fatal(err)
	}
	r := DefaultRoute()
	r.ID = "route-test"
	r.ServiceID = "service-test"
	r.Component = "app"
	r.Listen = address
	r.Upstream = upstream
	r.WAF.Mode = "off"
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 1, Routes: []Route{r}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = e.Close(ctx)
		_ = listener.Close()
	})
	return e, r
}

func request(t *testing.T, r Route, method, path, body string, headers http.Header) (int, string, http.Header) {
	t.Helper()
	q, err := http.NewRequest(method, "http://"+r.Listen+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	q.Header = headers
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	response, err := client.Do(q)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, string(data), response.Header
}

func TestForwardingCaptureRedactionAndUntrustedForwardedHeaders(t *testing.T) {
	var forwarded http.Header
	var gotBody string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = r.Header.Clone()
		data, _ := io.ReadAll(r.Body)
		gotBody = string(data)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "session=upstream-secret")
		fmt.Fprint(w, `{"token":"response-secret","ok":true}`)
	}))
	defer up.Close()
	c := &collected{}
	e, r := testEngine(t, up.URL, c)
	r.Capture.Mode = "bounded_body"
	p := Policy{SchemaVersion: 1, Revision: 2, Routes: []Route{r}}
	if err := e.Apply(p); err != nil {
		t.Fatal(err)
	}
	status, body, _ := request(t, r, "POST", "/raw?q=1&token=url-secret", `{"password":"body-secret","value":2}`, http.Header{"Content-Type": {"application/json"}, "Authorization": {"Bearer request-secret"}, "X-Forwarded-For": {"203.0.113.4"}, "Forwarded": {"for=203.0.113.5"}, "X-Real-Ip": {"203.0.113.6"}})
	if status != 200 || !strings.Contains(body, "response-secret") || !strings.Contains(gotBody, "body-secret") {
		t.Fatal("proxy altered application payload")
	}
	if forwarded.Get("Forwarded") != "" || forwarded.Get("X-Forwarded-For") != "127.0.0.1" || forwarded.Get("X-Real-Ip") != "127.0.0.1" {
		t.Fatal("spoofed client IP reached upstream")
	}
	x := waitFinal(t, c)
	encoded, _ := json.Marshal(x)
	for _, secret := range []string{"request-secret", "response-secret", "body-secret", "url-secret", "upstream-secret"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("capture exposed %s", secret)
		}
	}
	if x.State != "completed" || x.ClientIP != "127.0.0.1" || x.RequestBody.CapturedBytes > x.RequestBody.ObservedBytes || !strings.Contains(x.RequestBody.Data, "[REDACTED]") {
		t.Fatalf("wrong capture: %+v", x)
	}
}

func TestLargeChunkedBinaryAndCompressedBodiesForwardWithoutUnsafeCapture(t *testing.T) {
	payload := bytes.Repeat([]byte{0xff, 0x00, 0x12}, 10000)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		if !bytes.Equal(data, payload) {
			t.Error("upload changed")
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		for i := 0; i < len(data); i += 777 {
			end := i + 777
			if end > len(data) {
				end = len(data)
			}
			_, _ = w.Write(data[i:end])
			w.(http.Flusher).Flush()
		}
	}))
	defer up.Close()
	c := &collected{}
	e, r := testEngine(t, up.URL, c)
	r.Capture.Mode = "bounded_body"
	r.Capture.MaxBodyBytes = 128
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 2, Routes: []Route{r}}); err != nil {
		t.Fatal(err)
	}
	_, data, _ := request(t, r, "POST", "/upload", string(payload), http.Header{"Content-Type": {"application/octet-stream"}})
	if !bytes.Equal([]byte(data), payload) {
		t.Fatal("binary response changed")
	}
	x := waitFinal(t, c)
	if x.RequestBytes != int64(len(payload)) || x.ResponseBytes != int64(len(payload)) || x.RequestBody.Data != "" || x.ResponseBody.Data != "" || !x.Truncated {
		t.Fatalf("unbounded or incorrect capture: %+v", x)
	}
}

func TestStreamingProgressOmitsPartialSecretsAndFlushes(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: half-secret-")
		w.(http.Flusher).Flush()
		close(started)
		<-release
		fmt.Fprint(w, "tail\n\n")
	}))
	defer up.Close()
	c := &collected{}
	e, r := testEngine(t, up.URL, c)
	r.Capture.Mode = "bounded_body"
	r.Capture.BodyPatterns = []string{"half-secret-tail"}
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 2, Routes: []Route{r}}); err != nil {
		t.Fatal(err)
	}
	response, err := http.Get("http://" + r.Listen + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	<-started
	buffer := make([]byte, 5)
	if _, err := io.ReadFull(response.Body, buffer); err != nil {
		t.Fatal("SSE did not flush")
	}
	time.Sleep(1100 * time.Millisecond)
	for _, x := range c.all() {
		if x.RequestBody.Data != "" || x.ResponseBody.Data != "" {
			t.Fatal("partial streaming secret was published")
		}
	}
	close(release)
	_, _ = io.ReadAll(response.Body)
	final := waitFinal(t, c)
	if strings.Contains(final.ResponseBody.Data, "half-secret") {
		t.Fatal("cross-chunk secret not redacted")
	}
}

func TestWebsocketUpgradeAndCounters(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer connection.CloseNow()
		kind, data, err := connection.Read(r.Context())
		if err == nil {
			_ = connection.Write(r.Context(), kind, data)
		}
	}))
	defer up.Close()
	c := &collected{}
	_, r := testEngine(t, up.URL, c)
	connection, _, err := websocket.Dial(context.Background(), "ws://"+r.Listen+"/socket", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.Write(context.Background(), websocket.MessageText, []byte("opaque frame")); err != nil {
		t.Fatal(err)
	}
	_, data, err := connection.Read(context.Background())
	if err != nil || string(data) != "opaque frame" {
		t.Fatal("WebSocket forwarding failed")
	}
	_ = connection.Close(websocket.StatusNormalClosure, "done")
	x := waitFinal(t, c)
	if x.Status != 101 || x.ResponseBody.Data != "" || x.ResponseBody.NotCapturedReason != "websocket_frames_not_captured" || x.RequestBytes == 0 || x.ResponseBytes == 0 {
		t.Fatalf("invalid handshake counters: %+v", x)
	}
}

func TestBadPolicyAndBindFailureRetainLiveRevisionAndExactRepeat(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer up.Close()
	e, r := testEngine(t, up.URL, &collected{})
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	bad := r
	bad.ID = "route-busy"
	bad.Listen = busy.Addr().String()
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 2, Routes: []Route{r, bad}}); err == nil {
		t.Fatal("occupied port accepted")
	}
	if e.Status().AppliedRevision != 1 {
		t.Fatal("failed apply changed live revision")
	}
	if status, body, _ := request(t, r, "GET", "/", "", nil); status != 200 || body != "ok" {
		t.Fatal("LKG no longer routes")
	}
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 1, Routes: []Route{r}}); err != nil {
		t.Fatal("exact repeat rejected")
	}
	r.Upstream = "http://127.0.0.1:1"
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 1, Routes: []Route{r}}); err == nil {
		t.Fatal("same revision changed content")
	}
}

func TestWAFRateBurstObserveEnforceExpiryRestartAndIsolation(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 30, 1, 0, 0, 0, time.UTC)
	w := newWAF(dir, 4, false, now)
	r := DefaultRoute()
	r.ID = "route"
	r.ServiceID = "service"
	r.WAF.Mode = "enforce"
	r.WAF.RatePerSecond = 1
	r.WAF.Burst = 1
	r.WAF.ViolationThreshold = 2
	r.WAF.BanTTLSeconds = 2
	if w.check(r, "192.0.2.1", now).blocked {
		t.Fatal("initial burst denied")
	}
	if d := w.check(r, "192.0.2.1", now); !d.blocked || d.reason != "request_rate" {
		t.Fatal("rate not enforced")
	}
	if d := w.check(r, "192.0.2.1", now); !d.blocked || d.reason != "autoban" {
		t.Fatal("autoban missing")
	}
	restarted := newWAF(dir, 4, true, now.Add(time.Second))
	if d := restarted.check(r, "192.0.2.1", now.Add(time.Second)); !d.blocked || d.retryAfter != 1 {
		t.Fatal("ban did not preserve absolute expiry")
	}
	other := r
	other.ServiceID = "other"
	if restarted.check(other, "192.0.2.1", now).blocked {
		t.Fatal("service scopes mixed")
	}
	if restarted.check(r, "192.0.2.1", now.Add(3*time.Second)).blocked {
		t.Fatal("expired ban prolonged")
	}
	r.WAF.Mode = "observe_only"
	for range 5 {
		if w.check(r, "192.0.2.2", now).blocked {
			t.Fatal("observe-only blocked")
		}
	}
}

func TestWAFBoundedStateAndPersistentFailureFailClosed(t *testing.T) {
	now := time.Now()
	w := newWAF(t.TempDir(), 2, false, now)
	r := DefaultRoute()
	r.ID = "route"
	r.ServiceID = "service"
	r.WAF.Mode = "enforce"
	r.WAF.MaxIPStates = 2
	r.WAF.Burst = 1
	r.WAF.ViolationThreshold = 1
	w.check(r, "192.0.2.1", now)
	w.check(r, "192.0.2.2", now)
	if d := w.check(r, "192.0.2.3", now); !d.blocked || d.reason != "ip_state_capacity" {
		t.Fatal("IP churn exceeded capacity")
	}
	w.directory = filepath.Join(t.TempDir(), "missing")
	if d := w.check(r, "192.0.2.1", now); !d.blocked || d.reason != "waf_state_unavailable" {
		t.Fatal("persistence failure not explicit")
	}
	if !w.check(r, "198.51.100.1", now).blocked {
		t.Fatal("degraded WAF failed open")
	}
}

func TestTrustedChainRejectsAmbiguityAndNormalizesMappedAddresses(t *testing.T) {
	r := httptest.NewRequest("GET", "http://service/", nil)
	r.RemoteAddr = "[::ffff:192.0.2.3]:123"
	r.Header.Set("X-Forwarded-For", "203.0.113.7, 192.0.2.2")
	peer, ip, source, err := ClientIP(r, []string{"192.0.2.0/24"})
	if err != nil || peer != "192.0.2.3" || ip != "203.0.113.7" || source != "trusted_x_forwarded_for" {
		t.Fatalf("bad trusted chain %s %s %s %v", peer, ip, source, err)
	}
	r.Header.Set("Forwarded", "for=198.51.100.2")
	if _, _, _, err := ClientIP(r, []string{"192.0.2.0/24"}); err == nil {
		t.Fatal("ambiguous chain accepted")
	}
	_, ip, _, err = ClientIP(r, nil)
	if err != nil || ip != "192.0.2.3" {
		t.Fatal("untrusted headers changed effective IP")
	}
}

func TestRecorderBlockCannotHoldForwardingAndControlRequiresToken(t *testing.T) {
	gate := make(chan struct{})
	c := &collected{gate: gate}
	defer close(gate)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer up.Close()
	e, r := testEngine(t, up.URL, c)
	for range 50 {
		if status, _, _ := request(t, r, "GET", "/", "", nil); status != 200 {
			t.Fatal("recorder blocked forwarding")
		}
	}
	if e.Status().Counters.CaptureDropped == 0 {
		t.Fatal("queue overload hidden")
	}
	h, err := e.ControlHandler(strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	q := httptest.NewRequest("GET", "http://private/v1/status", nil)
	out := httptest.NewRecorder()
	h.ServeHTTP(out, q)
	if out.Code != 401 {
		t.Fatal("unauthenticated control allowed")
	}
	q = httptest.NewRequest("GET", "http://private/v1/status", nil)
	q.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 32))
	out = httptest.NewRecorder()
	h.ServeHTTP(out, q)
	if out.Code != 200 {
		t.Fatal("authenticated status rejected")
	}
}

func TestControlStatusReportsAppliedNonLoopbackListeners(t *testing.T) {
	e, err := NewEngine(Options{StateDirectory: filepath.Join(t.TempDir(), "state"), Listen: func(_, address string) (net.Listener, error) {
		if address == "0.0.0.0:8071" {
			return nil, fmt.Errorf("test port is occupied")
		}
		return net.Listen("tcp4", "127.0.0.1:0")
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close(context.Background()) })
	const token = "test-status-control-token-0000000000000"
	handler, err := e.ControlHandler(token)
	if err != nil {
		t.Fatal(err)
	}
	readStatus := func() controlStatus {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		var status controlStatus
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &status) != nil {
			t.Fatalf("unexpected status response: %d %s", response.Code, response.Body.String())
		}
		return status
	}
	if got := readStatus(); got.PublicPortsByService == nil || len(got.PublicPortsByService) != 0 {
		t.Fatalf("new proxy should report known empty active listeners, got %+v", got)
	}
	public := DefaultRoute()
	public.ID, public.ServiceID, public.Component = "public", "bimba", "app"
	public.Listen, public.Upstream = "0.0.0.0:8070", "http://127.0.0.1:29080"
	private := public
	private.ID, private.Listen = "private", "127.0.0.2:29081"
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 1, Routes: []Route{public, private}}); err != nil {
		t.Fatal(err)
	}
	public.Listen = "0.0.0.0:8071"
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 2, Routes: []Route{public}}); err == nil {
		t.Fatal("proxy accepted an occupied port")
	}
	got := readStatus()
	if got.DesiredRevision != 2 || got.AppliedRevision != 1 || !slices.Equal(got.PublicPortsByService["bimba"], []int{8070}) {
		t.Fatalf("status did not preserve the previous applied public listener: %+v", got)
	}
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 3}); err != nil {
		t.Fatal(err)
	}
	if got := readStatus(); got.AppliedRevision != 3 || got.PublicPortsByService == nil || len(got.PublicPortsByService) != 0 {
		t.Fatalf("removed proxy listener is still reported: %+v", got)
	}
}

func TestPolicyFileRejectsLinksAndEmergencyPreservesMode(t *testing.T) {
	dir := t.TempDir()
	r := DefaultRoute()
	r.ID = "route"
	r.ServiceID = "service"
	r.Component = "app"
	r.Listen = "127.0.0.1:19000"
	r.Upstream = "http://127.0.0.1:18000"
	p := Policy{SchemaVersion: 1, Revision: 1, Routes: []Route{r}}
	file := filepath.Join(dir, "policy.json")
	b, _ := json.Marshal(p)
	if err := os.WriteFile(file, b, 0640); err != nil {
		t.Fatal(err)
	}
	release, err := LockPolicyDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	p.Revision = 2
	p.Routes[0].WAF.Mode = "off"
	if err := WriteDesiredPolicy(file, p, PolicyDigest(Policy{SchemaVersion: 1, Revision: 1, Routes: []Route{r}})); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(file)
	if st.Mode().Perm() != 0640 {
		t.Fatal("emergency changed file permissions")
	}
	link := filepath.Join(dir, "link")
	_ = os.Symlink(file, link)
	if _, err := LoadPolicyFile(link); err == nil {
		t.Fatal("policy symlink followed")
	}
}

type storeSink struct {
	store  *traffic.Store
	mu     sync.Mutex
	errors []error
}

func (s *storeSink) Submit(e traffic.Exchange) bool {
	_, err := s.store.Ingest(context.Background(), e)
	if err != nil {
		s.mu.Lock()
		s.errors = append(s.errors, err)
		s.mu.Unlock()
	}
	return err == nil
}

func TestEngineToRealRecorderKeepsMetadataAndRedactedDetail(t *testing.T) {
	store, err := traffic.Open(traffic.Config{StateDirectory: filepath.Join(t.TempDir(), "traffic")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sink := &storeSink{store: store}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"token":"x","value":"safe"}`)
	}))
	defer up.Close()
	e, r := testEngine(t, up.URL, sink)
	r.Capture.Mode = "bounded_body"
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 2, Routes: []Route{r}}); err != nil {
		t.Fatal(err)
	}
	_, _, _ = request(t, r, "GET", "/?password=private", "", http.Header{"Authorization": {"Bearer private"}})
	deadline := time.Now().Add(time.Second)
	var page traffic.Page
	for time.Now().Before(deadline) {
		page, err = store.List(context.Background(), traffic.Query{Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Records) == 1 && page.Records[0].State == "completed" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if len(page.Records) != 1 || page.Records[0].State != "completed" {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		t.Fatalf("real recorder rejected exchange: %v; page %+v", sink.errors, page)
	}
	detail, err := store.Detail(context.Background(), page.Records[0].RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(detail.ResponseBody.Data, `"x"`) || !strings.Contains(detail.ResponseBody.Data, "[REDACTED]") {
		t.Fatal("payload was not redacted before storage")
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.errors) > 0 {
		t.Fatalf("recorder rejected an intermediate/final event: %v", sink.errors)
	}
}

func TestPreflightNoPolicyWriteAndRejectsUnreachableOrOccupied(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("preflight made application HTTP request") }))
	defer up.Close()
	e, err := NewEngine(Options{StateDirectory: filepath.Join(t.TempDir(), "proxy")})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(context.Background())
	port, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := port.Addr().String()
	_ = port.Close()
	r := DefaultRoute()
	r.ID = "route"
	r.ServiceID = "service"
	r.Component = "app"
	r.Listen = address
	r.Upstream = up.URL
	p := Policy{SchemaVersion: 1, Revision: 1, Routes: []Route{r}}
	if err := e.Preflight(p); err != nil {
		t.Fatal(err)
	}
	if e.Status().AppliedRevision != 0 {
		t.Fatal("preflight applied policy")
	}
	if _, err := os.Stat(filepath.Join(e.options.StateDirectory, "policy.json")); !os.IsNotExist(err) {
		t.Fatal("preflight wrote LKG")
	}
	busy, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	if err := e.Preflight(p); err == nil {
		t.Fatal("preflight accepted occupied listener")
	}
}

func TestTruncatedSecretAndRegexpExpansionNeverPublished(t *testing.T) {
	p := DefaultRoute().Capture
	p.Mode = "bounded_body"
	p.MaxBodyBytes = 16
	p.BodyPatterns = []string{"secret-.*-tail"}
	redact := newRedactor(p)
	c := newBodyCapture(p, http.Header{"Content-Type": {"text/plain"}}, redact)
	c.write([]byte("secret-private-over-boundary-tail"))
	c.complete = true
	if b := c.snapshot(); b.Data != "" || !b.Truncated || b.NotCapturedReason == "" {
		t.Fatal("partial secret exposed")
	}
	p.MaxBodyBytes = 65536
	p.BodyPatterns = []string{".", ".", ".", ".", ".", ".", ".", "."}
	r := newRedactor(p)
	if s := r.text(strings.Repeat("x", 65536)); len(s) > 65536 || strings.Contains(s, "xxxx") {
		t.Fatal("regex replacement expansion exceeded capture budget")
	}
}

func TestEarlyRejectionIsRecordedWithActualPeerAndNoUpstreamCall(t *testing.T) {
	calls := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer up.Close()
	c := &collected{}
	e, r := testEngine(t, up.URL, c)
	r.Host = "allowed.example"
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 2, Routes: []Route{r}}); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := request(t, r, "GET", "/", "", nil); status != 421 {
		t.Fatal("unknown host accepted")
	}
	x := waitFinal(t, c)
	if x.Status != 421 || x.PeerIP != "127.0.0.1" || x.WAFDecision != "not_evaluated" || x.ResponseBytes == 0 || calls != 0 {
		t.Fatalf("early denial missing %+v", x)
	}
}

func TestWAFHTTPDenialDoesNotReachUpstreamAndHasRetryAfter(t *testing.T) {
	calls := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer up.Close()
	e, r := testEngine(t, up.URL, &collected{})
	r.WAF.Mode = "enforce"
	r.WAF.RatePerSecond = .001
	r.WAF.Burst = 1
	r.WAF.StateTTLSeconds = 1000
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 2, Routes: []Route{r}}); err != nil {
		t.Fatal(err)
	}
	request(t, r, "GET", "/", "", nil)
	status, _, headers := request(t, r, "GET", "/", "", http.Header{"X-Forwarded-For": {"203.0.113.4"}})
	if status != 429 || headers.Get("Retry-After") == "" || calls != 1 {
		t.Fatal("keep-alive/IP spoof bypassed per-request WAF")
	}
}

func TestSerializedHTMLBudgetKeepsMetadataInsteadOfDroppingExchange(t *testing.T) {
	store, err := traffic.Open(traffic.Config{StateDirectory: filepath.Join(t.TempDir(), "traffic")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sink := &storeSink{store: store}
	body := strings.Repeat("<", 65536)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, body)
	}))
	defer up.Close()
	e, r := testEngine(t, up.URL, sink)
	r.Capture.Mode = "bounded_body"
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 2, Routes: []Route{r}}); err != nil {
		t.Fatal(err)
	}
	_, got, _ := request(t, r, "GET", "/", "", nil)
	if got != body {
		t.Fatal("HTML payload changed")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		p, err := store.List(context.Background(), traffic.Query{Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Records) == 1 && p.Records[0].State == "completed" {
			d, err := store.Detail(context.Background(), p.Records[0].RequestID)
			if err != nil || !d.Truncated || d.ResponseBody.Data != "" || d.ResponseBody.NotCapturedReason == "" {
				t.Fatal("encoded body budget not explicit")
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("entire metadata record was dropped")
}

func TestRevisionZeroOnlyBootstrapsClosedEmptyPolicy(t *testing.T) {
	p, err := NormalizePolicy(Policy{SchemaVersion: 1, Revision: 0, Routes: []Route{}})
	if err != nil || p.Routes == nil {
		t.Fatal("empty revision0 bootstrap rejected")
	}
	e, err := NewEngine(Options{StateDirectory: filepath.Join(t.TempDir(), "proxy")})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(context.Background())
	if err := e.Apply(p); err != nil {
		t.Fatal(err)
	}
	if s := e.Status(); s.Routes != 0 || s.AppliedRevision != 0 || s.LastError != "" {
		t.Fatal("bootstrap opened listener or reported failure")
	}
	r := DefaultRoute()
	r.ID = "route"
	r.ServiceID = "service"
	r.Component = "app"
	r.Listen = "127.0.0.1:19000"
	r.Upstream = "http://127.0.0.1:18000"
	if _, err := NormalizePolicy(Policy{SchemaVersion: 1, Revision: 0, Routes: []Route{r}}); err == nil {
		t.Fatal("revision0 was allowed to activate routing")
	}
}

func TestMetadataCaptureBudgetsAreExplicitWithoutChangingForwarding(t *testing.T) {
	largeHeader := strings.Repeat("h", 5000)
	largeQuery := strings.Repeat("q", 9000)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Large") != largeHeader || r.URL.Query().Get("value") != largeQuery {
			t.Error("capture budget changed forwarded metadata")
		}
		w.Header().Set("X-Large", largeHeader)
		fmt.Fprint(w, "ok")
	}))
	defer up.Close()
	c := &collected{}
	_, r := testEngine(t, up.URL, c)
	status, body, headers := request(t, r, "GET", "/?value="+largeQuery, "", http.Header{"X-Large": {largeHeader}})
	if status != 200 || body != "ok" || headers.Get("X-Large") != largeHeader {
		t.Fatal("capture budget changed forwarded response")
	}
	x := waitFinal(t, c)
	if !x.Truncated || !strings.Contains(x.URL, "omitted_query_budget") || len(x.RequestHeaders.Get("X-Large")) > 4110 || len(x.ResponseHeaders.Get("X-Large")) > 4110 {
		t.Fatal("metadata capture truncation was not explicit and bounded")
	}
	for _, initial := range c.all() {
		if initial.State == "in_progress" && !initial.Truncated {
			t.Fatal("initial metadata capture truncation was not explicit")
		}
	}
}

func TestStalledUploadExpiresAndReleasesRequestCapacity(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer up.Close()
	c := &collected{}
	e, r := testEngine(t, up.URL, c)
	r.Limits.MaxConcurrent = 1
	r.Limits.MaxConnectionSeconds = 1
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 2, Routes: []Route{r}}); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", r.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 1000\r\n\r\nx", r.Listen); err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, conn)
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("stalled upload survived route connection deadline")
	}
	x := waitFinal(t, c)
	if x.State != "aborted" {
		t.Fatal("expired upload was not marked aborted")
	}
	status, body, _ := request(t, r, "GET", "/", "", http.Header{})
	if status != 200 || body != "ok" {
		t.Fatal("expired upload did not release request capacity")
	}
}
