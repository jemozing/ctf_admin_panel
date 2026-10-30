package traffic

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type testClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *testClock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *testClock) Advance(d time.Duration) { c.mu.Lock(); c.at = c.at.Add(d); c.mu.Unlock() }

func recorder(t *testing.T, modify func(*Config)) (*Store, *testClock) {
	t.Helper()
	clock := &testClock{at: time.Now().UTC()}
	c := Config{StateDirectory: filepath.Join(t.TempDir(), "state"), QuotaBytes: 8 << 20, PerServiceBytes: 1 << 20, MinimumFreeBytes: 1, Now: clock.Now}
	if modify != nil {
		modify(&c)
	}
	store, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store, clock
}
func observation(clock *testClock, id, service string) Exchange {
	at := clock.Now()
	end := at.Add(time.Millisecond)
	return Exchange{Metadata: Metadata{RequestID: id, CollectorEpoch: "collector-one", ServiceID: service, RouteID: "route-" + service, PolicyRevision: 1, At: at, UpdatedAt: at, EndAt: &end, State: "completed", PeerIP: "127.0.0.1", ClientIP: "192.0.2.10", ClientIPSource: "peer", Method: "GET", URL: "/test", Upstream: "http://127.0.0.1:8123", Status: 200, ResponseSource: "upstream", DurationMS: 1, RequestBytes: 10, ResponseBytes: 10, WAFDecision: "allow"}}
}

func TestRecorderRedactsBeforeDiskAndMetadataNeverContainsPayload(t *testing.T) {
	s, clock := recorder(t, nil)
	e := observation(clock, "request-secret", "service-a")
	secret := "CONTROL_PRIVATE_VALUE_1729274629"
	e.URL = "/view?token=" + secret + "&safe=visible"
	e.RequestHeaders = http.Header{"Authorization": {"Bearer " + secret}, "Cookie": {"session=" + secret}, "X-Visible": {"public"}}
	e.ResponseHeaders = http.Header{"Set-Cookie": {"private=" + secret}}
	data := `{"password":"` + secret + `","nested":[{"token":"` + secret + `"}],"visible":"ok","large_integer":9007199254740993}`
	e.RequestBody = Body{Encoding: "utf8", Data: data, ObservedBytes: int64(len(data)), CapturedBytes: int64(len(data)), ContentType: "application/json"}
	e.ResponseBody = Body{Encoding: "base64", Data: base64.StdEncoding.EncodeToString([]byte(secret)), ObservedBytes: int64(len(secret)), CapturedBytes: int64(len(secret)), ContentType: "application/octet-stream"}
	if _, err := s.Ingest(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	page, err := s.List(context.Background(), Query{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(page)
	if bytes.Contains(b, []byte(secret)) || bytes.Contains(b, []byte("request_headers")) || bytes.Contains(b, []byte("request_body")) {
		t.Fatal("list leaked capture fields")
	}
	detail, err := s.Detail(context.Background(), e.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = json.Marshal(detail)
	if bytes.Contains(b, []byte(secret)) {
		t.Fatal("detail leaked a control secret")
	}
	if detail.RequestHeaders.Get("Authorization") != "[REDACTED]" || detail.ResponseBody.Data != "" || detail.ResponseBody.NotCapturedReason != "unsupported_body_format" {
		t.Fatalf("redaction or omission absent: %#v", detail.ResponseBody)
	}
	if !strings.Contains(detail.RequestBody.Data, "9007199254740993") {
		t.Fatal("capture rounded a large JSON integer")
	}
	if e.RequestHeaders.Get("Authorization") != "Bearer "+secret {
		t.Fatal("recorder modified caller's forwarding headers")
	}
	for _, name := range []string{"traffic.sqlite", "traffic.sqlite-journal"} {
		raw, err := os.ReadFile(filepath.Join(s.config.StateDirectory, name))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("secret reached recorder disk")
		}
	}
}

func TestQueriesIsolateServicesAndNormalizeIPFamilies(t *testing.T) {
	s, clock := recorder(t, nil)
	for i, item := range []struct {
		id, service, ip, method string
		status                  int
		decision                string
	}{{"a", "one", "::ffff:192.0.2.10", "GET", 200, "allow"}, {"b", "two", "192.0.2.11", "POST", 429, "rate_limited"}, {"c", "one", "2001:db8::1", "POST", 502, "allow"}} {
		e := observation(clock, item.id, item.service)
		e.ClientIP = item.ip
		e.Method = item.method
		e.Status = item.status
		e.WAFDecision = item.decision
		e.URL = "/literal%25_under_score"
		e.UpdatedAt = e.At.Add(time.Duration(i) * time.Millisecond)
		if _, err := s.Ingest(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		q    Query
		want string
	}{{Query{ServiceIDs: []string{"two"}}, "b"}, {Query{ServiceIDs: []string{"one"}, IP: "192.0.2.0/24"}, "a"}, {Query{IP: "::ffff:192.0.2.10/128"}, "a"}, {Query{IP: "2001:db8::/32", Status: "5xx"}, "c"}, {Query{WAF: "rate_limited", Method: "POST"}, "b"}} {
		p, err := s.List(context.Background(), test.q)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Records) != 1 || p.Records[0].RequestID != test.want {
			t.Fatalf("filter %#v returned %#v", test.q, p.Records)
		}
	}
	if _, err := s.List(context.Background(), Query{IP: "10.0.0.0/garbage"}); err == nil {
		t.Fatal("invalid CIDR accepted")
	}
	p, err := s.List(context.Background(), Query{URL: "' OR 1=1 --"})
	if err != nil || len(p.Records) != 0 {
		t.Fatal("URL search was treated as SQL")
	}
}

func TestLiveUpdatesHaveMonotonicCursorAndTerminalRecordsAreImmutable(t *testing.T) {
	s, clock := recorder(t, nil)
	e := observation(clock, "stream-one", "one")
	e.State = "in_progress"
	e.EndAt = nil
	e.Status = 0
	first, err := s.Ingest(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := s.List(context.Background(), Query{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Second)
	e.UpdatedAt = clock.Now()
	e.State = "completed"
	e.Status = 200
	e.ResponseBytes = 100
	end := clock.Now()
	e.EndAt = &end
	second, err := s.Ingest(context.Background(), e)
	if err != nil || second <= first {
		t.Fatalf("stream did not advance: %d %v", second, err)
	}
	live, err := s.List(context.Background(), Query{Cursor: initial.LiveCursor})
	if err != nil || len(live.Records) != 1 || live.Records[0].RequestID != e.RequestID || live.Records[0].State != "completed" {
		t.Fatal("completion update was missed")
	}
	again, err := s.Ingest(context.Background(), e)
	if err != nil || again != second {
		t.Fatal("final delivery replay was not idempotent")
	}
	e.ResponseBytes++
	if _, err := s.Ingest(context.Background(), e); !errors.Is(err, ErrConflict) {
		t.Fatal("terminal traffic observation was rewritten")
	}
	e.ResponseBytes--
	e.ServiceID = "other"
	if _, err := s.Ingest(context.Background(), e); !errors.Is(err, ErrConflict) {
		t.Fatal("exchange identity changed")
	}
}

func TestQuotaRotationSignalsCursorGapAndKeepsOtherService(t *testing.T) {
	s, clock := recorder(t, func(c *Config) { c.PerServiceBytes = MaxExchangeBytes; c.MaxRecords = 100 })
	body := strings.Repeat("x", 60<<10)
	makeEntry := func(id, service string) Exchange {
		e := observation(clock, id, service)
		e.RequestBody = Body{Encoding: "utf8", Data: body, ObservedBytes: int64(len(body)), CapturedBytes: int64(len(body)), ContentType: "text/plain"}
		e.ResponseBody = e.RequestBody
		return e
	}
	if _, err := s.Ingest(context.Background(), makeEntry("b", "other")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest(context.Background(), makeEntry("a1", "busy")); err != nil {
		t.Fatal(err)
	}
	page, _ := s.List(context.Background(), Query{})
	for _, id := range []string{"a2", "a3"} {
		if _, err := s.Ingest(context.Background(), makeEntry(id, "busy")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Detail(context.Background(), "a1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("service quota did not rotate oldest record")
	}
	if _, err := s.Detail(context.Background(), "b"); err != nil {
		t.Fatal("another service's quota evicted unrelated data")
	}
	older, err := s.List(context.Background(), Query{Cursor: page.NextCursor})
	if err != nil || !older.Gap {
		t.Fatal("expired cursor did not disclose a gap")
	}
	status, err := s.Status(context.Background())
	if err != nil || status.DiskBytes > status.QuotaBytes || status.Counters.Rotated == 0 {
		t.Fatal("physical quota/accounting failed")
	}
}

func TestRetentionAndRestartPublishUnknownPreviousCounters(t *testing.T) {
	s, clock := recorder(t, func(c *Config) { c.Retention = time.Second })
	e := observation(clock, "expire", "one")
	if _, err := s.Ingest(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	page, _ := s.List(context.Background(), Query{})
	clock.Advance(2 * time.Second)
	if _, err := s.Detail(context.Background(), e.RequestID); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired body still retrievable")
	}
	if _, err := s.Ingest(context.Background(), e); !errors.Is(err, ErrExpired) {
		t.Fatal("late stream update reinserted expired capture")
	}
	config := s.config
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	status, err := next.Status(context.Background())
	if err != nil || !status.PreviousEpochCountersUnknown || status.CountersScope != "current_recorder_epoch" {
		t.Fatal("restart silently reset known counters")
	}
	p, err := next.List(context.Background(), Query{Cursor: page.LiveCursor})
	if err != nil || !p.Gap || p.Epoch == page.Epoch {
		t.Fatal("restart cursor did not disclose epoch change")
	}
}

func TestReserveFailurePublishesLossWithoutPartialRecord(t *testing.T) {
	s, clock := recorder(t, func(c *Config) { c.MinimumFreeBytes = 1 << 62 })
	if _, err := s.Ingest(context.Background(), observation(clock, "no-space", "one")); !errors.Is(err, ErrQuota) {
		t.Fatal("free space reserve ignored")
	}
	status, err := s.Status(context.Background())
	if err != nil || status.StoredRecords != 0 || status.Counters.Rejected != 1 || status.LastError != "free_space_reserve" {
		t.Fatal("reserve failure was hidden")
	}
}

func TestSQLiteWriteFailureKeepsLastCommittedCountsAndFailsCaptureClosed(t *testing.T) {
	s, clock := recorder(t, nil)
	if _, err := s.Ingest(context.Background(), observation(clock, "committed", "one")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER test_write_failure BEFORE INSERT ON exchanges WHEN NEW.request_id='fail' BEGIN SELECT RAISE(ABORT,'simulated write failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest(context.Background(), observation(clock, "fail", "one")); err == nil {
		t.Fatal("write failure accepted")
	}
	status, err := s.Status(context.Background())
	if err != nil || status.Available || status.StoredRecords != 1 || status.Counters.WriteErrors != 1 || status.LastError != "storage_write_failed" {
		t.Fatalf("write failure or last committed counts hidden: %#v %v", status, err)
	}
	if _, err := s.Detail(context.Background(), "fail"); !errors.Is(err, ErrNotFound) {
		t.Fatal("failed transaction published an observation")
	}
	if _, err := s.Ingest(context.Background(), observation(clock, "later", "one")); err == nil {
		t.Fatal("uncertain writer silently resumed capture")
	}
	if _, err := s.Detail(context.Background(), "committed"); err != nil {
		t.Fatal("last committed observation lost")
	}
}

func TestHTTPAuthRolesStrictQueriesAndReadOnlyMetadata(t *testing.T) {
	s, clock := recorder(t, nil)
	tokens := Tokens{Ingest: strings.Repeat("i", 40), Read: strings.Repeat("r", 40)}
	handler, err := Handler(s, tokens)
	if err != nil {
		t.Fatal(err)
	}
	e := observation(clock, "http-record", "one")
	e.ResponseBody = Body{Encoding: "utf8", Data: "visible-detail-marker", ObservedBytes: 21, CapturedBytes: 21, ContentType: "text/plain"}
	body, _ := json.Marshal(e)
	call := func(method, path, token string, body []byte) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, bytes.NewReader(body))
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	for _, test := range []struct{ method, path, token string }{{"GET", "/v1/exchanges", tokens.Ingest}, {"POST", "/v1/exchanges", tokens.Read}, {"GET", "/v1/exchanges", ""}} {
		if r := call(test.method, test.path, test.token, body); r.Code != 401 {
			t.Fatalf("credential role bypass: %d", r.Code)
		}
	}
	if r := call("POST", "/v1/exchanges", tokens.Ingest, body); r.Code != 202 {
		t.Fatalf("ingest failed: %d %s", r.Code, r.Body.String())
	}
	list := call("GET", "/v1/exchanges", tokens.Read, nil)
	if list.Code != 200 || strings.Contains(list.Body.String(), "visible-detail-marker") || strings.Contains(list.Body.String(), "response_body") {
		t.Fatal("metadata endpoint disclosed body")
	}
	detail := call("GET", "/v1/exchanges/http-record", tokens.Read, nil)
	if detail.Code != 200 || !strings.Contains(detail.Body.String(), "visible-detail-marker") {
		t.Fatal("authorized detail missing")
	}
	for _, query := range []string{"limit=0", "limit=201", "limit=5&limit=6", "unknown=true", "from=garbage", "ip=bad", "status=9xx"} {
		if r := call("GET", "/v1/exchanges?"+query, tokens.Read, nil); r.Code != 400 {
			t.Fatalf("invalid query accepted: %s", query)
		}
	}
	if _, err := ParseQuery(url.Values{"service_id": {"one", "two"}, "limit": {"50"}}); err != nil {
		t.Fatal(err)
	}
}
