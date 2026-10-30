package packets

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func reverseFlowFixture(r Record, id string) Record {
	data := append([]byte{}, r.Data...)
	copy(data[26:30], r.Data[30:34])
	copy(data[30:34], r.Data[26:30])
	binary.BigEndian.PutUint16(data[34:36], uint16(r.DestinationPort))
	binary.BigEndian.PutUint16(data[36:38], uint16(r.SourcePort))
	r.Data = data
	r.PacketID = id
	r.SourceIP, r.DestinationIP = r.DestinationIP, r.SourceIP
	r.SourcePort, r.DestinationPort = r.DestinationPort, r.SourcePort
	r.Direction = "egress"
	return r
}
func TestFlowArchiveMetadataScopeFreezesWindowAndKeepsOppositeDirection(t *testing.T) {
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, nil)
	r := fixture(now.Add(-time.Second), "request")
	r.VersionBindings = []VersionBinding{{ServiceID: "game", Component: "api", ReleaseID: "release-1", SourceDigest: "sha256:" + strings.Repeat("a", 64)}}
	mustIngest(t, s, r)
	reply := reverseFlowFixture(r, "reply")
	reply.At = now.Add(-500 * time.Millisecond)
	mustIngest(t, s, reply)
	q := Query{ServiceIDs: []string{"game"}, SourcePort: r.SourcePort, Direction: "ingress", Limit: 50}
	page, err := s.FlowList(context.Background(), q)
	if err != nil || len(page.Flows) != 1 || page.Flows[0].PacketCount != 2 || page.SnapshotCursor == "" || page.Query.Until == "" || page.Query.From == "" {
		t.Fatalf("flow selection lost reply/frozen scope: %+v %v", page, err)
	}
	raw, _ := json.Marshal(page)
	if bytes.Contains(raw, []byte(`"data":`)) || bytes.Contains(raw, []byte(`"chunks":`)) || bytes.Contains(raw, []byte(`"datagrams":`)) {
		t.Fatal("metadata flow page leaked payload")
	}
	detail, err := s.FlowDetail(context.Background(), FlowDetailRequest{Query: page.Query, FlowID: page.Flows[0].ID})
	if err != nil || len(detail.Datagrams) != 2 || len(detail.VersionBindings) != 1 || !bytes.Equal(detail.Datagrams[0].Data, []byte{0, 255, 65, 10}) {
		t.Fatalf("sensitive flow detail lost datagrams/version: %+v %v", detail, err)
	}
	newer := fixture(now, "new-request")
	mustIngest(t, s, newer)
	frozen, err := s.FlowDetail(context.Background(), FlowDetailRequest{Query: page.Query, FlowID: detail.ID})
	if err != nil || frozen.PacketCount != 2 {
		t.Fatal("snapshot detail silently included newer capture")
	}
	fresh, err := s.FlowList(context.Background(), q)
	if err != nil || fresh.Flows[0].PacketCount != 3 {
		t.Fatal("fresh window did not advance")
	}
}
func TestFlowArchiveHTTPReadBoundaryAndTypedQueries(t *testing.T) {
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, nil)
	mustIngest(t, s, fixture(now, "http-flow"))
	tokens := Tokens{Ingest: strings.Repeat("i", 40), Read: strings.Repeat("r", 40)}
	handler, err := Handler(s, tokens)
	if err != nil {
		t.Fatal(err)
	}
	call := func(h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://archive"+path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, h := range []http.Handler{handler, ReadOnly(handler)} {
		if w := call(h, "GET", "/v1/flows", tokens.Ingest, ""); w.Code != 401 {
			t.Fatal("ingest token read flows")
		}
		if w := call(h, "GET", "/v1/flows?protocol=udp&protocol=tcp", tokens.Read, ""); w.Code != 400 {
			t.Fatal("duplicate flow filters accepted")
		}
		w := call(h, "GET", "/v1/flows?protocol=udp", tokens.Read, "")
		if w.Code != 200 {
			t.Fatalf("private flow list failed: %d %s", w.Code, w.Body.String())
		}
		var page FlowPage
		if json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Flows) != 1 {
			t.Fatal("bad flow metadata")
		}
		body, _ := json.Marshal(FlowDetailRequest{Query: page.Query, FlowID: page.Flows[0].ID})
		w = call(h, "POST", "/v1/flows/detail", tokens.Read, string(body))
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"datagrams"`) {
			t.Fatalf("private detail failed: %d", w.Code)
		}
		if w = call(h, "POST", "/v1/flows/detail", tokens.Read, `{"query":{},"flow_id":"../bad"}`); w.Code != 400 {
			t.Fatal("invalid flow ID accepted")
		}
		if w = call(h, "POST", "/v1/flows/detail", tokens.Read, `{"query":{},"flow_id":"flow-1","capture":"any"}`); w.Code != 400 {
			t.Fatal("unknown flow field accepted")
		}
	}
	for _, path := range []string{"/v1/flows", "/v1/flows/detail"} {
		if w := call(IngestOnly(handler), "GET", path, tokens.Read, ""); w.Code != 404 {
			t.Fatal("network endpoint exposed flow reads")
		}
	}
}
func TestFlowArchiveHasBoundedConcurrencyAndLockWait(t *testing.T) {
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, nil)
	flowAnalysisSlots <- struct{}{}
	flowAnalysisSlots <- struct{}{}
	if _, err := s.FlowList(context.Background(), Query{}); !errors.Is(err, ErrFlowBusy) {
		t.Fatal("flow analysis concurrency unbounded")
	}
	<-flowAnalysisSlots
	<-flowAnalysisSlots
	s.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	start := time.Now()
	_, err := s.FlowList(ctx, Query{})
	s.mu.Unlock()
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("flow waited beyond deadline: %v", err)
	}
}

func TestFlowHTTPOverloadIsExplicitAndDoesNotReachAnalysis(t *testing.T) {
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, nil)
	tokens := Tokens{Ingest: strings.Repeat("i", 40), Read: strings.Repeat("r", 40)}
	handler, err := Handler(s, tokens)
	if err != nil {
		t.Fatal(err)
	}
	flowAnalysisSlots <- struct{}{}
	flowAnalysisSlots <- struct{}{}
	defer func() { <-flowAnalysisSlots; <-flowAnalysisSlots }()
	request := httptest.NewRequest("GET", "http://archive/v1/flows", nil)
	request.Header.Set("Authorization", "Bearer "+tokens.Read)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, request)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "busy_or_timeout") {
		t.Fatalf("overload not reported: %d %s", w.Code, w.Body.String())
	}
}
