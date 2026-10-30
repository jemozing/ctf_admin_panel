package packets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/traffic"
)

func fixture(at time.Time, id string) Record {
	// An Ethernet + IPv4 + UDP datagram carrying binary bytes, including NUL.
	data := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 8, 0, 0x45, 0, 0, 32, 0, 1, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 9, 0x30, 0x39, 0x1f, 0x90, 0, 12, 0, 0, 0, 0xff, 0x41, 0x0a}
	return Record{Metadata: Metadata{PacketID: id, CollectorEpoch: "capture-epoch", PolicyRevision: 1, At: at, ServiceID: "game", Component: "api", Interface: "eth0", IfIndex: 2, Direction: "ingress", Protocol: "udp", SourceIP: "192.0.2.1", DestinationIP: "198.51.100.9", SourcePort: 12345, DestinationPort: 8080, WireLength: len(data), CapturedLength: len(data), LinkType: 1, Attribution: "unique"}, Data: data}
}
func openTest(t *testing.T, now func() time.Time, adjust func(*Config)) *Store {
	t.Helper()
	c := Config{StateDirectory: filepath.Join(t.TempDir(), "state"), QuotaBytes: 4 << 20, PerServiceBytes: 256 << 10, MinimumFreeBytes: 1, Retention: time.Hour, MaxRecords: 100, Now: now}
	if adjust != nil {
		adjust(&c)
	}
	s, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func mustIngest(t *testing.T, s *Store, r Record) int64 {
	t.Helper()
	n, err := s.Ingest(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestMetadataSeparationAndPCAP(t *testing.T) {
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, nil)
	r := fixture(now, "packet-1")
	mustIngest(t, s, r)
	m, err := s.Detail(context.Background(), r.PacketID)
	if err != nil || m.CapturedLength != len(r.Data) {
		t.Fatalf("detail: %+v %v", m, err)
	}
	page, err := s.List(context.Background(), Query{IP: "198.51.100.0/24", Protocol: "udp", DestinationPort: 8080})
	if err != nil || len(page.Records) != 1 {
		t.Fatalf("list: %+v %v", page, err)
	}
	encoded, _ := json.Marshal(page)
	if bytes.Contains(encoded, []byte(`"data"`)) || bytes.Contains(encoded, []byte(base64.StdEncoding.EncodeToString(r.Data))) {
		t.Fatal("metadata list leaked bytes")
	}
	raw, err := s.Raw(context.Background(), r.PacketID)
	if err != nil || !bytes.Equal(raw.Data, r.Data) {
		t.Fatalf("raw changed binary data: %v", err)
	}
	export, err := s.ExportPCAP(context.Background(), ExportRequest{})
	if err != nil || export.Packets != 1 || export.Truncated {
		t.Fatalf("export: %+v %v", export, err)
	}
	b := export.Data
	if len(b) != 24+16+len(r.Data) || binary.LittleEndian.Uint32(b[:4]) != 0xa1b2c3d4 || binary.LittleEndian.Uint16(b[4:6]) != 2 || binary.LittleEndian.Uint16(b[6:8]) != 4 || binary.LittleEndian.Uint32(b[20:24]) != 1 {
		t.Fatal("invalid classic Ethernet PCAP header")
	}
	if binary.LittleEndian.Uint32(b[24:28]) != uint32(now.Unix()) || binary.LittleEndian.Uint32(b[28:32]) != uint32(now.Nanosecond()/1000) || int(binary.LittleEndian.Uint32(b[32:36])) != len(r.Data) || int(binary.LittleEndian.Uint32(b[36:40])) != r.WireLength || !bytes.Equal(b[40:], r.Data) {
		t.Fatal("invalid timestamp/length/data in PCAP record")
	}
	seq, err := s.Ingest(context.Background(), r)
	if err != nil || seq != m.Sequence {
		t.Fatalf("idempotent retry: %d %v", seq, err)
	}
	r.Data = append([]byte(nil), r.Data...)
	r.Data[0] ^= 1
	if _, err := s.Ingest(context.Background(), r); !errors.Is(err, ErrConflict) {
		t.Fatalf("overwrite accepted: %v", err)
	}
}

func TestAmbiguousAttributionAndFilters(t *testing.T) {
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, nil)
	r := fixture(now, "ambiguous")
	r.Attribution = "ambiguous"
	r.ServiceID = ""
	r.Component = ""
	r.Candidates = []Candidate{{"game-b", "web"}, {"game-a", "api"}}
	mustIngest(t, s, r)
	for _, q := range []Query{{ServiceIDs: []string{"game-a"}, Component: "api"}, {ServiceIDs: []string{"game-b"}, Component: "web"}, {IP: "192.0.2.0/24"}, {IP: "::ffff:192.0.2.0/120"}} {
		p, err := s.List(context.Background(), q)
		if err != nil || len(p.Records) != 1 || p.Records[0].ServiceID != "" || len(p.Records[0].Candidates) != 2 {
			t.Fatalf("candidate filter %+v: %+v %v", q, p, err)
		}
	}
	p, err := s.List(context.Background(), Query{ServiceIDs: []string{"game-a"}, Component: "web"})
	if err != nil || len(p.Records) != 0 {
		t.Fatalf("cross-candidate component leaked: %+v %v", p, err)
	}
	st, _ := s.Status(context.Background())
	if st.StoredRecords != 1 || s.serviceBytes["game-a"] != st.StoredBytes || s.serviceBytes["game-b"] != st.StoredBytes {
		t.Fatal("ambiguous packet not charged to each service")
	}
}

func TestPCAPTruncationMetadataOnlyAndBounds(t *testing.T) {
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, nil)
	r := fixture(now, "short")
	r.Data = r.Data[:32]
	r.CapturedLength = 32
	r.Truncated = true
	mustIngest(t, s, r)
	meta := fixture(now, "metadata")
	meta.Data = nil
	meta.CapturedLength = 0
	meta.Truncated = true
	meta.NotCapturedReason = "metadata_only"
	mustIngest(t, s, meta)
	e, err := s.ExportPCAP(context.Background(), ExportRequest{})
	if err != nil || e.Packets != 2 {
		t.Fatalf("export metadata: %+v %v", e, err)
	}
	if binary.LittleEndian.Uint32(e.Data[32:36]) != 32 || binary.LittleEndian.Uint32(e.Data[36:40]) != uint32(r.WireLength) {
		t.Fatal("captured/original length collapsed")
	}
	offset := 24 + 16 + 32
	if binary.LittleEndian.Uint32(e.Data[offset+8:offset+12]) != 0 || binary.LittleEndian.Uint32(e.Data[offset+12:offset+16]) != uint32(meta.WireLength) {
		t.Fatal("metadata-only PCAP invalid")
	}
	for _, request := range []ExportRequest{{MaxPackets: 1}, {MaxBytes: 24 + 16 + 32}, {MaxBytes: 24}} {
		e, err := s.ExportPCAP(context.Background(), request)
		if err != nil || !e.Truncated || len(e.Data) > MaxExportBytes {
			t.Fatalf("export bound: %+v %v", e, err)
		}
	}
	for _, request := range []ExportRequest{{MaxPackets: MaxExportPackets + 1}, {MaxBytes: MaxExportBytes + 1}, {MaxBytes: 23}, {Query: Query{Limit: 10}}, {Query: Query{Protocol: "icmp"}}} {
		if _, err := s.ExportPCAP(context.Background(), request); err == nil {
			t.Fatalf("invalid export accepted: %+v", request)
		}
	}
}

func TestRecordValidation(t *testing.T) {
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, nil)
	cases := []struct {
		name   string
		change func(*Record)
	}{
		{"linktype", func(r *Record) { r.LinkType = 101 }}, {"length", func(r *Record) { r.CapturedLength++ }}, {"wire", func(r *Record) { r.WireLength = 13 }}, {"truncated", func(r *Record) { r.Truncated = true }}, {"reason", func(r *Record) { r.NotCapturedReason = "metadata_only" }}, {"epoch", func(r *Record) { r.CollectorEpoch = "" }}, {"policy", func(r *Record) { r.PolicyRevision = 0 }}, {"sequence", func(r *Record) { r.Sequence = 9 }}, {"unknown", func(r *Record) { r.Attribution = "unknown" }}, {"candidate", func(r *Record) { r.Candidates = []Candidate{{"unrelated", "x"}} }}, {"interface", func(r *Record) { r.Interface = "../../eth0" }}, {"IP", func(r *Record) { r.SourceIP = "192.0.2.1%zone" }}, {"future", func(r *Record) { r.At = now.Add(time.Hour) }}, {"udpflags", func(r *Record) { r.TCPFlags = 2 }}, {"protocol", func(r *Record) { r.Protocol = "icmp" }}, {"direction", func(r *Record) { r.Direction = "unknown" }}, {"port", func(r *Record) { r.SourcePort = 65536 }}, {"ambiguousduplicate", func(r *Record) {
			r.Attribution = "ambiguous"
			r.ServiceID = ""
			r.Component = ""
			r.Candidates = []Candidate{{"a", "b"}, {"a", "b"}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := fixture(now, tc.name)
			tc.change(&r)
			if _, err := s.Ingest(context.Background(), r); err == nil {
				t.Fatal("malformed record accepted")
			}
		})
	}
	r := fixture(now.Add(-2*time.Hour), "expired")
	if _, err := s.Ingest(context.Background(), r); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	st, _ := s.Status(context.Background())
	if st.StoredRecords != 0 || st.Counters.Rejected != uint64(len(cases)+1) {
		t.Fatalf("invalid record stored: %+v", st)
	}
}

func TestQuotaRetentionCursorRestart(t *testing.T) {
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, func(c *Config) { c.MaxRecords = 2 })
	for i := 0; i < 2; i++ {
		mustIngest(t, s, fixture(now, fmt.Sprintf("p%d", i)))
	}
	page, _ := s.List(context.Background(), Query{Limit: 1})
	if !page.HasMore || page.NextCursor == "" {
		t.Fatal("missing pagination")
	}
	mustIngest(t, s, fixture(now, "p2"))
	if _, err := s.Raw(context.Background(), "p0"); !errors.Is(err, ErrNotFound) {
		t.Fatal("count rotation failed")
	}
	oldCursor := s.cursor(1, "after")
	p, _ := s.List(context.Background(), Query{Cursor: oldCursor})
	if !p.Gap || len(p.Records) != 2 {
		t.Fatalf("rotation gap absent: %+v", p)
	}
	st, _ := s.Status(context.Background())
	if st.StoredRecords != 2 || st.Counters.Rotated != 1 || st.DiskBytes > st.QuotaBytes {
		t.Fatalf("quota: %+v", st)
	}
	config := s.config
	epoch := st.Epoch
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	p, err = again.List(context.Background(), Query{Cursor: oldCursor})
	if err != nil || !p.Gap || p.Epoch == epoch || !p.Counters.PreviousEpochCountersUnknown {
		t.Fatalf("restart epoch: %+v %v", p, err)
	}
	now = now.Add(2 * time.Hour)
	p, err = again.List(context.Background(), Query{})
	if err != nil || len(p.Records) != 0 || p.Counters.StoredRecords != 0 {
		t.Fatalf("retention: %+v %v", p, err)
	}
}

func TestPerServiceQuotaReserveAndWriteFailure(t *testing.T) {
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, func(c *Config) { c.PerServiceBytes = MaxRecordBytes })
	for i := 0; i < 5; i++ {
		r := fixture(now, fmt.Sprintf("large%d", i))
		r.Data = bytes.Repeat([]byte{0x42}, 60000)
		r.CapturedLength = len(r.Data)
		r.WireLength = len(r.Data)
		mustIngest(t, s, r)
	}
	st, _ := s.Status(context.Background())
	if st.StoredBytes > MaxRecordBytes || st.StoredRecords != 2 || st.Counters.Rotated != 3 {
		t.Fatalf("per-service budget not applied: %+v", st)
	}
	// Reserve exhaustion latches capture closed but leaves existing bytes readable.
	s.config.MinimumFreeBytes = 1 << 62
	if _, err := s.Ingest(context.Background(), fixture(now, "reserve")); !errors.Is(err, ErrQuota) {
		t.Fatalf("reserve accepted: %v", err)
	}
	st, _ = s.Status(context.Background())
	if st.Available || st.LastError != "free_space_reserve" {
		t.Fatalf("reserve status: %+v", st)
	}
	if _, err := s.Raw(context.Background(), "large4"); err != nil {
		t.Fatalf("reserve hid retained data: %v", err)
	}
	other := openTest(t, func() time.Time { return now }, nil)
	mustIngest(t, other, fixture(now, "retained"))
	if _, err := other.db.Exec(`CREATE TRIGGER fail_packet BEFORE INSERT ON packets BEGIN SELECT RAISE(FAIL,'simulated disk failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := other.Ingest(context.Background(), fixture(now, "write-failed")); err == nil {
		t.Fatal("write failure ignored")
	}
	st, _ = other.Status(context.Background())
	if st.Available || st.Counters.WriteErrors != 1 {
		t.Fatalf("write failure status: %+v", st)
	}
	if _, err := other.Raw(context.Background(), "retained"); err != nil {
		t.Fatal(err)
	}
}

func TestStrictQueryAndIPv6(t *testing.T) {
	for _, raw := range []string{"protocol=tcp&protocol=udp", "ip=bad", "unknown=1", "limit=0", "limit=201", "source_port=-1", "direction=sideways", "from=2030-01-02T00:00:00Z&until=2030-01-01T00:00:00Z", "ip=::ffff:192.0.2.0/80", "cursor=bad", "ip=%zz", "component="} {
		if _, err := ParseRawQuery(raw); err == nil {
			t.Fatalf("invalid query accepted: %s", raw)
		}
	}
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, nil)
	r := fixture(now, "ipv6")
	r.SourceIP = "2001:db8::1"
	r.DestinationIP = "2001:db8:1::2"
	mustIngest(t, s, r)
	for _, ip := range []string{"2001:db8::/32", "2001:db8:1::2", "2001:db8::1"} {
		p, err := s.List(context.Background(), Query{IP: ip})
		if err != nil || len(p.Records) != 1 {
			t.Fatalf("IPv6 filter %s: %v", ip, err)
		}
	}
}

func TestConcurrentBoundedStore(t *testing.T) {
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, func(c *Config) { c.MaxRecords = 10 })
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				r := fixture(now, fmt.Sprintf("%d-%d", n, i))
				if _, err := s.Ingest(context.Background(), r); err != nil {
					t.Error(err)
				}
				if _, err := s.List(context.Background(), Query{Limit: 2}); err != nil {
					t.Error(err)
				}
				if _, err := s.ExportPCAP(context.Background(), ExportRequest{MaxPackets: 2}); err != nil {
					t.Error(err)
				}
			}
		}(worker)
	}
	wg.Wait()
	st, _ := s.Status(context.Background())
	if st.StoredRecords != 10 || st.Counters.Ingested != 40 || st.Counters.Rotated != 30 {
		t.Fatalf("concurrent bounds: %+v", st)
	}
}

const ingestToken = "ingest-012345678901234567890123456789"
const readToken = "reader-012345678901234567890123456789"

func request(h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestHTTPAuthorityAndStrictBodies(t *testing.T) {
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, nil)
	h, err := Handler(s, Tokens{Ingest: ingestToken, Read: readToken})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(fixture(now, "http"))
	if w := request(h, "POST", "/v1/packets", ingestToken, string(b)); w.Code != 202 {
		t.Fatalf("ingest %d %s", w.Code, w.Body)
	}
	for _, path := range []string{"/v1/packets", "/v1/status", "/v1/packets/http", "/v1/packets/http/raw"} {
		if w := request(h, "GET", path, ingestToken, ""); w.Code != 401 {
			t.Fatalf("ingest read %s: %d", path, w.Code)
		}
		if w := request(h, "GET", path, readToken, ""); w.Code != 200 {
			t.Fatalf("read %s: %d", path, w.Code)
		}
	}
	for _, body := range []string{`{}`, string(b) + `{}`, strings.TrimSuffix(string(b), "}") + `,"unexpected":true}`, `{"packet_id":"a","data":"@@bad"}`} {
		if w := request(h, "POST", "/v1/packets", ingestToken, body); w.Code != 400 {
			t.Fatalf("body accepted: %d", w.Code)
		}
	}
	if w := request(h, "POST", "/v1/packets", readToken, string(b)); w.Code != 401 {
		t.Fatal("reader could ingest")
	}
	if w := request(h, "POST", "/v1/export", ingestToken, `{}`); w.Code != 401 {
		t.Fatal("ingest could export")
	}
	if w := request(h, "GET", "/v1/packets?limit=1&limit=2", readToken, ""); w.Code != 400 {
		t.Fatal("duplicate filter accepted")
	}
	if w := request(IngestOnly(h), "GET", "/v1/packets/http/raw", readToken, ""); w.Code != 404 {
		t.Fatal("network listener exposed raw data")
	}
	if w := request(ReadOnly(h), "POST", "/v1/packets", ingestToken, string(b)); w.Code != 404 {
		t.Fatal("read socket ingested bytes")
	}
	if w := request(h, "POST", "/v1/export", readToken, `{"query":{"service_ids":["game"]},"max_packets":1}`); w.Code != 200 {
		t.Fatalf("export %d %s", w.Code, w.Body)
	}
	if w := request(h, "GET", "/v1/packets/http", readToken, ""); strings.Contains(w.Body.String(), `"data"`) {
		t.Fatal("metadata detail leaked payload")
	}
}

func TestPrivateUnixReadClient(t *testing.T) {
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, nil)
	r := fixture(now, "unix")
	mustIngest(t, s, r)
	h, _ := Handler(s, Tokens{Ingest: ingestToken, Read: readToken})
	dir, err := os.MkdirTemp("/tmp", "ctfm-packets-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "read.sock")
	listener, cleanup, err := traffic.ListenPrivateUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	server := &http.Server{Handler: ReadOnly(h), ReadHeaderTimeout: time.Second}
	go server.Serve(listener)
	defer server.Close()
	client, err := NewUnixClient(path, readToken)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	p, err := client.List(context.Background(), Query{ServiceIDs: []string{"game"}})
	if err != nil || len(p.Records) != 1 {
		t.Fatalf("unix list: %+v %v", p, err)
	}
	if _, err := client.Detail(context.Background(), r.PacketID); err != nil {
		t.Fatal(err)
	}
	raw, err := client.Raw(context.Background(), r.PacketID)
	if err != nil || !bytes.Equal(raw.Data, r.Data) {
		t.Fatalf("unix raw: %v", err)
	}
	e, err := client.ExportPCAP(context.Background(), ExportRequest{MaxPackets: 1})
	if err != nil || e.Packets != 1 {
		t.Fatalf("unix export: %v", err)
	}
	if _, err := client.Status(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := client.Ingest(context.Background(), r); err == nil {
		t.Fatal("read client ingested")
	}
}

func TestBothEndpointDirectionIsStoredAndFilteredWithoutInventingIngress(t *testing.T) {
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, nil)
	r := fixture(now, "both-endpoints")
	r.Direction = "ambiguous"
	r.ServiceID = ""
	r.Component = ""
	r.Attribution = "ambiguous"
	r.Candidates = []Candidate{{ServiceID: "source-game", Component: "api"}, {ServiceID: "destination-game", Component: "app"}}
	mustIngest(t, s, r)
	q, err := ParseRawQuery("service_id=source-game&direction=ambiguous")
	if err != nil {
		t.Fatal(err)
	}
	page, err := s.List(context.Background(), q)
	if err != nil || len(page.Records) != 1 || page.Records[0].Direction != "ambiguous" {
		t.Fatalf("both-endpoint record hidden: %+v %v", page, err)
	}
	for _, direction := range []string{"ingress", "egress"} {
		q.Direction = direction
		page, err = s.List(context.Background(), q)
		if err != nil || len(page.Records) != 0 {
			t.Fatal("ambiguous direction was silently assigned")
		}
	}
}
