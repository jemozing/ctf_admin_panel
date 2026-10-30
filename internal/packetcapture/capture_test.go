package packetcapture

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/packets"
)

type sinkFunc func(packets.Record) bool

func (f sinkFunc) Submit(r packets.Record) bool { return f(r) }

type fixtureSource struct {
	frames chan Frame
	closed chan struct{}
	once   sync.Once
}

func newFixtureSource() *fixtureSource {
	return &fixtureSource{frames: make(chan Frame, 8), closed: make(chan struct{})}
}
func (s *fixtureSource) Read(ctx context.Context) (Frame, error) {
	select {
	case <-ctx.Done():
		return Frame{}, ctx.Err()
	case <-s.closed:
		return Frame{}, errors.New("closed")
	case f := <-s.frames:
		return f, nil
	}
}
func (s *fixtureSource) Close() error { s.once.Do(func() { close(s.closed) }); return nil }

func testPolicy() Policy {
	return Policy{SchemaVersion: 1, Revision: 1, Enabled: true, Snaplen: 0, MaxPacketsPerSecond: 100000, LeaseUntil: time.Now().Add(30 * time.Second), Interfaces: []InterfacePolicy{{Name: "fixture0", Index: 7, Endpoints: []Endpoint{{ServiceID: "game", Component: "app", Protocol: "tcp", Address: "172.20.0.5", Port: 7000}}}}}
}

func testInterfaces() ([]Interface, error) {
	return []Interface{{Name: "fixture0", Index: 7, MTU: 1500, HardwareAddr: "02:00:00:00:00:01", Supported: true, Up: true}}, nil
}

func newTestEngine(t *testing.T, sink Sink) (*Engine, *fixtureSource) {
	t.Helper()
	source := newFixtureSource()
	e, err := New(Options{Sink: sink, Interfaces: testInterfaces, OpenSource: func(Interface) (Source, error) { return source, nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := e.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return e, source
}

func ethernetFrame(proto string, ipv6 bool, source, destination string, sourcePort, destinationPort int, payload []byte) []byte {
	iplen := 20
	if ipv6 {
		iplen = 40
	}
	transport := 20
	if proto == "udp" {
		transport = 8
	}
	data := make([]byte, 14+iplen+transport+len(payload))
	data[0] = 2
	data[6] = 2
	offset := 14
	next := byte(6)
	if proto == "udp" {
		next = 17
	}
	if ipv6 {
		binary.BigEndian.PutUint16(data[12:14], 0x86dd)
		data[offset] = 0x60
		binary.BigEndian.PutUint16(data[offset+4:offset+6], uint16(transport+len(payload)))
		data[offset+6] = next
		src, dst := netip.MustParseAddr(source).As16(), netip.MustParseAddr(destination).As16()
		copy(data[offset+8:offset+24], src[:])
		copy(data[offset+24:offset+40], dst[:])
	} else {
		binary.BigEndian.PutUint16(data[12:14], 0x0800)
		data[offset] = 0x45
		binary.BigEndian.PutUint16(data[offset+2:offset+4], uint16(iplen+transport+len(payload)))
		data[offset+9] = next
		src, dst := netip.MustParseAddr(source).As4(), netip.MustParseAddr(destination).As4()
		copy(data[offset+12:offset+16], src[:])
		copy(data[offset+16:offset+20], dst[:])
	}
	offset += iplen
	binary.BigEndian.PutUint16(data[offset:offset+2], uint16(sourcePort))
	binary.BigEndian.PutUint16(data[offset+2:offset+4], uint16(destinationPort))
	if proto == "tcp" {
		data[offset+12] = 5 << 4
		data[offset+13] = 0x18
	} else {
		binary.BigEndian.PutUint16(data[offset+4:offset+6], uint16(transport+len(payload)))
	}
	copy(data[offset+transport:], payload)
	return data
}

func inject(e *Engine, data []byte) {
	e.mu.Lock()
	worker := e.workers["fixture0"]
	e.mu.Unlock()
	e.observe(worker, Frame{Data: data, WireLength: len(data), At: time.Now().UTC()})
}
func takeRecord(t *testing.T, ch <-chan packets.Record) packets.Record {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(time.Second):
		t.Fatal("packet not delivered")
		return packets.Record{}
	}
}

func TestInjectedSourceMatchesOnlyApprovedEndpointAndMetadataDefault(t *testing.T) {
	output := make(chan packets.Record, 8)
	e, source := newTestEngine(t, sinkFunc(func(r packets.Record) bool { output <- r; return true }))
	p := testPolicy()
	if err := e.Apply(p); err != nil {
		t.Fatal(err)
	}
	unmatched := ethernetFrame("tcp", false, "172.20.0.9", "172.20.0.5", 50000, 7001, []byte("secret-unrelated"))
	inject(e, unmatched)
	data := ethernetFrame("tcp", false, "172.20.0.9", "172.20.0.5", 50000, 7000, []byte("game-secret"))
	source.frames <- Frame{Data: data, WireLength: len(data), At: time.Now()}
	r := takeRecord(t, output)
	if r.ServiceID != "game" || r.Direction != "ingress" || r.Attribution != "unique" || r.CapturedLength != 0 || len(r.Data) != 0 || r.NotCapturedReason != "metadata_only" || !r.Truncated || r.PolicyRevision != 1 || r.LinkType != 1 || r.PacketID == "" || r.CollectorEpoch == "" {
		t.Fatalf("incorrect metadata: %+v", r)
	}
	if e.Status().Counters.Unmatched != 1 {
		t.Fatal("unmatched packet was not counted")
	}
	select {
	case r := <-output:
		t.Fatalf("unrelated packet retained: %+v", r)
	default:
	}
}

func TestByteCaptureSnaplenAndAmbiguousAttribution(t *testing.T) {
	output := make(chan packets.Record, 8)
	e, _ := newTestEngine(t, sinkFunc(func(r packets.Record) bool { output <- r; return true }))
	p := testPolicy()
	p.Snaplen = 64
	p.Interfaces[0].Endpoints = append(p.Interfaces[0].Endpoints, Endpoint{ServiceID: "second", Component: "app", Address: "172.20.0.5", Protocol: "tcp", Port: 7000})
	if err := e.Apply(p); err != nil {
		t.Fatal(err)
	}
	data := ethernetFrame("tcp", false, "172.20.0.5", "172.20.0.9", 7000, 50000, []byte(strings.Repeat("x", 100)))
	inject(e, data)
	r := takeRecord(t, output)
	if r.CapturedLength != 64 || len(r.Data) != 64 || !r.Truncated || r.ServiceID != "" || r.Attribution != "ambiguous" || len(r.Candidates) != 2 || r.Direction != "egress" {
		t.Fatalf("incorrect byte capture: %+v", r)
	}
}

func TestPolicyValidationAndAtomicFailure(t *testing.T) {
	e, _ := newTestEngine(t, sinkFunc(func(packets.Record) bool { return true }))
	p := testPolicy()
	if err := e.Apply(p); err != nil {
		t.Fatal(err)
	}
	digest := e.Status().Digest
	cases := map[string]func(*Policy){"wildcard": func(p *Policy) { p.Interfaces[0].Endpoints[0].Address = "0.0.0.0" }, "cidr": func(p *Policy) { p.Interfaces[0].Endpoints[0].Address = "172.20.0.0/16" }, "protocol": func(p *Policy) { p.Interfaces[0].Endpoints[0].Protocol = "icmp" }, "interface identity": func(p *Policy) { p.Interfaces[0].Index = 8 }, "snaplen": func(p *Policy) { p.Snaplen = 1 }, "lease expired": func(p *Policy) { p.LeaseUntil = time.Now().Add(-time.Second) }, "lease too long": func(p *Policy) { p.LeaseUntil = time.Now().Add(61 * time.Second) }, "same revision scope": func(p *Policy) { p.Interfaces[0].Endpoints[0].Port++ }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			bad := testPolicy()
			mutate(&bad)
			if err := e.Apply(bad); err == nil {
				t.Fatal("unsafe policy accepted")
			}
			if e.Status().Digest != digest || !e.Status().Running {
				t.Fatal("failed activation replaced active scope")
			}
		})
	}
	duplicate := testPolicy()
	duplicate.Interfaces = append(duplicate.Interfaces, InterfacePolicy{Name: "fixture1", Index: 8, Endpoints: duplicate.Interfaces[0].Endpoints})
	if _, err := NormalizePolicy(duplicate); err == nil {
		t.Fatal("same endpoint on two capture points accepted")
	}
}

func TestQueuePressureNeverBlocksReceiveAndCountsLoss(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	e, _ := newTestEngine(t, sinkFunc(func(packets.Record) bool { once.Do(func() { close(entered) }); <-release; return false }))
	defer close(release)
	p := testPolicy()
	if err := e.Apply(p); err != nil {
		t.Fatal(err)
	}
	data := ethernetFrame("tcp", false, "172.20.0.9", "172.20.0.5", 50000, 7000, nil)
	inject(e, data)
	<-entered
	started := time.Now()
	for range QueueCapacity + 10 {
		inject(e, data)
	}
	s := e.Status()
	if time.Since(started) > time.Second || s.Counters.QueueDropped < 10 || s.QueueDepth != QueueCapacity {
		t.Fatalf("receive loop blocked or loss hidden: %+v", s)
	}
}

func TestRateLimitCountsDroppedPackets(t *testing.T) {
	e, _ := newTestEngine(t, sinkFunc(func(packets.Record) bool { return true }))
	p := testPolicy()
	p.MaxPacketsPerSecond = 1
	if err := e.Apply(p); err != nil {
		t.Fatal(err)
	}
	data := ethernetFrame("tcp", false, "172.20.0.9", "172.20.0.5", 50000, 7000, nil)
	inject(e, data)
	inject(e, data)
	if s := e.Status(); s.Counters.RateDropped != 1 || s.Counters.Matched != 2 {
		t.Fatalf("unexpected counters: %+v", s.Counters)
	}
}

func TestLeaseExpiryClosesSourcesAndFreshLeaseReopens(t *testing.T) {
	var mu sync.Mutex
	var opened []*fixtureSource
	e, err := New(Options{Sink: sinkFunc(func(packets.Record) bool { return true }), Interfaces: testInterfaces, OpenSource: func(Interface) (Source, error) {
		s := newFixtureSource()
		mu.Lock()
		opened = append(opened, s)
		mu.Unlock()
		return s, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(context.Background())
	p := testPolicy()
	p.LeaseUntil = time.Now().Add(80 * time.Millisecond)
	if err = e.Apply(p); err != nil {
		t.Fatal(err)
	}
	digest := e.Status().Digest
	deadline := time.Now().Add(time.Second)
	for !e.Status().LeaseExpired && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	data := ethernetFrame("tcp", false, "172.20.0.9", "172.20.0.5", 50000, 7000, nil)
	e.mu.Lock()
	old := e.workers["fixture0"]
	e.mu.Unlock()
	if old != nil {
		e.observe(old, Frame{Data: data, WireLength: len(data)})
	}
	if e.Status().Counters.Enqueued != 0 || e.Status().Running {
		t.Fatal("expired lease still ingests packets")
	}
	time.Sleep(250 * time.Millisecond)
	mu.Lock()
	first := opened[0]
	mu.Unlock()
	select {
	case <-first.closed:
	default:
		t.Fatal("expired raw source remains open")
	}
	p.LeaseUntil = time.Now().Add(30 * time.Second)
	if err = e.Apply(p); err != nil {
		t.Fatal(err)
	}
	if s := e.Status(); !s.Running || s.Digest != digest || s.Revision != 1 {
		t.Fatalf("lease refresh changed scope: %+v", s)
	}
	mu.Lock()
	count := len(opened)
	mu.Unlock()
	if count != 2 {
		t.Fatalf("renewed lease opened %d sources", count)
	}
}

func TestPauseRequiresFreshLeaseAndKeepsApprovedIdentity(t *testing.T) {
	var opened int
	e, err := New(Options{Sink: sinkFunc(func(packets.Record) bool { return true }), Interfaces: testInterfaces, OpenSource: func(Interface) (Source, error) { opened++; return newFixtureSource(), nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(context.Background())
	p := testPolicy()
	if err = e.Apply(p); err != nil {
		t.Fatal(err)
	}
	digest := e.Status().Digest
	if err = e.Pause(); err != nil {
		t.Fatal(err)
	}
	if s := e.Status(); s.Running || !s.Paused || !s.LeaseExpired || s.Revision != p.Revision || s.Digest != digest {
		t.Fatalf("pause changed identity or retained capture: %+v", s)
	}
	if err = e.Apply(p); err == nil {
		t.Fatal("old desired lease resumed paused capture")
	}
	p.LeaseUntil = p.LeaseUntil.Add(time.Second)
	if err = e.Apply(p); err != nil {
		t.Fatal(err)
	}
	if !e.Status().Running || opened != 2 {
		t.Fatal("fresh verified lease did not reopen sources")
	}
	p.LeaseUntil = p.LeaseUntil.Add(time.Second)
	if err = e.Apply(p); err != nil {
		t.Fatal(err)
	}
	if opened != 2 {
		t.Fatal("lease-only refresh reopened sockets")
	}
}

func TestDesiredPolicyFileStrictBoundsAndUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	p := testPolicy()
	body, _ := json.Marshal(p)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicyFile(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0660); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicyFile(path); err == nil {
		t.Fatal("group-writable policy accepted")
	}
	_ = os.Chmod(path, 0600)
	link := filepath.Join(filepath.Dir(path), "policy-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicyFile(link); err == nil {
		t.Fatal("symlink policy accepted")
	}
	for _, bad := range []string{string(body) + ` {}`, `{"unexpected":true}`, strings.Repeat("x", MaxPolicyBytes+1)} {
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPolicyFile(path); err == nil {
			t.Fatal("invalid policy file accepted")
		}
	}
}

func TestOfflineFramesReachArchiveAndPCAPWithoutApplicationDecode(t *testing.T) {
	ctx := context.Background()
	store, err := packets.Open(packets.Config{StateDirectory: filepath.Join(t.TempDir(), "archive"), QuotaBytes: 4 << 20, PerServiceBytes: 1 << 20, MinimumFreeBytes: 1, MaxRecords: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	stored := make(chan error, 1)
	e, _ := newTestEngine(t, sinkFunc(func(r packets.Record) bool { _, err := store.Ingest(ctx, r); stored <- err; return err == nil }))
	p := testPolicy()
	p.Snaplen = 65535
	if err = e.Apply(p); err != nil {
		t.Fatal(err)
	}
	// These bytes resemble a gRPC envelope but remain opaque TCP bytes.
	data := ethernetFrame("tcp", false, "172.20.0.9", "172.20.0.5", 50000, 7000, []byte{0, 0, 0, 0, 4, 't', 'e', 's', 't'})
	inject(e, data)
	select {
	case err = <-stored:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("fixture capture not archived")
	}
	page, err := store.List(ctx, packets.Query{ServiceIDs: []string{"game"}, Protocol: "tcp", Limit: 10})
	if err != nil || len(page.Records) != 1 {
		t.Fatalf("query: %+v %v", page, err)
	}
	raw, err := store.Raw(ctx, page.Records[0].PacketID)
	if err != nil || string(raw.Data) != string(data) {
		t.Fatalf("raw bytes changed: %v", err)
	}
	exported, err := store.ExportPCAP(ctx, packets.ExportRequest{Query: packets.Query{ServiceIDs: []string{"game"}}, MaxPackets: 10})
	if err != nil {
		t.Fatal(err)
	}
	if exported.Packets != 1 || len(exported.Data) != 24+16+len(data) || binary.LittleEndian.Uint32(exported.Data[20:24]) != 1 || string(exported.Data[40:]) != string(data) {
		t.Fatal("Ethernet PCAP record did not preserve exact frame")
	}
}

func TestLoopbackOnlySuppressesOutgoingClone(t *testing.T) {
	output := make(chan packets.Record, 8)
	e, err := New(Options{Sink: sinkFunc(func(r packets.Record) bool { output <- r; return true }), Interfaces: func() ([]Interface, error) {
		return []Interface{{Name: "fixture0", Index: 7, Supported: true, Loopback: true, Up: true}}, nil
	}, OpenSource: func(Interface) (Source, error) { return newFixtureSource(), nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(context.Background())
	if err = e.Apply(testPolicy()); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	w := e.workers["fixture0"]
	e.mu.Unlock()
	data := ethernetFrame("tcp", false, "172.20.0.9", "172.20.0.5", 50000, 7000, nil)
	for _, kind := range []uint8{4, 0, 0} {
		e.observe(w, Frame{Data: data, WireLength: len(data), PacketType: kind})
	}
	takeRecord(t, output)
	takeRecord(t, output)
	if s := e.Status(); s.Counters.DuplicateSuppressed != 1 || s.Counters.Enqueued != 2 {
		t.Fatal("loopback deduplication hid a genuine repeated packet")
	}
}

func TestControlAuthenticationAndPreflightNoActivation(t *testing.T) {
	e, _ := newTestEngine(t, sinkFunc(func(packets.Record) bool { return true }))
	token := strings.Repeat("s", 32)
	handler, err := e.ControlHandler(token)
	if err != nil {
		t.Fatal(err)
	}
	p := testPolicy()
	p.Enabled = false
	p.LeaseUntil = time.Time{}
	body, _ := json.Marshal(p)
	for _, test := range []struct {
		method, path, authorization, origin, body string
		want                                      int
	}{{"GET", "/v1/status", "", "", "", 401}, {"GET", "/v1/status", "Bearer " + token, "https://foreign.invalid", "", 401}, {"GET", "/v1/status?x=1", "Bearer " + token, "", "", 400}, {"POST", "/v1/preflight", "Bearer " + token, "", string(body), 200}, {"POST", "/v1/preflight", "Bearer " + token, "", `{"schema_version":1,"unknown":true}`, 400}, {"GET", "/healthz", "", "", "", 200}} {
		t.Run(fmt.Sprintf("%s-%s-%d", test.method, test.path, test.want), func(t *testing.T) {
			r := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			r.Header.Set("Authorization", test.authorization)
			r.Header.Set("Origin", test.origin)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != test.want {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
		})
	}
	if e.Status().Revision != 0 {
		t.Fatal("preflight changed active policy")
	}
}

func TestParserIPv4IPv6UDPAndMalformedFrames(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, protocol := range []string{"tcp", "udp"} {
			src, dst := "172.20.0.9", "172.20.0.5"
			if v6 {
				src, dst = "fd00::9", "fd00::5"
			}
			data := ethernetFrame(protocol, v6, src, dst, 55555, 7000, []byte("payload"))
			parsed, ok := parseEthernet(data)
			if !ok || parsed.protocol != protocol || parsed.source.String() != src || parsed.destination.String() != dst || parsed.destinationPort != 7000 {
				t.Fatalf("failed bounded parse %+v", parsed)
			}
			for n := range len(data) - len("payload") {
				if _, ok := parseEthernet(data[:n]); ok {
					t.Fatalf("accepted incomplete %s IPv6=%v at %d", protocol, v6, n)
				}
			}
		}
	}
	fragment := ethernetFrame("tcp", false, "172.20.0.9", "172.20.0.5", 50000, 7000, nil)
	fragment[14+6] = 0x20
	if _, ok := parseEthernet(fragment); ok {
		t.Fatal("fragment attributed without reassembly")
	}
	badUDP := ethernetFrame("udp", false, "172.20.0.9", "172.20.0.5", 50000, 7000, nil)
	badUDP[14+20+5] = 7
	if _, ok := parseEthernet(badUDP); ok {
		t.Fatal("short UDP accepted")
	}
	zeroUDP := ethernetFrame("udp", false, "172.20.0.9", "172.20.0.5", 0, 7000, nil)
	if parsed, ok := parseEthernet(zeroUDP); !ok || parsed.sourcePort != 0 {
		t.Fatal("valid UDP zero source port discarded")
	}
}

func FuzzBoundedEthernetParser(f *testing.F) {
	f.Add(ethernetFrame("tcp", false, "172.20.0.9", "172.20.0.5", 50000, 7000, []byte("fixture")))
	f.Add(ethernetFrame("udp", true, "fd00::9", "fd00::5", 50000, 7000, nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65535 {
			t.Skip()
		}
		_, _ = parseEthernet(data)
	})
}

func BenchmarkParseMatchedTCP(b *testing.B) {
	data := ethernetFrame("tcp", false, "172.20.0.9", "172.20.0.5", 50000, 7000, []byte(strings.Repeat("x", 1024)))
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		if _, ok := parseEthernet(data); !ok {
			b.Fatal("fixture failed")
		}
	}
}

func TestBothSelectedEndpointsHaveExplicitAmbiguousDirection(t *testing.T) {
	output := make(chan packets.Record, 8)
	e, _ := newTestEngine(t, sinkFunc(func(r packets.Record) bool { output <- r; return true }))
	p := testPolicy()
	p.Interfaces[0].Endpoints = append(p.Interfaces[0].Endpoints, Endpoint{ServiceID: "second", Component: "api", Address: "172.20.0.9", Protocol: "tcp", Port: 8000})
	if err := e.Apply(p); err != nil {
		t.Fatal(err)
	}
	inject(e, ethernetFrame("tcp", false, "172.20.0.5", "172.20.0.9", 7000, 8000, []byte("between games")))
	r := takeRecord(t, output)
	if r.Direction != "ambiguous" || r.Attribution != "ambiguous" || len(r.Candidates) != 2 || r.ServiceID != "" {
		t.Fatalf("one service direction was invented: %+v", r.Metadata)
	}
}
