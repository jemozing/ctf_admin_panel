package flows

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

func frame(proto string, reverse bool, seq uint32, flags byte, payload []byte) Packet {
	src, dst := []byte{172, 20, 0, 5}, []byte{172, 20, 0, 6}
	sport, dport := uint16(5000), uint16(7000)
	sip, dip := "172.20.0.5", "172.20.0.6"
	if reverse {
		src, dst = dst, src
		sport, dport = dport, sport
		sip, dip = dip, sip
	}
	h := 20
	next := byte(6)
	if proto == "udp" {
		h = 8
		next = 17
	}
	data := make([]byte, 14+20+h+len(payload))
	data[12], data[13] = 8, 0
	data[14] = 0x45
	binary.BigEndian.PutUint16(data[16:18], uint16(20+h+len(payload)))
	data[23] = next
	copy(data[26:30], src)
	copy(data[30:34], dst)
	binary.BigEndian.PutUint16(data[34:36], sport)
	binary.BigEndian.PutUint16(data[36:38], dport)
	if proto == "tcp" {
		binary.BigEndian.PutUint32(data[38:42], seq)
		data[46] = 5 << 4
		data[47] = flags
	} else {
		binary.BigEndian.PutUint16(data[38:40], uint16(8+len(payload)))
	}
	copy(data[34+h:], payload)
	return Packet{ID: "packet", At: time.Unix(1700000000, 0).UTC(), CollectorEpoch: "collector", PolicyRevision: 1, Interface: "br-a", IfIndex: 7, ServiceID: "game", Component: "app", Protocol: proto, SourceIP: sip, DestinationIP: dip, SourcePort: int(sport), DestinationPort: int(dport), TCPFlags: flags, WireLength: len(data), CapturedLength: len(data), Data: data}
}
func records(packets ...Packet) []Packet {
	for n := range packets {
		packets[n].ID = "packet-" + strings.Repeat("x", n%5) + string(rune('a'+n))
		packets[n].Sequence = int64(n + 1)
		packets[n].At = packets[n].At.Add(time.Duration(n) * time.Millisecond)
	}
	return packets
}
func analyze(t *testing.T, input []Packet, options Options) Snapshot {
	t.Helper()
	s, e := Analyze(context.Background(), input, options)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func payload(d Direction) string {
	var out strings.Builder
	for _, c := range d.Chunks {
		out.Write(c.Data)
	}
	return out.String()
}
func TestBidirectionalReassemblyReorderRetransmitAndConflict(t *testing.T) {
	input := records(frame("tcp", false, 100, 2, nil), frame("tcp", true, 200, 18, nil), frame("tcp", false, 101, 16, []byte("hello ")), frame("tcp", false, 110, 16, []byte("ld")), frame("tcp", false, 107, 16, []byte("wor")), frame("tcp", false, 101, 16, []byte("hello ")), frame("tcp", false, 102, 16, []byte("Z")), frame("tcp", true, 201, 16, []byte("ok")))
	s := analyze(t, input, Options{})
	if len(s.Details) != 1 {
		t.Fatalf("wrong flows: %+v", s.Flows)
	}
	f := s.Details[0]
	a, b := f.Directions[0], f.Directions[1]
	if payload(a) != "hello world" || payload(b) != "ok" || len(a.Gaps) > 0 || a.OutOfOrder != 1 || a.Retransmissions != 2 || a.ConflictingOverlaps != 1 || !a.Incomplete || a.Midstream || b.Midstream {
		t.Fatalf("unsafe reassembly: %+v a=%q b=%q", f, payload(a), payload(b))
	}
	for n := 1; n < len(a.Chunks); n++ {
		if a.Chunks[n-1].Offset+int64(len(a.Chunks[n-1].Data)) > a.Chunks[n].Offset {
			t.Fatal("assembled chunks overlap")
		}
	}
	meta, _ := json.Marshal(s.Flows)
	if bytes.Contains(meta, []byte("hello")) || bytes.Contains(meta, []byte(`"data"`)) {
		t.Fatal("flow metadata contains payload")
	}
}
func TestGapsTruncatedCaptureAndMidstreamNeverFabricateBytes(t *testing.T) {
	p := frame("tcp", false, 101, 16, []byte("abcde"))
	p.Data = p.Data[:55]
	p.CapturedLength = len(p.Data)
	p.Truncated = true
	s := analyze(t, records(frame("tcp", false, 100, 2, nil), p, frame("tcp", false, 109, 16, []byte("tail"))), Options{})
	d := s.Details[0].Directions[0]
	if payload(d) != "atail" || len(d.Gaps) != 1 || d.Gaps[0].Offset != 1 || d.Gaps[0].Length != 7 || !d.Truncated || !d.Incomplete {
		t.Fatalf("gap lost: %+v", d)
	}
	s = analyze(t, records(frame("tcp", false, 100, 16, []byte("first"))), Options{})
	if !s.Details[0].Midstream || !s.Details[0].Incomplete {
		t.Fatal("midstream capture presented as complete")
	}
}
func TestSequenceWrapAndEarlierOutOfOrderData(t *testing.T) {
	s := analyze(t, records(frame("tcp", false, math.MaxUint32-2, 2, nil), frame("tcp", false, math.MaxUint32-1, 16, []byte("ab")), frame("tcp", false, 0, 16, []byte("cd"))), Options{})
	d := s.Details[0].Directions[0]
	if payload(d) != "abcd" || len(d.Gaps) != 0 {
		t.Fatalf("sequence wrap corrupts bytes: %+v", d)
	}
	s = analyze(t, records(frame("tcp", false, 104, 16, []byte("tail")), frame("tcp", false, 100, 16, []byte("head"))), Options{})
	d = s.Details[0].Directions[0]
	if payload(d) != "headtail" || d.StartSequence != 100 || !d.Midstream {
		t.Fatalf("earlier range failed: %+v", d)
	}
}
func TestTupleReuseEpochAndPolicyBoundariesDoNotMerge(t *testing.T) {
	input := records(frame("tcp", false, 100, 2, nil), frame("tcp", true, 200, 18, nil), frame("tcp", false, 101, 17, nil), frame("tcp", true, 201, 17, nil), frame("tcp", false, 100, 2, nil), frame("tcp", false, 101, 16, []byte("new")))
	s := analyze(t, input, Options{})
	if len(s.Flows) != 2 {
		t.Fatal("reused tuple merged")
	}
	closed := 0
	for _, f := range s.Flows {
		if f.Closed {
			closed++
		}
	}
	if closed != 1 {
		t.Fatal("FIN state lost")
	}
	input = records(frame("tcp", false, 100, 2, nil), frame("tcp", false, 101, 16, []byte("other")))
	input[1].CollectorEpoch = "new-epoch"
	s = analyze(t, input, Options{})
	if len(s.Flows) != 2 {
		t.Fatal("collector epoch merged")
	}
	input[1].CollectorEpoch = input[0].CollectorEpoch
	input[1].PolicyRevision = 2
	s = analyze(t, input, Options{})
	if len(s.Flows) != 2 {
		t.Fatal("policy revision merged")
	}
}
func TestMirroredTCPRangesRetainPointsWithoutDuplicatingBytes(t *testing.T) {
	a := frame("tcp", false, 100, 2, nil)
	b := frame("tcp", false, 101, 16, []byte("once"))
	mirror := b
	mirror.Interface = "br-b"
	mirror.IfIndex = 8
	mirror.ServiceID = "second"
	s := analyze(t, records(a, b, mirror), Options{})
	if len(s.Flows) != 1 || len(s.Flows[0].ObservationPoints) != 2 || s.Flows[0].Retransmissions != 1 || len(s.Flows[0].Candidates) != 2 || s.Flows[0].ServiceID != "" || payload(s.Details[0].Directions[0]) != "once" {
		t.Fatalf("mirrored observation lost provenance or duplicated data: %+v", s.Flows)
	}
}
func TestUDPDatagramBoundariesIncludingDuplicatesAndEmpty(t *testing.T) {
	a := frame("udp", false, 0, 0, []byte("same"))
	b := a
	b.Interface = "br-other"
	b.IfIndex = 8
	c := frame("udp", true, 0, 0, nil)
	s := analyze(t, records(a, b, c), Options{})
	if len(s.Flows) != 1 || len(s.Details[0].Datagrams) != 3 || len(s.Details[0].Directions) != 0 {
		t.Fatalf("UDP incorrectly reassembled/deduplicated: %+v", s)
	}
	if !bytes.Equal(s.Details[0].Datagrams[0].Data, s.Details[0].Datagrams[1].Data) || s.Details[0].Datagrams[2].CapturedLength != 0 || !s.Details[0].Datagrams[2].PayloadLengthKnown {
		t.Fatal("datagram contents/empty boundary lost")
	}
}
func TestAnalysisLimitsCancellationAndMetadataOnly(t *testing.T) {
	data := records(frame("tcp", false, 100, 2, nil), frame("tcp", false, 101, 16, []byte("123456")))
	s := analyze(t, data, Options{MaxDirectionBytes: 4})
	d := s.Details[0].Directions[0]
	if payload(d) != "1234" || !d.Truncated || len(d.Gaps) != 1 {
		t.Fatal("direction cap missing")
	}
	s = analyze(t, data, Options{MaxPackets: 1})
	if !s.Truncated || s.ScannedPackets != 1 {
		t.Fatal("packet bound ignored")
	}
	s = analyze(t, data, Options{MaxBytes: 1})
	if !s.Truncated || s.ScannedPackets != 0 {
		t.Fatal("byte bound ignored")
	}
	p := frame("tcp", false, 100, 2, nil)
	p.Data = nil
	p.CapturedLength = 0
	p.Truncated = true
	s = analyze(t, records(p), Options{})
	if !s.Details[0].Incomplete || s.Details[0].PayloadBytes != 0 {
		t.Fatal("metadata-only fabricated stream")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Analyze(ctx, data, Options{}); e != context.Canceled {
		t.Fatalf("cancel ignored: %v", e)
	}
	if _, e := Analyze(context.Background(), data, Options{MaxFlows: MaxFlows + 1}); e == nil {
		t.Fatal("invalid bounds accepted")
	}
}
func TestMalformedAndForgedHeadersDoNotEnterStream(t *testing.T) {
	p := frame("tcp", false, 100, 2, nil)
	p.SourceIP = "10.0.0.1"
	s := analyze(t, records(p), Options{})
	if len(s.Flows) != 0 {
		t.Fatal("forged metadata accepted")
	}
	p = frame("tcp", false, 100, 2, nil)
	p.Data[46] = 0
	s = analyze(t, records(p), Options{})
	if len(s.Flows) != 1 || !s.Flows[0].Incomplete || s.Flows[0].PayloadBytes != 0 {
		t.Fatal("invalid TCP header became payload")
	}
}

func TestEarlierMidstreamRebaseStillHonorsDirectionByteCap(t *testing.T) {
	s := analyze(t, records(frame("tcp", false, 104, 16, []byte("tail")), frame("tcp", false, 100, 16, []byte("head"))), Options{MaxDirectionBytes: 4})
	d := s.Details[0].Directions[0]
	if payload(d) != "head" || d.CapturedBytes > 4 || !d.Truncated || len(d.Gaps) == 0 {
		t.Fatalf("rebasing bypassed byte cap: %+v", d)
	}
}
func TestUDPConversationBytesAndFlowCountStayBounded(t *testing.T) {
	packets := []Packet{}
	for n := 0; n < 40; n++ {
		p := frame("udp", false, 0, 0, bytes.Repeat([]byte{'x'}, 60000))
		p.ID = "large-" + string(rune('a'+n))
		p.Sequence = int64(n)
		packets = append(packets, p)
	}
	s := analyze(t, packets, Options{})
	if len(s.Details) != 1 || s.Details[0].PayloadBytes > 2*MaxDirectionBytes || !s.Details[0].Truncated {
		t.Fatal("UDP detail exceeded response budget")
	}
	a, b := frame("tcp", false, 100, 2, nil), frame("tcp", false, 101, 2, nil)
	b.SourcePort = 5001
	binary.BigEndian.PutUint16(b.Data[34:36], 5001)
	s = analyze(t, records(a, b), Options{MaxFlows: 1})
	if len(s.Flows) != 1 || !s.Truncated {
		t.Fatal("flow cap ignored")
	}
}
func TestVersionProvenanceNeverInventsOneRelease(t *testing.T) {
	a, b := frame("tcp", false, 100, 2, nil), frame("tcp", false, 101, 16, []byte("versioned"))
	a.VersionBindings = []VersionBinding{{"game", "app", "release-a", "sha256:aaa"}}
	b.VersionBindings = []VersionBinding{{"game", "app", "release-b", "sha256:bbb"}}
	s := analyze(t, records(a, b), Options{})
	if len(s.Flows[0].VersionBindings) != 2 || !s.Flows[0].Incomplete {
		t.Fatal("mixed version provenance hidden")
	}
}

func TestRepeatedISNAfterPayloadStartsConservativeNewIncarnation(t *testing.T) {
	s := analyze(t, records(frame("tcp", false, 100, 2, nil), frame("tcp", false, 101, 16, []byte("old")), frame("tcp", false, 100, 2, nil), frame("tcp", false, 101, 16, []byte("new"))), Options{})
	if len(s.Details) != 2 {
		t.Fatal("new SYN with reused ISN merged sessions")
	}
	for _, d := range s.Details {
		value := payload(d.Directions[0])
		if value != "old" && value != "new" {
			t.Fatalf("incarnations contaminated: %q", value)
		}
	}
}
func TestIPv6TransportHeadersAndFragmentRefusal(t *testing.T) {
	ipv4 := frame("udp", false, 0, 0, []byte("ipv6-data"))
	transport := ipv4.Data[34:]
	data := make([]byte, 14+40+len(transport))
	data[12], data[13] = 0x86, 0xdd
	data[14] = 0x60
	binary.BigEndian.PutUint16(data[18:20], uint16(len(transport)))
	data[20] = 17
	copy(data[22:38], []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(data[38:54], []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	copy(data[54:], transport)
	p := ipv4
	p.Data = data
	p.SourceIP = "2001:db8::1"
	p.DestinationIP = "2001:db8::2"
	p.WireLength = len(data)
	p.CapturedLength = len(data)
	s := analyze(t, records(p), Options{})
	if len(s.Details) != 1 || string(s.Details[0].Datagrams[0].Data) != "ipv6-data" {
		t.Fatal("IPv6 UDP payload lost")
	}
	data[20] = 44
	s = analyze(t, records(p), Options{})
	if len(s.Details[0].Datagrams[0].Data) != 0 || !s.Details[0].Incomplete {
		t.Fatal("IP fragment was interpreted as transport payload")
	}
}
func TestMetadataHeavyInputsRespectAnalysisByteBudget(t *testing.T) {
	input := records(frame("tcp", false, 100, 2, nil), frame("tcp", false, 101, 16, []byte("x")))
	for n := 0; n < 256; n++ {
		input[0].Candidates = append(input[0].Candidates, Candidate{strings.Repeat("x", 128), strings.Repeat("y", 128)})
	}
	s := analyze(t, input, Options{MaxBytes: 4096})
	if !s.Truncated || s.ScannedPackets != 0 {
		t.Fatal("metadata bypassed memory scan budget")
	}
}
func FuzzTransportParser(f *testing.F) {
	for _, p := range []Packet{frame("tcp", false, 100, 2, []byte("hello")), frame("udp", false, 0, 0, []byte{0, 1, 2})} {
		f.Add(p.Data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65535 {
			return
		}
		p, ok := parsePacket(data)
		if ok {
			if len(p.payload) > p.wirePayload || p.wirePayload < 0 || (p.protocol != "tcp" && p.protocol != "udp") {
				t.Fatal("invalid parsed range")
			}
		}
	})
}

func TestPeerACKExposesMissingTailWithoutInventingBytes(t *testing.T) {
	syn, synack, data, ack := frame("tcp", false, 100, 2, nil), frame("tcp", true, 200, 18, nil), frame("tcp", false, 101, 16, []byte("abc")), frame("tcp", true, 201, 16, nil)
	binary.BigEndian.PutUint32(ack.Data[42:46], 109)
	s := analyze(t, records(syn, synack, data, ack), Options{})
	d := s.Details[0].Directions[0]
	if payload(d) != "abc" || len(d.Gaps) != 1 || d.Gaps[0].Offset != 3 || d.Gaps[0].Length != 5 {
		t.Fatalf("missing ACK-proven tail hidden: %+v", d)
	}
}

func TestMixedLegacyPayloadCannotBorrowPinnedDescriptorProvenance(t *testing.T) {
	syn, first, second := frame("tcp", false, 100, 2, nil), frame("tcp", false, 101, 16, []byte("legacy")), frame("tcp", false, 107, 16, []byte("pinned"))
	second.VersionBindings = []VersionBinding{{"game", "app", "release-1", "sha256:approved"}}
	s := analyze(t, records(syn, first, second), Options{})
	if len(s.Flows) != 1 || !s.Flows[0].MissingVersionBindings || len(s.Flows[0].VersionBindings) != 1 {
		t.Fatal("legacy payload silently borrowed another packet's version")
	}
	found := false
	for _, reason := range s.Flows[0].Reasons {
		found = found || reason == "packet_version_binding_missing"
	}
	if !found {
		t.Fatal("missing payload version has no explicit reason")
	}
	first.VersionBindings = second.VersionBindings
	s = analyze(t, records(syn, first, second), Options{})
	if s.Flows[0].MissingVersionBindings {
		t.Fatal("unversioned SYN invented missing payload provenance")
	}
	udp := frame("udp", false, 0, 0, []byte("unbound"))
	s = analyze(t, records(udp), Options{})
	if !s.Flows[0].MissingVersionBindings {
		t.Fatal("UDP payload omitted missing-version marker")
	}
}
