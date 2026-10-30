package packets

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/flows"
	"github.com/ctf-service-manager/ctf-service-manager/internal/protocols"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func archiveGRPCFrames(t *testing.T) ([]byte, []byte) {
	t.Helper()
	frame := func(value []byte) []byte {
		out := make([]byte, 5)
		binary.BigEndian.PutUint32(out[1:], uint32(len(value)))
		return append(out, value...)
	}
	var client, server bytes.Buffer
	client.WriteString("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	write := func(buffer *bytes.Buffer, response bool) {
		framer := http2.NewFramer(buffer, nil)
		if err := framer.WriteSettings(); err != nil {
			t.Fatal(err)
		}
		var block bytes.Buffer
		encoder := hpack.NewEncoder(&block)
		headers := []hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "http"}, {Name: ":path", Value: "/game.Service/Check"}, {Name: "content-type", Value: "application/grpc"}}
		if response {
			headers = []hpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "content-type", Value: "application/grpc"}}
		}
		for _, h := range headers {
			if err := encoder.WriteField(h); err != nil {
				t.Fatal(err)
			}
		}
		if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, BlockFragment: block.Bytes()}); err != nil {
			t.Fatal(err)
		}
		message := []byte{10, 6, 's', 'a', 'm', 'p', 'l', 'e'}
		if response {
			message = []byte{10, 2, 'o', 'k'}
		}
		if err := framer.WriteData(1, !response, frame(message)); err != nil {
			t.Fatal(err)
		}
		if response {
			block.Reset()
			if err := encoder.WriteField(hpack.HeaderField{Name: "grpc-status", Value: "0"}); err != nil {
				t.Fatal(err)
			}
			if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, EndStream: true, BlockFragment: block.Bytes()}); err != nil {
				t.Fatal(err)
			}
		}
	}
	write(&client, false)
	write(&server, true)
	return client.Bytes(), server.Bytes()
}
func archiveTCPRecord(at time.Time, id string, reverse bool, sequence uint32, flags byte, payload []byte, pins []VersionBinding) Record {
	source, destination := [4]byte{192, 0, 2, 1}, [4]byte{172, 20, 0, 5}
	sourceIP, destinationIP := "192.0.2.1", "172.20.0.5"
	sourcePort, destinationPort := 40000, 7000
	direction := "ingress"
	if reverse {
		source, destination = destination, source
		sourceIP, destinationIP = destinationIP, sourceIP
		sourcePort, destinationPort = destinationPort, sourcePort
		direction = "egress"
	}
	data := make([]byte, 54+len(payload))
	data[12], data[13] = 8, 0
	data[14] = 0x45
	binary.BigEndian.PutUint16(data[16:18], uint16(40+len(payload)))
	data[22] = 64
	data[23] = 6
	copy(data[26:30], source[:])
	copy(data[30:34], destination[:])
	binary.BigEndian.PutUint16(data[34:36], uint16(sourcePort))
	binary.BigEndian.PutUint16(data[36:38], uint16(destinationPort))
	binary.BigEndian.PutUint32(data[38:42], sequence)
	data[46] = 0x50
	data[47] = flags
	copy(data[54:], payload)
	return Record{Metadata: Metadata{VersionBindings: append([]VersionBinding{}, pins...), PacketID: id, CollectorEpoch: "decode-epoch", PolicyRevision: 1, At: at, ServiceID: "game", Component: "api", Interface: "br-game", IfIndex: 7, Direction: direction, Protocol: "tcp", SourceIP: sourceIP, DestinationIP: destinationIP, SourcePort: sourcePort, DestinationPort: destinationPort, TCPFlags: flags, WireLength: len(data), CapturedLength: len(data), LinkType: 1, Attribution: "unique"}, Data: data}
}
func archiveGRPCFlow(t *testing.T, s *Store, now time.Time, clientPins, serverPins []VersionBinding) FlowDecodeRequest {
	t.Helper()
	client, server := archiveGRPCFrames(t)
	records := []Record{archiveTCPRecord(now.Add(-time.Second), "syn", false, 100, 2, nil, clientPins), archiveTCPRecord(now.Add(-900*time.Millisecond), "syn-ack", true, 1000, 18, nil, serverPins), archiveTCPRecord(now.Add(-800*time.Millisecond), "request", false, 101, 24, client, clientPins), archiveTCPRecord(now.Add(-700*time.Millisecond), "response", true, 1001, 24, server, serverPins), archiveTCPRecord(now.Add(-600*time.Millisecond), "client-fin", false, 101+uint32(len(client)), 17, nil, clientPins), archiveTCPRecord(now.Add(-500*time.Millisecond), "server-fin", true, 1001+uint32(len(server)), 17, nil, serverPins)}
	for _, record := range records {
		mustIngest(t, s, record)
	}
	page, err := s.FlowList(context.Background(), Query{Protocol: "tcp", Limit: 50})
	if err != nil || len(page.Flows) != 1 {
		t.Fatalf("gRPC flow assembly: %+v %v", page, err)
	}
	return FlowDecodeRequest{Query: page.Query, FlowID: page.Flows[0].ID}
}
func TestFlowDecodeUsesOnlyCapturedDescriptorVersionPins(t *testing.T) {
	now := time.Now().UTC()
	binding := archiveDescriptorBinding("release-one")
	pins := []VersionBinding{{ServiceID: "game", Component: "api", ReleaseID: binding.ReleaseID, SourceDigest: binding.SourceDigest}}
	s := openTest(t, func() time.Time { return now }, nil)
	descriptor := confirmArchiveDescriptor(t, s, binding)
	request := archiveGRPCFlow(t, s, now, pins, pins)
	request.DescriptorID = descriptor.ID
	result, err := s.FlowDecode(context.Background(), request)
	if err != nil || result.Protocol != "grpc" || len(result.RPCs) != 1 || result.RPCs[0].GRPCStatus == nil || *result.RPCs[0].GRPCStatus != 0 || len(result.RPCs[0].RequestMessages) != 1 {
		t.Fatalf("flow decode: %+v %v", result, err)
	}
	var decoded map[string]any
	if json.Unmarshal(result.RPCs[0].RequestMessages[0].JSON, &decoded) != nil || decoded["flag"] != "sample" || result.RPCs[0].RequestMessages[0].Type != "game.Request" {
		t.Fatal("captured release did not select descriptor fields")
	}
	other := binding
	other.SourceDigest = "sha256:" + strings.Repeat("b", 64)
	wrong := confirmArchiveDescriptor(t, s, other)
	request.DescriptorID = wrong.ID
	if _, err := s.FlowDecode(context.Background(), request); err == nil {
		t.Fatal("same release with different captured source digest accepted")
	}
	request.DescriptorID = ""
	raw, err := s.FlowDecode(context.Background(), request)
	if err != nil || len(raw.RPCs[0].RequestMessages[0].JSON) != 0 || raw.RPCs[0].RequestMessages[0].Type != "" {
		t.Fatal("raw decode invented protobuf names")
	}
}
func TestFlowDecodeLegacyAndMixedVersionProvenanceNeverGuessDescriptor(t *testing.T) {
	now := time.Now().UTC()
	binding := archiveDescriptorBinding("release-one")
	pins := []VersionBinding{{ServiceID: "game", Component: "api", ReleaseID: binding.ReleaseID, SourceDigest: binding.SourceDigest}}
	for _, scenario := range []string{"legacy", "mixed", "partially-bound"} {
		t.Run(scenario, func(t *testing.T) {
			s := openTest(t, func() time.Time { return now }, nil)
			descriptor := confirmArchiveDescriptor(t, s, binding)
			a, b := pins, pins
			if scenario == "legacy" {
				a, b = nil, nil
			} else if scenario == "partially-bound" {
				b = nil
			} else {
				b = []VersionBinding{{ServiceID: "game", Component: "api", ReleaseID: "release-two", SourceDigest: "sha256:" + strings.Repeat("b", 64)}}
			}
			request := archiveGRPCFlow(t, s, now, a, b)
			request.DescriptorID = descriptor.ID
			if _, err := s.FlowDecode(context.Background(), request); err == nil {
				t.Fatalf("%s source provenance received protobuf field names", scenario)
			}
			request.DescriptorID = ""
			raw, err := s.FlowDecode(context.Background(), request)
			if err != nil || raw.Protocol != "grpc" || len(raw.RPCs[0].RequestMessages[0].JSON) > 0 {
				t.Fatalf("%s raw fallback unavailable: %+v %v", scenario, raw, err)
			}
		})
	}
}
func TestProtocolDirectionStopsBeforeHolesAndRejectsConflictingBytes(t *testing.T) {
	direction := flows.Direction{Chunks: []flows.Chunk{{Offset: 0, Data: []byte("prefix")}, {Offset: 12, Data: []byte("must not join")}}, Gaps: []flows.Gap{{Offset: 6, Length: 6, Reason: "missing"}}, Midstream: true}
	got := protocolDirection(direction)
	if !bytes.Equal(got.Data, []byte("prefix")) || !got.Gap || !got.PrefixMissing {
		t.Fatal("TCP bytes crossed an uncaptured hole")
	}
	direction = flows.Direction{Chunks: []flows.Chunk{{Offset: 0, Data: []byte("arbitrarily kept overlap")}}, ConflictingOverlaps: 1, Incomplete: true}
	got = protocolDirection(direction)
	if !got.Truncated && len(got.Data) > 0 {
		t.Fatal("conflicting TCP bytes presented as an unambiguous decoder input")
	}
}
func TestTerminatedExchangeDecodeIsOfflineAndBounded(t *testing.T) {
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, nil)
	frame := func(value []byte) []byte {
		out := make([]byte, 5)
		binary.BigEndian.PutUint32(out[1:], uint32(len(value)))
		return append(out, value...)
	}
	ex := protocols.Exchange{RequestHeaders: []protocols.Header{{Name: ":method", Value: "POST"}, {Name: ":path", Value: "/game.Service/Check"}, {Name: "content-type", Value: "application/grpc"}}, ResponseHeaders: []protocols.Header{{Name: ":status", Value: "200"}, {Name: "content-type", Value: "application/grpc"}}, ResponseTrailers: []protocols.Header{{Name: "grpc-status", Value: "0"}}, RequestBody: frame([]byte{10, 1, 'x'}), ResponseBody: frame([]byte{10, 2, 'o', 'k'}), RequestComplete: true, ResponseComplete: true}
	r, err := s.ExchangeDecode(context.Background(), ExchangeDecodeRequest{Exchange: ex})
	if err != nil || r.Protocol != "grpc" || len(r.RPCs) != 1 || r.RPCs[0].RequestMessages[0].Type != "" || !bytes.Equal(r.RPCs[0].RequestMessages[0].Data, []byte{10, 1, 'x'}) {
		t.Fatalf("terminated exchange: %+v %v", r, err)
	}
	ex.RequestTruncated = true
	r, err = s.ExchangeDecode(context.Background(), ExchangeDecodeRequest{Exchange: ex})
	if err != nil || !r.Incomplete || !r.Truncated {
		t.Fatal("omitted terminated body appeared complete")
	}
	ex.RequestBody = make([]byte, protocols.MaxInputBytes+1)
	r, err = s.ExchangeDecode(context.Background(), ExchangeDecodeRequest{Exchange: ex})
	if err != nil || r.Status != "limit" {
		t.Fatal("exchange input limit bypassed")
	}
}
func TestFlowDecodeUDPDoesNotClaimTCPOrGRPC(t *testing.T) {
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, nil)
	mustIngest(t, s, fixture(now, "udp-decode"))
	p, err := s.FlowList(context.Background(), Query{Protocol: "udp"})
	if err != nil || len(p.Flows) != 1 {
		t.Fatal(err)
	}
	r, err := s.FlowDecode(context.Background(), FlowDecodeRequest{Query: p.Query, FlowID: p.Flows[0].ID})
	if err != nil || r.Status != "unsupported" || r.Protocol != "unknown" || len(r.RPCs) > 0 {
		t.Fatalf("UDP invented TCP/gRPC: %s %v", fmt.Sprint(r), err)
	}
}
