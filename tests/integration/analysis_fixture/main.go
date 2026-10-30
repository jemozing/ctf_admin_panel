// Trusted offline fixture seeding and synthetic packet generation. This helper
// never opens Docker, raw sockets, network connections, or a real installation.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/packets"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

type output struct {
	ServiceID             string           `json:"service_id"`
	ReleaseID             string           `json:"release_id"`
	SourceDigest          string           `json:"source_digest"`
	Descriptor            []byte           `json:"descriptor"`
	Records               []packets.Record `json:"records"`
	Ports                 map[string]int   `json:"ports"`
	RequestBytes          []byte           `json:"request_bytes"`
	ResponseBytes         []byte           `json:"response_bytes"`
	SeededFixtureRegistry bool             `json:"seeded_fixture_registry"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "analysis fixture refused:", err)
		os.Exit(1)
	}
}
func run() error {
	flags := flag.NewFlagSet("analysis-fixture", flag.ContinueOnError)
	directory := flags.String("root", "", "new dedicated private fixture under /tmp")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	root, err := filepath.Abs(*directory)
	if err != nil {
		return err
	}
	canonical, err := filepath.EvalSymlinks(root)
	tmp, te := filepath.EvalSymlinks("/tmp")
	info, se := os.Lstat(root)
	if err != nil || te != nil || se != nil || canonical != root || filepath.Dir(root) != tmp || !strings.HasPrefix(filepath.Base(root), "ctfm-analysis-panel-") || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("new canonical0700 /tmp/ctfm-analysis-panel-* root required")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Geteuid() {
		return errors.New("fixture root owner mismatch")
	}
	database := filepath.Join(root, "executor-state", "executor.db")
	if _, err := os.Lstat(database); !os.IsNotExist(err) {
		return errors.New("fixture executor database already exists")
	}
	for _, name := range []string{"games/game", "workspaces/game", "executor-state"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0700); err != nil {
			return err
		}
	}
	id, releaseID := domain.ID("fixture-game"), domain.ID("fixture-release")
	tree := domain.Hash([]byte("trusted synthetic fixture source version one"))
	config := domain.Hash([]byte("synthetic lexical configuration only; no Docker"))
	image := domain.Hash([]byte("synthetic immutable image reference; no actual image"))
	now := time.Now().UTC()
	service := domain.Service{SchemaVersion: 1, ID: id, Name: "Synthetic analysis fixture", ProjectDirectory: filepath.Join(root, "games/game"), SourceDirectory: filepath.Join(root, "workspaces/game"), ComposeProject: "fixture-game", ComposeFiles: []string{"compose.yaml"}, ManagedPaths: []domain.ManagedPath{{Path: "app", Kind: domain.ManagedCode}}, Targets: []string{"fixture-app"}, Containers: []domain.ContainerRef{{Component: "fixture-app", ID: strings.Repeat("a", 64), ImageID: image, Role: domain.RoleApplication}}, PolicyRevision: 1, FileMapRevision: 1}
	db, err := store.Open(database)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx := context.Background()
	proposal, err := db.CreateProposal(ctx, "fixture-proposal", service, config, "fixture-seeder", now)
	if err != nil {
		return err
	}
	if _, err = db.ApproveProposal(ctx, proposal.ID, proposal.Digest, "fixture-seeder", now); err != nil {
		return err
	}
	release, err := domain.NewRelease(domain.ReleaseSpec{SchemaVersion: 1, ID: releaseID, ServiceID: id, CreatedAt: now, Author: "fixture-seeder", Source: domain.ReleaseImported, SnapshotID: "fixture-baseline", TreeDigest: tree, ConfigurationDigest: config, PolicyRevision: 1, FileMapRevision: 1, Images: []domain.ImageRef{{Component: "fixture-app", ImageID: image, RetentionTag: "ctf-manager/fixture-game:fixture-release-fixture-app"}}})
	if err != nil {
		return err
	}
	if err = db.PutImmutable(ctx, "release", releaseID, id, release); err != nil {
		return err
	}
	state := map[string]any{"policy_revision": 1, "sequence": 1, "service_id": id, "current_release_id": releaseID, "baseline_id": "fixture-baseline", "active_snapshot_id": "fixture-baseline", "containers": service.Containers}
	if err = db.PutImmutable(ctx, "runtime_state", "fixture-state", id, state); err != nil {
		return err
	}
	descriptor, err := descriptorSet()
	if err != nil {
		return err
	}
	request, response, err := wire()
	if err != nil {
		return err
	}
	result := output{ServiceID: string(id), ReleaseID: string(releaseID), SourceDigest: string(tree), Descriptor: descriptor, Ports: map[string]int{"known": 40001, "legacy": 40002, "wrong-version": 40003, "mixed-version": 40004}, RequestBytes: request, ResponseBytes: response, SeededFixtureRegistry: true}
	index := 0
	for _, group := range []string{"known", "legacy", "wrong-version", "mixed-version"} {
		port := result.Ports[group]
		pieces := []struct {
			fromClient bool
			flags      byte
			sequence   uint32
			data       []byte
		}{{true, 2, 1000, nil}, {false, 18, 2000, nil}, {true, 24, 1001, request}, {false, 24, 2001, response}, {true, 17, 1001 + uint32(len(request)), nil}, {false, 17, 2001 + uint32(len(response)), nil}}
		for n, part := range pieces {
			index++
			src, dst, srcPort, dstPort, direction := "172.20.0.9", "172.20.0.5", port, 7000, "ingress"
			if !part.fromClient {
				src, dst, srcPort, dstPort, direction = dst, src, dstPort, srcPort, "egress"
			}
			raw := ethernet(src, dst, srcPort, dstPort, part.sequence, part.flags, part.data)
			r := packets.Record{Metadata: packets.Metadata{PacketID: fmt.Sprintf("analysis-%s-%02d", group, n), CollectorEpoch: "synthetic-analysis-epoch", PolicyRevision: 1, At: now.Add(-time.Second).Add(time.Duration(index) * time.Millisecond), ServiceID: string(id), Component: "fixture-app", Interface: "br-smokefixture", IfIndex: 7, Direction: direction, Protocol: "tcp", SourceIP: src, DestinationIP: dst, SourcePort: srcPort, DestinationPort: dstPort, TCPFlags: part.flags, WireLength: len(raw), CapturedLength: len(raw), LinkType: 1, Attribution: "unique"}, Data: raw}
			if group != "legacy" {
				pin := packets.VersionBinding{ServiceID: string(id), Component: "fixture-app", ReleaseID: string(releaseID), SourceDigest: string(tree)}
				if group == "wrong-version" || group == "mixed-version" && n == 3 {
					pin.ReleaseID = "other-release"
					pin.SourceDigest = string(domain.Hash([]byte("other captured source")))
				}
				r.VersionBindings = []packets.VersionBinding{pin}
			}
			result.Records = append(result.Records, r)
		}
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
func descriptorSet() ([]byte, error) {
	optional := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	str := descriptorpb.FieldDescriptorProto_TYPE_STRING
	boolean := descriptorpb.FieldDescriptorProto_TYPE_BOOL
	set := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{Name: proto.String("analysis.proto"), Package: proto.String("demo"), Syntax: proto.String("proto3"), MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Request"), Field: []*descriptorpb.FieldDescriptorProto{{Name: proto.String("name"), Number: proto.Int32(1), Label: &optional, Type: &str}}}, {Name: proto.String("Response"), Field: []*descriptorpb.FieldDescriptorProto{{Name: proto.String("ok"), Number: proto.Int32(1), Label: &optional, Type: &boolean}}}}, Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("Echo"), Method: []*descriptorpb.MethodDescriptorProto{{Name: proto.String("Chat"), InputType: proto.String(".demo.Request"), OutputType: proto.String(".demo.Response"), ClientStreaming: proto.Bool(true), ServerStreaming: proto.Bool(true)}}}}}}}
	return proto.Marshal(set)
}
func wire() ([]byte, []byte, error) {
	var client, server bytes.Buffer
	client.WriteString(http2.ClientPreface)
	cf, sf := http2.NewFramer(&client, nil), http2.NewFramer(&server, nil)
	if err := cf.WriteSettings(); err != nil {
		return nil, nil, err
	}
	if err := sf.WriteSettings(); err != nil {
		return nil, nil, err
	}
	headers := func(fr *http2.Framer, end bool, fields []hpack.HeaderField) error {
		var block bytes.Buffer
		encoder := hpack.NewEncoder(&block)
		for _, field := range fields {
			if err := encoder.WriteField(field); err != nil {
				return err
			}
		}
		return fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, EndStream: end, BlockFragment: block.Bytes()})
	}
	if err := headers(cf, false, []hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "http"}, {Name: ":path", Value: "/demo.Echo/Chat"}, {Name: ":authority", Value: "fixture-game"}, {Name: "content-type", Value: "application/grpc+proto"}, {Name: "te", Value: "trailers"}}); err != nil {
		return nil, nil, err
	}
	if err := cf.WriteData(1, true, grpcMessage([]byte{10, 5, 'a', 'l', 'i', 'c', 'e'})); err != nil {
		return nil, nil, err
	}
	if err := headers(sf, false, []hpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "content-type", Value: "application/grpc+proto"}}); err != nil {
		return nil, nil, err
	}
	if err := sf.WriteData(1, false, grpcMessage([]byte{8, 1})); err != nil {
		return nil, nil, err
	}
	if err := headers(sf, true, []hpack.HeaderField{{Name: "grpc-status", Value: "0"}, {Name: "grpc-message", Value: "fixture%20complete"}}); err != nil {
		return nil, nil, err
	}
	return client.Bytes(), server.Bytes(), nil
}
func grpcMessage(data []byte) []byte {
	out := make([]byte, 5+len(data))
	binary.BigEndian.PutUint32(out[1:5], uint32(len(data)))
	copy(out[5:], data)
	return out
}
func ethernet(source, destination string, srcPort, dstPort int, sequence uint32, flags byte, payload []byte) []byte {
	out := make([]byte, 54+len(payload))
	out[12], out[13] = 8, 0
	out[14] = 0x45
	binary.BigEndian.PutUint16(out[16:18], uint16(40+len(payload)))
	out[22], out[23] = 64, 6
	src, dst := netip.MustParseAddr(source).As4(), netip.MustParseAddr(destination).As4()
	copy(out[26:30], src[:])
	copy(out[30:34], dst[:])
	binary.BigEndian.PutUint16(out[34:36], uint16(srcPort))
	binary.BigEndian.PutUint16(out[36:38], uint16(dstPort))
	binary.BigEndian.PutUint32(out[38:42], sequence)
	out[46] = 0x50
	out[47] = flags
	copy(out[54:], payload)
	return out
}
