package packetcapture

import (
	"strings"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/packets"
)

func TestCapturePinsOnlyMatchedEndpointVersionsAndRequiresNewPolicyRevision(t *testing.T) {
	output := make(chan packets.Record, 8)
	engine, _ := newTestEngine(t, sinkFunc(func(r packets.Record) bool { output <- r; return true }))
	policy := testPolicy()
	policy.Interfaces[0].Endpoints[0].ReleaseID = "release-1"
	policy.Interfaces[0].Endpoints[0].SourceDigest = "sha256:" + strings.Repeat("a", 64)
	policy.Interfaces[0].Endpoints = append(policy.Interfaces[0].Endpoints, Endpoint{ServiceID: "unmatched", Component: "api", Address: "172.20.0.9", Protocol: "tcp", Port: 9000, ReleaseID: "release-other", SourceDigest: "sha256:" + strings.Repeat("b", 64)})
	if err := engine.Apply(policy); err != nil {
		t.Fatal(err)
	}
	inject(engine, ethernetFrame("tcp", false, "172.20.0.8", "172.20.0.5", 50000, 7000, []byte("one")))
	first := takeRecord(t, output)
	if len(first.VersionBindings) != 1 || first.VersionBindings[0].ServiceID != "game" || first.VersionBindings[0].ReleaseID != "release-1" || first.VersionBindings[0].SourceDigest != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("unmatched endpoint or unpinned version recorded: %+v", first.VersionBindings)
	}
	policy.Interfaces[0].Endpoints[0].ReleaseID = "release-2"
	if err := engine.Apply(policy); err == nil {
		t.Fatal("version changed at same policy revision")
	}
	inject(engine, ethernetFrame("tcp", false, "172.20.0.8", "172.20.0.5", 50000, 7000, []byte("rejected")))
	rejected := takeRecord(t, output)
	if rejected.PolicyRevision != 1 || rejected.VersionBindings[0].ReleaseID != "release-1" {
		t.Fatal("failed activation changed pinned version")
	}
	policy.Revision++
	if err := engine.Apply(policy); err != nil {
		t.Fatal(err)
	}
	inject(engine, ethernetFrame("tcp", false, "172.20.0.8", "172.20.0.5", 50000, 7000, []byte("two")))
	second := takeRecord(t, output)
	if second.PolicyRevision != 2 || second.VersionBindings[0].ReleaseID != "release-2" || second.CollectorEpoch != first.CollectorEpoch || second.PacketID == first.PacketID {
		t.Fatal("new mapping revision did not preserve exact observed provenance")
	}
}
func TestAmbiguousCaptureVersionsKeepEachCandidateAndLegacyPolicyWorks(t *testing.T) {
	output := make(chan packets.Record, 8)
	engine, _ := newTestEngine(t, sinkFunc(func(r packets.Record) bool { output <- r; return true }))
	policy := testPolicy()
	if err := engine.Apply(policy); err != nil {
		t.Fatal(err)
	}
	inject(engine, ethernetFrame("tcp", false, "172.20.0.8", "172.20.0.5", 50000, 7000, nil))
	if legacy := takeRecord(t, output); len(legacy.VersionBindings) != 0 {
		t.Fatal("legacy policy invented version bindings")
	}
	policy.Revision++
	policy.Interfaces[0].Endpoints[0].ReleaseID = "release-1"
	policy.Interfaces[0].Endpoints = append(policy.Interfaces[0].Endpoints, Endpoint{ServiceID: "second", Component: "api", Address: "172.20.0.5", Protocol: "tcp", Port: 7000, ReleaseID: "release-2"})
	if err := engine.Apply(policy); err != nil {
		t.Fatal(err)
	}
	inject(engine, ethernetFrame("tcp", false, "172.20.0.8", "172.20.0.5", 50000, 7000, nil))
	r := takeRecord(t, output)
	if r.Attribution != "ambiguous" || r.ServiceID != "" || len(r.Candidates) != 2 || len(r.VersionBindings) != 2 {
		t.Fatalf("ambiguous version association collapsed: %+v", r.Metadata)
	}
	for _, b := range r.VersionBindings {
		if b.ServiceID == "game" && b.ReleaseID != "release-1" || b.ServiceID == "second" && b.ReleaseID != "release-2" {
			t.Fatal("candidate version association changed")
		}
	}
}
func TestCaptureVersionIdentityBoundsAreValidated(t *testing.T) {
	for _, edit := range []func(*Endpoint){func(e *Endpoint) { e.ReleaseID = "../escape" }, func(e *Endpoint) { e.SourceDigest = "sha256:" + strings.Repeat("g", 64) }, func(e *Endpoint) { e.SourceDigest = "sha256:abcd" }} {
		policy := testPolicy()
		edit(&policy.Interfaces[0].Endpoints[0])
		if _, err := NormalizePolicy(policy); err == nil {
			t.Fatal("unsafe endpoint version accepted")
		}
	}
}
