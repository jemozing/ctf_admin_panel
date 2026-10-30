package packets

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func versionFixture() VersionBinding {
	return VersionBinding{ServiceID: "game", Component: "api", ReleaseID: "release-1", SourceDigest: "sha256:" + strings.Repeat("a", 64)}
}
func TestCapturedVersionBindingsAreAssociatedAndBounded(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name string
		edit func(*Record)
	}{
		{"unrelated-service", func(r *Record) { r.VersionBindings[0].ServiceID = "other" }},
		{"unrelated-component", func(r *Record) { r.VersionBindings[0].Component = "db" }},
		{"empty-binding", func(r *Record) { r.VersionBindings[0].ReleaseID = ""; r.VersionBindings[0].SourceDigest = "" }},
		{"invalid-release", func(r *Record) { r.VersionBindings[0].ReleaseID = "../release" }},
		{"invalid-digest", func(r *Record) { r.VersionBindings[0].SourceDigest = "sha256:" + strings.Repeat("g", 64) }},
		{"uppercase-digest", func(r *Record) { r.VersionBindings[0].SourceDigest = "sha256:" + strings.Repeat("A", 64) }},
		{"short-digest", func(r *Record) { r.VersionBindings[0].SourceDigest = "sha256:aa" }},
		{"duplicate-binding", func(r *Record) { r.VersionBindings = append(r.VersionBindings, r.VersionBindings[0]) }},
		{"too-many", func(r *Record) {
			for len(r.VersionBindings) <= 256 {
				r.VersionBindings = append(r.VersionBindings, r.VersionBindings[0])
			}
		}},
		{"ambiguous-empty-association", func(r *Record) {
			r.ServiceID = ""
			r.Component = ""
			r.Attribution = "ambiguous"
			r.Candidates = []Candidate{{"game", "api"}, {"second", "app"}}
			r.VersionBindings[0].ServiceID = ""
			r.VersionBindings[0].Component = ""
		}},
		{"ambiguous-unrelated-association", func(r *Record) {
			r.ServiceID = ""
			r.Component = ""
			r.Attribution = "ambiguous"
			r.Candidates = []Candidate{{"game", "api"}, {"second", "app"}}
			r.VersionBindings[0].ServiceID = "other"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := fixture(now, "versioned")
			r.VersionBindings = []VersionBinding{versionFixture()}
			tc.edit(&r)
			if err := validateRecord(&r, now); err == nil {
				t.Fatal("unsafe version binding accepted")
			}
		})
	}
}
func TestCapturedVersionsRoundTripLegacyAndCandidateScope(t *testing.T) {
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, nil)
	for _, tc := range []struct {
		name      string
		bindings  []VersionBinding
		ambiguous bool
	}{
		{"legacy", nil, false},
		{"release-only", []VersionBinding{{ServiceID: "game", Component: "api", ReleaseID: "release-1"}}, false},
		{"source-only", []VersionBinding{{ServiceID: "game", Component: "api", SourceDigest: versionFixture().SourceDigest}}, false},
		{"full", []VersionBinding{versionFixture()}, false},
		{"ambiguous", []VersionBinding{versionFixture(), {ServiceID: "second", Component: "app", ReleaseID: "release-2"}}, true},
	} {
		r := fixture(now, tc.name)
		r.VersionBindings = tc.bindings
		if tc.ambiguous {
			r.ServiceID = ""
			r.Component = ""
			r.Attribution = "ambiguous"
			r.Candidates = []Candidate{{"game", "api"}, {"second", "app"}}
		}
		mustIngest(t, s, r)
		detail, err := s.Detail(context.Background(), r.PacketID)
		if err != nil || len(detail.VersionBindings) != len(tc.bindings) {
			t.Fatalf("version provenance lost: %+v %v", detail, err)
		}
		for n, v := range detail.VersionBindings {
			if v != tc.bindings[n] {
				t.Fatal("version binding changed during storage")
			}
		}
	}
	page, err := s.FlowList(context.Background(), Query{})
	if err != nil || len(page.Flows) != 1 {
		t.Fatalf("flow provenance lookup: %+v %v", page, err)
	}
	if len(page.Flows[0].VersionBindings) < 2 || !page.Flows[0].Incomplete {
		t.Fatal("version transitions were silently assigned one release")
	}
}

func TestMaximumCandidateScopedVersionsAreAcceptedWithoutArbitraryOwner(t *testing.T) {
	now := time.Now().UTC()
	r := fixture(now, "max-associated-versions")
	r.ServiceID = ""
	r.Component = ""
	r.Attribution = "ambiguous"
	for n := 0; n < 256; n++ {
		id := fmt.Sprintf("game-%d", n)
		r.Candidates = append(r.Candidates, Candidate{ServiceID: id, Component: "app"})
		r.VersionBindings = append(r.VersionBindings, VersionBinding{ServiceID: id, Component: "app", ReleaseID: "release-1"})
	}
	if err := validateRecord(&r, now); err != nil || len(r.VersionBindings) != 256 || r.ServiceID != "" {
		t.Fatalf("maximum associated versions rejected/assigned: %v", err)
	}
}
