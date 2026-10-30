package executor

import (
	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/secrets"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogDecodingPreservesSourcesDeduplicatesIdentityAndRedactsBeforeCut(t *testing.T) {
	prefix := "2026-10-19T00:00:00.000000001Z "
	secret := "private-test-secret"
	line := strings.Repeat("x", 16380) + secret + "\x1b[31m"
	redact := func(s string) string { return strings.ReplaceAll(s, secret, "[REDACTED]") }
	records := decodeLogLines([]byte(prefix+line+"\n"+prefix+"same\n"+prefix+"same\n"), "app", "container-a", "stderr", redact, transport.LogQuery{Component: "*", Tail: 200})
	if len(records) != 3 || !records[0].Truncated || strings.Contains(records[0].Text, "private") || records[0].Stream != "stderr" || records[0].ContainerID != "container-a" || records[1].ID == records[2].ID {
		t.Fatalf("unsafe record mapping: %+v", records)
	}
	repeat := decodeLogLines([]byte(prefix+"same\n"+prefix+"same\n"), "app", "container-a", "stderr", redact, transport.LogQuery{Component: "*", Tail: 200})
	if repeat[0].ID != records[1].ID || repeat[1].ID != records[2].ID {
		t.Fatal("repeated tail changed record identity")
	}
	replaced := decodeLogLines([]byte(prefix+"same\n"), "app", "container-b", "stderr", redact, transport.LogQuery{Component: "*", Tail: 200})
	if replaced[0].ID == repeat[0].ID {
		t.Fatal("recreated container merged with old identity")
	}
	filtered := decodeLogLines([]byte(prefix+"error one\n"+prefix+"error debug\n"), "app", "a", "stdout", redact, transport.LogQuery{Component: "*", Tail: 200, Include: "error", Exclude: "debug", Search: "ONE"})
	if len(filtered) != 1 || filtered[0].Text != "error one" {
		t.Fatal(filtered)
	}
	if string(completeLogPrefix([]byte("complete\nprivate-prefix"))) != "complete\n" || len(completeLogPrefix([]byte("private-prefix"))) != 0 {
		t.Fatal("partial raw secret can escape")
	}
}
func TestKnownEnvironmentAndMultilineFileSecretsAreRedacted(t *testing.T) {
	vault, err := secrets.Open(filepath.Join(t.TempDir(), "vault"))
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()
	env, err := vault.Import("environment", []byte(`{"PASSWORD":"abc$private","PUBLIC":"setting"}`))
	if err != nil {
		t.Fatal(err)
	}
	file, err := vault.Import("secret-file", []byte("first-private-line\nsecond-private-line"))
	if err != nil {
		t.Fatal(err)
	}
	m := Manager{Vault: vault}
	redact, err := m.displayRedactor(t.Context(), domain.Service{SecretVersions: []domain.SecretVersionRef{env, file}})
	if err != nil {
		t.Fatal(err)
	}
	got := redact("abc$private setting second-private-line")
	if strings.Contains(got, "private") || strings.Contains(got, "setting") {
		t.Fatal("private input leaked", got)
	}
	if err := vault.Revoke(env); err != nil {
		t.Fatal(err)
	}
	if _, err = m.displayRedactor(t.Context(), domain.Service{SecretVersions: []domain.SecretVersionRef{env}}); err == nil {
		t.Fatal("missing redactor material silently ignored")
	}
}
func TestFilesCompareImmutableCandidateAndExposeOnlyApprovedBoundedCode(t *testing.T) {
	f := newPlanningFixture(t)
	writePlanningFile(t, f.workspaceFile, "version = 2\n")
	candidate, err := f.m.capture(t.Context(), f.s, "defender", domain.SnapshotCandidate, f.s.SourceDirectory)
	if err != nil {
		t.Fatal(err)
	}
	st, err := f.m.state(t.Context(), f.s)
	if err != nil {
		t.Fatal(err)
	}
	st.CandidateID = candidate.ID
	if err = f.m.saveState(t.Context(), &st); err != nil {
		t.Fatal(err)
	}
	writePlanningFile(t, f.workspaceFile, "version = 3\n")
	result, err := f.m.Files(t.Context(), f.s.ID, transport.FilesQuery{Comparison: "candidate", Path: "app/main.py"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Changes) != 1 || result.File == nil || result.File.Before == nil || result.File.After == nil || *result.File.Before != "version = 1\n" || *result.File.After != "version = 2\n" {
		t.Fatalf("mutable workspace substituted for candidate: %+v", result)
	}
	if _, err = f.m.Files(t.Context(), f.s.ID, transport.FilesQuery{Comparison: "candidate", Path: "app/not-managed-secret"}); err == nil {
		t.Fatal("arbitrary file read accepted")
	}
	if fileTextAllowed(f.s, "app/.env") || fileTextAllowed(f.s, "app/secrets/key") || fileTextAllowed(f.s, "app/server.key") {
		t.Fatal("sensitive path allowed")
	}
	changed := candidate.Manifest.Entries()[1]
	changed.Path = "app/main.py"
	changed.Size = 99
	root, _ := f.m.Snapshots.ContentPath(candidate.ID)
	if text, reason := previewText(t.Context(), root, &changed, true, func(s string) string { return s }); text != nil || reason == "" {
		t.Fatal("concurrent/corrupt file sent as verified")
	}
	if err = os.Remove(f.activeFile); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(f.workspaceFile, f.activeFile); err != nil {
		t.Fatal(err)
	}
	if _, err = f.m.Files(t.Context(), f.s.ID, transport.FilesQuery{Comparison: "candidate"}); err == nil {
		t.Fatal("active symlink escaped file policy")
	}
}
func TestPartialRuntimeNeverClaimsOldReleaseActiveOrOldChecksHealthy(t *testing.T) {
	f := newPlanningFixture(t)
	st, err := f.m.state(t.Context(), f.s)
	if err != nil {
		t.Fatal(err)
	}
	makeDetails := func(id string) transport.ServiceDetails {
		return transport.ServiceDetails{CurrentReleaseID: st.CurrentReleaseID, ObservedState: "requires_recovery", Containers: []docker.Container{{ID: id, Component: "app", ImageID: string(f.s.Containers[0].ImageID)}}, Health: []domain.HealthSignal{{Source: domain.HealthFunctional, State: domain.HealthHealthy}}}
	}
	good := makeDetails(f.s.Containers[0].ID)
	f.m.detailObservations(t.Context(), f.s, st, &good)
	if good.CurrentReleaseID != st.CurrentReleaseID || good.ComponentVersions[0].State != "matches_recorded_image" {
		t.Fatal("unchanged runtime became unknown")
	}
	partial := makeDetails(strings.Repeat("b", 64))
	f.m.detailObservations(t.Context(), f.s, st, &partial)
	if partial.CurrentReleaseID != "" || partial.ObservedState != "requires_recovery" || partial.ComponentVersions[0].State != "image_matches_identity_changed" || partial.Health[0].State != domain.HealthUnknown {
		t.Fatalf("partial switch misrepresented: %+v", partial)
	}
	writePlanningFile(t, f.activeFile, "external edit\n")
	drift := makeDetails(f.s.Containers[0].ID)
	f.m.detailObservations(t.Context(), f.s, st, &drift)
	if drift.Drift.State != "changed" || drift.CurrentReleaseID != "" || drift.Health[0].State != domain.HealthUnknown {
		t.Fatal("file drift kept historical healthy active release")
	}
}

func TestComponentReleaseObservationReportsUniquePartialVersionAndAmbiguity(t *testing.T) {
	f := newPlanningFixture(t)
	writePlanningFile(t, f.workspaceFile, "version = 2\n")
	candidate, err := f.m.capture(t.Context(), f.s, "defender", domain.SnapshotCandidate, f.s.SourceDirectory)
	if err != nil {
		t.Fatal(err)
	}
	spec := f.release.Spec()
	spec.ID = "release-new"
	spec.SnapshotID = candidate.ID
	spec.TreeDigest = candidate.ManifestDigest
	spec.Source = domain.ReleaseWorkspace
	spec.Images[0].ImageID = domain.Hash([]byte("new image"))
	spec.Images[0].RetentionTag = retentionTag(f.s, spec.ID, "app")
	next, err := domain.NewRelease(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.m.Store.PutImmutable(t.Context(), "release", spec.ID, f.s.ID, next); err != nil {
		t.Fatal(err)
	}
	st, err := f.m.state(t.Context(), f.s)
	if err != nil {
		t.Fatal(err)
	}
	writePlanningFile(t, f.activeFile, "version = 2\n")
	actual := docker.Container{ID: strings.Repeat("c", 64), Component: "app", ImageID: string(spec.Images[0].ImageID), Mounts: []docker.Mount{{Type: "bind", Source: filepath.Join(f.s.ProjectDirectory, "app"), Target: "/app"}}}
	result := transport.ServiceDetails{CurrentReleaseID: st.CurrentReleaseID, ObservedState: "requires_recovery", Containers: []docker.Container{actual}}
	f.m.detailObservations(t.Context(), f.s, st, &result)
	if result.CurrentReleaseID != "" || result.ComponentVersions[0].ObservedReleaseID != spec.ID || result.ComponentVersions[0].ReleaseEvidence != "image_and_managed_bind_tree" {
		t.Fatalf("new component version hidden after partial switch: %+v", result)
	}
	duplicateSpec := next.Spec()
	duplicateSpec.ID = "release-same-image"
	duplicateSpec.Images[0].RetentionTag = retentionTag(f.s, duplicateSpec.ID, "app")
	duplicate, err := domain.NewRelease(duplicateSpec)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.m.Store.PutImmutable(t.Context(), "release", duplicateSpec.ID, f.s.ID, duplicate); err != nil {
		t.Fatal(err)
	}
	result = transport.ServiceDetails{Containers: []docker.Container{actual}}
	f.m.detailObservations(t.Context(), f.s, st, &result)
	if v := result.ComponentVersions[0]; v.ObservedReleaseID != "" || len(v.PossibleReleaseIDs) != 2 || v.AmbiguityReason == "" {
		t.Fatalf("ambiguous image guessed a release: %+v", v)
	}
	// Recover can restore a captured external edit using original images. Such a
	// tree is a recovery point, not evidence that immutable baseline is active.
	st.ActiveSnapshotID = candidate.ID
	actual.ImageID = string(f.s.Containers[0].ImageID)
	actual.ID = f.s.Containers[0].ID
	result = transport.ServiceDetails{CurrentReleaseID: st.CurrentReleaseID, Containers: []docker.Container{actual}}
	f.m.detailObservations(t.Context(), f.s, st, &result)
	if result.CurrentReleaseID != "" || result.Drift.State != "unverified" || result.ComponentVersions[0].ObservedReleaseID != "" {
		t.Fatalf("external recovery files falsely labelled baseline: %+v", result)
	}
}
