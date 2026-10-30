package domain

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var testTime = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

func serviceFixture() Service {
	return Service{
		SchemaVersion: SchemaVersion, ID: "flags", Name: "Flag service",
		ProjectDirectory: "/srv/ctf/flags", SourceDirectory: "/srv/workspaces/flags",
		ComposeProject: "round_one", ComposeFiles: []string{"compose.yaml", "compose.ctf.yaml"},
		ManagedPaths: []ManagedPath{{Path: "app", Kind: ManagedCode}, {Path: "Dockerfile", Kind: ManagedConfig}},
		Targets:      []string{"app"}, PolicyRevision: 1, FileMapRevision: 1,
		Containers: []ContainerRef{
			{Component: "app", ID: strings.Repeat("a", 64), ImageID: Hash([]byte("app")), Role: RoleApplication},
			{Component: "db", ID: strings.Repeat("b", 64), ImageID: Hash([]byte("db")), Role: RoleDatabase},
		},
		DataPaths: []DataPath{{Name: "database", Kind: StorageNamedVolume, Source: "round_one_db", Target: "/var/lib/database", Component: "db", Significant: true}},
	}
}

func TestRegistrationRejectsUnsafeDataAndWorkspaceMappings(t *testing.T) {
	if err := serviceFixture().Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(*Service)
	}{
		{"workspace inside active tree", func(s *Service) { s.SourceDirectory = s.ProjectDirectory + "/source" }},
		{"active inside workspace", func(s *Service) { s.SourceDirectory = "/srv/ctf" }},
		{"traversal", func(s *Service) { s.ManagedPaths[0].Path = "app/../../etc" }},
		{"noncanonical path", func(s *Service) { s.ManagedPaths[0].Path = "app/../app" }},
		{"code overlaps preserved data", func(s *Service) {
			s.DataPaths[0].Kind = StorageBind
			s.DataPaths[0].Source = s.ProjectDirectory + "/app/state"
		}},
		{"workspace inside data mount", func(s *Service) { s.DataPaths[0].Kind = StorageBind; s.DataPaths[0].Source = "/srv/workspaces" }},
		{"significant anonymous volume", func(s *Service) { s.DataPaths[0].Kind = StorageAnonymousVolume }},
		{"significant writable layer", func(s *Service) { s.DataPaths[0].Kind = StorageWritableLayer; s.DataPaths[0].Source = "" }},
		{"unknown mount", func(s *Service) { s.DataPaths[0].Kind = "unknown" }},
		{"unknown update target", func(s *Service) { s.Targets = []string{"other"} }},
		{"short container ID", func(s *Service) { s.Containers[0].ID = "abc123" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := serviceFixture()
			tc.change(&s)
			if s.Validate() == nil {
				t.Fatal("unsafe registration accepted")
			}
		})
	}
	// Explicit disposable writable state is supported and never presented as preserved.
	s := serviceFixture()
	s.DataPaths = append(s.DataPaths, DataPath{Name: "scratch", Kind: StorageWritableLayer, Target: "/tmp", Component: "app", LossAccepted: true})
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRegistrationConflictUsesPathBoundaries(t *testing.T) {
	a, b := serviceFixture(), serviceFixture()
	b.ID = "other"
	b.ComposeProject = "other"
	if !a.Conflicts(b) {
		t.Fatal("same managed tree accepted as independent registration")
	}
	b.ProjectDirectory = "/srv/ctf/flags-next"
	b.SourceDirectory = "/srv/workspaces/flags-next"
	b.DataPaths[0].Source = "flags_next_db"
	if a.Conflicts(b) {
		t.Fatal("sibling names with common string prefix must not conflict")
	}
	b.ComposeProject = a.ComposeProject
	if !a.Conflicts(b) {
		t.Fatal("same Compose project must conflict even with distinct trees")
	}
	b.ComposeProject = "other"
	b.DataPaths[0].Source = a.DataPaths[0].Source
	if !a.Conflicts(b) {
		t.Fatal("unconfirmed shared storage accepted")
	}
	a.DataPaths[0].SharedResource = "shared-db"
	b.DataPaths[0].SharedResource = "shared-db"
	if a.Conflicts(b) {
		t.Fatal("explicit shared dependency rejected")
	}
}

func TestManifestOwnsInputsAndBindsEverySecurityAttribute(t *testing.T) {
	entries := []ManifestEntry{
		{Path: "app/main.py", Type: EntryFile, Size: 4, Digest: Hash([]byte("pass")), Mode: 0644, UID: 1000, GID: 1000},
		{Path: "app", Type: EntryDirectory, Mode: 0755, UID: 1000, GID: 1000},
	}
	m, err := NewManifest(entries)
	if err != nil {
		t.Fatal(err)
	}
	original := m.Digest()
	entries[0].Mode = 0777
	copyEntries := m.Entries()
	copyEntries[0].UID = 0
	if m.Digest() != original {
		t.Fatal("caller mutated immutable manifest")
	}
	reversed, err := NewManifest([]ManifestEntry{m.Entries()[1], m.Entries()[0]})
	if err != nil {
		t.Fatal(err)
	}
	if reversed.Digest() != original {
		t.Fatal("input order changed canonical digest")
	}
	for _, mutate := range []func(*ManifestEntry){
		func(e *ManifestEntry) { e.Mode = 0600 }, func(e *ManifestEntry) { e.UID = 0 }, func(e *ManifestEntry) { e.GID = 0 },
		func(e *ManifestEntry) { e.Digest = Hash([]byte("evil")) }, func(e *ManifestEntry) { e.Size++ },
	} {
		changed := m.Entries()
		mutate(&changed[1])
		other, err := NewManifest(changed)
		if err != nil {
			t.Fatal(err)
		}
		if other.Digest() == original {
			t.Fatal("security-relevant attribute missing from digest")
		}
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Manifest
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Verify(original); err != nil {
		t.Fatal(err)
	}
}

func TestManifestRejectsTraversalAndSpecialFiles(t *testing.T) {
	link := func(p, target string) ManifestEntry {
		return ManifestEntry{Path: p, Type: EntrySymlink, Mode: 0777, Size: int64(len(target)), LinkTarget: target, Digest: Hash([]byte(target))}
	}
	cases := [][]ManifestEntry{
		{{Path: "../outside", Type: EntryDirectory, Mode: 0755}},
		{{Path: "app", Type: EntryFile, Mode: 04755, Digest: Hash(nil)}},
		{{Path: "fifo", Type: "fifo", Mode: 0600}},
		{link("app/link", "../../etc/passwd")},
		{link("app/link", "/etc/passwd")},
		{link("app/link", "target"), {Path: "app/link/nested", Type: EntryFile, Digest: Hash(nil), Mode: 0644}},
		{{Path: "app", Type: EntryFile, Digest: Hash(nil), Mode: 0644}, {Path: "app/x", Type: EntryFile, Digest: Hash(nil), Mode: 0644}},
	}
	for i, entries := range cases {
		if _, err := NewManifest(entries); err == nil {
			t.Fatalf("unsafe manifest %d accepted", i)
		}
	}
	if _, err := NewManifest([]ManifestEntry{link("app/link", "../shared")}); err != nil {
		t.Fatalf("contained relative symlink rejected: %v", err)
	}
}

func releaseFixture() ReleaseSpec {
	return ReleaseSpec{SchemaVersion: SchemaVersion, ID: "release-1", ServiceID: "flags", CreatedAt: testTime, Author: "admin", Source: ReleaseWorkspace,
		SnapshotID: "source-1", TreeDigest: Hash([]byte("tree")), ConfigurationDigest: Hash([]byte("config")), PolicyRevision: 1, FileMapRevision: 1,
		Images:  []ImageRef{{Component: "app", ImageID: Hash([]byte("image")), RetentionTag: "ctf-manager/flags:release-1-app"}},
		Secrets: []SecretVersionRef{{SecretID: "database-password", Version: "version-1"}},
		Data:    []DataReference{{Name: "database", Identity: "round_one_db", Compatibility: DataCompatible, Evidence: "test round with current schema"}},
	}
}

func TestReleaseImmutableAndSecretsAreVersioned(t *testing.T) {
	spec := releaseFixture()
	release, err := NewRelease(spec)
	if err != nil {
		t.Fatal(err)
	}
	before := release.Digest()
	spec.Secrets[0].Version = "version-2"
	spec.Images[0].ImageID = Hash([]byte("changed"))
	copySpec := release.Spec()
	copySpec.Secrets[0].Version = "version-3"
	bytesCopy := release.CanonicalJSON()
	bytesCopy[0] = '!'
	if release.Digest() != before || release.Spec().Secrets[0].Version != "version-1" {
		t.Fatal("approved release changed through caller memory")
	}
	changed, err := NewRelease(spec)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Digest() == before {
		t.Fatal("image or secret version absent from release digest")
	}
	raw, err := json.Marshal(release)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Release
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Digest() != before {
		t.Fatal("release round-trip changed digest")
	}
	unknown := strings.TrimSuffix(string(raw), "}") + `,"expanded_environment":{"SECRET":"plaintext"}}`
	if err := json.Unmarshal([]byte(unknown), &decoded); err == nil {
		t.Fatal("unrecognized secret-bearing field accepted")
	}
}

func operationFixture(t *testing.T) Operation {
	t.Helper()
	op, err := NewOperation(OperationSpec{ID: "operation-1", Kind: OperationDeploy, Initiator: "admin", IdempotencyKey: "request-1", ServiceID: "flags", ReleaseID: "release-1",
		ExpectedPolicyRevision: 1, ExpectedTreeDigest: Hash([]byte("active tree")), Resources: []string{"service:flags", "compose:round_one"}, TimeoutSeconds: 300}, testTime)
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func TestOperationCannotReportFalseSuccessOrCancelAfterSwitch(t *testing.T) {
	op := operationFixture(t)
	if err := op.Transition(OperationSucceeded, OutcomeEvidence{}, testTime); err == nil {
		t.Fatal("queued operation succeeded")
	}
	if err := op.Transition(OperationRunning, OutcomeEvidence{}, testTime); err != nil {
		t.Fatal(err)
	}
	if err := op.BeginMutation("", testTime); err == nil {
		t.Fatal("switch allowed without recovery point")
	}
	if err := op.BeginMutation("recovery-1", testTime); err != nil {
		t.Fatal(err)
	}
	known := OutcomeEvidence{ActualStateKnown: true, ResultRecorded: true}
	if err := op.Transition(OperationCancelled, known, testTime); err == nil {
		t.Fatal("cancelled after mutation without confirmed return")
	}
	if err := op.Transition(OperationSucceeded, OutcomeEvidence{ActualStateKnown: true}, testTime); err == nil {
		t.Fatal("success without durable outcome")
	}
	if err := op.Transition(OperationFailed, OutcomeEvidence{Reason: "lost Docker response"}, testTime); err == nil {
		t.Fatal("failure falsely claims known final state")
	}
	if err := op.Transition(OperationInterrupted, OutcomeEvidence{Reason: "lost Docker response"}, testTime); err != nil {
		t.Fatal(err)
	}
	if err := op.Transition(OperationRunning, OutcomeEvidence{}, testTime); err == nil {
		t.Fatal("interrupted operation resumed blindly")
	}
	if err := op.Transition(OperationCancelled, OutcomeEvidence{ActualStateKnown: true, ResultRecorded: true, ReturnedToPrevious: true}, testTime); err != nil {
		t.Fatal(err)
	}
	if err := op.Transition(OperationRunning, known, testTime); err == nil {
		t.Fatal("terminal operation restarted")
	}
}

func TestHealthAndRollbackDoNotInferSuccess(t *testing.T) {
	signal := HealthSignal{Source: HealthDocker, State: HealthNotConfigured}
	if signal.EffectiveState(testTime) != HealthNotConfigured {
		t.Fatal("missing check misreported")
	}
	signal = HealthSignal{Source: HealthFunctional, State: HealthHealthy, ObservedAt: testTime, ValidUntil: testTime.Add(time.Minute)}
	if signal.EffectiveState(testTime.Add(time.Minute)) != HealthStale {
		t.Fatal("expired health considered successful")
	}
	if (ReleaseEvent{ID: "event-1", ReleaseID: "release-1", At: testTime, Status: ReleaseLocallyVerified, Source: HealthManual}).Validate() == nil {
		t.Fatal("manual confirmation masquerades as local verification")
	}
	ready := RollbackAvailability{true, true, true, true, true, true, true}
	if !ready.Available() {
		t.Fatal("complete rollback rejected")
	}
	ready.SecretsAvailable = false
	if ready.Available() {
		t.Fatal("missing secret allows rollback")
	}
	snapshot := Snapshot{Purpose: SnapshotBaseline}
	if !snapshot.Protected(false, false) {
		t.Fatal("baseline selected by ordinary retention")
	}
	snapshot.Purpose = SnapshotManual
	if !snapshot.Protected(false, true) {
		t.Fatal("active recovery point selected by retention")
	}
}
