package executor

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/filesystem"
)

func TestGitCandidateUsesFrozenComposeAndAppliesGitCode(t *testing.T) {
	f := gitPlanningFixture(t)
	f.s.ComposeFiles = []string{"compose.yaml", "deployment/nested/override.yaml", "base.yaml"}
	f.s.ManagedPaths = append(f.s.ManagedPaths,
		domain.ManagedPath{Path: "compose.yaml", Kind: domain.ManagedConfig},
		domain.ManagedPath{Path: "deployment/nested/override.yaml", Kind: domain.ManagedConfig},
		domain.ManagedPath{Path: "base.yaml", Kind: domain.ManagedConfig},
	)
	writeGitComposeFixture(t, f.s.ProjectDirectory, "compose.yaml", "published port 18024", 0640)
	writeGitComposeFixture(t, f.s.ProjectDirectory, "deployment/nested/override.yaml", "approved mounts", 0600)
	writeGitComposeFixture(t, f.s.ProjectDirectory, "base.yaml", "Git-visible input", 0600)
	baseline, err := f.m.capture(t.Context(), f.s, "local-admin", domain.SnapshotBaseline, f.s.ProjectDirectory)
	if err != nil {
		t.Fatal(err)
	}
	state := runtimeState{BaselineID: baseline.ID}

	source := t.TempDir()
	writeGitComposeFixture(t, source, "app/main.py", "version = 2\n", 0644)
	writeGitComposeFixture(t, source, "compose.yaml", "unapproved public port", 0644)
	writeGitComposeFixture(t, source, "base.yaml", "Git-visible input", 0644)
	oldCandidate, err := f.m.capture(t.Context(), f.s, "local-admin", domain.SnapshotCandidate, source)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.m.guardComposeInputs(t.Context(), f.s, state, oldCandidate); err == nil || !strings.Contains(err.Error(), "frozen Compose input") {
		t.Fatalf("ordinary Build guard should reject changed local or legacy candidate: %v", err)
	}

	hostOnly, err := f.m.preserveGitComposeInputs(t.Context(), f.s, state, source)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(hostOnly, []string{"compose.yaml", "deployment/nested/override.yaml"}) {
		t.Fatalf("incorrect host-only Compose provenance: %v", hostOnly)
	}
	provenance := &domain.GitProvenance{
		URL: "https://github.com/example/game.git", Ref: "refs/heads/main", Commit: strings.Repeat("a", 40),
		SourceRevision: 1, HostComposeInputs: hostOnly,
	}
	candidate, err := f.m.capture(t.Context(), f.s, "web-admin", domain.SnapshotCandidate, source, provenance)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.m.guardComposeInputs(t.Context(), f.s, state, candidate); err != nil {
		t.Fatalf("Git candidate should pass Build guard: %v", err)
	}
	snapshot, err := f.m.loadSnapshot(t.Context(), candidate.ID)
	if err != nil || !reflect.DeepEqual(snapshot.GitSource, provenance) {
		t.Fatalf("Git provenance was not recorded: %v", err)
	}
	for _, file := range f.s.ComposeFiles {
		if got, want := gitComposeTestEntry(t, candidate.Manifest, file), gitComposeTestEntry(t, baseline.Manifest, file); got != want {
			t.Fatalf("frozen file %s: got %+v, want %+v", file, got, want)
		}
	}
	for _, parent := range []string{"deployment", "deployment/nested"} {
		if got, want := gitComposeTestEntry(t, candidate.Manifest, parent), gitComposeTestEntry(t, baseline.Manifest, parent); got != want {
			t.Fatalf("parent %s: got %+v, want %+v", parent, got, want)
		}
	}

	content, err := f.m.Snapshots.ContentPath(candidate.ID)
	if err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(t.TempDir(), "build-context")
	if err := materializeReleaseBuild(t.Context(), f.s, snapshot, content, staging); err != nil {
		t.Fatal(err)
	}
	for _, name := range hostOnly {
		if _, err := os.Lstat(filepath.Join(staging, filepath.FromSlash(name))); !os.IsNotExist(err) {
			t.Fatalf("host-only Compose leaked into Git build context: %s, %v", name, err)
		}
	}
	if got, err := os.ReadFile(filepath.Join(staging, "base.yaml")); err != nil || string(got) != "Git-visible input" {
		t.Fatalf("Git-visible Compose missing from compatible build context: %q, %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(staging, "app", "main.py")); err != nil || string(got) != "version = 2\n" {
		t.Fatalf("Git code missing from build context: %q, %v", got, err)
	}
	invalid := snapshot
	invalid.GitSource = &domain.GitProvenance{HostComposeInputs: []string{"app/main.py"}}
	if err := materializeReleaseBuild(t.Context(), f.s, invalid, content, filepath.Join(t.TempDir(), "invalid")); err == nil {
		t.Fatal("build accepted an exclusion outside the approved Compose list")
	}
	if err := filesystem.Apply(t.Context(), content, f.s.ProjectDirectory, baseline.Manifest, candidate.Manifest, f.s.ManagedPaths, filesystem.ApplyOptions{
		ApplicationsStopped: true,
		PreserveOwnership:   true,
	}); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"app/main.py":                     "version = 2\n",
		"compose.yaml":                    "published port 18024",
		"base.yaml":                       "Git-visible input",
		"deployment/nested/override.yaml": "approved mounts",
	} {
		got, err := os.ReadFile(filepath.Join(f.s.ProjectDirectory, name))
		if err != nil || string(got) != want {
			t.Fatalf("applied %s: %q, %v", name, got, err)
		}
	}
}

func TestGitCandidateIgnoresComposeSubtreesAndUntrackedFrozenInputs(t *testing.T) {
	f := gitPlanningFixture(t)
	f.s.ComposeFiles = []string{"compose.yaml", "app/absent.yaml", "deploy/not-managed.yaml"}
	f.s.ManagedPaths = append(f.s.ManagedPaths, domain.ManagedPath{Path: "compose.yaml", Kind: domain.ManagedConfig})
	writeGitComposeFixture(t, f.s.ProjectDirectory, "compose.yaml", "approved", 0600)
	baseline, err := f.m.capture(t.Context(), f.s, "local-admin", domain.SnapshotBaseline, f.s.ProjectDirectory)
	if err != nil {
		t.Fatal(err)
	}

	source := t.TempDir()
	writeGitComposeFixture(t, source, "app/main.py", "new content", 0644)
	writeGitComposeFixture(t, source, "app/absent.yaml", "not approved", 0644)
	writeGitComposeFixture(t, source, "compose.yaml/attempt", "not approved", 0644)
	writeGitComposeFixture(t, source, "deploy", "unmanaged Git file", 0644)
	state := runtimeState{BaselineID: baseline.ID}
	if _, err := f.m.preserveGitComposeInputs(t.Context(), f.s, state, source); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(source, "app/absent.yaml")); !os.IsNotExist(err) {
		t.Fatalf("Compose file absent from baseline was imported: %v", err)
	}
	compose, err := os.ReadFile(filepath.Join(source, "compose.yaml"))
	if err != nil || string(compose) != "approved" {
		t.Fatalf("protected path has wrong type or bytes: %q, %v", compose, err)
	}
	if got, err := os.ReadFile(filepath.Join(source, "deploy")); err != nil || string(got) != "unmanaged Git file" {
		t.Fatalf("unmanaged ancestor modified: %q, %v", got, err)
	}
}

func TestGitCandidateNeedsManagedFilesOutsideFrozenCompose(t *testing.T) {
	f := gitPlanningFixture(t)
	f.s.ComposeFiles = []string{"app/compose.yaml"}
	f.s.ManagedPaths[0].Exclusions = []string{"uploads"}
	source := t.TempDir()
	writeGitComposeFixture(t, source, "app/compose.yaml/attempt", "not a source file", 0644)
	writeGitComposeFixture(t, source, "app/uploads/runtime.db", "excluded", 0644)
	_, err := f.m.preserveGitComposeInputs(t.Context(), f.s, runtimeState{BaselineID: f.baseline.ID}, source)
	if err == nil || !strings.Contains(err.Error(), "none of the approved managed paths") {
		t.Fatalf("frozen or excluded files must not satisfy Git source validation: %v", err)
	}
}

func TestGitCandidateAllowsUnchangedManagedComposeOnly(t *testing.T) {
	f := gitPlanningFixture(t)
	f.s.ComposeFiles = []string{"compose.yaml", "override.yaml"}
	f.s.ManagedPaths = []domain.ManagedPath{
		{Path: "compose.yaml", Kind: domain.ManagedConfig},
		{Path: "override.yaml", Kind: domain.ManagedConfig},
	}
	writeGitComposeFixture(t, f.s.ProjectDirectory, "compose.yaml", "approved", 0600)
	writeGitComposeFixture(t, f.s.ProjectDirectory, "override.yaml", "approved override", 0600)
	baseline, err := f.m.capture(t.Context(), f.s, "local-admin", domain.SnapshotBaseline, f.s.ProjectDirectory)
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	writeGitComposeFixture(t, source, "compose.yaml", "approved", 0644)
	writeGitComposeFixture(t, source, "override.yaml", "approved override", 0644)
	state := runtimeState{BaselineID: baseline.ID}
	if hostOnly, err := f.m.preserveGitComposeInputs(t.Context(), f.s, state, source); err != nil || len(hostOnly) != 0 {
		t.Fatalf("unchanged Compose-only source should still be accepted: %v, %v", hostOnly, err)
	}
	writeGitComposeFixture(t, source, "override.yaml", "different", 0644)
	if _, err := f.m.preserveGitComposeInputs(t.Context(), f.s, state, source); err == nil || !strings.Contains(err.Error(), "none of the approved managed paths") {
		t.Fatalf("unapproved Compose cannot satisfy Git source validation: %v", err)
	}
}

func TestGitCandidateRejectsConflictingFrozenComposeParent(t *testing.T) {
	f := gitPlanningFixture(t)
	f.s.ComposeFiles = []string{"app/nested/compose.yaml"}
	writeGitComposeFixture(t, f.s.ProjectDirectory, "app/nested/compose.yaml", "approved", 0640)
	baseline, err := f.m.capture(t.Context(), f.s, "local-admin", domain.SnapshotBaseline, f.s.ProjectDirectory)
	if err != nil {
		t.Fatal(err)
	}

	source := t.TempDir()
	writeGitComposeFixture(t, source, "app/main.py", "new content", 0644)
	writeGitComposeFixture(t, source, "app/nested", "wrong type", 0644)
	_, err = f.m.preserveGitComposeInputs(t.Context(), f.s, runtimeState{BaselineID: baseline.ID}, source)
	if err == nil || !strings.Contains(err.Error(), "conflicts with a frozen Compose directory") {
		t.Fatalf("conflicting parent should block candidate: %v", err)
	}
}

func writeGitComposeFixture(t *testing.T, root, name, value string, mode os.FileMode) {
	t.Helper()
	filename := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(filename), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(value), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filename, mode); err != nil {
		t.Fatal(err)
	}
}

func gitComposeTestEntry(t *testing.T, manifest domain.Manifest, name string) domain.ManifestEntry {
	t.Helper()
	for _, entry := range manifest.Entries() {
		if entry.Path == name {
			return entry
		}
	}
	t.Fatalf("missing manifest entry %q", name)
	return domain.ManifestEntry{}
}
