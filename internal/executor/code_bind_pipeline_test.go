package executor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/filesystem"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

// This fixture exercises the real snapshot store, file materialization and
// release observation without Docker. It does not claim container Stop/Build/Up
// acceptance: Apply's stopped-target gate is supplied explicitly by the test.
func codeBindPlanningFixture(t *testing.T) *planningFixture {
	t.Helper()
	f := newPlanningFixture(t)
	f.s.ManagedPaths[0].Exclusions = []string{"db.db", "uploads", ".env"}
	f.s.Containers = append(f.s.Containers, domain.ContainerRef{
		Component: "cleaner", Role: domain.RoleAuxiliary,
		ID: strings.Repeat("b", 64), ImageID: domain.Hash([]byte("cleaner-image")),
	})
	f.s.Targets = append(f.s.Targets, "cleaner")
	for _, component := range []string{"app", "cleaner"} {
		f.s.DataPaths = append(f.s.DataPaths, domain.DataPath{
			Name: component + "-code", Kind: domain.StorageBind,
			Source: f.s.ProjectDirectory, Target: "/app", Component: component,
			LossAccepted: true, AllowCodeUpdates: true,
		})
	}
	return f
}

func TestCodeBindPolicyRequiresExplicitConsentAndOmitsDisposableDataReferences(t *testing.T) {
	f := codeBindPlanningFixture(t)
	for i := range f.s.DataPaths {
		f.s.DataPaths[i].AllowCodeUpdates = false
	}
	if err := f.s.Validate(); err == nil {
		t.Fatal("default data bind was allowed to overlap managed code")
	}
	for i := range f.s.DataPaths {
		if f.s.DataPaths[i].Kind == domain.StorageBind {
			f.s.DataPaths[i].AllowCodeUpdates = true
		}
	}
	if err := f.s.Validate(); err != nil {
		t.Fatalf("explicit disposable code bind policy rejected: %v", err)
	}
	refs := dataReferences(f.s)
	if len(refs) != 1 || refs[0].Name != "game-data" {
		t.Fatalf("disposable code binds falsely classified as preserved data: %+v", refs)
	}
	f.s.Targets = []string{"app"}
	if err := f.s.Validate(); err == nil {
		t.Fatal("shared writable-code consumer outside update targets was accepted")
	}
}

func TestCodeBindReleaseEvidenceNeverPromisesUnchangedData(t *testing.T) {
	for _, significant := range []bool{false, true} {
		t.Run(map[bool]string{false: "code-only", true: "code-with-persistent-data"}[significant], func(t *testing.T) {
			f := codeBindPlanningFixture(t)
			if !significant {
				f.s.DataPaths = append([]domain.DataPath{}, f.s.DataPaths[1:]...)
			}
			f.s.PolicyRevision++
			now := time.Now().UTC()
			proposal, err := f.m.Store.CreateProposal(t.Context(), "code-bind-evidence-policy", f.s, domain.Hash([]byte("test-frozen-configuration")), "test-admin", now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.m.Store.ApproveProposal(t.Context(), proposal.ID, proposal.Digest, "test-admin", now); err != nil {
				t.Fatal(err)
			}
			release := putCodeBindRelease(t, f, f.baseline, "code-evidence-release")
			view, err := f.m.ReleaseEvidence(t.Context(), f.s.ID, release.Spec().ID)
			if err != nil {
				t.Fatal(err)
			}
			expected := "code_bind_loss_accepted"
			if significant {
				expected = "confirmation_required_and_code_bind_loss_accepted"
			}
			if view.Checks["data"] != expected || view.DataConfirmationRequired != significant {
				t.Fatalf("release evidence promises incorrect data behavior: %+v", view)
			}
			if view.CanApply || view.Checks["images"] != "unavailable" {
				t.Fatal("metadata-only fixture falsely establishes executable runtime")
			}
		})
	}
}

func putCodeBindRelease(t *testing.T, f *planningFixture, snapshot domain.Snapshot, id domain.ID) domain.Release {
	t.Helper()
	images := []domain.ImageRef{}
	for _, ref := range f.s.Containers {
		images = append(images, domain.ImageRef{Component: ref.Component, ImageID: ref.ImageID, RetentionTag: retentionTag(f.s, id, ref.Component)})
	}
	release, err := domain.NewRelease(domain.ReleaseSpec{
		SchemaVersion: domain.SchemaVersion, ID: id, ServiceID: f.s.ID,
		CreatedAt: time.Now().UTC(), Author: "test-admin", Source: domain.ReleaseWorkspace,
		SnapshotID: snapshot.ID, TreeDigest: snapshot.ManifestDigest,
		ConfigurationDigest: domain.Hash([]byte("test-frozen-configuration")),
		PolicyRevision:      f.s.PolicyRevision, FileMapRevision: f.s.FileMapRevision,
		Images: images, Data: dataReferences(f.s),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.m.Store.PutImmutable(t.Context(), "release", id, f.s.ID, release); err != nil {
		t.Fatal(err)
	}
	return release
}

func assertCodeBindBytes(t *testing.T, file, expected string) {
	t.Helper()
	actual, err := os.ReadFile(file)
	if err != nil || string(actual) != expected {
		t.Fatalf("unexpected file contents for %s: %v", filepath.Base(file), err)
	}
}

func TestCodeBindSnapshotsMaterializeAndRollbackSelectedCodeWithoutRuntimeData(t *testing.T) {
	f := codeBindPlanningFixture(t)
	if err := f.s.Validate(); err != nil {
		t.Fatal(err)
	}
	// Include runtime files both outside managed roots and in literal exclusions
	// inside a managed directory. Candidate-only copies must also stay excluded.
	runtimePaths := []string{"db.db", "uploads/user-file", "app/db.db", "app/uploads/user-file", "app/.env"}
	for _, base := range []string{f.s.ProjectDirectory, f.s.SourceDirectory} {
		for _, relative := range runtimePaths {
			name := filepath.Join(base, relative)
			if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
				t.Fatal(err)
			}
			writePlanningFile(t, name, "runtime-initial")
		}
	}
	removed := filepath.Join(f.s.ProjectDirectory, "app", "remove.py")
	writePlanningFile(t, removed, "old-module")
	baseline, err := f.m.capture(t.Context(), f.s, "test-admin", domain.SnapshotBaseline, f.s.ProjectDirectory)
	if err != nil {
		t.Fatal(err)
	}
	baselineRelease := putCodeBindRelease(t, f, baseline, "code-baseline")
	writePlanningFile(t, f.workspaceFile, "version = 2\n")
	writePlanningFile(t, filepath.Join(f.s.SourceDirectory, "app", "new.py"), "new-module")
	candidate, err := f.m.capture(t.Context(), f.s, "test-admin", domain.SnapshotCandidate, f.s.SourceDirectory)
	if err != nil {
		t.Fatal(err)
	}
	candidateRelease := putCodeBindRelease(t, f, candidate, "code-candidate")
	for _, snapshot := range []domain.Snapshot{baseline, candidate} {
		for _, entry := range snapshot.Manifest.Entries() {
			if strings.Contains(entry.Path, "db.db") || strings.Contains(entry.Path, "uploads") || strings.HasSuffix(entry.Path, ".env") {
				t.Fatalf("runtime data entered a code snapshot: %s", entry.Path)
			}
		}
	}
	content, err := f.m.Snapshots.ContentPath(candidate.ID)
	if err != nil {
		t.Fatal(err)
	}
	buildContext := filepath.Join(filepath.Dir(f.s.ProjectDirectory), "build-context")
	if err := filesystem.MaterializeBuild(t.Context(), content, buildContext, candidate.Manifest); err != nil {
		t.Fatal(err)
	}
	assertCodeBindBytes(t, filepath.Join(buildContext, "app", "main.py"), "version = 2\n")
	for _, relative := range runtimePaths {
		if _, err := os.Lstat(filepath.Join(buildContext, relative)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("runtime path entered build context: %s (%v)", relative, err)
		}
	}
	if err := filesystem.Apply(t.Context(), content, f.s.ProjectDirectory, baseline.Manifest, candidate.Manifest, f.s.ManagedPaths, filesystem.ApplyOptions{}); err == nil {
		t.Fatal("materialization accepted unconfirmed stopped-target gate")
	}
	assertCodeBindBytes(t, f.activeFile, "version = 1\n")
	if err := filesystem.Apply(t.Context(), content, f.s.ProjectDirectory, baseline.Manifest, candidate.Manifest, f.s.ManagedPaths, filesystem.ApplyOptions{ApplicationsStopped: true}); err != nil {
		t.Fatal(err)
	}
	assertCodeBindBytes(t, f.activeFile, "version = 2\n")
	if _, err := os.Lstat(removed); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("deleted managed module remained after materialization")
	}
	assertCodeBindBytes(t, filepath.Join(f.s.ProjectDirectory, "app", "new.py"), "new-module")
	for _, relative := range runtimePaths {
		assertCodeBindBytes(t, filepath.Join(f.s.ProjectDirectory, relative), "runtime-initial")
		writePlanningFile(t, filepath.Join(f.s.ProjectDirectory, relative), "runtime-after-deploy")
	}
	// Both releases deliberately reuse identical images. Root-bind tree evidence
	// must distinguish them after selected host code changes.
	actual := docker.Container{ID: f.s.Containers[0].ID, Component: "app", ImageID: string(f.s.Containers[0].ImageID), Mounts: []docker.Mount{{Type: "bind", Source: f.s.ProjectDirectory, Target: "/app"}}}
	observeRelease := func(recorded domain.Release, snapshot domain.Snapshot, expected domain.ID) {
		t.Helper()
		state := runtimeState{ServiceID: f.s.ID, CurrentReleaseID: recorded.Spec().ID, ActiveSnapshotID: snapshot.ID, Containers: f.s.Containers}
		view := transport.ComponentVersion{State: "matches_recorded_image", PossibleReleaseIDs: []domain.ID{}}
		drift := f.m.driftObservation(t.Context(), f.s, state)
		f.m.componentReleaseObservation(t.Context(), f.s, state, actual, drift, true, &view)
		if view.ObservedReleaseID != expected || view.ReleaseEvidence != "image_and_managed_bind_tree" || len(view.PossibleReleaseIDs) != 1 {
			t.Fatalf("root-bind image equality hid selected-code version: %+v", view)
		}
	}
	observeRelease(baselineRelease, baseline, candidateRelease.Spec().ID)
	baselineContent, err := f.m.Snapshots.ContentPath(baseline.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := filesystem.Apply(t.Context(), baselineContent, f.s.ProjectDirectory, candidate.Manifest, baseline.Manifest, f.s.ManagedPaths, filesystem.ApplyOptions{ApplicationsStopped: true}); err != nil {
		t.Fatal(err)
	}
	assertCodeBindBytes(t, f.activeFile, "version = 1\n")
	assertCodeBindBytes(t, removed, "old-module")
	if _, err := os.Lstat(filepath.Join(f.s.ProjectDirectory, "app", "new.py")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("candidate-only module remained after rollback materialization")
	}
	for _, relative := range runtimePaths {
		assertCodeBindBytes(t, filepath.Join(f.s.ProjectDirectory, relative), "runtime-after-deploy")
	}
	observeRelease(candidateRelease, candidate, baselineRelease.Spec().ID)
}
