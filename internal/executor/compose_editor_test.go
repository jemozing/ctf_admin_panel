package executor

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/filesystem"
	"github.com/ctf-service-manager/ctf-service-manager/internal/jobs"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"github.com/moby/moby/client"
)

const composeEditorBaseline = "services:\n  app:\n    image: app:v1\n"

func composeEditorFixture(t *testing.T) *planningFixture {
	t.Helper()
	f := newPlanningFixture(t)
	f.s.ID = "editor"
	f.s.ComposeProject = "editor"
	f.s.ProjectDirectory += "-editor"
	f.s.SourceDirectory += "-editor"
	f.s.Containers[0].ID = strings.Repeat("b", 64)
	f.s.DataPaths[0].Source = "editor_game-data"
	writeGitComposeFixture(t, f.s.ProjectDirectory, "app/main.py", "version = 1\n", 0600)
	writeGitComposeFixture(t, f.s.SourceDirectory, "app/main.py", "unrelated code in workspace", 0600)
	f.activeFile = filepath.Join(f.s.ProjectDirectory, "app", "main.py")
	f.workspaceFile = filepath.Join(f.s.SourceDirectory, "app", "main.py")
	f.s.ComposeFiles = []string{"compose.yaml", "compose.override.yaml"}
	for _, name := range f.s.ComposeFiles {
		f.s.ManagedPaths = append(f.s.ManagedPaths, domain.ManagedPath{Path: name, Kind: domain.ManagedConfig})
	}
	writeGitComposeFixture(t, f.s.ProjectDirectory, "compose.yaml", composeEditorBaseline, 0640)
	writeGitComposeFixture(t, f.s.ProjectDirectory, "compose.override.yaml", "services:\n  app:\n    restart: always\n", 0644)
	writeGitComposeFixture(t, f.s.SourceDirectory, "compose.yaml", "unrelated workspace edits", 0600)
	writeGitComposeFixture(t, f.s.SourceDirectory, "compose.override.yaml", "not approved", 0600)
	configuration := Configuration{Model: map[string]any{"services": map[string]any{"app": map[string]any{"image": "app:v1", "restart": "always"}}}}
	digest, err := f.m.storeComposeConfiguration(t.Context(), f.s, configuration)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	proposal, err := f.m.Store.CreateProposal(t.Context(), "editor-policy", f.s, digest, "local-admin", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Store.ApproveProposal(t.Context(), proposal.ID, proposal.Digest, "local-admin", now); err != nil {
		t.Fatal(err)
	}
	f.baseline, err = f.m.capture(t.Context(), f.s, "local-admin", domain.SnapshotBaseline, f.s.ProjectDirectory)
	if err != nil {
		t.Fatal(err)
	}
	base := f.release.Spec()
	base.ID = "release-editor-base"
	base.ServiceID, base.SnapshotID, base.TreeDigest, base.ConfigurationDigest = f.s.ID, f.baseline.ID, f.baseline.ManifestDigest, digest
	base.Data = dataReferences(f.s)
	base.Images[0].RetentionTag = retentionTag(f.s, base.ID, "app")
	f.release, err = domain.NewRelease(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.m.Store.PutImmutable(t.Context(), "release", base.ID, f.s.ID, f.release); err != nil {
		t.Fatal(err)
	}
	st := runtimeState{ServiceID: f.s.ID, CurrentReleaseID: base.ID, ActiveSnapshotID: f.baseline.ID, BaselineID: f.baseline.ID, Containers: f.s.Containers}
	if err := f.m.saveState(t.Context(), &st); err != nil {
		t.Fatal(err)
	}
	plugin := filepath.Join(filepath.Dir(f.s.ProjectDirectory), "test-compose")
	const normalize = `#!/bin/sh
set -eu
inputs=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --file)
      inputs=$((inputs+1))
      if [ "$inputs" = 1 ]; then
        limit=$(sed -n 's/^ *cpus: //p' "$2")
      else
        grep -q 'restart: always' "$2"
      fi
      shift
      ;;
  esac
  shift
done
test "$inputs" = 2
printf '{"services":{"app":{"image":"app:v1","restart":"always","cpus":%s}}}' "$limit"
`
	if err := os.WriteFile(plugin, []byte(normalize), 0700); err != nil {
		t.Fatal(err)
	}
	f.m.Config.ComposeBinary = plugin
	f.m.Config.DiscoveryRoots = []string{f.s.ProjectDirectory}
	return f
}

func TestComposeEditorReviewsAndBuildsOnlyTheDraft(t *testing.T) {
	f := composeEditorFixture(t)
	ctx := t.Context()
	api, err := client.New(client.WithHost("http://docker.invalid"), client.WithAPIVersion("1.56"), client.WithHTTPClient(&http.Client{Transport: statsRoundTripper(func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/system/df"):
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"ImageUsage":{"TotalSize":1}}`))}, nil
		case strings.HasSuffix(r.URL.Path, "/tag"):
			return &http.Response{StatusCode: http.StatusCreated, Body: http.NoBody}, nil
		default:
			t.Fatalf("unexpected Docker request: %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	})}))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	f.m.Engine = &docker.Engine{Client: api}
	document, err := f.m.ComposeDocument(ctx, f.s.ID)
	if err != nil || document.Path != "compose.yaml" || document.Content != composeEditorBaseline || document.Revision.Validate() != nil {
		t.Fatalf("editor did not open approved source: %+v, %v", document, err)
	}
	content := composeEditorBaseline + "    cpus: 0.5\n"
	req := transport.SubmitRequest{ServiceID: f.s.ID, Action: domain.OperationPrepareCompose, IdempotencyKey: "compose-editor", ComposeDraft: &transport.ComposeDraft{Content: content, Revision: document.Revision}}
	plan, err := f.m.Preview(ctx, req)
	if err != nil || plan.ComposeChange || len(plan.ChangedFiles) != 1 || plan.ChangedFiles[0].Path != document.Path || len(plan.ComposeChanges) != 1 || plan.ComposeChanges[0].After != "0.5" {
		t.Fatalf("unexpected draft preview: %+v, %v", plan, err)
	}
	if _, err := f.m.LoadConfiguration(ctx, plan.ComposeDraftConfiguration); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("preview persisted a configuration: %v", err)
	}
	bad := req
	bad.ComposeDraft = &transport.ComposeDraft{Content: "services: [secret-marker", Revision: document.Revision}
	var editorError *transport.ComposeEditorError
	if _, err := f.m.Preview(ctx, bad); !errors.As(err, &editorError) || strings.Contains(err.Error(), "secret-marker") {
		t.Fatalf("invalid YAML was accepted or disclosed: %v", err)
	}
	bad.ComposeDraft = &transport.ComposeDraft{Content: content, Revision: domain.Hash([]byte("different release"))}
	if _, err := f.m.Preview(ctx, bad); !errors.Is(err, transport.ErrComposeEditorStale) {
		t.Fatalf("stale revision accepted: %v", err)
	}
	bad.PlanDigest = plan.PlanDigest
	bad.ComposeDraft = &transport.ComposeDraft{Content: content + "# edited after review\n", Revision: document.Revision}
	if _, err := f.m.Submit(ctx, transport.Principal{UID: 1000}, bad); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("different YAML accepted with a reviewed digest: %v", err)
	}
	req.PlanDigest = plan.PlanDigest
	op, err := f.m.Submit(ctx, transport.Principal{UID: 1000}, req)
	if err != nil {
		t.Fatal(err)
	}
	op, err = jobs.New(f.m.Store).Start(ctx, op.Spec.ID)
	if err != nil {
		t.Fatal(err)
	}
	st, err := f.m.state(ctx, f.s)
	if err != nil {
		t.Fatal(err)
	}
	currentDigest := f.release.Spec().ConfigurationDigest
	current, err := f.m.LoadConfiguration(ctx, currentDigest)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.m.prepareComposeRelease(ctx, f.s, st, op, operationInput{req, plan}, current, currentDigest); err != nil {
		t.Fatal(err)
	}
	var candidateID domain.ID
	if err := f.m.Store.Get(ctx, "compose_preparation", op.Spec.ID, &candidateID); err != nil {
		t.Fatal(err)
	}
	candidate, err := f.m.loadSnapshot(ctx, candidateID)
	if err != nil || candidate.ManifestDigest != plan.ComposeSourceTree {
		t.Fatalf("candidate mismatch: %v", err)
	}
	approvedEntries, nextEntries := f.baseline.Manifest.Entries(), candidate.Manifest.Entries()
	for i, want := range approvedEntries {
		if want.Path == document.Path {
			want.Size, want.Digest = int64(len(content)), domain.Hash([]byte(content))
		}
		if nextEntries[i] != want {
			t.Fatalf("unrelated content or metadata changed: %+v, want %+v", nextEntries[i], want)
		}
	}
	for file, want := range map[string]string{
		filepath.Join(f.s.ProjectDirectory, document.Path): composeEditorBaseline,
		filepath.Join(f.s.SourceDirectory, document.Path):  "unrelated workspace edits",
		f.activeFile:    "version = 1\n",
		f.workspaceFile: "unrelated code in workspace",
	} {
		got, err := os.ReadFile(file)
		if err != nil || string(got) != want {
			t.Fatalf("preparation changed live/workspace file %s: %v", file, err)
		}
	}
	var release domain.Release
	releases, err := f.m.Store.List(ctx, "release", f.s.ID)
	if err != nil || len(releases) != 2 {
		t.Fatalf("draft did not create a release: %v", err)
	}
	for _, row := range releases {
		if row.ID != st.CurrentReleaseID {
			if err := f.m.Store.Get(ctx, "release", row.ID, &release); err != nil {
				t.Fatal(err)
			}
		}
	}
	if release.Spec().ConfigurationDigest != plan.ComposeDraftConfiguration || !reflect.DeepEqual(release.Spec().Data, f.release.Spec().Data) {
		t.Fatal("draft release did not retain approved persistent data identities and configuration")
	}
	deploy, err := f.m.Preview(ctx, transport.SubmitRequest{ServiceID: f.s.ID, Action: domain.OperationDeploy, ReleaseID: release.Spec().ID})
	if err != nil || !deploy.ComposeChange || !deploy.DataCompatibilityRequired || !deploy.HasRollback {
		t.Fatalf("draft bypassed the release switch safety gates: %+v, %v", deploy, err)
	}
	next, _ := f.m.Snapshots.ContentPath(candidateID)
	dataPath := filepath.Join(f.s.ProjectDirectory, "persistent-data")
	writePlanningFile(t, dataPath, "existing player data")
	if err := filesystem.Apply(ctx, next, f.s.ProjectDirectory, f.baseline.Manifest, candidate.Manifest, f.s.ManagedPaths, filesystem.ApplyOptions{ApplicationsStopped: true}); err != nil {
		t.Fatal(err)
	}
	st.CurrentReleaseID, st.ActiveSnapshotID = release.Spec().ID, candidateID
	if err := f.m.saveState(ctx, &st); err != nil {
		t.Fatal(err)
	}
	currentDocument, err := f.m.ComposeDocument(ctx, f.s.ID)
	if err != nil || currentDocument.Revision == document.Revision || currentDocument.Content != content {
		t.Fatalf("editor did not reflect active revision: %+v, %v", currentDocument, err)
	}
	rollback, err := f.m.Preview(ctx, transport.SubmitRequest{ServiceID: f.s.ID, Action: domain.OperationRollback, ReleaseID: f.release.Spec().ID})
	if err != nil || !rollback.ComposeChange || !rollback.DataCompatibilityRequired {
		t.Fatalf("draft did not preserve a reversible Compose change: %+v, %v", rollback, err)
	}
	previous, _ := f.m.Snapshots.ContentPath(f.baseline.ID)
	if err := filesystem.Apply(ctx, previous, f.s.ProjectDirectory, candidate.Manifest, f.baseline.Manifest, f.s.ManagedPaths, filesystem.ApplyOptions{ApplicationsStopped: true}); err != nil {
		t.Fatal(err)
	}
	for file, want := range map[string]string{dataPath: "existing player data", filepath.Join(f.s.ProjectDirectory, document.Path): composeEditorBaseline} {
		if got, err := os.ReadFile(file); err != nil || string(got) != want {
			t.Fatalf("rollback did not preserve %s: %v", file, err)
		}
	}
}
