package executor

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/secrets"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func gitPlanningFixture(t *testing.T) *planningFixture {
	t.Helper()
	f := newPlanningFixture(t)
	vault, err := secrets.Open(filepath.Join(f.m.Config.StateDirectory, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vault.Close() })
	f.m.Vault = vault
	return f
}

func TestGitConfigurationVaultCredentialsAreWriteOnlyAndScopedToURLAndUsername(t *testing.T) {
	f := gitPlanningFixture(t)
	const token = "PRIVATE_TOKEN_f06e1a9b"
	req := transport.GitSourceRequest{URL: "https://github.com/SibirCTF/ncdex.git", Token: token, Username: "oauth2"}
	view, err := f.m.ConfigureGitSource(t.Context(), f.s.ID, req)
	if err != nil {
		t.Fatal(err)
	}
	if !view.Configured || !view.HasCredentials || view.Ref != "HEAD" || view.Revision != 1 {
		t.Fatalf("bad view: %#v", view)
	}
	encoded, _ := json.Marshal(view)
	if strings.Contains(string(encoded), token) || strings.Contains(string(encoded), "credential\"") {
		t.Fatal("credential leaked to public view")
	}
	configuration, err := f.m.gitConfiguration(t.Context(), f.s.ID)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := f.m.Vault.Read(*configuration.Credential)
	if err != nil || string(secret) != token {
		t.Fatal("token missing from immutable vault")
	}
	records, err := f.m.Store.List(t.Context(), "git_source", f.s.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if strings.Contains(string(record.Payload), token) {
			t.Fatal("token persisted to database")
		}
	}
	req.Token = ""
	req.Ref = "main"
	view, err = f.m.ConfigureGitSource(t.Context(), f.s.ID, req)
	if err != nil || !view.HasCredentials {
		t.Fatalf("same repository forgot token: %v", err)
	}
	req.URL = "https://gitlab.com/example/other.git"
	view, err = f.m.ConfigureGitSource(t.Context(), f.s.ID, req)
	if err != nil || view.HasCredentials {
		t.Fatalf("credentials crossed repository boundary: %v", err)
	}
	req.Token = token
	if _, err = f.m.ConfigureGitSource(t.Context(), f.s.ID, req); err != nil {
		t.Fatal(err)
	}
	req.Token = ""
	req.ClearCredentials = true
	view, err = f.m.ConfigureGitSource(t.Context(), f.s.ID, req)
	if err != nil || view.HasCredentials {
		t.Fatalf("credential removal failed: %v", err)
	}
}

func TestGitPreviewBindsConfigurationAndQueuedFetchBlocksReconfiguration(t *testing.T) {
	f := gitPlanningFixture(t)
	config := transport.GitSourceRequest{URL: "https://github.com/SibirCTF/ncdex.git", Ref: "main"}
	if _, err := f.m.ConfigureGitSource(t.Context(), f.s.ID, config); err != nil {
		t.Fatal(err)
	}
	req := transport.SubmitRequest{ServiceID: f.s.ID, Action: domain.OperationFetchSource, IdempotencyKey: "git-fetch", Initiator: "web-admin"}
	first, err := f.m.Preview(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if first.GitSource == nil || first.GitSource.Revision != 1 || len(first.ChangedFiles) != 0 {
		t.Fatalf("preview promises unknown remote tree: %#v", first)
	}
	config.Ref = "release"
	if _, err := f.m.ConfigureGitSource(t.Context(), f.s.ID, config); err != nil {
		t.Fatal(err)
	}
	fresh, err := f.m.Preview(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.PlanDigest == first.PlanDigest {
		t.Fatal("configuration change did not invalidate preview")
	}
	req.PlanDigest = first.PlanDigest
	if _, err := f.m.Submit(t.Context(), transport.Principal{}, req); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale source accepted: %v", err)
	}
	req.PlanDigest = fresh.PlanDigest
	op, err := f.m.Submit(t.Context(), transport.Principal{}, req)
	if err != nil {
		t.Fatal(err)
	}
	if op.Spec.Kind != domain.OperationFetchSource || op.State != domain.OperationQueued {
		t.Fatal("fetch did not enter durable queue")
	}
	if _, err := f.m.ConfigureGitSource(t.Context(), f.s.ID, config); !errors.Is(err, store.ErrBusy) {
		t.Fatalf("changed source of pending fetch: %v", err)
	}
	for _, name := range []string{f.activeFile, f.workspaceFile} {
		data, err := os.ReadFile(name)
		if err != nil || string(data) != "version = 1\n" {
			t.Fatal("preview/configuration modified service files")
		}
	}
}

func TestGitCandidateFreezesExactCommitInSnapshotAndPublicView(t *testing.T) {
	f := gitPlanningFixture(t)
	config := transport.GitSourceRequest{URL: "https://github.com/SibirCTF/ncdex.git", Ref: "main"}
	if _, err := f.m.ConfigureGitSource(t.Context(), f.s.ID, config); err != nil {
		t.Fatal(err)
	}
	provenance := &domain.GitProvenance{URL: config.URL, Ref: config.Ref, Commit: strings.Repeat("a", 40), SourceRevision: 1}
	snap, err := f.m.capture(t.Context(), f.s, "web-admin", domain.SnapshotCandidate, f.s.SourceDirectory, provenance)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := f.m.loadSnapshot(t.Context(), snap.ID)
	if err != nil || loaded.GitSource == nil || loaded.GitSource.Commit != provenance.Commit {
		t.Fatalf("provenance lost: %v", err)
	}
	view, err := f.m.GitSource(t.Context(), f.s.ID)
	if err != nil || view.LastFetch == nil || view.LastFetch.SnapshotID != snap.ID || view.LastFetch.Commit != provenance.Commit {
		t.Fatalf("candidate not visible: %#v %v", view, err)
	}
	config.Ref = "other"
	if _, err := f.m.ConfigureGitSource(t.Context(), f.s.ID, config); err != nil {
		t.Fatal(err)
	}
	view, err = f.m.GitSource(t.Context(), f.s.ID)
	if err != nil || view.LastFetch != nil {
		t.Fatal("old repository fetch shown as new source")
	}
	loaded, err = f.m.loadSnapshot(t.Context(), snap.ID)
	if err != nil || loaded.GitSource.Ref != "main" {
		t.Fatal("source edit changed immutable candidate")
	}
}
