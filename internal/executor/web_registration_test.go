package executor

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/jobs"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func TestRegistrationComposeLabelsCannotEscapeSelectedProject(t *testing.T) {
	for _, input := range []string{"", "compose.yaml", "/srv/project/../other/compose.yaml", "/etc/compose.yaml", "/srv/project/compose.yaml,/srv/project/compose.yaml"} {
		if _, err := registrationComposeFiles("/srv/project", input); err == nil {
			t.Errorf("accepted untrusted label %q", input)
		}
	}
	files, err := registrationComposeFiles("/srv/project", "/srv/project/compose.yaml,/srv/project/deploy/override.yaml")
	if err != nil || !reflect.DeepEqual(files, []string{"compose.yaml", "deploy/override.yaml"}) {
		t.Fatalf("ordered compose inputs: %#v %v", files, err)
	}
}

func TestRegistrationApprovalRetriesQueueExactlyOneBaseline(t *testing.T) {
	f := newPlanningFixture(t)
	previous, err := f.m.state(t.Context(), f.s)
	if err != nil {
		t.Fatal(err)
	}
	empty := runtimeState{Sequence: previous.Sequence, ServiceID: f.s.ID, PolicyRevision: f.s.PolicyRevision, Containers: f.s.Containers}
	if err := f.m.saveState(t.Context(), &empty); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Store.PutImmutable(t.Context(), "web_registration_draft", f.s.ID, f.s.ID, f.s); err != nil {
		t.Fatal(err)
	}
	p, err := f.m.Store.GetProposal(t.Context(), "planning-policy")
	if err != nil {
		t.Fatal(err)
	}
	input := transport.RegistrationApproveRequest{ProposalID: p.ID, Digest: p.Digest, Initiator: "web-admin"}
	var wg sync.WaitGroup
	results := make(chan transport.RegistrationApproval, 8)
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := f.m.ApproveRegistration(t.Context(), input)
			results <- v
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var operation domain.ID
	for result := range results {
		if result.Initialized || result.InitializationError != "" || result.Operation == nil {
			t.Fatalf("wrong pending state: %#v", result)
		}
		if operation != "" && operation != result.Operation.Spec.ID {
			t.Fatal("retry queued a duplicate baseline")
		}
		operation = result.Operation.Spec.ID
	}
	ops, err := f.m.Store.ListOperations(t.Context())
	if err != nil || len(ops) != 1 {
		t.Fatalf("operations: %d %v", len(ops), err)
	}
	input.Digest = domain.Hash([]byte("tampered"))
	if _, err := f.m.ApproveRegistration(t.Context(), input); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("unreviewed digest accepted: %v", err)
	}
	input.Digest = p.Digest
	manager := jobs.New(f.m.Store)
	if _, err := manager.Start(t.Context(), operation); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Transition(t.Context(), operation, domain.OperationFailed, domain.OutcomeEvidence{ActualStateKnown: true, ResultRecorded: true, Reason: "injected baseline copy failure"}); err != nil {
		t.Fatal(err)
	}
	failed, err := f.m.ApproveRegistration(t.Context(), input)
	if err != nil || failed.Initialized || failed.InitializationError != "" || failed.Operation == nil || failed.Operation.Spec.ID == operation || failed.Operation.State != domain.OperationQueued {
		t.Fatalf("explicit retry did not queue a fresh non-mutating baseline: %#v %v", failed, err)
	}
	again, err := f.m.ApproveRegistration(t.Context(), input)
	if err != nil || again.Operation.Spec.ID != failed.Operation.Spec.ID {
		t.Fatalf("retry duplicated second attempt: %#v %v", again, err)
	}
}

func TestRegistrationApprovalIsInitializedAfterCompletedBaseline(t *testing.T) {
	f := newPlanningFixture(t)
	f.m.Config.WorkspaceRoots = []string{filepath.Dir(f.s.SourceDirectory)}
	if err := f.m.Store.PutImmutable(t.Context(), "web_registration_draft", f.s.ID, f.s.ID, f.s); err != nil {
		t.Fatal(err)
	}
	p, err := f.m.Store.GetProposal(t.Context(), "planning-policy")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		result, err := f.m.ApproveRegistration(t.Context(), transport.RegistrationApproveRequest{ProposalID: p.ID, Digest: p.Digest, Initiator: "web-admin"})
		if err != nil || !result.Initialized || result.Operation != nil {
			t.Fatalf("complete retry: %#v %v", result, err)
		}
	}
}

func TestRegistrationSeedRetriesPartialStagingWithoutPublishingPartialWorkspace(t *testing.T) {
	f := newPlanningFixture(t)
	f.m.Config.WorkspaceRoots = []string{filepath.Dir(f.s.SourceDirectory)}
	if err := f.m.Store.PutImmutable(t.Context(), "web_registration_draft", f.s.ID, f.s.ID, f.s); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(f.s.SourceDirectory, "app")); err != nil {
		t.Fatal(err)
	}
	seed := registrationSeed{SnapshotID: f.baseline.ID, Temporary: ".ctfm-seed-partial", TreeDigest: f.baseline.ManifestDigest}
	if err := f.m.Store.PutImmutable(t.Context(), "registration_seed", f.s.ID, f.s.ID, seed); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(filepath.Dir(f.s.SourceDirectory), seed.Temporary)
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "incomplete"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	f.m.Config.Storage.SnapshotMaxBytes = 1
	if err := f.m.seedRegistrationWorkspace(t.Context(), f.s, f.baseline); err == nil {
		t.Fatal("quota failure ignored")
	}
	entries, err := os.ReadDir(f.s.SourceDirectory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed seed published partial source: %#v %v", entries, err)
	}
	f.m.Config.Storage.SnapshotMaxBytes = 0
	if err := f.m.seedRegistrationWorkspace(t.Context(), f.s, f.baseline); err != nil {
		t.Fatal(err)
	}
	if !registrationWorkspaceMatches(t.Context(), f.s, f.baseline) {
		t.Fatal("retry did not publish baseline source")
	}
	if _, err := os.Lstat(staging); !os.IsNotExist(err) {
		t.Fatalf("owned staging not cleaned: %v", err)
	}
	if err := os.WriteFile(f.workspaceFile, []byte("author edits after initialization"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.m.seedRegistrationWorkspace(t.Context(), f.s, f.baseline); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.workspaceFile)
	if err != nil || string(data) != "author edits after initialization" {
		t.Fatal("initialized author workspace overwritten")
	}
}

func TestRegistrationSeedRecoversPublishBeforeMarkerAndPreservesUnknownEdits(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "published", true: "author-edits"}[changed], func(t *testing.T) {
			f := newPlanningFixture(t)
			f.m.Config.WorkspaceRoots = []string{filepath.Dir(f.s.SourceDirectory)}
			if err := f.m.Store.PutImmutable(t.Context(), "web_registration_draft", f.s.ID, f.s.ID, f.s); err != nil {
				t.Fatal(err)
			}
			seed := registrationSeed{SnapshotID: f.baseline.ID, Temporary: ".ctfm-seed-published", TreeDigest: f.baseline.ManifestDigest}
			if err := f.m.Store.PutImmutable(t.Context(), "registration_seed", f.s.ID, f.s.ID, seed); err != nil {
				t.Fatal(err)
			}
			if changed {
				if err := os.WriteFile(f.workspaceFile, []byte("preserve unknown author edits"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := f.m.seedRegistrationWorkspace(t.Context(), f.s, f.baseline)
			if changed {
				if err == nil {
					t.Fatal("unknown workspace accepted as initialized")
				}
				data, _ := os.ReadFile(f.workspaceFile)
				if string(data) != "preserve unknown author edits" {
					t.Fatal("unknown edits overwritten")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				var complete registrationSeed
				if err := f.m.Store.Get(t.Context(), "registration_initialized", f.s.ID, &complete); err != nil || complete.TreeDigest != seed.TreeDigest {
					t.Fatalf("publication receipt not recovered: %#v %v", complete, err)
				}
			}
		})
	}
}

func TestRegistrationSeedRecoversMissingDestinationAfterReceipt(t *testing.T) {
	f := newPlanningFixture(t)
	f.m.Config.WorkspaceRoots = []string{filepath.Dir(f.s.SourceDirectory)}
	if err := f.m.Store.PutImmutable(t.Context(), "web_registration_draft", f.s.ID, f.s.ID, f.s); err != nil {
		t.Fatal(err)
	}
	seed := registrationSeed{SnapshotID: f.baseline.ID, Temporary: ".ctfm-seed-gap", TreeDigest: f.baseline.ManifestDigest}
	if err := f.m.Store.PutImmutable(t.Context(), "registration_seed", f.s.ID, f.s.ID, seed); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(f.s.SourceDirectory); err != nil {
		t.Fatal(err)
	}
	ready, err := f.m.registrationInitialized(t.Context(), f.s, f.baseline.ID)
	if err != nil || ready {
		t.Fatalf("missing workspace is initialized: %v %v", ready, err)
	}
	if err := f.m.seedRegistrationWorkspace(t.Context(), f.s, f.baseline); err != nil {
		t.Fatal(err)
	}
	ready, err = f.m.registrationInitialized(t.Context(), f.s, f.baseline.ID)
	if err != nil || !ready || !registrationWorkspaceMatches(t.Context(), f.s, f.baseline) {
		t.Fatalf("missing destination not recovered: %v %v", ready, err)
	}
}

func TestRegistrationManagedDraftExcludesDataAndSecretTrees(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"app", "app/.git", "app/secrets", "app/nested", "data", "with-data/game-data", "safe"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"app/main.py", "app/.env", "app/secrets/password", "app/.git/config", "compose.yaml", ".env", "private.key", "data/flag", "with-data/main.go", "safe/start.sh"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("test"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/etc", filepath.Join(root, "app", "outside")); err != nil {
		t.Fatal(err)
	}
	managed, err := registrationManagedPaths(root, []string{"compose.yaml"}, []string{filepath.Join(root, "with-data", "game-data")})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]domain.ManagedPath{}
	for _, entry := range managed {
		seen[entry.Path] = entry
	}
	for _, unsafe := range []string{"data", ".env", "private.key", "with-data"} {
		if _, ok := seen[unsafe]; ok {
			t.Errorf("managed data/secret path %q", unsafe)
		}
	}
	if seen["compose.yaml"].Kind != domain.ManagedConfig || seen["safe"].Kind != domain.ManagedCode {
		t.Fatalf("missing code/config: %#v", managed)
	}
	if !reflect.DeepEqual(seen["app"].Exclusions, []string{".env", ".git", "outside", "secrets"}) {
		t.Fatalf("literal exclusions: %#v", seen["app"].Exclusions)
	}
}

func TestRegistrationIdentityAllowsClassificationButBindsDiscoveredRuntime(t *testing.T) {
	draft := domain.Service{SchemaVersion: 1, ID: "service-test", Name: "old", ProjectDirectory: "/srv/game", SourceDirectory: "/srv/workspaces/service-test", ComposeProject: "game", ComposeFiles: []string{"compose.yaml"}, Profiles: []string{}, PolicyRevision: 1, FileMapRevision: 1, Containers: []domain.ContainerRef{{Component: "app", ID: strings.Repeat("a", 64), ImageID: domain.Hash([]byte("image")), Role: domain.RoleApplication}}}
	clone := func() domain.Service {
		v := draft
		v.Containers = append([]domain.ContainerRef{}, draft.Containers...)
		return v
	}
	edited := clone()
	edited.Name = "chosen"
	edited.Containers[0].Role = domain.RoleAuxiliary
	edited.ManagedPaths = []domain.ManagedPath{{Path: "app", Kind: domain.ManagedCode}}
	if !sameRegistrationIdentity(clone(), edited) {
		t.Fatal("classification/name edit rejected")
	}
	for _, mutate := range []func(*domain.Service){func(v *domain.Service) { v.ProjectDirectory = "/etc" }, func(v *domain.Service) { v.SourceDirectory = "/srv/workspaces/existing" }, func(v *domain.Service) { v.ComposeFiles = []string{"changed.yaml"} }, func(v *domain.Service) { v.Containers[0].ID = strings.Repeat("b", 64) }, func(v *domain.Service) { v.PolicyRevision = 2 }} {
		v := clone()
		mutate(&v)
		if sameRegistrationIdentity(clone(), v) {
			t.Fatalf("identity change accepted: %#v", v)
		}
	}
}

func TestWebRegistrationDoesNotInspectUnapprovedOrAliasedDirectory(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	approved := filepath.Join(root, "approved")
	outside := filepath.Join(root, "outside")
	for _, dir := range []string{approved, outside} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(approved, "alias")); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Config: config.Config{DiscoveryRoots: []string{approved}}}
	for _, dir := range []string{outside, filepath.Join(approved, "alias"), filepath.Join(approved, "..", "outside")} {
		_, err := m.InspectRegistration(t.Context(), transport.RegistrationInspectRequest{ProjectDirectory: dir})
		var invalid *transport.RegistrationInputError
		if !errors.As(err, &invalid) {
			t.Fatalf("path reached Docker or wrong diagnostic: %s %v", dir, err)
		}
	}
}

func TestRegistrationWorkspaceCannotOverwriteOrAliasExistingFiles(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{Config: config.Config{WorkspaceRoots: []string{root}}}
	name := filepath.Join(root, "service-new")
	if err := m.ensureRegistrationWorkspace(name); err != nil {
		t.Fatal(err)
	}
	if err := m.ensureRegistrationWorkspace(name); err != nil {
		t.Fatalf("empty retry: %v", err)
	}
	if err := os.WriteFile(filepath.Join(name, "author-edit"), []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.ensureRegistrationWorkspace(name); err == nil {
		t.Fatal("nonempty workspace accepted")
	}
	if err := os.Symlink(name, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := m.ensureRegistrationWorkspace(filepath.Join(root, "alias")); err == nil {
		t.Fatal("symlink workspace accepted")
	}
	if err := m.ensureRegistrationWorkspace(filepath.Join(root, "nested", "other")); err == nil {
		t.Fatal("non-generated nested path accepted")
	}
}
