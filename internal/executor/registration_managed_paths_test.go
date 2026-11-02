package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func managedPathsFixture(t *testing.T) (*Manager, domain.Service, string) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(base, "games", "filestorage")
	for _, name := range []string{"templates", "templates/uploads", "templates/__pycache__", "uploads", "cleaner", "data", "persistent-store"} {
		if err := os.MkdirAll(filepath.Join(project, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"docker-compose.yml", "Dockerfile", "main.py", "db.py", "requirements.txt", "db.db", "db.db-journal", "db.db-wal", "db.db-shm", "other.sqlite", "other.sqlite3-wal", ".env", "private.key", "templates/index.html", "templates/session.sqlite3-shm", "uploads/flag", "templates/uploads/flag", "templates/__pycache__/module.pyc", "cleaner/cleaner.sh", "data/flag", "persistent-store/flag"} {
		if err := os.WriteFile(filepath.Join(project, name), []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(base, filepath.Join(project, "outside")); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(base, "state", "executor.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	draft := domain.Service{ID: "draft-code", ProjectDirectory: project, ComposeFiles: []string{"docker-compose.yml"}, DataPaths: []domain.DataPath{
		{Name: "mount-web", Kind: domain.StorageBind, Source: project, Target: "/app", Component: "web", Significant: true},
		{Name: "mount-cleaner", Kind: domain.StorageBind, Source: project, Target: "/app", Component: "cleaner", Significant: true},
		{Name: "protected-data", Kind: domain.StorageBind, Source: filepath.Join(project, "persistent-store"), Target: "/data", Component: "web", Significant: true},
		{Name: "database-volume", Kind: domain.StorageNamedVolume, Source: "fixture-volume", Target: "/database", Component: "database", Significant: true},
	}}
	if err := db.PutImmutable(t.Context(), "web_registration_draft", draft.ID, draft.ID, draft); err != nil {
		t.Fatal(err)
	}
	return &Manager{Config: config.Config{DiscoveryRoots: []string{filepath.Join(base, "games")}}, Store: db}, draft, base
}

func TestResolveManagedPathsRequiresAllOverlappingCodeBindingsAndKeepsDraftImmutable(t *testing.T) {
	manager, draft, _ := managedPathsFixture(t)
	for _, selected := range [][]string{nil, {"mount-web"}} {
		result, err := manager.ResolveRegistrationManagedPaths(t.Context(), transport.RegistrationManagedPathsRequest{ServiceID: draft.ID, CodeBindings: selected})
		if err != nil || len(result.ManagedPaths) != 0 {
			t.Fatalf("persistent overlapping root must remain excluded: %#v %v", result, err)
		}
	}
	result, err := manager.ResolveRegistrationManagedPaths(t.Context(), transport.RegistrationManagedPathsRequest{ServiceID: draft.ID, CodeBindings: []string{"mount-web", "mount-cleaner"}})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]domain.ManagedPath{}
	for _, item := range result.ManagedPaths {
		seen[item.Path] = item
	}
	for _, expected := range []string{"Dockerfile", "main.py", "db.py", "requirements.txt", "templates", "cleaner"} {
		if seen[expected].Kind != domain.ManagedCode {
			t.Errorf("missing code suggestion %q", expected)
		}
	}
	if seen["docker-compose.yml"].Kind != domain.ManagedConfig {
		t.Fatal("Compose file lost configuration classification")
	}
	for _, unsafe := range []string{"db.db", "db.db-journal", "db.db-wal", "db.db-shm", "other.sqlite", "other.sqlite3-wal", "uploads", "data", "persistent-store", ".env", "private.key", "outside"} {
		if _, found := seen[unsafe]; found {
			t.Errorf("runtime/secret/symlink suggestion %q", unsafe)
		}
	}
	if !reflect.DeepEqual(seen["templates"].Exclusions, []string{"__pycache__", "session.sqlite3-shm", "uploads"}) {
		t.Fatalf("nested runtime exclusions: %#v", seen["templates"].Exclusions)
	}
	var after domain.Service
	if err := manager.Store.Get(t.Context(), "web_registration_draft", draft.ID, &after); err != nil || !reflect.DeepEqual(after, draft) {
		t.Fatalf("read-only resolver changed immutable draft: %#v %v", after, err)
	}
	if _, err := manager.Store.GetService(t.Context(), draft.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("suggestion unexpectedly registered a service: %v", err)
	}
}

func TestResolveManagedPathsRejectsUnknownNonBindAndOutOfProjectSources(t *testing.T) {
	manager, draft, base := managedPathsFixture(t)
	for _, selected := range [][]string{{"missing"}, {"database-volume"}, {"mount-web", "mount-web"}, {"../escape"}} {
		_, err := manager.ResolveRegistrationManagedPaths(t.Context(), transport.RegistrationManagedPathsRequest{ServiceID: draft.ID, CodeBindings: selected})
		var invalid *transport.RegistrationInputError
		if !errors.As(err, &invalid) {
			t.Errorf("invalid bind selection accepted: %#v %v", selected, err)
		}
	}
	for i, source := range []string{filepath.Join(base, "outside"), filepath.Dir(draft.ProjectDirectory), draft.ProjectDirectory + "-sibling"} {
		copy := draft
		copy.ID = domain.ID([]string{"draft-outside", "draft-parent", "draft-sibling"}[i])
		copy.DataPaths = []domain.DataPath{{Name: "outside", Kind: domain.StorageBind, Source: source, Target: "/app", Component: "web"}}
		if err := manager.Store.PutImmutable(t.Context(), "web_registration_draft", copy.ID, copy.ID, copy); err != nil {
			t.Fatal(err)
		}
		_, err := manager.ResolveRegistrationManagedPaths(t.Context(), transport.RegistrationManagedPathsRequest{ServiceID: copy.ID, CodeBindings: []string{"outside"}})
		var invalid *transport.RegistrationInputError
		if !errors.As(err, &invalid) {
			t.Errorf("out-of-project bind source accepted: %v", err)
		}
	}
}

func TestResolveManagedPathsRejectsMissingStaleAndAliasedDraftDirectories(t *testing.T) {
	manager, draft, base := managedPathsFixture(t)
	_, err := manager.ResolveRegistrationManagedPaths(t.Context(), transport.RegistrationManagedPathsRequest{ServiceID: "draft-missing"})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown draft: %v", err)
	}
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(draft.ProjectDirectory, draft.ProjectDirectory+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, draft.ProjectDirectory); err != nil {
		t.Fatal(err)
	}
	_, err = manager.ResolveRegistrationManagedPaths(t.Context(), transport.RegistrationManagedPathsRequest{ServiceID: draft.ID})
	var invalid *transport.RegistrationInputError
	if !errors.As(err, &invalid) {
		t.Fatalf("aliased draft project accepted: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = manager.ResolveRegistrationManagedPaths(ctx, transport.RegistrationManagedPathsRequest{ServiceID: draft.ID}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled resolver: %v", err)
	}
}
