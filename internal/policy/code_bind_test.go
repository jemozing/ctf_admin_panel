package policy

import (
	"path/filepath"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

func rootCodeFixture(t *testing.T) *registrationFixture {
	t.Helper()
	f := newFixture(t)
	f.containers[0].Mounts = []docker.Mount{{Type: "bind", Source: f.service.ProjectDirectory, Target: "/app"}}
	f.service.DataPaths = append(f.service.DataPaths, domain.DataPath{Name: "project-code", Component: "app", Kind: domain.StorageBind, Source: f.service.ProjectDirectory, Target: "/app", LossAccepted: true, AllowCodeUpdates: true})
	f.modifyDocument(t, func(doc map[string]any) {
		doc["services"].(map[string]any)["app"].(map[string]any)["volumes"] = []any{map[string]any{"type": "bind", "source": f.service.ProjectDirectory, "target": "/app"}}
	})
	f.containers = inspectedFixture(t, f.containers)
	return f
}

func TestRootCodeBindRequiresMatchingRuntimeAndExplicitScopedConsent(t *testing.T) {
	f := rootCodeFixture(t)
	if err := ValidateRegistration(f.config, f.service, f.report, f.containers); err != nil {
		t.Fatalf("explicit disposable root code bind rejected: %#v", RegistrationIssues(f.config, f.service, f.report, f.containers))
	}
	f.service.DataPaths[3].AllowCodeUpdates = false
	assertIssue(t, f, "invalid_service")
	f.service.DataPaths[3].AllowCodeUpdates = true
	f.service.DataPaths[3].LossAccepted = false
	assertIssue(t, f, "invalid_service")
}

func TestRootCodeBindConsentDoesNotWaiveRuntimeIdentityOrReadOnly(t *testing.T) {
	t.Run("runtime source changed", func(t *testing.T) {
		f := rootCodeFixture(t)
		f.containers[0].Mounts[0].Source = filepath.Join(f.service.ProjectDirectory, "app")
		assertIssue(t, f, "storage_identity_mismatch")
	})
	t.Run("read only mount", func(t *testing.T) {
		f := rootCodeFixture(t)
		f.containers[0].Mounts[0].ReadOnly = true
		f.modifyDocument(t, func(doc map[string]any) {
			doc["services"].(map[string]any)["app"].(map[string]any)["volumes"].([]any)[0].(map[string]any)["read_only"] = true
		})
		f.containers = inspectedFixture(t, f.containers)
		assertIssue(t, f, "code_bind_not_writable")
	})
}

func TestCodeModeRequiresReadOnlyConsumersToStopToo(t *testing.T) {
	f := rootCodeFixture(t)
	shared := docker.Mount{Type: "bind", Source: filepath.Join(f.service.ProjectDirectory, "app"), Target: "/shared-code", ReadOnly: true}
	f.containers[1].Mounts = append(f.containers[1].Mounts, shared)
	f.modifyDocument(t, func(doc map[string]any) {
		db := doc["services"].(map[string]any)["db"].(map[string]any)
		db["volumes"] = append(db["volumes"].([]any), map[string]any{"type": "bind", "source": shared.Source, "target": shared.Target, "read_only": true})
	})
	f.containers = inspectedFixture(t, f.containers)
	assertIssue(t, f, "code_consumer_not_target")
	f.service.Targets = append(f.service.Targets, "db")
	for _, issue := range RegistrationIssues(f.config, f.service, f.report, f.containers) {
		if issue.Code == "code_consumer_not_target" {
			t.Fatal("consumer remains unstopped after adding its update target")
		}
	}
	// Target selection does not waive the existing parent-path trust boundary.
	assertIssue(t, f, "game_writable_bind_parent")
}

func TestSharedRootCodeBindRequiresBothConsumersConsentAndTargets(t *testing.T) {
	f := rootCodeFixture(t)
	f.service.DataPaths[0] = domain.DataPath{Name: "shared-code", Component: "db", Kind: domain.StorageBind, Source: f.service.ProjectDirectory, Target: "/shared", LossAccepted: true, AllowCodeUpdates: true}
	f.containers[1].Mounts = []docker.Mount{{Type: "bind", Source: f.service.ProjectDirectory, Target: "/shared"}}
	f.modifyDocument(t, func(doc map[string]any) {
		doc["services"].(map[string]any)["db"].(map[string]any)["volumes"] = []any{map[string]any{"type": "bind", "source": f.service.ProjectDirectory, "target": "/shared"}}
	})
	f.containers = inspectedFixture(t, f.containers)
	assertIssue(t, f, "invalid_service")
	f.service.Targets = append(f.service.Targets, "db")
	if err := ValidateRegistration(f.config, f.service, f.report, f.containers); err != nil {
		t.Fatalf("shared root code bind rejected: %#v", RegistrationIssues(f.config, f.service, f.report, f.containers))
	}
	f.service.DataPaths[0].AllowCodeUpdates = false
	assertIssue(t, f, "invalid_service")
}
