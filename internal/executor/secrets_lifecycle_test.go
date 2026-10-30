package executor

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/maintenance"
)

func secretAdminFixture(t *testing.T) (*SecretsAdmin, config.Config) {
	t.Helper()
	f := newPlanningFixture(t)
	c := config.Config{StateDirectory: f.m.Config.StateDirectory, Socket: filepath.Join(f.m.Config.StateDirectory, "executor.sock"), DockerHost: "unix:///unused.sock", DockerBinary: "/usr/bin/true", DiscoveryRoots: []string{f.s.ProjectDirectory}, WorkspaceRoots: []string{f.s.SourceDirectory}, WebUID: os.Geteuid(), Development: true}
	if err := f.m.Store.Close(); err != nil {
		t.Fatal(err)
	}
	a, err := OpenSecretsAdmin(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	return a, c
}

func TestSecretLifecycleShowsDependenciesAndRequiresConfirmedRevocation(t *testing.T) {
	a, _ := secretAdminFixture(t)
	ref, err := a.Import(t.Context(), "service-env", []byte("secret-marker-for-lifecycle"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.Import(t.Context(), "service-env", []byte("new-private-version"))
	if err != nil {
		t.Fatal(err)
	}
	c := Configuration{Environment: map[string]domain.SecretVersionRef{"app": ref}, FileInputs: map[string]domain.SecretVersionRef{"secrets/key": ref}}
	if err := a.db.PutImmutable(t.Context(), "configuration", "config-secret", "flags", c); err != nil {
		t.Fatal(err)
	}
	spec := domain.ReleaseSpec{SchemaVersion: 1, ID: "release-secret", ServiceID: "flags", CreatedAt: time.Now().UTC(), Author: "local-admin", Source: domain.ReleaseImported, SnapshotID: "baseline", TreeDigest: domain.Hash([]byte("tree")), ConfigurationDigest: domain.Hash([]byte("config")), PolicyRevision: 1, FileMapRevision: 1, Images: []domain.ImageRef{{Component: "app", ImageID: domain.Hash([]byte("image")), RetentionTag: "ctf-manager/flags:release-secret-app"}}, Secrets: []domain.SecretVersionRef{ref}}
	release, err := domain.NewRelease(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.db.PutImmutable(t.Context(), "release", spec.ID, spec.ServiceID, release); err != nil {
		t.Fatal(err)
	}
	plan, err := a.Plan(t.Context(), "revoke", ref)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(plan)
	if len(plan.Version.Dependents) != 3 || !strings.Contains(string(encoded), "release-secret") || strings.Contains(string(encoded), "secret-marker-for-lifecycle") {
		t.Fatalf("unsafe/incomplete dependencies: %s", encoded)
	}
	if err := a.Change(t.Context(), "revoke", ref, domain.Hash([]byte("wrong"))); err == nil {
		t.Fatal("unconfirmed revocation accepted")
	}
	if _, err := a.vault.Read(ref); err != nil {
		t.Fatal("failed confirmation mutated secret", err)
	}
	if err := a.Change(t.Context(), "revoke", ref, plan.ConfirmationDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := a.vault.Read(ref); err == nil {
		t.Fatal("revoked release secret is available")
	}
	if _, err := a.vault.Read(second); err != nil {
		t.Fatal("revoking one version affected another", err)
	}
	root := filepath.Join(a.config.StateDirectory, "runtime-inputs")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	name := string(domain.Hash([]byte("secrets/key/" + string(ref.SecretID) + "/" + string(ref.Version))))[7:]
	if err := os.WriteFile(filepath.Join(root, name), []byte("secret-marker-for-lifecycle"), 0444); err != nil {
		t.Fatal(err)
	}
	deletePlan, err := a.Plan(t.Context(), "delete", ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Change(t.Context(), "delete", ref, deletePlan.ConfirmationDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(err) {
		t.Fatal("materialized secret input survived deletion", err)
	}
	records, err := a.db.List(t.Context(), "maintenance_audit", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 8 {
		t.Fatalf("missing import/revoke/delete local audit: %d", len(records))
	}
	for _, record := range records {
		if strings.Contains(string(record.Payload), "secret-marker") {
			t.Fatal("secret leaked to local audit")
		}
	}
}

func TestSecretMutationRejectsUnresolvedJobsAndMaintenanceConflict(t *testing.T) {
	a, c := secretAdminFixture(t)
	op, err := domain.NewOperation(domain.OperationSpec{ID: "queued-secret", Kind: domain.OperationPrepare, Initiator: "admin", IdempotencyKey: "queued-secret", ServiceID: "flags", ExpectedPolicyRevision: 1, ExpectedTreeDigest: domain.Hash([]byte("tree")), Resources: []string{"service:flags"}, TimeoutSeconds: 30}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.db.BeginOperation(t.Context(), op, domain.Hash([]byte("queued"))); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Import(t.Context(), "blocked", []byte("value")); err == nil {
		t.Fatal("secret changed with unresolved operation")
	}
	if _, err := maintenance.Acquire(c.StateDirectory, true); !errors.Is(err, maintenance.ErrActive) {
		t.Fatalf("backup can overlap secret maintenance: %v", err)
	}
	if _, err := OpenSecretsAdmin(c); !errors.Is(err, maintenance.ErrActive) {
		t.Fatalf("concurrent secret maintenance accepted: %v", err)
	}
}
