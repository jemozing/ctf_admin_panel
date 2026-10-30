package executor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/secrets"
)

func TestDiagnosticRedactionAcrossEveryWriteBoundary(t *testing.T) {
	secret := "private-token-123"
	for split := 1; split < len(secret); split++ {
		var output strings.Builder
		w := newDiagnosticWriter(func(s string) error { output.WriteString(s); return nil }, []string{secret})
		for _, part := range []string{"compiler ", secret[:split], secret[split:], " failed\x00\x1b\n"} {
			if _, err := w.Write([]byte(part)); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.String(), secret) || !strings.Contains(output.String(), "[REDACTED]") || strings.ContainsAny(output.String(), "\x00\x1b") {
			t.Fatalf("unsafe command output at split %d: %q", split, output.String())
		}
	}
}

func TestDiagnosticPersistenceFailurePropagates(t *testing.T) {
	want := errors.New("journal disk full")
	w := newDiagnosticWriter(func(string) error { return want }, nil)
	if _, err := w.Write([]byte("compiler output")); !errors.Is(err, want) {
		t.Fatalf("lost writer failure: %v", err)
	}
	if !errors.Is(w.Close(), want) {
		t.Fatal("Close lost writer failure")
	}
}

func TestFailedComposeBuildRetainsRedactedDiagnostics(t *testing.T) {
	f := newPlanningFixture(t)
	vault, err := secrets.Open(filepath.Join(f.m.Config.StateDirectory, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()
	f.m.Vault = vault
	ref, err := vault.Import("build-env", []byte(`{"PASSWORD":"sensitive-build-password"}`))
	if err != nil {
		t.Fatal(err)
	}
	c := Configuration{Environment: map[string]domain.SecretVersionRef{"app": ref}}
	plugin := filepath.Join(t.TempDir(), "compose")
	if err := os.WriteFile(plugin, []byte("#!/bin/sh\nprintf 'compiler error: sensitive-build-password\\n' >&2\nexit 3\n"), 0700); err != nil {
		t.Fatal(err)
	}
	f.m.Config.ComposeBinary = plugin
	f.m.Config.DockerHost = "unix:///unused-test.sock"
	f.m.Config.DockerBinary = "/unused/docker"
	op, err := domain.NewOperation(domain.OperationSpec{ID: "failed-build", Kind: domain.OperationBuild, Initiator: "local-admin", IdempotencyKey: "failed-build", ServiceID: f.s.ID, ExpectedPolicyRevision: 1, ExpectedTreeDigest: f.baseline.ManifestDigest, Resources: []string{"service:" + string(f.s.ID)}, TimeoutSeconds: 30}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.m.Store.BeginOperation(t.Context(), op, domain.Hash([]byte("build"))); err != nil {
		t.Fatal(err)
	}
	err = f.m.composeActionWithDiagnostics(t.Context(), f.s, op.Spec.ID, c, map[string]any{"services": map[string]any{"app": map[string]any{"image": "fixture:1"}}}, "build", []string{"app"}, nil)
	if err == nil {
		t.Fatal("failing Compose returned success")
	}
	log, err := f.m.OperationDiagnostics(t.Context(), op.Spec.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	for _, chunk := range log.Chunks {
		text.WriteString(chunk.Content)
	}
	if !strings.Contains(text.String(), "compiler error") || !strings.Contains(text.String(), "[REDACTED]") || strings.Contains(text.String(), "sensitive-build-password") {
		t.Fatalf("failed build output missing or unsafe: %q", text.String())
	}
}
