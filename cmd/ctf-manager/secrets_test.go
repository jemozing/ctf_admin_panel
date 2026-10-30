package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/executor"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
)

func secretCLIConfig(t *testing.T) config.Config {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "executor")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(state, "executor.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	return config.Config{StateDirectory: state, Socket: filepath.Join(root, "ipc", "executor.sock"), DockerHost: "unix:///unused-test.sock", DockerBinary: "/unavailable/docker", DiscoveryRoots: []string{filepath.Join(root, "projects")}, WorkspaceRoots: []string{filepath.Join(root, "workspaces")}, WebUID: os.Geteuid(), Development: true}
}

func TestSecretCLIUsesPrivateInputAndExplicitDependencyConfirmation(t *testing.T) {
	c := secretCLIConfig(t)
	var output, diagnostic bytes.Buffer
	const value = "CLI_PRIVATE_SECRET_do_not_print"
	if err := runSecrets(c, []string{"secrets", "import", "--secret-id", "test-env", "--stdin"}, strings.NewReader(value), &output, &diagnostic); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), value) || strings.Contains(diagnostic.String(), value) {
		t.Fatal("CLI returned secret value")
	}
	var imported struct {
		Reference domain.SecretVersionRef `json:"reference"`
	}
	if err := json.Unmarshal(output.Bytes(), &imported); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	args := []string{"secrets", "revoke", "--secret-id", string(imported.Reference.SecretID), "--version", string(imported.Reference.Version)}
	if err := runSecrets(c, args, strings.NewReader(""), &output, &diagnostic); err == nil {
		t.Fatal("CLI revocation did not request plan confirmation")
	}
	var plan executor.SecretChangePlan
	if err := json.Unmarshal(output.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.ConfirmationDigest == "" {
		t.Fatal("dependency plan missing digest")
	}
	output.Reset()
	if err := runSecrets(c, append(args, "--confirm", string(plan.ConfirmationDigest)), strings.NewReader(""), &output, &diagnostic); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"result": "succeeded"`) {
		t.Fatal("confirmed revocation missing result", output.String())
	}
	file := filepath.Join(t.TempDir(), "public-input")
	if err := os.WriteFile(file, []byte(value), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := openSecretInput(file); err == nil {
		t.Fatal("world-readable secret input accepted")
	}
	link := filepath.Join(t.TempDir(), "secret-link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openSecretInput(link); err == nil {
		t.Fatal("symlink secret input accepted")
	}
}
