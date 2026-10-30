package docker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
)

func TestPinnedComposeCommandUsesControlledIdentityAndEnvironment(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://untrusted.invalid:2375")
	c := config.Config{DockerBinary: "/usr/bin/docker", ComposeBinary: "/opt/tools/multicall", DockerHost: "unix:///var/run/docker.sock"}
	cmd := command(c, context.Background(), "", "compose", "version", "--short")
	if cmd.Path != c.ComposeBinary || cmd.Args[0] != "docker-compose" {
		t.Fatalf("incorrect pinned plugin: %q %q", cmd.Path, cmd.Args)
	}
	if strings.Contains(strings.Join(cmd.Env, "\n"), "untrusted.invalid") {
		t.Fatal("inherited untrusted Docker endpoint")
	}
	if !strings.Contains(strings.Join(cmd.Env, "\n"), "HOME=/nonexistent") {
		t.Fatal("inherited user Docker configuration")
	}
}

func TestAnalyzeDoesNotExposeSecretsAndBlocksUnsafeProfiles(t *testing.T) {
	doc := map[string]any{"services": map[string]any{"app": map[string]any{"environment": map[string]any{"PASSWORD": "do-not-disclose"}, "privileged": true, "volumes": []any{map[string]any{"type": "volume", "target": "/data"}}}}}
	r := Analyze(ComposeInput{ProjectDirectory: "/srv/service"}, doc)
	if len(r.Issues) != 2 {
		t.Fatalf("issues: %+v", r.Issues)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "do-not-disclose") {
		t.Fatal("report discloses environment value")
	}
	if len(r.Normalized) == 0 {
		t.Fatal("missing private normalized plan")
	}
}

func TestPreflightRejectsExternalInputBeforeCompose(t *testing.T) {
	for _, doc := range []map[string]any{
		{"include": "https://example.invalid/compose.yaml"},
		{"services": map[string]any{"app": map[string]any{"env_file": "/etc/shadow"}}},
		{"services": map[string]any{"app": map[string]any{"extends": map[string]any{"file": "remote.yaml"}}}},
	} {
		if err := preflightYAML(doc, "/srv/service"); err == nil {
			t.Fatalf("accepted %+v", doc)
		}
	}
}

func TestNormalizeDecodesComposeRendererDollarsBeforeFreezing(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "compose.yaml"), []byte("services:\n  app:\n    image: alpine:3.21.3\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Captured canonical JSON shape from Compose 5.5 config after interpolation:
	// its renderer doubles dollars in both values and mapping keys.
	rendered := `{"name":"literal-test","services":{"app":{"image":"alpine:3.21.3","environment":{"YAML_LITERAL":"pa$$word-$${HOME}","ENV_LITERAL":"pa$$word-$${HOME}-$$$$","END":"plain$$"},"command":["echo","hello $$VAR","$${HOME}","plain$$","$$$$"],"entrypoint":["echo","entry$$NAME"],"healthcheck":{"test":["CMD-SHELL","echo $$VALUE"]},"labels":{"literal$$key":"value$$foo"}}}}`
	plugin := filepath.Join(root, "compose")
	if err := os.WriteFile(plugin, []byte("#!/bin/sh\ncat <<'CTFM_JSON'\n"+rendered+"\nCTFM_JSON\n"), 0700); err != nil {
		t.Fatal(err)
	}
	c := config.Config{DockerBinary: "/unused/docker", ComposeBinary: plugin, DockerHost: "unix:///unused.sock", DiscoveryRoots: []string{project}, Development: true}
	input := ComposeInput{ProjectDirectory: project, ProjectName: "literal-test", Files: []string{"compose.yaml"}}
	report, err := Normalize(t.Context(), c, input)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(report.Normalized, &doc); err != nil {
		t.Fatal(err)
	}
	service := doc["services"].(map[string]any)["app"].(map[string]any)
	env := service["environment"].(map[string]any)
	if env["YAML_LITERAL"] != "pa$word-${HOME}" || env["ENV_LITERAL"] != "pa$word-${HOME}-$$" || env["END"] != "plain$" {
		t.Fatalf("frozen environment does not match effective values: %#v", env)
	}
	if service["labels"].(map[string]any)["literal$key"] != "value$foo" {
		t.Fatal("rendered mapping key/value not decoded")
	}
	command := service["command"].([]any)
	if command[1] != "hello $VAR" || command[2] != "${HOME}" || command[3] != "plain$" || command[4] != "$$" {
		t.Fatalf("command is not effective literal text: %#v", command)
	}
	if service["entrypoint"].([]any)[1] != "entry$NAME" || service["healthcheck"].(map[string]any)["test"].([]any)[1] != "echo $VALUE" {
		t.Fatal("entrypoint/healthcheck dollars not decoded")
	}
	// A generated Compose input must safely restore the same escaped values,
	// while preserving literal mapping keys (Compose does not interpolate keys).
	encoded, err := marshalComposeModel(doc)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip map[string]any
	if err := json.Unmarshal(encoded, &roundtrip); err != nil {
		t.Fatal(err)
	}
	output := roundtrip["services"].(map[string]any)["app"].(map[string]any)
	if output["environment"].(map[string]any)["YAML_LITERAL"] != "pa$$word-$${HOME}" || output["labels"].(map[string]any)["literal$key"] != "value$$foo" {
		t.Fatal("effective model not safely serialized for execution")
	}
	public, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(public), "pa$") {
		t.Fatal("literal secret leaked into public report")
	}
}
