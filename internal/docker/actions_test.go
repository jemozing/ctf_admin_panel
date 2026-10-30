package docker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
)

func TestComposeActionPreservesNormalizedLiteralDollars(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	capture := filepath.Join(root, "captured.json")
	script := filepath.Join(root, "compose")
	// The fake plugin captures exactly the file supplied to the real Compose
	// executable, before Compose's second interpolation pass.
	body := "#!/bin/sh\nwhile [ $# -gt 0 ]; do\nif [ \"$1\" = \"--file\" ]; then shift; cp \"$1\" " + shellQuote(capture) + "; exit 0; fi\nshift\ndone\nexit 1\n"
	if err := os.WriteFile(script, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	original := map[string]any{
		"name": "literal-test",
		"services": map[string]any{"app": map[string]any{
			"image":       "fixture:1",
			"environment": map[string]string{"PASSWORD": "pa$word", "LITERAL": "${HOME}", "DOLLARS": "$$", "PATH": "$PATH", "OTHER": "no dollars"},
			"command":     []string{"sh", "-c", "printf '%s' \"$PASSWORD\""},
			"healthcheck": map[string]any{"test": []string{"CMD-SHELL", "test \"$STATUS\" = healthy"}},
			"labels":      map[string]string{"literal$key": "value$literal"},
			"mem_limit":   json.Number("9007199254740993"),
		}},
	}
	before, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	c := config.Config{StateDirectory: state, DockerHost: "unix:///unavailable-test.sock", DockerBinary: "/unavailable/docker", ComposeBinary: script}
	if err := ComposeAction(t.Context(), c, "literal-test", root, original, "up", []string{"app"}, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `9007199254740993`) {
		t.Fatal("integer precision changed")
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	service := got["services"].(map[string]any)["app"].(map[string]any)
	wanted := map[string]any{"PASSWORD": "pa$$word", "LITERAL": "$${HOME}", "DOLLARS": "$$$$", "PATH": "$$PATH", "OTHER": "no dollars"}
	if !reflect.DeepEqual(service["environment"], wanted) {
		t.Fatalf("normalized environment would be reinterpolated: %#v", service["environment"])
	}
	if command := service["command"].([]any)[2]; command != `printf '%s' "$$PASSWORD"` {
		t.Fatalf("shell command would be reinterpolated: %s", command)
	}
	if health := service["healthcheck"].(map[string]any)["test"].([]any)[1]; health != `test "$$STATUS" = healthy` {
		t.Fatalf("healthcheck would be reinterpolated: %s", health)
	}
	labels := service["labels"].(map[string]any)
	if labels["literal$key"] != "value$$literal" {
		t.Fatal("label value or key changed incorrectly")
	}
	after, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("frozen normalized configuration was mutated")
	}
}
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

func TestComposeBuildUsesDisposableWritablePrivateDockerConfig(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	poison := filepath.Join(root, "inherited-config")
	t.Setenv("DOCKER_CONFIG", poison)
	t.Setenv("HOME", root)
	capture := filepath.Join(root, "observed-configs")
	plugin := filepath.Join(root, "compose")
	// Model Buildx writing its local state. A read-only executor root permits
	// these writes only in the administrator-owned operation directory.
	body := "#!/bin/sh\n[ -n \"$DOCKER_CONFIG\" ] || exit 42\n[ \"$HOME\" = /nonexistent ] || exit 43\n[ -d \"$DOCKER_CONFIG\" ] || exit 44\nprintf '%s\\n' \"$DOCKER_CONFIG\" >> " + shellQuote(capture) + "\nprintf 'builder-state' > \"$DOCKER_CONFIG/state\"\n"
	if err := os.WriteFile(plugin, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	c := config.Config{StateDirectory: state, DockerHost: "unix:///test.sock", DockerBinary: "/unavailable/docker", ComposeBinary: plugin}
	for i := 0; i < 2; i++ {
		if err := ComposeAction(t.Context(), c, "private-config", root, map[string]any{}, "build", []string{"app"}, &strings.Builder{}); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	paths := strings.Fields(string(data))
	if len(paths) != 2 || paths[0] == paths[1] {
		t.Fatalf("Docker config was reused between actions: %v", paths)
	}
	for _, name := range paths {
		if !strings.HasPrefix(name, state+string(filepath.Separator)) {
			t.Fatalf("Docker config escaped executor state: %s", name)
		}
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Fatalf("Docker config survived its operation: %v", err)
		}
	}
	if _, err := os.Stat(poison); !os.IsNotExist(err) {
		t.Fatalf("inherited config was used: %v", err)
	}
}
