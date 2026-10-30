package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/moby/moby/client"
)

// ComposeAction accepts only fixed application operations on executor-generated
// configuration. User requests never supply flags, commands, or filenames.
func ComposeAction(ctx context.Context, c config.Config, project, directory string, model map[string]any, action string, targets []string, output io.Writer) error {
	if len(targets) == 0 {
		return errors.New("explicit component targets are required")
	}
	for _, name := range append([]string{project}, targets...) {
		if name == "" || strings.Trim(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != "" || strings.HasPrefix(name, "-") {
			return errors.New("invalid Compose identifier")
		}
	}
	temp, err := os.MkdirTemp(c.StateDirectory, "compose-operation-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	data, err := marshalComposeModel(model)
	if err != nil {
		return err
	}
	file := filepath.Join(temp, "compose.json")
	if err := os.WriteFile(file, data, 0600); err != nil {
		return err
	}
	env := filepath.Join(temp, "empty.env")
	if err := os.WriteFile(env, nil, 0600); err != nil {
		return err
	}
	args := []string{"compose", "--progress", "plain", "--project-name", project, "--project-directory", directory, "--file", file, "--env-file", env}
	switch action {
	case "build":
		args = append(args, "build")
	case "up":
		args = append(args, "up", "--detach", "--no-build", "--pull", "never", "--no-deps", "--force-recreate")
	default:
		return errors.New("unsupported Compose action")
	}
	args = append(args, targets...)
	cmd := command(c, ctx, directory, args...)
	// Buildx persists local builder state even for the Docker driver. Keep that
	// state inside this private operation instead of HOME=/nonexistent or an
	// inherited Docker config which could contain credentials/plugin settings.
	dockerConfig := filepath.Join(temp, "docker-config")
	if err := os.Mkdir(dockerConfig, 0700); err != nil {
		return err
	}
	cmd.Env = append(cmd.Env, "DOCKER_CONFIG="+dockerConfig)
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Run(); err != nil {
		return errors.New("Compose action failed; inspect the bounded operation journal")
	}
	return nil
}

// Compose parses and interpolates this executor-generated file again. Values
// already came from `compose config`; escape dollars to preserve literal secret,
// command, healthcheck and label contents through that second parse. Keys are
// deliberately untouched. Decoding with UseNumber preserves integer precision.
func marshalComposeModel(model map[string]any) ([]byte, error) {
	encoded, err := json.Marshal(model)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var copy any
	if err := decoder.Decode(&copy); err != nil {
		return nil, err
	}
	return json.Marshal(escapeComposeValues(copy))
}
func escapeComposeValues(value any) any {
	switch v := value.(type) {
	case string:
		return strings.ReplaceAll(v, "$", "$$")
	case map[string]any:
		for key, value := range v {
			v[key] = escapeComposeValues(value)
		}
	case []any:
		for index, value := range v {
			v[index] = escapeComposeValues(value)
		}
	}
	return value
}
func (e *Engine) RetainImage(ctx context.Context, imageID, tag string) error {
	_, err := e.Client.ImageTag(ctx, client.ImageTagOptions{Source: imageID, Target: tag})
	return err
}
func (e *Engine) Stop(ctx context.Context, id string) error {
	seconds := 10
	_, err := e.Client.ContainerStop(ctx, id, client.ContainerStopOptions{Timeout: &seconds})
	return err
}
func (e *Engine) Start(ctx context.Context, id string) error {
	_, err := e.Client.ContainerStart(ctx, id, client.ContainerStartOptions{})
	return err
}
func (e *Engine) Restart(ctx context.Context, id string) error {
	seconds := 10
	_, err := e.Client.ContainerRestart(ctx, id, client.ContainerRestartOptions{Timeout: &seconds})
	return err
}
