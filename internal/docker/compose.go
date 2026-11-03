package docker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"gopkg.in/yaml.v3"
)

type ComposeInput struct {
	ProjectDirectory string   `json:"project_directory"`
	ProjectName      string   `json:"project_name"`
	Files            []string `json:"files"`
	Profiles         []string `json:"profiles,omitempty"`
}

type Issue struct {
	Component string `json:"component,omitempty"`
	Code      string `json:"code"`
	Message   string `json:"message"`
}
type Component struct {
	Name             string   `json:"name"`
	Image            string   `json:"image,omitempty"`
	BuildContext     string   `json:"build_context,omitempty"`
	EnvironmentNames []string `json:"environment_names,omitempty"`
	Mounts           []Mount  `json:"mounts"`
}
type ComposeReport struct {
	Input               ComposeInput `json:"input"`
	ConfigurationDigest string       `json:"configuration_digest"`
	Components          []Component  `json:"components"`
	Issues              []Issue      `json:"issues"`
	// Normalized may contain secrets. It is never serialized into user-visible output.
	Normalized    json.RawMessage   `json:"-"`
	PrivateInputs map[string][]byte `json:"-"`
}

type limitedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	free := b.limit - b.buffer.Len()
	if free > 0 {
		_, _ = b.buffer.Write(p[:min(free, n)])
	}
	if n > free {
		b.truncated = true
	}
	return n, nil
}

func command(c config.Config, ctx context.Context, dir string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, c.DockerBinary, append([]string{"--host", c.DockerHost}, args...)...)
	if len(args) > 0 && args[0] == "compose" && c.ComposeBinary != "" {
		cmd = exec.CommandContext(ctx, c.ComposeBinary, args[1:]...)
		// Some installations use one multicall executable behind docker-compose
		// symlinks. Preserve the plugin identity without trusting inherited PATH.
		cmd.Args[0] = "docker-compose"
	}
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin", "HOME=/nonexistent", "DOCKER_HOST=" + c.DockerHost, "COMPOSE_ANSI=never", "COMPOSE_INTERACTIVE_NO_CLI=1"}
	cmd.WaitDelay = 2 * time.Second
	return cmd
}

func ComposeVersion(ctx context.Context, c config.Config) (string, error) {
	cmd := command(c, ctx, "", "compose", "version", "--short")
	raw, err := cmd.Output()
	return strings.TrimSpace(string(raw)), err
}

func Normalize(ctx context.Context, c config.Config, input ComposeInput) (ComposeReport, error) {
	return normalize(ctx, c, input, nil)
}

// NormalizeWithComposeFiles uses immutable candidate bytes for every registered
// Compose file. Project-relative paths still resolve against the active project.
func NormalizeWithComposeFiles(ctx context.Context, c config.Config, input ComposeInput, overrides map[string][]byte) (ComposeReport, error) {
	if len(overrides) == 0 || len(overrides) != len(input.Files) {
		return ComposeReport{}, errors.New("candidate must supply every registered Compose file")
	}
	for name := range overrides {
		if name == ".env" || filepath.Clean(name) != name || !slices.Contains(input.Files, name) {
			return ComposeReport{}, errors.New("candidate Compose file is outside the registered file set")
		}
	}
	return normalize(ctx, c, input, overrides)
}

func normalize(ctx context.Context, c config.Config, input ComposeInput, overrides map[string][]byte) (ComposeReport, error) {
	report := ComposeReport{Input: input, Components: []Component{}, Issues: []Issue{}}
	if err := c.CheckPath(input.ProjectDirectory, false); err != nil {
		return report, err
	}
	if input.ProjectName == "" || strings.Trim(input.ProjectName, "abcdefghijklmnopqrstuvwxyz0123456789_-") != "" {
		return report, errors.New("explicit lowercase Compose project name is required")
	}
	if len(input.Files) == 0 {
		return report, errors.New("at least one explicit Compose file is required")
	}
	root, err := os.OpenRoot(input.ProjectDirectory)
	if err != nil {
		return report, err
	}
	defer root.Close()
	// Compose only reads frozen inputs. Reading the original YAML again after
	// preflight would allow a concurrent replacement to introduce env_file/include.
	frozen, err := os.MkdirTemp("", "ctfm-compose-")
	if err != nil {
		return report, err
	}
	defer os.RemoveAll(frozen)
	privateInputs := map[string][]byte{}
	frozenPaths := map[string]string{}
	freeze := func(name string) (string, error) {
		if strings.Contains(name, "$") {
			return "", errors.New("dynamic input paths are outside the MVP profile")
		}
		rel := name
		if filepath.IsAbs(name) {
			var err error
			rel, err = filepath.Rel(input.ProjectDirectory, name)
			if err != nil {
				return "", err
			}
		}
		if !filepath.IsLocal(rel) || rel == "." {
			return "", errors.New("Compose input is outside project")
		}
		original := filepath.Join(input.ProjectDirectory, rel)
		if previous, ok := frozenPaths[original]; ok {
			return previous, nil
		}
		f, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			return "", err
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() {
			return "", errors.New("Compose input must be a regular file")
		}
		data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
		if err != nil {
			return "", err
		}
		if len(data) > 1<<20 {
			return "", errors.New("Compose input exceeds 1 MiB")
		}
		if len(privateInputs) >= 128 {
			return "", errors.New("too many Compose file inputs")
		}
		privateInputs[original] = data
		p := filepath.Join(frozen, fmt.Sprintf("input-%d", len(privateInputs)))
		if err := os.WriteFile(p, data, 0600); err != nil {
			return "", err
		}
		frozenPaths[original] = p
		return p, nil
	}
	env, err := freeze(".env")
	if errors.Is(err, os.ErrNotExist) {
		env = filepath.Join(frozen, "empty.env")
		err = os.WriteFile(env, nil, 0600)
	}
	if err != nil {
		return report, err
	}
	args := []string{"compose", "--project-name", input.ProjectName, "--project-directory", input.ProjectDirectory, "--env-file", env}
	restorePaths := map[string]string{}
	for _, name := range input.Files {
		if !filepath.IsLocal(name) || name == "." || strings.Contains(name, "\\") {
			return report, errors.New("Compose file must be project-relative")
		}
		raw, overridden := overrides[name]
		if !overridden {
			raw, err = readComposeYAML(root, name)
			if err != nil {
				return report, err
			}
		}
		if len(raw) > 1<<20 {
			return report, errors.New("Compose file exceeds 1 MiB")
		}
		var document map[string]any
		if overridden {
			document, err = decodeCandidateCompose(raw)
			if err != nil {
				return report, fmt.Errorf("invalid or unsupported Compose YAML in %s", name)
			}
		} else if err := yaml.Unmarshal(raw, &document); err != nil {
			return report, fmt.Errorf("invalid Compose YAML in %s", name)
		}
		if err := preflightYAML(document, input.ProjectDirectory); err != nil {
			return report, err
		}
		services, _ := document["services"].(map[string]any)
		for _, rawService := range services {
			service, _ := rawService.(map[string]any)
			if files, ok := service["env_file"]; ok {
				if s, ok := files.(string); ok {
					files = []any{s}
				}
				items := files.([]any)
				for i, item := range items {
					p, _ := item.(string)
					object, isObject := item.(map[string]any)
					if isObject {
						p, _ = object["path"].(string)
					}
					frozenPath, err := freeze(p)
					if err != nil {
						return report, err
					}
					if isObject {
						object["path"] = frozenPath
					} else {
						items[i] = frozenPath
					}
				}
				service["env_file"] = items
			}
		}
		for _, section := range []string{"secrets", "configs"} {
			items, _ := document[section].(map[string]any)
			for _, value := range items {
				object, _ := value.(map[string]any)
				if p, ok := object["file"].(string); ok {
					frozenPath, err := freeze(p)
					if err != nil {
						return report, err
					}
					original := p
					if !filepath.IsAbs(original) {
						original = filepath.Join(input.ProjectDirectory, original)
					}
					restorePaths[frozenPath] = original
					object["file"] = frozenPath
				}
			}
		}
		encoded, err := yaml.Marshal(document)
		if err != nil {
			return report, err
		}
		file := filepath.Join(frozen, fmt.Sprintf("compose-%d.yaml", len(args)))
		if err := os.WriteFile(file, encoded, 0600); err != nil {
			return report, err
		}
		args = append(args, "--file", file)
	}
	for _, p := range input.Profiles {
		if p == "" || strings.Trim(p, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != "" {
			return report, errors.New("invalid profile")
		}
		args = append(args, "--profile", p)
	}
	args = append(args, "config", "--format", "json")
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := command(c, ctx, input.ProjectDirectory, args...)
	stdout := &limitedBuffer{limit: 8 << 20}
	stderr := &limitedBuffer{limit: 8192}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return report, fmt.Errorf("Compose normalization failed (details withheld because they may contain secrets): %w", err)
	}
	if stdout.truncated {
		return report, errors.New("normalized Compose exceeds 8 MiB")
	}
	var normalized map[string]any
	// Compose's renderer escapes dollars for round-tripping through another
	// Compose parse, even in JSON map keys. Store effective literal values so
	// inspection, secret freezing and configuration digests match the container.
	// ComposeAction re-escapes values only when emitting a new Compose input.
	literal := bytes.ReplaceAll(stdout.buffer.Bytes(), []byte("$$"), []byte("$"))
	if err := json.Unmarshal(literal, &normalized); err != nil {
		return report, errors.New("Compose returned invalid JSON")
	}
	for _, section := range []string{"secrets", "configs"} {
		items, _ := normalized[section].(map[string]any)
		for _, value := range items {
			object, _ := value.(map[string]any)
			if file, ok := object["file"].(string); ok {
				if original, ok := restorePaths[file]; ok {
					object["file"] = original
				}
			}
		}
	}
	if err := normalizeDeployLimits(normalized); err != nil {
		return report, err
	}
	report = Analyze(input, normalized)
	report.PrivateInputs = privateInputs
	return report, nil
}

func readComposeYAML(root *os.Root, name string) ([]byte, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("Compose YAML must be a regular file")
	}
	return io.ReadAll(io.LimitReader(f, (1<<20)+1))
}

func decodeCandidateCompose(raw []byte) (map[string]any, error) {
	var document map[string]any
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var node yaml.Node
	if err := decoder.Decode(&node); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&yaml.Node{}); err != io.EOF {
		return nil, errors.New("exactly one Compose YAML document is required")
	}
	if hasCustomYAMLTag(&node) {
		return nil, errors.New("custom Compose YAML tags are outside the candidate profile")
	}
	if err := node.Decode(&document); err != nil {
		return nil, err
	}
	return document, nil
}

func hasCustomYAMLTag(node *yaml.Node) bool {
	if node.Tag != "" && !strings.HasPrefix(node.Tag, "!!") {
		return true
	}
	return slices.ContainsFunc(node.Content, hasCustomYAMLTag)
}

func preflightYAML(doc map[string]any, root string) error {
	if _, ok := doc["include"]; ok {
		return errors.New("Compose include is outside the MVP profile")
	}
	services, _ := doc["services"].(map[string]any)
	for _, raw := range services {
		s, _ := raw.(map[string]any)
		for _, key := range []string{"extends", "post_start", "pre_stop", "provider"} {
			if _, ok := s[key]; ok {
				return fmt.Errorf("Compose %s is outside the MVP profile", key)
			}
		}
		if files, ok := s["env_file"]; ok {
			if str, ok := files.(string); ok {
				files = []any{str}
			}
			items, ok := files.([]any)
			if !ok {
				return errors.New("invalid env_file")
			}
			for _, item := range items {
				p, _ := item.(string)
				if object, ok := item.(map[string]any); ok {
					p, _ = object["path"].(string)
				}
				if p == "" {
					return errors.New("invalid env_file path")
				}
				absolute := p
				if !filepath.IsAbs(p) {
					absolute = filepath.Join(root, p)
				}
				rel, err := filepath.Rel(root, absolute)
				if err != nil || !filepath.IsLocal(rel) {
					return errors.New("env_file must stay within the registered project")
				}
			}
		}
	}
	// File-backed secrets/configs need immutable import, not arbitrary file reads by config.
	for _, section := range []string{"secrets", "configs"} {
		items, _ := doc[section].(map[string]any)
		for _, raw := range items {
			object, _ := raw.(map[string]any)
			if file, ok := object["file"].(string); ok {
				p := file
				if !filepath.IsAbs(p) {
					p = filepath.Join(root, p)
				}
				rel, err := filepath.Rel(root, p)
				if err != nil || !filepath.IsLocal(rel) {
					return fmt.Errorf("%s file must stay within project", section)
				}
			}
		}
	}
	return nil
}

// Analyze checks a normalized model without invoking Docker. It never exposes environment values.
func Analyze(input ComposeInput, doc map[string]any) ComposeReport {
	raw, _ := json.Marshal(doc)
	sum := sha256.Sum256(raw)
	r := ComposeReport{Input: input, ConfigurationDigest: "sha256:" + hex.EncodeToString(sum[:]), Components: []Component{}, Issues: []Issue{}, Normalized: raw}
	issue := func(component, code, message string) { r.Issues = append(r.Issues, Issue{component, code, message}) }
	services, _ := doc["services"].(map[string]any)
	if len(services) == 0 {
		issue("", "no_services", "no services found")
	}
	for name, value := range services {
		s, ok := value.(map[string]any)
		if !ok {
			issue(name, "invalid_service", "invalid component")
			continue
		}
		component := Component{Name: name, Mounts: []Mount{}}
		component.Image, _ = s["image"].(string)
		for _, key := range []string{"privileged", "devices", "device_cgroup_rules", "cap_add", "pid", "ipc", "uts", "cgroup_parent", "use_api_socket", "post_start", "pre_stop", "provider", "volumes_from", "gpus"} {
			if v, ok := s[key]; ok && v != nil && v != false {
				issue(name, "unsupported_privilege", key+" requires a profile outside MVP")
			}
		}
		if options, exists := s["security_opt"]; exists {
			items, ok := options.([]any)
			if !ok {
				issue(name, "unsupported_privilege", "invalid security_opt")
			} else {
				for _, item := range items {
					value, _ := item.(string)
					if value != "no-new-privileges:true" && value != "no-new-privileges=true" && value != "no-new-privileges" {
						issue(name, "unsupported_privilege", "security_opt is outside the no-new-privileges profile")
					}
				}
			}
		}
		if mode, _ := s["network_mode"].(string); mode != "" && mode != "none" && mode != "bridge" {
			issue(name, "unsupported_network_mode", "custom network namespaces are outside MVP")
		}
		if b, ok := s["build"].(map[string]any); ok {
			component.BuildContext, _ = b["context"].(string)
			if !filepath.IsAbs(component.BuildContext) {
				issue(name, "remote_context", "build context must be a local absolute path")
			} else if rel, err := filepath.Rel(input.ProjectDirectory, component.BuildContext); err != nil || !filepath.IsLocal(rel) && rel != "." {
				issue(name, "external_context", "build context must remain inside registered project")
			}
			for _, key := range []string{"additional_contexts", "entitlements", "ssh", "privileged", "network", "dockerfile_inline"} {
				if _, ok := b[key]; ok {
					issue(name, "unsupported_build", key+" is outside the initial build profile")
				}
			}
			if dockerfile, _ := b["dockerfile"].(string); dockerfile != "" && (!filepath.IsLocal(dockerfile) || strings.Contains(dockerfile, "\\")) {
				issue(name, "external_dockerfile", "Dockerfile must stay within the build context")
			}
		}
		if env, ok := s["environment"].(map[string]any); ok {
			for key := range env {
				component.EnvironmentNames = append(component.EnvironmentNames, key)
			}
			sort.Strings(component.EnvironmentNames)
		}
		if mounts, ok := s["volumes"].([]any); ok {
			for _, entry := range mounts {
				m, _ := entry.(map[string]any)
				kind, _ := m["type"].(string)
				source, _ := m["source"].(string)
				target, _ := m["target"].(string)
				ro, _ := m["read_only"].(bool)
				component.Mounts = append(component.Mounts, Mount{Type: kind, Source: source, Target: target, ReadOnly: ro})
				if kind == "volume" && source == "" {
					issue(name, "anonymous_volume", "anonymous volume must be classified or migrated before recreation")
				}
				if kind == "bind" && (!filepath.IsAbs(source) || !strings.HasPrefix(target, "/")) {
					issue(name, "invalid_bind", "bind source/target must be absolute")
				}
				if strings.HasSuffix(source, "docker.sock") {
					issue(name, "docker_socket_mount", "Docker socket cannot be mounted into managed services")
				}
			}
		}
		r.Components = append(r.Components, component)
	}
	if volumes, ok := doc["volumes"].(map[string]any); ok {
		for name, entry := range volumes {
			v, _ := entry.(map[string]any)
			if driver, _ := v["driver"].(string); driver != "" && driver != "local" {
				issue("", "volume_driver", "volume "+name+" uses unsupported driver")
			}
			if opts, ok := v["driver_opts"].(map[string]any); ok && len(opts) > 0 {
				issue("", "volume_driver_options", "custom volume driver options are outside MVP")
			}
		}
	}
	sort.Slice(r.Components, func(i, j int) bool { return r.Components[i].Name < r.Components[j].Name })
	sort.Slice(r.Issues, func(i, j int) bool {
		a, b := r.Issues[i], r.Issues[j]
		return a.Component+a.Code+a.Message < b.Component+b.Code+b.Message
	})
	return r
}
