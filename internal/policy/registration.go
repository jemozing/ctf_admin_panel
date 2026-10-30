// Package policy validates administrator-approved registrations against normalized
// Compose and a fresh Docker inventory. It performs no Docker calls or mutations.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"syscall"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

// Issue is a blocking diagnostic. Messages contain no environment/command values.
type Issue struct {
	Component string `json:"component,omitempty"`
	Code      string `json:"code"`
	Path      string `json:"path,omitempty"`
	Message   string `json:"message"`
}

// RegistrationError preserves all deterministic diagnostics for CLI/API callers.
type RegistrationError struct {
	Issues []Issue `json:"issues"`
}

func (e *RegistrationError) Error() string {
	return fmt.Sprintf("registration rejected: %d blocking issue(s)", len(e.Issues))
}

// ValidateRegistration checks the current observation and confines web-proposed
// paths to bootstrap roots. Call again immediately before approving a proposal.
func ValidateRegistration(c config.Config, service domain.Service, report docker.ComposeReport, containers []docker.Container) error {
	issues := RegistrationIssues(c, service, report, containers)
	if len(issues) == 0 {
		return nil
	}
	return &RegistrationError{Issues: issues}
}

// RegistrationIssues is the diagnostic form of ValidateRegistration. All returned
// issues block approval. Private executor inspection evidence is required;
// a public inventory DTO cannot authorize a registration.
func RegistrationIssues(c config.Config, service domain.Service, report docker.ComposeReport, containers []docker.Container) []Issue {
	issues := []Issue{}
	add := func(component, code, path, message string) {
		issues = append(issues, Issue{Component: component, Code: code, Path: path, Message: message})
	}
	if err := c.Validate(); err != nil {
		add("", "invalid_bootstrap", "", "executor bootstrap does not satisfy the local profile")
		return issues
	}
	if err := service.Validate(); err != nil {
		add("", "invalid_service", "", err.Error())
		return issues
	}
	if !c.Development && c.WebUID == 0 {
		add("", "privileged_web_uid", "", "production web process must have an unprivileged UID")
	}
	for _, item := range []struct {
		name      string
		path      string
		workspace bool
	}{{"project", service.ProjectDirectory, false}, {"workspace", service.SourceDirectory, true}} {
		if err := c.CheckPath(item.path, item.workspace); err != nil {
			add("", "unapproved_"+item.name, item.path, "directory must exist inside the approved root without symbolic-link aliases")
		} else if err := stableParents(c, item.path); err != nil {
			add("", "unstable_"+item.name+"_parent", item.path, err.Error())
		}
	}
	for _, relative := range service.ComposeFiles {
		absolute := filepath.Join(service.ProjectDirectory, relative)
		if err := regularProjectEntry(absolute); err != nil {
			add("", "unsafe_compose_path", relative, "Compose file must be an existing regular file without symbolic-link aliases")
		}
	}
	for _, managed := range service.ManagedPaths {
		active := filepath.Join(service.ProjectDirectory, managed.Path)
		if err := canonicalEntry(active); err != nil {
			add("", "unsafe_managed_path", managed.Path, "managed root must exist without symbolic-link aliases or special files")
		}
		// The workspace may be populated from the baseline after registration.
		// Existing parents must still be checked when the final entry is absent.
		if err := safeWorkspaceEntry(service.SourceDirectory, managed.Path); err != nil {
			add("", "unsafe_workspace_entry", managed.Path, "workspace entry or existing parent is a symbolic-link alias, special file, or unreadable")
		}
	}
	if report.Input.ProjectDirectory != service.ProjectDirectory || report.Input.ProjectName != service.ComposeProject || !slices.Equal(report.Input.Files, service.ComposeFiles) || !slices.Equal(report.Input.Profiles, service.Profiles) {
		add("", "compose_input_mismatch", "", "Compose input differs from the approved project, files, or profiles")
	}
	// Re-analyze the normalized document to prevent an incomplete/fabricated issue
	// list from approving privileges omitted from the report's public projection.
	var document map[string]any
	if len(report.Normalized) == 0 || json.Unmarshal(report.Normalized, &document) != nil || document == nil {
		add("", "missing_normalization", "", "normalized Compose model is required for approval")
	} else {
		if name, _ := document["name"].(string); name != service.ComposeProject {
			add("", "normalized_project_mismatch", "", "normalized Compose project name differs from registration")
		}
		checked := docker.Analyze(report.Input, document)
		if checked.ConfigurationDigest != report.ConfigurationDigest || domain.Digest(report.ConfigurationDigest).Validate() != nil {
			add("", "configuration_digest_mismatch", "", "normalized configuration does not match its digest")
		}
		if !reflect.DeepEqual(checked.Components, report.Components) {
			add("", "component_projection_mismatch", "", "component projection differs from the normalized Compose model")
		}
		for _, issue := range checked.Issues {
			add(issue.Component, "compose_"+issue.Code, "", issue.Message)
		}
	}
	for _, issue := range report.Issues {
		add(issue.Component, "compose_"+issue.Code, "", issue.Message)
	}

	registered := map[string]domain.ContainerRef{}
	for _, container := range service.Containers {
		registered[container.Component] = container
	}
	compose := map[string]docker.Component{}
	for _, component := range report.Components {
		if _, duplicate := compose[component.Name]; duplicate {
			add(component.Name, "duplicate_compose_component", "", "Compose component occurs more than once")
		}
		compose[component.Name] = component
		if _, exists := registered[component.Name]; !exists {
			add(component.Name, "unregistered_compose_component", "", "every Compose component must be explicitly registered")
		}
	}
	observed := map[string]docker.Container{}
	for _, container := range containers {
		if _, duplicate := observed[container.Component]; duplicate {
			add(container.Component, "duplicate_runtime_component", "", "replicas and duplicate runtime components are outside the initial profile")
		}
		observed[container.Component] = container
		ref, exists := registered[container.Component]
		if !exists {
			add(container.Component, "unregistered_runtime_component", "", "runtime inventory contains an unregistered component")
			continue
		}
		if container.Project != service.ComposeProject {
			add(container.Component, "project_label_mismatch", "", "runtime Compose project label differs from registration")
		}
		if container.ID != ref.ID {
			add(container.Component, "container_id_mismatch", "", "full runtime container ID differs from registration")
		}
		if container.ImageID != string(ref.ImageID) {
			add(container.Component, "image_id_mismatch", "", "immutable runtime image ID differs from registration")
		}
		for _, issue := range container.RuntimeIssues(document, service.ComposeProject) {
			add(issue.Component, issue.Code, "", issue.Message)
		}
	}
	for name := range registered {
		if _, ok := compose[name]; !ok {
			add(name, "missing_compose_component", "", "registered component is absent from normalized Compose")
		}
		if _, ok := observed[name]; !ok {
			add(name, "missing_runtime_component", "", "registered component is absent from fresh runtime inventory")
		}
	}

	dataByTarget := map[string]domain.DataPath{}
	layers := map[string]int{}
	for _, data := range service.DataPaths {
		if data.Kind == domain.StorageWritableLayer {
			layers[data.Component]++
			continue
		}
		key := data.Component + "\x00" + data.Target
		if _, duplicate := dataByTarget[key]; duplicate {
			add(data.Component, "duplicate_storage_target", data.Target, "a mount target must have exactly one storage classification")
		}
		dataByTarget[key] = data
	}
	for component := range registered {
		if layers[component] == 0 {
			add(component, "unclassified_writable_layer", "", "every component needs an explicit disposable writable-layer declaration after significant data is externalized")
		}
	}
	volumeNames := composeVolumeNames(document, service.ComposeProject)
	usedData := map[string]bool{}
	writableBinds := []docker.Mount{}
	for _, container := range containers {
		for _, mount := range container.Mounts {
			if mount.Type == "bind" && !mount.ReadOnly {
				writableBinds = append(writableBinds, mount)
			}
		}
	}
	for component, container := range observed {
		model, exists := compose[component]
		if !exists {
			continue
		}
		expected := map[string]docker.Mount{}
		for _, mount := range model.Mounts {
			if _, duplicate := expected[mount.Target]; duplicate {
				add(component, "duplicate_compose_mount", mount.Target, "Compose mount targets must be unique")
			}
			expected[mount.Target] = mount
		}
		actual := map[string]bool{}
		for _, mount := range container.Mounts {
			if domain.ValidateAbsolutePath(mount.Target) != nil {
				add(component, "invalid_runtime_mount_target", mount.Target, "runtime mount target must be canonical, absolute, and below container root")
			}
			if actual[mount.Target] {
				add(component, "duplicate_runtime_mount", mount.Target, "runtime mount targets must be unique")
			}
			actual[mount.Target] = true
			planned, exists := expected[mount.Target]
			if !exists {
				add(component, "runtime_mount_not_in_compose", mount.Target, "runtime mount is absent from Compose; image-declared volumes need explicit preservation mapping")
			} else if !sameMount(planned, mount, volumeNames) {
				add(component, "runtime_mount_mismatch", mount.Target, "mount type, source identity, or read-only mode differs from normalized Compose")
			}
			key := component + "\x00" + mount.Target
			data, classified := dataByTarget[key]
			if classified && storageMatches(data, mount) {
				usedData[key] = true
			} else if classified {
				add(component, "storage_identity_mismatch", mount.Target, "registered storage identity differs from the runtime mount")
			} else if mount.Type != "bind" || !managedBind(service, mount.Source) {
				add(component, "unclassified_runtime_mount", mount.Target, "mount must be exact approved managed code/config or explicitly classified storage")
			}
			switch mount.Type {
			case "bind":
				if err := approvedBind(c, mount.Source); err != nil {
					add(component, "unsafe_bind_source", mount.Source, err.Error())
				}
				if sensitiveHostPath(c, mount.Source) || mount.Target == "/run/docker.sock" || mount.Target == "/var/run/docker.sock" {
					add(component, "sensitive_host_mount", mount.Source, "host control paths, executor state, and Docker sockets cannot be mounted")
				}
				if domain.PathsOverlap(service.SourceDirectory, mount.Source) {
					add(component, "workspace_mount_overlap", mount.Source, "source workspace must remain outside every game bind mount")
				}
				for _, other := range writableBinds {
					if within(other.Source, filepath.Dir(mount.Source)) {
						add(component, "game_writable_bind_parent", mount.Source, "bind source parent lies inside a writable game mount")
					}
				}
			case "volume", "tmpfs":
			default:
				add(component, "unsupported_runtime_mount", mount.Target, "runtime mount type is outside the initial profile")
			}
		}
		for target := range expected {
			if !actual[target] {
				add(component, "missing_runtime_mount", target, "Compose mount is absent from runtime inventory")
			}
		}
	}
	for key, data := range dataByTarget {
		if !usedData[key] {
			add(data.Component, "unobserved_storage", data.Target, "registered storage must match a mount in the fresh runtime inventory")
		}
	}
	return sortedUnique(issues)
}

func sortedUnique(issues []Issue) []Issue {
	sort.Slice(issues, func(i, j int) bool {
		a, b := issues[i], issues[j]
		return a.Component+"\x00"+a.Code+"\x00"+a.Path+"\x00"+a.Message < b.Component+"\x00"+b.Code+"\x00"+b.Path+"\x00"+b.Message
	})
	return slices.Compact(issues)
}

func composeVolumeNames(document map[string]any, project string) map[string]string {
	out := map[string]string{}
	volumes, _ := document["volumes"].(map[string]any)
	for logical, raw := range volumes {
		value, _ := raw.(map[string]any)
		actual, _ := value["name"].(string)
		if actual == "" {
			actual = project + "_" + logical
		}
		out[logical] = actual
	}
	return out
}

func sameMount(expected, actual docker.Mount, volumeNames map[string]string) bool {
	if expected.Type != actual.Type || expected.Target != actual.Target || expected.ReadOnly != actual.ReadOnly {
		return false
	}
	source := expected.Source
	if expected.Type == "volume" && source != "" {
		if resolved, ok := volumeNames[source]; ok {
			source = resolved
		}
	}
	return expected.Type == "tmpfs" || expected.Type == "volume" && source == "" || source == actual.Source
}

func storageMatches(data domain.DataPath, actual docker.Mount) bool {
	switch data.Kind {
	case domain.StorageBind:
		return actual.Type == "bind" && data.Source == actual.Source
	case domain.StorageNamedVolume, domain.StorageAnonymousVolume:
		return actual.Type == "volume" && data.Source != "" && data.Source == actual.Source
	case domain.StorageTmpfs:
		return actual.Type == "tmpfs"
	}
	return false
}

func managedBind(service domain.Service, source string) bool {
	for _, managed := range service.ManagedPaths {
		if source == filepath.Join(service.ProjectDirectory, managed.Path) {
			return true
		}
	}
	return false
}

func canonicalEntry(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return fmt.Errorf("path must exist without symbolic-link aliases")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() && !info.IsDir() {
		return fmt.Errorf("path must be a regular file or directory")
	}
	return nil
}

// A missing final workspace file is allowed, but a symlink in an existing
// ancestor must not hide behind ENOENT from the final lookup.
func safeWorkspaceEntry(root, relative string) error {
	current := root
	parts := strings.Split(relative, string(filepath.Separator))
	for i, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("unsafe workspace path")
		}
		if i < len(parts)-1 && !info.IsDir() || !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("workspace parent must be a directory and leaf must be a regular file or directory")
		}
	}
	return nil
}

func regularProjectEntry(path string) error {
	if err := canonicalEntry(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("regular file required")
	}
	return nil
}

func approvedBind(c config.Config, path string) error {
	if domain.ValidateAbsolutePath(path) != nil || canonicalEntry(path) != nil {
		return fmt.Errorf("bind source must exist without symbolic-link aliases or special files")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("bind source changed while being inspected")
	}
	check := path
	if !info.IsDir() {
		check = filepath.Dir(path)
	}
	if c.CheckPath(check, false) != nil {
		return fmt.Errorf("bind source must be inside an administrator-approved discovery root")
	}
	return stableParents(c, path)
}

func stableParents(c config.Config, path string) error {
	// Development mode can be tested under OS temporary roots. It deliberately
	// does not claim production ownership isolation or trusted parent metadata.
	if c.Development {
		return nil
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("host parent directories must exist without symbolic links")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode().Perm()&0022 != 0 || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) || stat.Uid == uint32(c.WebUID) {
			return fmt.Errorf("host parent directories must be root/executor-owned and not writable by web, group, or others")
		}
		if parent == string(filepath.Separator) {
			return nil
		}
	}
}

func sensitiveHostPath(c config.Config, source string) bool {
	for _, forbidden := range []string{"/proc", "/sys", "/dev", "/run", "/var/run", "/etc", "/root", "/boot", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/var/lib/docker", "/var/lib/containerd", c.StateDirectory, c.Socket, c.DockerBinary, c.ComposeBinary} {
		if forbidden != "" && domain.PathsOverlap(source, forbidden) {
			return true
		}
	}
	return source == "/" || strings.HasSuffix(source, "/docker.sock")
}

func within(root, child string) bool {
	return root != "" && child != "" && (root == child || strings.HasPrefix(child, root+string(filepath.Separator)))
}
