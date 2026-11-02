package domain

import (
	"fmt"
	"path"
	"strings"
)

type ManagedKind string

const (
	ManagedCode   ManagedKind = "code"
	ManagedConfig ManagedKind = "configuration"
)

// Path maps the same relative path in SourceDirectory and ProjectDirectory.
// Exclusions are literal paths relative to Path, not globs.
type ManagedPath struct {
	Path       string      `json:"path"`
	Kind       ManagedKind `json:"kind"`
	Exclusions []string    `json:"exclusions,omitempty"`
}

type StorageKind string

const (
	StorageBind            StorageKind = "bind"
	StorageNamedVolume     StorageKind = "named_volume"
	StorageAnonymousVolume StorageKind = "anonymous_volume"
	StorageWritableLayer   StorageKind = "writable_layer"
	StorageTmpfs           StorageKind = "tmpfs"
)

// Source is an absolute host path for bind storage and the actual Docker volume
// name for volumes. Target is the absolute path inside Component's container.
type DataPath struct {
	Name         string      `json:"name"`
	Kind         StorageKind `json:"kind"`
	Source       string      `json:"source,omitempty"`
	Target       string      `json:"target"`
	Component    string      `json:"component"`
	Significant  bool        `json:"significant"`
	LossAccepted bool        `json:"loss_accepted"`
	// Explicitly permits managed code inside this disposable bind. It never
	// authorizes source-workspace overlap or access outside the active project.
	AllowCodeUpdates bool `json:"allow_code_updates,omitempty"`
	SharedResource   ID   `json:"shared_resource,omitempty"`
}

type ComponentRole string

const (
	RoleApplication ComponentRole = "application"
	RoleDatabase    ComponentRole = "database"
	RoleCache       ComponentRole = "cache"
	RoleAuxiliary   ComponentRole = "auxiliary"
)

type ContainerRef struct {
	Component string        `json:"component"`
	ID        string        `json:"id"`
	ImageID   Digest        `json:"image_id"`
	Role      ComponentRole `json:"role"`
}

// Service is executor-owned registration policy. Runtime observations are separate.
// This value becomes trusted after administrator approval of its immutable digest.
type Service struct {
	SchemaVersion    int                `json:"schema_version"`
	ID               ID                 `json:"id"`
	Name             string             `json:"name"`
	Description      string             `json:"description,omitempty"`
	ProjectDirectory string             `json:"project_directory"`
	SourceDirectory  string             `json:"source_directory"`
	ComposeProject   string             `json:"compose_project"`
	ComposeFiles     []string           `json:"compose_files"`
	Profiles         []string           `json:"profiles,omitempty"`
	ManagedPaths     []ManagedPath      `json:"managed_paths"`
	DataPaths        []DataPath         `json:"data_paths,omitempty"`
	Targets          []string           `json:"targets"`
	Containers       []ContainerRef     `json:"containers"`
	PolicyRevision   uint64             `json:"policy_revision"`
	FileMapRevision  uint64             `json:"file_map_revision"`
	SecretVersions   []SecretVersionRef `json:"secret_versions,omitempty"`
	Checks           []HTTPCheck        `json:"checks,omitempty"`
}

func (s Service) Validate() error {
	if s.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported service schema version %d", s.SchemaVersion)
	}
	if err := s.ID.Validate(); err != nil {
		return err
	}
	if err := validateText(s.Name, "service name", 128); err != nil {
		return err
	}
	if err := ValidateAbsolutePath(s.ProjectDirectory); err != nil {
		return fmt.Errorf("project directory: %w", err)
	}
	if err := ValidateAbsolutePath(s.SourceDirectory); err != nil {
		return fmt.Errorf("source directory: %w", err)
	}
	if PathsOverlap(s.ProjectDirectory, s.SourceDirectory) {
		return fmt.Errorf("source workspace and active project must not overlap")
	}
	if !idPattern.MatchString(s.ComposeProject) {
		return fmt.Errorf("invalid Compose project name")
	}
	if s.PolicyRevision == 0 || s.FileMapRevision == 0 {
		return fmt.Errorf("policy and file map revisions must be positive")
	}
	if len(s.ComposeFiles) == 0 || len(s.ManagedPaths) == 0 || len(s.Targets) == 0 || len(s.Containers) == 0 {
		return fmt.Errorf("compose files, managed paths, targets and containers are required")
	}
	if err := uniquePaths(s.ComposeFiles); err != nil {
		return fmt.Errorf("compose files: %w", err)
	}
	seenProfiles := map[string]bool{}
	for _, profile := range s.Profiles {
		if err := validateComponent(profile); err != nil {
			return err
		}
		if seenProfiles[profile] {
			return fmt.Errorf("duplicate profile %q", profile)
		}
		seenProfiles[profile] = true
	}
	for i, item := range s.ManagedPaths {
		if err := ValidateRelativePath(item.Path); err != nil {
			return err
		}
		if item.Kind != ManagedCode && item.Kind != ManagedConfig {
			return fmt.Errorf("unclassified managed path %q", item.Path)
		}
		if err := uniquePaths(item.Exclusions); err != nil {
			return fmt.Errorf("exclusions: %w", err)
		}
		for _, previous := range s.ManagedPaths[:i] {
			if PathsOverlap(item.Path, previous.Path) {
				return fmt.Errorf("managed paths %q and %q overlap", item.Path, previous.Path)
			}
		}
	}
	components := map[string]bool{}
	containerIDs := map[string]bool{}
	for _, container := range s.Containers {
		if err := validateComponent(container.Component); err != nil {
			return err
		}
		if components[container.Component] {
			return fmt.Errorf("duplicate component %q; replicas are not supported in the initial profile", container.Component)
		}
		components[container.Component] = true
		if len(container.ID) != 64 || Digest("sha256:"+container.ID).Validate() != nil {
			return fmt.Errorf("container ID must be the full lowercase Docker ID")
		}
		if containerIDs[container.ID] {
			return fmt.Errorf("duplicate container ID")
		}
		containerIDs[container.ID] = true
		if err := container.ImageID.Validate(); err != nil {
			return fmt.Errorf("container image: %w", err)
		}
		switch container.Role {
		case RoleApplication, RoleDatabase, RoleCache, RoleAuxiliary:
		default:
			return fmt.Errorf("unclassified component %q", container.Component)
		}
	}
	seenTargets := map[string]bool{}
	for _, target := range s.Targets {
		if !components[target] || seenTargets[target] {
			return fmt.Errorf("unknown or duplicate update target %q", target)
		}
		seenTargets[target] = true
	}
	dataNames := map[string]bool{}
	for _, data := range s.DataPaths {
		if err := validateComponent(data.Name); err != nil {
			return err
		}
		if dataNames[data.Name] || !components[data.Component] {
			return fmt.Errorf("duplicate data name or unknown component for %q", data.Name)
		}
		dataNames[data.Name] = true
		if err := ValidateAbsolutePath(data.Target); err != nil {
			return fmt.Errorf("storage target: %w", err)
		}
		if data.SharedResource != "" {
			if err := data.SharedResource.Validate(); err != nil {
				return err
			}
		}
		if data.Significant && data.LossAccepted {
			return fmt.Errorf("significant data %q cannot be declared disposable", data.Name)
		}
		if data.AllowCodeUpdates {
			if data.Kind != StorageBind || data.Significant || !data.LossAccepted {
				return fmt.Errorf("storage %q requires a disposable bind with explicit loss acceptance for code updates", data.Name)
			}
			if !seenTargets[data.Component] {
				return fmt.Errorf("code bind %q requires its component %q to be an update target", data.Name, data.Component)
			}
			if data.Source != s.ProjectDirectory && !strings.HasPrefix(data.Source, s.ProjectDirectory+"/") {
				return fmt.Errorf("code bind %q must remain inside the active project", data.Name)
			}
		}
		switch data.Kind {
		case StorageBind:
			if err := ValidateAbsolutePath(data.Source); err != nil {
				return err
			}
			if PathsOverlap(s.SourceDirectory, data.Source) {
				return fmt.Errorf("source workspace overlaps data mount %q", data.Name)
			}
			for _, managed := range s.ManagedPaths {
				active := path.Join(s.ProjectDirectory, managed.Path)
				if PathsOverlap(active, data.Source) && !data.AllowCodeUpdates {
					return fmt.Errorf("managed path overlaps persistent bind %q", data.Name)
				}
			}
		case StorageNamedVolume:
			if err := validateText(data.Source, "actual volume name", 255); err != nil {
				return err
			}
			if !volumePattern.MatchString(data.Source) {
				return fmt.Errorf("invalid actual volume name")
			}
		case StorageAnonymousVolume:
			return fmt.Errorf("anonymous volume %q is unsupported for managed recreation in the initial profile", data.Name)
		case StorageWritableLayer, StorageTmpfs:
			if data.Significant || !data.LossAccepted {
				return fmt.Errorf("storage %q blocks recreation until significant data is migrated or loss explicitly accepted", data.Name)
			}
			if data.Source != "" {
				return fmt.Errorf("volatile storage has no host source")
			}
		default:
			return fmt.Errorf("unclassified storage %q", data.Name)
		}
	}
	if len(s.Checks) > 16 {
		return fmt.Errorf("at most 16 local checks are supported")
	}
	checks := map[ID]bool{}
	for _, check := range s.Checks {
		if err := check.Validate(); err != nil {
			return err
		}
		if checks[check.ID] {
			return fmt.Errorf("duplicate check ID")
		}
		checks[check.ID] = true
	}
	return validateSecrets(s.SecretVersions)
}

func uniquePaths(values []string) error {
	seen := map[string]bool{}
	for _, value := range values {
		if err := ValidateRelativePath(value); err != nil {
			return err
		}
		if seen[value] {
			return fmt.Errorf("duplicate path %q", value)
		}
		seen[value] = true
	}
	return nil
}

// Conflicts reports independent registrations which must be rejected. Explicitly
// shared data stores are not registrations of the same project; operations lock them.
func (s Service) Conflicts(other Service) bool {
	if s.ID == other.ID || s.ComposeProject == other.ComposeProject {
		return true
	}
	for _, left := range s.ManagedPaths {
		for _, right := range other.ManagedPaths {
			if PathsOverlap(path.Join(s.ProjectDirectory, left.Path), path.Join(other.ProjectDirectory, right.Path)) {
				return true
			}
		}
	}
	for _, left := range s.DataPaths {
		if left.Kind == StorageBind {
			if PathsOverlap(left.Source, other.SourceDirectory) {
				return true
			}
			for _, managed := range other.ManagedPaths {
				if PathsOverlap(left.Source, path.Join(other.ProjectDirectory, managed.Path)) {
					return true
				}
			}
		}
		for _, right := range other.DataPaths {
			shared := left.Kind == StorageNamedVolume && right.Kind == StorageNamedVolume && left.Source == right.Source
			shared = shared || left.Kind == StorageBind && right.Kind == StorageBind && PathsOverlap(left.Source, right.Source)
			if shared && (left.SharedResource == "" || left.SharedResource != right.SharedResource) {
				return true
			}
		}
	}
	for _, right := range other.DataPaths {
		if right.Kind == StorageBind {
			if PathsOverlap(right.Source, s.SourceDirectory) {
				return true
			}
			for _, managed := range s.ManagedPaths {
				if PathsOverlap(right.Source, path.Join(s.ProjectDirectory, managed.Path)) {
					return true
				}
			}
		}
	}
	return PathsOverlap(s.SourceDirectory, other.SourceDirectory) || PathsOverlap(s.SourceDirectory, other.ProjectDirectory) || PathsOverlap(other.SourceDirectory, s.ProjectDirectory)
}
