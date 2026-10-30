package executor

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/filesystem"
	"github.com/ctf-service-manager/ctf-service-manager/internal/jobs"
	"github.com/ctf-service-manager/ctf-service-manager/internal/storage"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"github.com/moby/moby/client"
)

func registrationInvalid(message string) error {
	return &transport.RegistrationInputError{Message: message}
}

func (m *Manager) RegistrationOptions(context.Context) (transport.RegistrationOptions, error) {
	return transport.RegistrationOptions{DiscoveryRoots: append([]string{}, m.Config.DiscoveryRoots...), WorkspaceRoots: append([]string{}, m.Config.WorkspaceRoots...)}, nil
}

// InspectRegistration reads only a selected approved directory and matching
// Compose labels. It neither starts containers nor returns the normalized model
// (which may contain secrets). The immutable draft binds identity to discovery.
func (m *Manager) InspectRegistration(ctx context.Context, input transport.RegistrationInspectRequest) (transport.RegistrationInspection, error) {
	var result transport.RegistrationInspection
	if err := m.Config.CheckPath(input.ProjectDirectory, false); err != nil {
		return result, registrationInvalid("Project directory must exist within an approved discovery root without symbolic links")
	}
	projects, err := m.Engine.Client.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("label", "com.docker.compose.project")})
	if err != nil {
		return result, err
	}
	var project string
	var files, profiles []string
	for _, item := range projects.Items {
		if item.Labels["com.docker.compose.project.working_dir"] != input.ProjectDirectory || item.Labels["com.docker.compose.oneoff"] == "True" {
			continue
		}
		name := item.Labels["com.docker.compose.project"]
		selected, err := registrationComposeFiles(input.ProjectDirectory, item.Labels["com.docker.compose.project.config_files"])
		if err != nil {
			return result, err
		}
		selectedProfiles := []string{}
		if value := item.Labels["com.docker.compose.project.profiles"]; value != "" {
			selectedProfiles = strings.Split(value, ",")
			sort.Strings(selectedProfiles)
		}
		if project != "" && (project != name || !reflect.DeepEqual(files, selected) || !reflect.DeepEqual(profiles, selectedProfiles)) {
			return result, registrationInvalid("Directory has ambiguous Compose project, files or profiles; resolve Docker label conflicts before registration")
		}
		project, files, profiles = name, selected, selectedProfiles
	}
	if project == "" {
		return result, registrationInvalid("No existing Compose containers match this directory. Start the service using its Compose project before importing it")
	}
	report, err := docker.Normalize(ctx, m.Config, docker.ComposeInput{ProjectDirectory: input.ProjectDirectory, ProjectName: project, Files: files, Profiles: profiles})
	if err != nil {
		return result, registrationInvalid("Compose configuration could not be safely normalized; verify the selected path and supported Compose profile")
	}
	containers, err := m.Engine.Inventory(ctx, project)
	if err != nil {
		return result, err
	}
	if len(containers) == 0 {
		return result, registrationInvalid("Compose project has no containers to import")
	}
	id := NewID("service-")
	service := domain.Service{SchemaVersion: domain.SchemaVersion, ID: id, Name: project, ProjectDirectory: input.ProjectDirectory, SourceDirectory: filepath.Join(m.Config.WorkspaceRoots[0], string(id)), ComposeProject: project, ComposeFiles: files, Profiles: profiles, PolicyRevision: 1, FileMapRevision: 1, ManagedPaths: []domain.ManagedPath{}, DataPaths: []domain.DataPath{}, Targets: []string{}, Containers: []domain.ContainerRef{}}
	warnings := []string{"Review component roles, managed code and every storage declaration. Writable-layer loss requires explicit acknowledgement; significant game data must be externalized."}
	for _, issue := range report.Issues {
		warnings = append(warnings, issue.Code+": "+issue.Message)
	}
	components := map[string]docker.Component{}
	for _, component := range report.Components {
		components[component.Name] = component
	}
	dataBinds := []string{}
	for index, c := range containers {
		role := suggestRegistrationRole(c.Component, components[c.Component].Image)
		service.Containers = append(service.Containers, domain.ContainerRef{Component: c.Component, ID: c.ID, ImageID: domain.Digest(c.ImageID), Role: role})
		if role == domain.RoleApplication {
			service.Targets = append(service.Targets, c.Component)
		}
		// Leave loss unacknowledged in the draft; discovery cannot decide whether
		// flags or other significant data live in the writable container layer.
		service.DataPaths = append(service.DataPaths, domain.DataPath{Name: fmt.Sprintf("layer-%d", index), Kind: domain.StorageWritableLayer, Component: c.Component, Target: "/ctfm-writable-layer", Significant: false, LossAccepted: false})
		for mountIndex, mount := range c.Mounts {
			if mount.Type == "bind" && mount.ReadOnly && withinProject(input.ProjectDirectory, mount.Source) && !sensitiveRegistrationName(filepath.Base(mount.Source)) {
				continue
			}
			data := domain.DataPath{Name: fmt.Sprintf("mount-%d-%d", index, mountIndex), Component: c.Component, Source: mount.Source, Target: mount.Target, Significant: true}
			switch mount.Type {
			case "bind":
				data.Kind = domain.StorageBind
				dataBinds = append(dataBinds, mount.Source)
			case "volume":
				data.Kind = domain.StorageNamedVolume
			case "tmpfs":
				data.Kind = domain.StorageTmpfs
				data.Source = ""
				data.Significant = false
			default:
				warnings = append(warnings, "Unsupported storage type in "+c.Component)
				continue
			}
			service.DataPaths = append(service.DataPaths, data)
		}
	}
	service.ManagedPaths, err = registrationManagedPaths(input.ProjectDirectory, files, dataBinds)
	if err != nil {
		return result, err
	}
	if len(service.Targets) == 0 {
		warnings = append(warnings, "No application update target was inferred. Select at least one application component explicitly.")
	}
	if len(service.ManagedPaths) == 0 {
		warnings = append(warnings, "No safe managed code paths were inferred. Add explicit code/configuration paths excluding game data.")
	}
	if err := m.Store.PutImmutable(ctx, "web_registration_draft", id, id, service); err != nil {
		return result, err
	}
	result.Service, result.Warnings = service, warnings
	return result, nil
}

func registrationComposeFiles(directory, raw string) ([]string, error) {
	if raw == "" {
		return nil, registrationInvalid("Compose config_files label is missing; import requires the original explicit Compose files")
	}
	files := []string{}
	seen := map[string]bool{}
	for _, value := range strings.Split(raw, ",") {
		if !filepath.IsAbs(value) {
			return nil, registrationInvalid("Compose config_files labels must contain absolute paths")
		}
		relative, err := filepath.Rel(directory, value)
		if err != nil || domain.ValidateRelativePath(relative) != nil {
			return nil, registrationInvalid("Compose files must remain inside the selected project directory")
		}
		if seen[relative] {
			return nil, registrationInvalid("Compose file labels contain duplicates")
		}
		seen[relative] = true
		files = append(files, relative)
	}
	return files, nil
}
func withinProject(root, name string) bool {
	return root == name || strings.HasPrefix(name, root+string(filepath.Separator))
}
func sensitiveRegistrationName(name string) bool {
	n := strings.ToLower(name)
	return strings.HasPrefix(n, ".") || n == "secrets" || n == "secret" || n == "data" || n == "db" || n == "database" || n == "volumes" || n == "logs" || n == "backup" || n == "backups" || strings.HasSuffix(n, ".pem") || strings.HasSuffix(n, ".key")
}
func suggestRegistrationRole(name, image string) domain.ComponentRole {
	value := strings.ToLower(name + " " + image)
	for _, db := range []string{"postgres", "mysql", "mariadb", "mongo", "database", "clickhouse"} {
		if strings.Contains(value, db) {
			return domain.RoleDatabase
		}
	}
	for _, cache := range []string{"redis", "memcached", "cache"} {
		if strings.Contains(value, cache) {
			return domain.RoleCache
		}
	}
	if name == "db" {
		return domain.RoleDatabase
	}
	return domain.RoleApplication
}
func registrationManagedPaths(directory string, files, dataBinds []string) ([]domain.ManagedPath, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, err
	}
	if len(entries) > 4096 {
		return nil, registrationInvalid("Project has too many top-level entries for automatic inspection")
	}
	managed := []domain.ManagedPath{}
	walked := 0
	for _, entry := range entries {
		name := entry.Name()
		if sensitiveRegistrationName(name) || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			continue
		}
		absolute := filepath.Join(directory, name)
		blocked := false
		for _, data := range dataBinds {
			blocked = blocked || domain.PathsOverlap(absolute, data)
		}
		if blocked {
			continue
		}
		kind := domain.ManagedCode
		for _, file := range files {
			if name == file {
				kind = domain.ManagedConfig
			}
		}
		exclusions := []string{}
		if info.IsDir() {
			// Select literal exclusions recursively without following symlinks.
			err = fs.WalkDir(root.FS(), name, func(current string, item fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				walked++
				if walked > 100000 {
					return registrationInvalid("Project exceeds the automatic inspection limit; split code into smaller service directories")
				}
				if current == name {
					return nil
				}
				if sensitiveRegistrationName(item.Name()) || item.Type()&os.ModeSymlink != 0 {
					rel, _ := filepath.Rel(name, current)
					exclusions = append(exclusions, rel)
					if item.IsDir() {
						return fs.SkipDir
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
		managed = append(managed, domain.ManagedPath{Path: name, Kind: kind, Exclusions: exclusions})
	}
	return managed, nil
}

func sameRegistrationIdentity(draft, edited domain.Service) bool {
	// Editable classification never changes Docker identities, approved roots,
	// original Compose inputs, policy revision or secret references.
	for i := range draft.Containers {
		draft.Containers[i].Role = ""
	}
	for i := range edited.Containers {
		edited.Containers[i].Role = ""
	}
	return draft.ID == edited.ID && draft.SchemaVersion == edited.SchemaVersion && draft.ProjectDirectory == edited.ProjectDirectory && draft.SourceDirectory == edited.SourceDirectory && draft.ComposeProject == edited.ComposeProject && reflect.DeepEqual(draft.ComposeFiles, edited.ComposeFiles) && reflect.DeepEqual(draft.Profiles, edited.Profiles) && reflect.DeepEqual(draft.Containers, edited.Containers) && edited.PolicyRevision == 1 && edited.FileMapRevision == 1 && len(edited.SecretVersions) == 0
}

func (m *Manager) ProposeRegistration(ctx context.Context, input transport.RegistrationProposalRequest) (store.Proposal, error) {
	m.registrationMu.Lock()
	defer m.registrationMu.Unlock()
	if err := input.Initiator.Validate(); err != nil {
		return store.Proposal{}, registrationInvalid("Authenticated administrator identity is required")
	}
	var draft domain.Service
	if err := m.Store.Get(ctx, "web_registration_draft", input.Service.ID, &draft); err != nil {
		return store.Proposal{}, err
	}
	// Compare value copies: role clearing must not change the actual proposal.
	copyDraft, copyEdited := draft, input.Service
	copyDraft.Containers = append([]domain.ContainerRef{}, draft.Containers...)
	copyEdited.Containers = append([]domain.ContainerRef{}, input.Service.Containers...)
	if !sameRegistrationIdentity(copyDraft, copyEdited) {
		return store.Proposal{}, registrationInvalid("Registration identity changed after inspection; inspect the project again")
	}
	if _, err := m.Store.GetService(ctx, input.Service.ID); err == nil {
		return store.Proposal{}, store.ErrConflict
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.Proposal{}, err
	}
	if err := input.Service.Validate(); err != nil {
		return store.Proposal{}, registrationInvalid(err.Error())
	}
	if err := m.ensureRegistrationWorkspace(input.Service.SourceDirectory); err != nil {
		return store.Proposal{}, err
	}
	return m.Propose(ctx, input.Service, input.Initiator)
}

func (m *Manager) ensureRegistrationWorkspace(name string) error {
	if len(m.Config.WorkspaceRoots) == 0 || filepath.Dir(name) != m.Config.WorkspaceRoots[0] {
		return registrationInvalid("Workspace must be the executor-generated directory within its approved root")
	}
	if err := m.Config.CheckPath(filepath.Dir(name), true); err != nil {
		return registrationInvalid("Approved workspace root is unavailable or has symbolic-link aliases")
	}
	root, err := os.OpenRoot(filepath.Dir(name))
	if err != nil {
		return err
	}
	defer root.Close()
	if err = root.Mkdir(filepath.Base(name), 0700); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := root.Lstat(filepath.Base(name))
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return registrationInvalid("Registration workspace must be a private real directory")
	}
	entries, err := os.ReadDir(name)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return registrationInvalid("New registration workspace must be empty")
	}
	return nil
}

func (m *Manager) ApproveRegistration(ctx context.Context, input transport.RegistrationApproveRequest) (transport.RegistrationApproval, error) {
	m.registrationMu.Lock()
	defer m.registrationMu.Unlock()
	result := transport.RegistrationApproval{}
	if input.ProposalID.Validate() != nil || input.Digest.Validate() != nil || input.Initiator.Validate() != nil {
		return result, registrationInvalid("Valid proposal, reviewed digest and administrator identity are required")
	}
	proposal, err := m.Store.GetProposal(ctx, input.ProposalID)
	if err != nil {
		return result, err
	}
	if proposal.Digest != input.Digest {
		return result, store.ErrConflict
	}
	var draft domain.Service
	if err := m.Store.Get(ctx, "web_registration_draft", proposal.Service.ID, &draft); err != nil {
		return result, err
	}
	// An already committed exact registration may have since acquired new runtime
	// container IDs. Approval retry therefore consults the committed policy first.
	service, err := m.Store.GetService(ctx, proposal.Service.ID)
	if errors.Is(err, store.ErrNotFound) {
		service, err = m.Approve(ctx, input.ProposalID, input.Digest, input.Initiator)
	} else if err == nil && !reflect.DeepEqual(service, proposal.Service) {
		return result, store.ErrConflict
	}
	if err != nil {
		return result, err
	}
	result.Service = service
	st, err := m.state(ctx, service)
	if err != nil {
		return result, err
	}
	key := "registration-" + string(input.ProposalID)
	ops, err := m.Store.ListOperations(ctx)
	if err != nil {
		return result, err
	}
	var existing *domain.Operation
	for _, op := range ops {
		if op.Spec.ServiceID == service.ID && op.Spec.Kind == domain.OperationSnapshot && op.Spec.Initiator == proposal.Actor && (op.Spec.IdempotencyKey == key || strings.HasPrefix(op.Spec.IdempotencyKey, key+"-")) && (existing == nil || op.CreatedAt.After(existing.CreatedAt)) {
			copy := op
			existing = &copy
		}
	}
	if existing != nil {
		result.Operation = existing
		if existing.State == domain.OperationQueued || existing.State == domain.OperationRunning {
			return result, nil
		}
		if existing.State == domain.OperationRequiresRecovery || existing.MutationStarted || existing.RecoveryPointID != "" {
			result.InitializationError = "Initialization operation requires recovery before retry"
			return result, nil
		}
		if existing.State == domain.OperationInterrupted {
			// A baseline snapshot cannot call BeginMutation. On explicit retry,
			// reacquire the same resource set to reject any conflicting owner,
			// then record the interrupted non-active effects as a failed attempt.
			m.artifactMu.Lock()
			finishErr := m.Store.Acquire(ctx, existing.Spec.ID, existing.Spec.Resources)
			if finishErr == nil {
				var finished domain.Operation
				finished, finishErr = jobs.New(m.Store).Transition(ctx, existing.Spec.ID, domain.OperationFailed, domain.OutcomeEvidence{ActualStateKnown: true, ResultRecorded: true, Reason: "administrator retried non-mutating registration baseline"})
				if finishErr == nil {
					existing = &finished
					result.Operation = existing
				}
			}
			m.artifactMu.Unlock()
			if finishErr != nil {
				return result, finishErr
			}
		}
	}
	if st.BaselineID != "" {
		// The baseline may have committed immediately before a failed source copy.
		// An explicit panel retry completes only this isolated workspace operation.
		m.artifactMu.Lock()
		snapshot, seedErr := m.loadSnapshot(ctx, st.BaselineID)
		if seedErr == nil {
			seedErr = m.seedRegistrationWorkspace(ctx, service, snapshot)
		}
		m.artifactMu.Unlock()
		if seedErr != nil {
			result.InitializationError = "Baseline exists, but source workspace initialization is incomplete. Correct its directory or disk permissions and retry this confirmation; existing author edits are preserved."
			return result, nil
		}
		result.Initialized = true
		return result, nil
	}
	if existing != nil {
		key += "-" + string(existing.Spec.ID)
	}
	req := transport.SubmitRequest{ServiceID: service.ID, Action: domain.OperationSnapshot, Initiator: proposal.Actor, IdempotencyKey: key}
	preview, err := m.Preview(ctx, req)
	if err == nil {
		req.PlanDigest = preview.PlanDigest
		var operation domain.Operation
		operation, err = m.Submit(ctx, transport.Principal{}, req)
		if err == nil {
			result.Operation = &operation
		}
	}
	if err != nil {
		result.InitializationError = "Registration is approved, but baseline initialization could not be queued. Retry this confirmation or create Snapshot from the panel."
	}
	return result, nil
}

type registrationSeed struct {
	SnapshotID domain.ID     `json:"snapshot_id"`
	Temporary  string        `json:"temporary"`
	TreeDigest domain.Digest `json:"tree_digest"`
}

// seedRegistrationWorkspace is called under artifactMu. Web-created workspaces
// are published by directory rename, so a failed copy never leaves half a tree
// in the user's source directory. The receipt makes crash cleanup/retry bounded.
func (m *Manager) seedRegistrationWorkspace(ctx context.Context, s domain.Service, snap domain.Snapshot) error {
	var draft domain.Service
	err := m.Store.Get(ctx, "web_registration_draft", s.ID, &draft)
	if errors.Is(err, store.ErrNotFound) {
		entries, err := os.ReadDir(s.SourceDirectory)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			content, _ := m.Snapshots.ContentPath(snap.ID)
			return filesystem.MaterializeBuild(ctx, content, s.SourceDirectory, snap.Manifest)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if len(m.Config.WorkspaceRoots) == 0 || draft.SourceDirectory != s.SourceDirectory || filepath.Dir(s.SourceDirectory) != m.Config.WorkspaceRoots[0] {
		return errors.New("registration workspace identity changed")
	}
	if err := m.Config.CheckPath(filepath.Dir(s.SourceDirectory), true); err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Dir(s.SourceDirectory))
	if err != nil {
		return err
	}
	defer root.Close()
	leaf := filepath.Base(s.SourceDirectory)
	var completed registrationSeed
	completionErr := m.Store.Get(ctx, "registration_initialized", s.ID, &completed)
	if completionErr != nil && !errors.Is(completionErr, store.ErrNotFound) {
		return completionErr
	}
	info, err := root.Lstat(leaf)
	if os.IsNotExist(err) && errors.Is(completionErr, store.ErrNotFound) {
		if err = root.Mkdir(leaf, 0700); err != nil {
			return err
		}
		info, err = root.Lstat(leaf)
	}
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm() != 0700 || !ok || owner.Uid != uint32(os.Geteuid()) {
		return errors.New("source workspace is not a private executor-owned directory")
	}
	if err := m.Config.CheckPath(s.SourceDirectory, true); err != nil {
		return err
	}
	if completionErr == nil {
		if completed.SnapshotID != snap.ID || completed.TreeDigest != snap.ManifestDigest {
			return errors.New("registration initialization snapshot changed")
		}
		return nil
	}
	var seed registrationSeed
	err = m.Store.Get(ctx, "registration_seed", s.ID, &seed)
	if errors.Is(err, store.ErrNotFound) {
		seed = registrationSeed{SnapshotID: snap.ID, Temporary: ".ctfm-seed-" + string(NewID("")), TreeDigest: snap.ManifestDigest}
		err = m.Store.PutImmutable(ctx, "registration_seed", s.ID, s.ID, seed)
	}
	if err != nil {
		return err
	}
	if seed.SnapshotID != snap.ID || seed.TreeDigest != snap.ManifestDigest || !strings.HasPrefix(seed.Temporary, ".ctfm-seed-") || filepath.Base(seed.Temporary) != seed.Temporary {
		return errors.New("registration seed receipt mismatch")
	}
	entries, err := os.ReadDir(s.SourceDirectory)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		if !registrationWorkspaceMatches(ctx, s, snap) {
			return errors.New("existing workspace differs from baseline; refusing to overwrite author edits")
		}
		return m.Store.PutImmutable(ctx, "registration_initialized", s.ID, s.ID, seed)
	}
	if existing, err := root.Lstat(seed.Temporary); err == nil {
		owner, ok := existing.Sys().(*syscall.Stat_t)
		if !existing.IsDir() || existing.Mode().Perm() != 0700 || !ok || owner.Uid != uint32(os.Geteuid()) {
			return errors.New("registration staging directory was replaced")
		}
		if err := root.RemoveAll(seed.Temporary); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	space, err := storage.Capacity(filepath.Dir(s.SourceDirectory))
	if err != nil {
		return err
	}
	policy := m.Config.Storage.Effective()
	if err := storage.CheckQuota(0, uint64(snap.Manifest.TotalBytes())+4096, policy.SnapshotMaxBytes, space, policy.MinimumFreeBytes, policy.MinimumFreeInodes, uint64(len(snap.Manifest.Entries())+1)); err != nil {
		return err
	}
	if err := root.Mkdir(seed.Temporary, 0700); err != nil {
		return err
	}
	temporary := filepath.Join(filepath.Dir(s.SourceDirectory), seed.Temporary)
	defer root.RemoveAll(seed.Temporary)
	content, _ := m.Snapshots.ContentPath(snap.ID)
	if err := filesystem.MaterializeBuild(ctx, content, temporary, snap.Manifest); err != nil {
		return err
	}
	// Removing an empty directory is required by renameat on some supported
	// development hosts. The receipt also covers a crash in this empty-name gap.
	if err := root.Remove(leaf); err != nil {
		return err
	}
	if err := root.Rename(seed.Temporary, leaf); err != nil {
		_ = root.Mkdir(leaf, 0700)
		return err
	}
	parent, err := root.Open(".")
	if err != nil {
		return err
	}
	err = parent.Sync()
	parent.Close()
	if err != nil {
		return err
	}
	return m.Store.PutImmutable(ctx, "registration_initialized", s.ID, s.ID, seed)
}

func (m *Manager) registrationInitialized(ctx context.Context, s domain.Service, baseline domain.ID) (bool, error) {
	if baseline == "" {
		return false, nil
	}
	var draft domain.Service
	if err := m.Store.Get(ctx, "web_registration_draft", s.ID, &draft); errors.Is(err, store.ErrNotFound) {
		return true, nil
	} else if err != nil {
		return false, err
	}
	var completed registrationSeed
	if err := m.Store.Get(ctx, "registration_initialized", s.ID, &completed); errors.Is(err, store.ErrNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if completed.SnapshotID != baseline || completed.TreeDigest.Validate() != nil {
		return false, errors.New("registration initialization marker mismatch")
	}
	if err := m.Config.CheckPath(s.SourceDirectory, true); err != nil {
		return false, nil
	}
	return true, nil
}

func registrationWorkspaceMatches(ctx context.Context, s domain.Service, snap domain.Snapshot) bool {
	actual, err := filesystem.Observe(ctx, s.SourceDirectory, s.ManagedPaths, nil)
	if err != nil {
		return false
	}
	a, b := actual.Entries(), snap.Manifest.Entries()
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		a[i].UID = b[i].UID
		a[i].GID = b[i].GID
	}
	manifest, err := domain.NewManifest(a)
	return err == nil && manifest.Digest() == snap.ManifestDigest
}
