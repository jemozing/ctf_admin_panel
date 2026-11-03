package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/filesystem"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func (m *Manager) approvedComposeSnapshot(ctx context.Context, s domain.Service, st runtimeState) (domain.Snapshot, error) {
	id := st.BaselineID
	if st.CurrentReleaseID != "" {
		release, err := m.loadRelease(ctx, s, st.CurrentReleaseID)
		if err != nil {
			return domain.Snapshot{}, err
		}
		id = release.Spec().SnapshotID
	}
	snapshot, err := m.loadSnapshot(ctx, id)
	if err != nil {
		return snapshot, err
	}
	if snapshot.ServiceID != s.ID || snapshot.FileMapRevision != s.FileMapRevision ||
		(snapshot.Purpose != domain.SnapshotBaseline && snapshot.Purpose != domain.SnapshotCandidate) {
		return domain.Snapshot{}, errors.New("invalid approved snapshot for Compose inputs")
	}
	return snapshot, nil
}

func (m *Manager) previewPrepareCompose(ctx context.Context, s domain.Service, st runtimeState, req transport.SubmitRequest, result *transport.PreviewResult) (domain.Manifest, error) {
	if st.CurrentReleaseID == "" {
		return domain.Manifest{}, errors.New("import a baseline release before preparing a Compose change")
	}
	if err := m.requireNoRuntimePortOverlay(ctx, s); err != nil {
		return domain.Manifest{}, err
	}
	result.ComposeFromGit = req.ComposeFromGit
	if req.ComposeFromGit {
		source, err := m.GitSource(ctx, s.ID)
		if err != nil {
			return domain.Manifest{}, err
		}
		if !source.Configured {
			return domain.Manifest{}, errors.New("configure a Git source first")
		}
		result.GitSource = &source
		return domain.Manifest{}, nil
	}
	target, err := filesystem.Observe(ctx, s.SourceDirectory, s.ManagedPaths, nil)
	if err == nil {
		result.ComposeSourceTree = target.Digest()
	}
	return target, err
}

func composeFileEntries(manifest domain.Manifest, files []string) map[string]domain.ManifestEntry {
	wanted := make(map[string]domain.ManifestEntry, len(files))
	for _, path := range files {
		wanted[path] = domain.ManifestEntry{}
	}
	for _, entry := range manifest.Entries() {
		if _, ok := wanted[entry.Path]; ok {
			wanted[entry.Path] = entry
		}
	}
	return wanted
}

func composeFileContentsChanged(current, proposed domain.Manifest, files []string) bool {
	before, after := composeFileEntries(current, files), composeFileEntries(proposed, files)
	for _, path := range files {
		a, b := before[path], after[path]
		if a.Type != b.Type || a.Digest != b.Digest {
			return true
		}
	}
	return false
}

func (m *Manager) previewComposeSwitch(ctx context.Context, s domain.Service, st runtimeState, release domain.ReleaseSpec, snapshot domain.Snapshot, result *transport.PreviewResult) error {
	if st.CurrentReleaseID == "" {
		return nil
	}
	active, err := m.loadRelease(ctx, s, st.CurrentReleaseID)
	if err != nil {
		return err
	}
	activeSpec := active.Spec()
	if activeSpec.SnapshotID != snapshot.ID {
		current, err := m.approvedComposeSnapshot(ctx, s, st)
		if err != nil {
			return err
		}
		result.ComposeChange = composeFileContentsChanged(current.Manifest, snapshot.Manifest, s.ComposeFiles)
	}
	if activeSpec.ConfigurationDigest != release.ConfigurationDigest {
		result.ComposeChange = true
		old, err := m.LoadConfiguration(ctx, activeSpec.ConfigurationDigest)
		if err != nil {
			return err
		}
		next, err := m.LoadConfiguration(ctx, release.ConfigurationDigest)
		if err != nil {
			return err
		}
		changes, err := docker.ComposeResourceChanges(old.Model, next.Model, s.Targets)
		if err != nil {
			return err
		}
		for _, change := range changes {
			result.ComposeChanges = append(result.ComposeChanges, transport.ComposeResourceChange(change))
		}
	}
	if result.ComposeChange {
		return m.requireNoRuntimePortOverlay(ctx, s)
	}
	return nil
}

func (m *Manager) prepareComposeRelease(ctx context.Context, s domain.Service, st runtimeState, op domain.Operation, input operationInput, current Configuration, configDigest domain.Digest) error {
	if err := m.stage(ctx, op.Spec.ID, domain.StageCopying); err != nil {
		return err
	}
	source := s.SourceDirectory
	var provenance *domain.GitProvenance
	if input.Request.ComposeFromGit {
		tree, gitSource, err := m.fetchConfiguredGitTree(ctx, s.ID)
		if err != nil {
			return err
		}
		defer tree.Close()
		source, provenance = tree.Directory, gitSource
		provenance.ComposeRevision = true
	}
	observed, err := filesystem.Observe(ctx, source, s.ManagedPaths, nil)
	if err != nil {
		return err
	}
	if !input.Request.ComposeFromGit && observed.Digest() != input.Plan.ComposeSourceTree {
		return errors.New("workspace changed after Compose preparation was reviewed")
	}
	approved, err := m.approvedComposeSnapshot(ctx, s, st)
	if err != nil {
		return err
	}
	if !composeFileContentsChanged(approved.Manifest, observed, s.ComposeFiles) {
		return errors.New("Compose files match the current configuration; use the ordinary build workflow")
	}
	before := composeFileEntries(approved.Manifest, s.ComposeFiles)
	after := composeFileEntries(observed, s.ComposeFiles)
	if provenance != nil && !hasGitFilesForComposeRevision(approved.Manifest, observed, before) {
		return errors.New("Git tree contains no approved managed files outside Compose inputs; verify repository subdirectory")
	}
	for _, path := range s.ComposeFiles {
		if before[path].Type != domain.EntryFile || after[path].Type != domain.EntryFile {
			return fmt.Errorf("Compose input %q must be a managed regular file in both revisions", path)
		}
	}
	if provenance != nil {
		// Git records executable bits, but does not record local ownership or
		// access restrictions. Keep them for registered Compose files.
		if err := keepGitComposePermissions(source, s.ComposeFiles, before); err != nil {
			return err
		}
		observed, err = filesystem.Observe(ctx, source, s.ManagedPaths, nil)
		if err != nil {
			return err
		}
		after = composeFileEntries(observed, s.ComposeFiles)
	}
	overrides := make(map[string][]byte, len(s.ComposeFiles))
	for _, path := range s.ComposeFiles {
		a, b := before[path], after[path]
		if b.Mode & ^a.Mode != 0 || b.UID != a.UID || b.GID != a.GID && b.Mode&0070 != 0 {
			return fmt.Errorf("Compose input %q changes file ownership or widens permissions", path)
		}
		data, err := filesystem.ReadVerifiedFile(ctx, source, b, 1<<20)
		if err != nil {
			return err
		}
		overrides[path] = data
	}
	next, nextDigest, err := m.prepareComposeConfiguration(ctx, s, current, configDigest, overrides)
	if err != nil {
		return err
	}
	candidate, err := m.capture(ctx, s, op.Spec.Initiator, domain.SnapshotCandidate, source, provenance)
	if err != nil {
		return err
	}
	if candidate.ManifestDigest != observed.Digest() {
		return errors.New("Compose candidate files changed after validation")
	}
	// A Build can release the artifact gate. Keep this snapshot alive until
	// its release exists or the preparation operation reaches a terminal state.
	if err := m.Store.PutImmutable(ctx, "compose_preparation", op.Spec.ID, s.ID, candidate.ID); err != nil {
		return err
	}
	if err := m.stage(ctx, op.Spec.ID, domain.StageBuilding); err != nil {
		return err
	}
	input.Plan.CandidateID = candidate.ID
	return m.buildRelease(ctx, s, st, op, input, next, nextDigest)
}

func keepGitComposePermissions(source string, files []string, approved map[string]domain.ManifestEntry) error {
	root, err := os.OpenRoot(source)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, path := range files {
		file, err := root.Open(path)
		if err != nil {
			return err
		}
		err = preserveGitComposeMetadata(file, approved[path])
		closeErr := file.Close()
		if err := errors.Join(err, closeErr); err != nil {
			return fmt.Errorf("preserve permissions of Compose input %q: %w", path, err)
		}
	}
	return nil
}

func hasGitFilesForComposeRevision(active, git domain.Manifest, compose map[string]domain.ManifestEntry) bool {
	for _, entry := range git.Entries() {
		if _, frozen := compose[entry.Path]; !frozen && entry.Type == domain.EntryFile {
			return true
		}
	}
	for _, entry := range active.Entries() {
		if _, frozen := compose[entry.Path]; !frozen && entry.Type == domain.EntryFile {
			return false
		}
	}
	return true
}

func (m *Manager) prepareComposeConfiguration(ctx context.Context, s domain.Service, current Configuration, currentDigest domain.Digest, overrides map[string][]byte) (Configuration, domain.Digest, error) {
	if len(current.FileInputs) != 0 {
		return Configuration{}, "", errors.New("Compose changes with file-backed runtime inputs require a separate policy review")
	}
	report, err := docker.NormalizeWithComposeFiles(ctx, m.Config, docker.ComposeInput{
		ProjectDirectory: s.ProjectDirectory, ProjectName: s.ComposeProject, Files: s.ComposeFiles, Profiles: s.Profiles,
	}, overrides)
	if err != nil {
		return Configuration{}, "", err
	}
	if len(report.Issues) > 0 {
		return Configuration{}, "", fmt.Errorf("new Compose is outside the supported profile (%s)", report.Issues[0].Code)
	}
	var proposed map[string]any
	if err := json.Unmarshal(report.Normalized, &proposed); err != nil {
		return Configuration{}, "", err
	}
	old, err := m.renderConfiguration(current)
	if err != nil {
		return Configuration{}, "", err
	}
	changes, err := docker.ComposeResourceChanges(old, proposed, s.Targets)
	if err != nil {
		return Configuration{}, "", err
	}
	if len(changes) == 0 {
		return current, currentDigest, nil
	}
	// The normalized candidate is only used to read the approved scalar
	// changes. Vault references and all other model settings stay frozen.
	encoded, err := json.Marshal(current)
	if err != nil {
		return Configuration{}, "", err
	}
	var next Configuration
	if err := json.Unmarshal(encoded, &next); err != nil {
		return Configuration{}, "", err
	}
	services := next.Model["services"].(map[string]any)
	sourceServices := proposed["services"].(map[string]any)
	for _, change := range changes {
		target := services[change.Component].(map[string]any)
		source := sourceServices[change.Component].(map[string]any)
		if value, ok := source[change.Setting]; ok {
			target[change.Setting] = value
		} else {
			delete(target, change.Setting)
		}
	}
	encoded, err = json.Marshal(next)
	if err != nil {
		return Configuration{}, "", err
	}
	digest := domain.Hash(encoded)
	if err := m.Store.PutImmutable(ctx, "configuration", domain.ID(string(digest)[7:]), s.ID, next); err != nil {
		return Configuration{}, "", err
	}
	return next, digest, nil
}
