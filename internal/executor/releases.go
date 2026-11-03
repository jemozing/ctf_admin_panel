package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/filesystem"
	"github.com/ctf-service-manager/ctf-service-manager/internal/jobs"
	"github.com/ctf-service-manager/ctf-service-manager/internal/storage"
)

func (m *Manager) importRelease(ctx context.Context, s domain.Service, author domain.ID, configuration domain.Digest, snapshot domain.Snapshot, actual []docker.Container) (domain.Release, error) {
	id := NewID("rel-")
	images := []domain.ImageRef{}
	for _, c := range actual {
		tag := retentionTag(s, id, c.Component)
		if err := m.Engine.RetainImage(ctx, c.ImageID, tag); err != nil {
			return domain.Release{}, err
		}
		images = append(images, domain.ImageRef{Component: c.Component, ImageID: domain.Digest(c.ImageID), RetentionTag: tag})
	}
	r, err := domain.NewRelease(domain.ReleaseSpec{SchemaVersion: domain.SchemaVersion, ID: id, ServiceID: s.ID, CreatedAt: time.Now().UTC(), Author: author, Source: domain.ReleaseImported, SnapshotID: snapshot.ID, TreeDigest: snapshot.ManifestDigest, ConfigurationDigest: configuration, PolicyRevision: s.PolicyRevision, FileMapRevision: s.FileMapRevision, Images: images, Secrets: s.SecretVersions, Data: dataReferences(s)})
	if err != nil {
		return r, err
	}
	return r, m.Store.PutImmutable(ctx, "release", id, s.ID, r)
}
func (m *Manager) buildRelease(ctx context.Context, s domain.Service, st runtimeState, op domain.Operation, input operationInput, c Configuration, configuration domain.Digest) error {
	snapshot, err := m.loadSnapshot(ctx, input.Plan.CandidateID)
	if err != nil {
		return err
	}
	if snapshot.ServiceID != s.ID || snapshot.Purpose != domain.SnapshotCandidate {
		return errors.New("build snapshot outside candidate policy")
	}
	if snapshot.FileMapRevision != s.FileMapRevision {
		return errors.New("candidate file map is stale")
	}
	if op.Spec.Kind != domain.OperationPrepareCompose {
		if err := m.guardComposeInputs(ctx, s, st, snapshot); err != nil {
			return err
		}
	}
	if err := ensureStaging(m.Config.StateDirectory); err != nil {
		return err
	}
	if err := m.preflightAllocation(ctx, stagingPath(m.Config.StateDirectory), uint64(snapshot.Manifest.TotalBytes())+4096, uint64(len(snapshot.Manifest.Entries())+3), m.Config.Storage.Effective().StagingMaxBytes); err != nil {
		return err
	}
	if err := m.checkDockerBudget(ctx, m.Config.Storage.Effective().BuildReserveBytes); err != nil {
		return err
	}
	temp, err := m.reserveBuildDirectory(ctx, s.ID, op.Spec.ID)
	if err != nil {
		return err
	}
	defer func() {
		_ = storage.RemoveStagingTree(context.WithoutCancel(ctx), stagingPath(m.Config.StateDirectory), filepath.Base(temp))
	}()
	content, _ := m.Snapshots.ContentPath(snapshot.ID)
	if err := materializeReleaseBuild(ctx, s, snapshot, content, temp); err != nil {
		return err
	}
	model, err := m.materializedConfiguration(c)
	if err != nil {
		return err
	}
	services, _ := model["services"].(map[string]any)
	id := NewID("rel-")
	images := []domain.ImageRef{}
	buildTargets := []string{}
	current, err := m.loadRelease(ctx, s, st.CurrentReleaseID)
	if err != nil {
		return err
	}
	currentImages := map[string]domain.ImageRef{}
	for _, image := range current.Spec().Images {
		currentImages[image.Component] = image
	}
	for name, raw := range services {
		component := raw.(map[string]any)
		tag := retentionTag(s, id, name)
		if build, ok := component["build"].(map[string]any); ok && hasTarget(s, name) {
			original, _ := build["context"].(string)
			relative, err := filepath.Rel(s.ProjectDirectory, original)
			if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				return errors.New("build context outside captured project")
			}
			build["context"] = filepath.Join(temp, relative)
			component["image"] = tag
			buildTargets = append(buildTargets, name)
		} else {
			previous, ok := currentImages[name]
			if !ok {
				return errors.New("current release lacks a component image")
			}
			if err := m.Engine.RetainImage(ctx, string(previous.ImageID), tag); err != nil {
				return err
			}
			images = append(images, domain.ImageRef{Component: name, ImageID: previous.ImageID, RetentionTag: tag})
		}
	}
	output := &boundedBuffer{limit: 1 << 20}
	if len(buildTargets) > 0 {
		if err := m.reserveDockerBuild(ctx, s.ID, op.Spec.ID, id, model); err != nil {
			return err
		}
		if err := m.withArtifactReleased(ctx, func(ctx context.Context) error {
			return m.composeActionWithDiagnostics(ctx, s, op.Spec.ID, c, model, "build", buildTargets, output)
		}); err != nil {
			return err
		}
	}
	if err := m.checkDockerBudget(ctx, 0); err != nil {
		return err
	}
	// Raw command output is represented here only by a digest. Separately bounded
	// diagnostics contain redacted text and require sensitive-access permission.
	evidence := struct {
		OutputDigest  domain.Digest `json:"output_digest"`
		CapturedBytes int           `json:"captured_bytes"`
		Truncated     bool          `json:"truncated"`
	}{domain.Hash(output.data), len(output.data), output.truncated}
	evidenceBytes, _ := json.Marshal(evidence)
	evidenceDigest := domain.Hash(evidenceBytes)
	if err := m.Store.PutImmutable(ctx, "build_evidence", domain.ID(string(evidenceDigest)[7:]), s.ID, evidence); err != nil {
		return err
	}
	for _, name := range buildTargets {
		tag := retentionTag(s, id, name)
		image, err := m.Engine.Client.ImageInspect(ctx, tag)
		if err != nil {
			return err
		}
		// Dockerfile VOLUME must not introduce a new anonymous store at recreation.
		for target := range image.Config.Volumes {
			declared := false
			for _, d := range s.DataPaths {
				declared = declared || d.Component == name && d.Target == target
			}
			if !declared {
				return fmt.Errorf("image introduces undeclared VOLUME in %s", name)
			}
		}
		images = append(images, domain.ImageRef{Component: name, ImageID: domain.Digest(image.ID), RetentionTag: tag, RegistryDigests: image.RepoDigests})
	}
	source := domain.ReleaseWorkspace
	if snapshot.GitSource != nil {
		source = domain.ReleaseGit
	}
	r, err := domain.NewRelease(domain.ReleaseSpec{SchemaVersion: domain.SchemaVersion, ID: id, ServiceID: s.ID, CreatedAt: time.Now().UTC(), Author: op.Spec.Initiator, Source: source, SnapshotID: snapshot.ID, TreeDigest: snapshot.ManifestDigest, ConfigurationDigest: configuration, PolicyRevision: s.PolicyRevision, FileMapRevision: s.FileMapRevision, Images: images, Secrets: s.SecretVersions, Data: dataReferences(s), BuildEvidenceDigest: evidenceDigest, GitSource: snapshot.GitSource})
	if err != nil {
		return err
	}
	if err := m.Store.PutImmutable(ctx, "release", id, s.ID, r); err != nil {
		return err
	}
	return m.event(ctx, op.Spec.ID, "release_built", string(id))
}
func pinModelImages(model map[string]any, images []domain.ImageRef) {
	services, _ := model["services"].(map[string]any)
	for _, image := range images {
		if component, ok := services[image.Component].(map[string]any); ok {
			component["image"] = string(image.ImageID)
			delete(component, "build")
			delete(component, "pull_policy")
		}
	}
}

// Runtime Compose file inputs live below executor-private state with public file
// mode only inside a private parent. Docker can bind each file for an application
// UID without granting dashboard access to the parent directory or original vault.
func (m *Manager) materializedConfiguration(c Configuration) (map[string]any, error) {
	model, err := m.renderConfiguration(c)
	if err != nil {
		return nil, err
	}
	root := filepath.Join(m.Config.StateDirectory, "runtime-inputs")
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	for key, ref := range c.FileInputs {
		parts := strings.Split(key, "/")
		if len(parts) != 2 {
			return nil, errors.New("invalid file input reference")
		}
		data, err := m.Vault.Read(ref)
		if err != nil {
			return nil, errors.New("required secret version unavailable")
		}
		name := string(domain.Hash([]byte(key + "/" + string(ref.SecretID) + "/" + string(ref.Version))))[7:]
		target := filepath.Join(root, name)
		file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0444)
		if err == nil {
			_, err = file.Write(data)
			if err == nil {
				err = file.Sync()
			}
			closeErr := file.Close()
			if err == nil {
				err = closeErr
			}
			if err != nil {
				return nil, err
			}
		} else if !os.IsExist(err) {
			return nil, err
		} else {
			info, err := os.Lstat(target)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0444 {
				return nil, errors.New("runtime input metadata changed")
			}
			existing, err := os.ReadFile(target)
			if err != nil || domain.Hash(existing) != domain.Hash(data) {
				return nil, errors.New("runtime input content changed")
			}
		}
		section, _ := model[parts[0]].(map[string]any)
		entry, _ := section[parts[1]].(map[string]any)
		entry["file"] = target
	}
	return model, nil
}
func (m *Manager) switchRelease(ctx context.Context, s domain.Service, st *runtimeState, op domain.Operation, input operationInput, currentConfiguration domain.Digest, currentModel map[string]any, actual []docker.Container) error {
	if st.CurrentReleaseID == "" || st.ActiveSnapshotID == "" {
		return errors.New("baseline and imported release are required before switching")
	}
	release, err := m.loadRelease(ctx, s, op.Spec.ReleaseID)
	if err != nil {
		return err
	}
	spec := release.Spec()
	if input.Plan.ComposeChange || spec.ConfigurationDigest != currentConfiguration {
		if !input.Request.ConfirmComposeChange {
			return errors.New("confirm the reviewed Compose configuration change before switching")
		}
		if err := m.requireNoRuntimePortOverlay(ctx, s); err != nil {
			return err
		}
	}
	configuration, err := m.LoadConfiguration(ctx, spec.ConfigurationDigest)
	if err != nil {
		return err
	}
	model, err := m.runtimeConfiguration(ctx, s, configuration)
	if err != nil {
		return err
	}
	pinModelImages(model, spec.Images)
	next, err := m.loadSnapshot(ctx, spec.SnapshotID)
	if err != nil {
		return err
	}
	if next.ManifestDigest != spec.TreeDigest {
		return errors.New("release tree integrity mismatch")
	}
	for _, ref := range spec.Secrets {
		if _, err := m.Vault.Read(ref); err != nil {
			return errors.New("release secret version unavailable")
		}
	}
	for _, image := range spec.Images {
		info, err := m.Engine.Client.ImageInspect(ctx, string(image.ImageID))
		if err != nil || info.ID != string(image.ImageID) {
			return errors.New("exact release image is unavailable; refusing to stop application")
		}
	}
	previous, err := m.loadSnapshot(ctx, st.ActiveSnapshotID)
	if err != nil {
		return err
	}
	observed, err := filesystem.Observe(ctx, s.ProjectDirectory, s.ManagedPaths, nil)
	if err != nil {
		return err
	}
	if observed.Digest() != previous.ManifestDigest {
		if !input.Request.AcceptFileDrift || !input.Plan.AcceptedFileDrift || observed.Digest() != input.Plan.CurrentTreeDigest {
			return errors.New("active files differ from current release; review and accept a fresh drift recovery plan")
		}
		if err := m.event(ctx, op.Spec.ID, "unverified_drift_accepted", "Reviewed managed file changes accepted as an unverified recovery point; application health is not confirmed"); err != nil {
			return err
		}
	}
	if err := m.stage(ctx, op.Spec.ID, domain.StageRecoveryPoint); err != nil {
		return err
	}
	reviewedDrift := domain.Digest("")
	if input.Plan.AcceptedFileDrift {
		reviewedDrift = input.Plan.CurrentTreeDigest
	}
	recoveryID, err := m.createRecoveryPoint(ctx, s, *st, op.Spec.Initiator, actual, reviewedDrift)
	if err != nil {
		return err
	}
	if input.Plan.AcceptedFileDrift {
		var point recoveryPoint
		if err := m.Store.Get(ctx, "recovery_point", recoveryID, &point); err != nil {
			return err
		}
		previous, err = m.loadSnapshot(ctx, point.SnapshotID)
		if err != nil {
			return err
		}
		if previous.ManifestDigest != observed.Digest() {
			return errors.New("active files changed while recording accepted drift")
		}
	}

	// Preserve the already approved actual volume identities. Neither `down` nor
	// a dependency service is part of the application recreation command.
	if err := m.checkDockerBudget(ctx, 0); err != nil {
		return err
	}
	if _, err := jobs.New(m.Store).BeginMutation(ctx, op.Spec.ID, recoveryID); err != nil {
		return err
	}
	for _, component := range actual {
		if hasTarget(s, component.Component) {
			if err := m.Engine.Stop(ctx, component.ID); err != nil {
				return errors.New("application stop failed")
			}
		}
	}
	stopped, err := m.Engine.Inventory(ctx, s.ComposeProject)
	if err != nil {
		return err
	}
	if err := confirmStopped(s, actual, stopped, currentModel); err != nil {
		return err
	}

	content, _ := m.Snapshots.ContentPath(next.ID)
	if err := filesystem.Apply(ctx, content, s.ProjectDirectory, previous.Manifest, next.Manifest, s.ManagedPaths, filesystem.ApplyOptions{ApplicationsStopped: true, PreserveOwnership: !m.Config.Development}); err != nil {
		return err
	}
	composeErr := m.composeActionWithDiagnostics(ctx, s, op.Spec.ID, configuration, model, "up", s.Targets, nil)
	observationErr := m.recordRuntimeSwitchObservation(ctx, s, op.Spec.ID, spec.ID, composeErr == nil)
	if composeErr != nil || observationErr != nil {
		return errors.Join(composeErr, observationErr)
	}
	// Observations are committed before warmup. A failing health check must never
	// make the previous release appear active after containers have been replaced.
	observedContainers, err := m.Engine.Inventory(ctx, s.ComposeProject)
	if err != nil {
		return err
	}
	if len(observedContainers) != len(st.Containers) {
		return errors.New("unexpected component count after switch")
	}
	refs := []domain.ContainerRef{}
	for _, old := range st.Containers {
		found := false
		for _, current := range observedContainers {
			if old.Component != current.Component {
				continue
			}
			expected := old.ImageID
			for _, image := range spec.Images {
				if image.Component == old.Component {
					expected = image.ImageID
				}
			}
			if current.ImageID != string(expected) {
				return errors.New("observed image differs from selected release")
			}
			if issues := current.RuntimeIssues(model, s.ComposeProject); len(issues) > 0 {
				return fmt.Errorf("observed runtime settings differ in %s (%s)", current.Component, issues[0].Code)
			}
			if !hasTarget(s, old.Component) && current.ID != old.ID {
				return errors.New("dependency was unexpectedly recreated")
			}
			refs = append(refs, domain.ContainerRef{Component: old.Component, ID: current.ID, ImageID: expected, Role: old.Role})
			found = true
		}
		if !found {
			return errors.New("release component missing after switch")
		}
	}
	st.Containers = refs
	st.CurrentReleaseID = spec.ID
	st.ActiveSnapshotID = next.ID
	if err := m.saveState(ctx, st); err != nil {
		return err
	}
	if err := m.event(ctx, op.Spec.ID, "release_observed", string(spec.ID)); err != nil {
		return err
	}
	if err := m.stage(ctx, op.Spec.ID, domain.StageWarmup); err != nil {
		return err
	}
	if err := m.warmup(ctx, s); err != nil {
		return err
	}
	return m.runChecks(ctx, s, op.Spec.ID)
}
func (m *Manager) warmupObserved(ctx context.Context, s domain.Service) error {
	policy, _, err := m.healthPolicy(ctx, s)
	if err != nil {
		return err
	}
	deadline := time.NewTimer(time.Duration(policy.WarmupSeconds) * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		items, err := m.Engine.Inventory(ctx, s.ComposeProject)
		if err != nil {
			return err
		}
		if err := exactTargets(s, items); err != nil {
			return err
		}
		ready := true
		for _, c := range items {
			if !hasTarget(s, c.Component) {
				continue
			}
			if c.State != "running" {
				ready = false
			}
			if c.Health == "unhealthy" {
				return errors.New("Docker healthcheck failed after switch")
			}
			if c.Health == "starting" {
				ready = false
			}
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("application warmup deadline exceeded")
		case <-ticker.C:
		}
	}
}

func materializeReleaseBuild(ctx context.Context, s domain.Service, snapshot domain.Snapshot, content, temp string) error {
	var hostOnly []string
	if snapshot.GitSource != nil {
		hostOnly = snapshot.GitSource.HostComposeInputs
		for _, name := range hostOnly {
			if !slices.Contains(s.ComposeFiles, name) {
				return fmt.Errorf("Git build exclusion %q is outside approved Compose inputs", name)
			}
		}
	}
	return filesystem.MaterializeBuild(ctx, content, temp, snapshot.Manifest, hostOnly...)
}

func (m *Manager) guardComposeInputs(ctx context.Context, s domain.Service, st runtimeState, candidate domain.Snapshot) error {
	baseline, err := m.approvedComposeSnapshot(ctx, s, st)
	if err != nil {
		return err
	}
	old := map[string]domain.ManifestEntry{}
	next := map[string]domain.ManifestEntry{}
	for _, e := range baseline.Manifest.Entries() {
		old[e.Path] = e
	}
	for _, e := range candidate.Manifest.Entries() {
		next[e.Path] = e
	}
	for _, name := range s.ComposeFiles {
		a, okA := old[name]
		b, okB := next[name]
		if okA != okB || a.Digest != b.Digest || a.Type != b.Type {
			return errors.New("candidate changes a frozen Compose input; administrator policy approval is required")
		}
	}
	return nil
}
