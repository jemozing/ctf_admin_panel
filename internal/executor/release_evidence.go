package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/filesystem"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func (m *Manager) driftObservation(ctx context.Context, s domain.Service, st runtimeState) transport.DriftObservation {
	v := transport.DriftObservation{State: "unknown", At: time.Now().UTC()}
	if st.ActiveSnapshotID == "" {
		v.Reason = "active release tree has not been recorded"
		return v
	}
	var expected domain.Snapshot
	if err := m.Store.Get(ctx, "snapshot", st.ActiveSnapshotID, &expected); err != nil || expected.ServiceID != s.ID {
		v.Reason = "recorded active manifest unavailable"
		return v
	}
	v.ExpectedDigest = expected.ManifestDigest
	observed, err := filesystem.Observe(ctx, s.ProjectDirectory, s.ManagedPaths, nil)
	if err != nil {
		v.Reason = "active tree cannot be safely observed"
		return v
	}
	v.CurrentDigest = observed.Digest()
	v.State = "unchanged"
	if v.CurrentDigest != v.ExpectedDigest {
		v.State = "changed"
		v.Reason = "active managed files differ from recorded release"
	}
	return v
}
func (m *Manager) detailObservations(ctx context.Context, s domain.Service, st runtimeState, result *transport.ServiceDetails) {
	result.Drift = m.driftObservation(ctx, s, st)
	result.ComponentVersions = []transport.ComponentVersion{}
	images := map[string]domain.Digest{}
	retainedImages := []domain.ImageRef{}
	releaseTreeMatches := false
	if st.CurrentReleaseID != "" {
		var release domain.Release
		if m.Store.Get(ctx, "release", st.CurrentReleaseID, &release) == nil {
			retainedImages = release.Spec().Images
			releaseTreeMatches = release.Spec().TreeDigest == result.Drift.ExpectedDigest
			for _, image := range release.Spec().Images {
				images[image.Component] = image.ImageID
			}
		}
	}
	if !releaseTreeMatches && result.Drift.State == "unchanged" {
		result.Drift.State = "unverified"
		result.Drift.Reason = "active files match a recovery point, but do not establish the immutable recorded release"
	}
	identities := map[string]string{}
	var runtimeModel map[string]any
	var runtimeModelErr error
	if m.Engine != nil {
		runtimeModel, runtimeModelErr = m.observationConfiguration(ctx, s)
		if runtimeModelErr == nil {
			pinModelImages(runtimeModel, retainedImages)
			// Reconcile each observed image's effective runtime settings. Image
			// version drift is reported separately and must not hide a uniquely
			// identified new component after a partial switch.
			for _, actual := range result.Containers {
				pinModelImages(runtimeModel, []domain.ImageRef{{Component: actual.Component, ImageID: domain.Digest(actual.ImageID)}})
			}
		}
	}
	for _, ref := range st.Containers {
		identities[ref.Component] = ref.ID
	}
	mixed := len(result.Containers) != len(st.Containers) || !releaseTreeMatches
	for _, registered := range s.Containers {
		v := transport.ComponentVersion{Component: registered.Component, RecordedReleaseID: st.CurrentReleaseID, RecordedImageID: images[registered.Component], State: "missing", PossibleReleaseIDs: []domain.ID{}}
		for _, c := range result.Containers {
			if c.Component != registered.Component {
				continue
			}
			v.ContainerID = c.ID
			v.ImageID = c.ImageID
			v.State = "unknown"
			if v.RecordedImageID != "" {
				v.State = "matches_recorded_image"
				if c.ImageID != string(v.RecordedImageID) {
					v.State = "different_image"
				} else if c.ID != identities[c.Component] {
					v.State = "image_matches_identity_changed"
				}
			}
			m.componentReleaseObservation(ctx, s, st, c, result.Drift, releaseTreeMatches, &v)
			if m.Engine != nil {
				if runtimeModelErr != nil {
					v.State = "runtime_configuration_unknown"
					v.ObservedReleaseID = ""
					v.AmbiguityReason = "frozen runtime configuration cannot be checked"
				} else if issues := c.RuntimeIssues(runtimeModel, s.ComposeProject); len(issues) > 0 {
					v.State = "runtime_configuration_changed"
					v.ObservedReleaseID = ""
					v.AmbiguityReason = "runtime configuration drift: " + issues[0].Code
				}
			}
		}
		mixed = mixed || v.State != "matches_recorded_image"
		result.ComponentVersions = append(result.ComponentVersions, v)
	}
	if mixed || result.Drift.State != "unchanged" {
		result.CurrentReleaseID = ""
		if result.ObservedState != "requires_recovery" && result.ObservedState != "interrupted" {
			result.ObservedState = "runtime_changed_or_partial"
		}
		for i := range result.Health {
			if result.Health[i].Source == domain.HealthFunctional || result.Health[i].Source == domain.HealthReadiness || result.Health[i].Source == domain.HealthManual {
				result.Health[i].State = domain.HealthUnknown
				result.Health[i].Reason = "recorded health does not establish the current changed runtime or file tree"
			}
		}
	}
}

// Resolve frozen file references for read-only inspection. Unlike runtime
// materialization, a status request must not create files or directories.
func (m *Manager) observationConfiguration(ctx context.Context, s domain.Service) (map[string]any, error) {
	digest, err := m.currentConfigurationDigest(ctx, s)
	if err != nil {
		return nil, err
	}
	configuration, err := m.LoadConfiguration(ctx, digest)
	if err != nil {
		return nil, err
	}
	model, err := m.renderConfiguration(configuration)
	if err != nil {
		return nil, err
	}
	for key, ref := range configuration.FileInputs {
		parts := strings.Split(key, "/")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid frozen input reference")
		}
		section, _ := model[parts[0]].(map[string]any)
		entry, _ := section[parts[1]].(map[string]any)
		if entry == nil {
			return nil, fmt.Errorf("invalid frozen input reference")
		}
		name := string(domain.Hash([]byte(key + "/" + string(ref.SecretID) + "/" + string(ref.Version))))[7:]
		entry["file"] = filepath.Join(m.Config.StateDirectory, "runtime-inputs", name)
	}
	if err := m.applyRuntimePorts(ctx, s, model); err != nil {
		return nil, err
	}
	return model, nil
}

// A container image can belong to several releases. Bind-mounted code also
// requires a matching observed managed tree; image equality alone is insufficient.
func (m *Manager) componentReleaseObservation(ctx context.Context, s domain.Service, st runtimeState, c docker.Container, drift transport.DriftObservation, currentTreeMatches bool, v *transport.ComponentVersion) {
	records, err := m.Store.List(ctx, "release", s.ID)
	if err != nil {
		v.AmbiguityReason = "release registry unavailable"
		return
	}
	boundCode := false
	for _, mount := range c.Mounts {
		if mount.Type != "bind" {
			continue
		}
		for _, managed := range s.ManagedPaths {
			if domain.PathsOverlap(filepath.Join(s.ProjectDirectory, managed.Path), mount.Source) {
				boundCode = true
			}
		}
	}
	for _, record := range records {
		var release domain.Release
		if json.Unmarshal(record.Payload, &release) != nil {
			continue
		}
		spec := release.Spec()
		if spec.PolicyRevision != s.PolicyRevision || spec.FileMapRevision != s.FileMapRevision {
			continue
		}
		retired, e := m.isRetired(ctx, "retired_release", spec.ID)
		if e != nil || retired {
			continue
		}
		if boundCode && (drift.CurrentDigest == "" || spec.TreeDigest != drift.CurrentDigest) {
			continue
		}
		for _, image := range spec.Images {
			if image.Component == c.Component && string(image.ImageID) == c.ImageID {
				v.PossibleReleaseIDs = append(v.PossibleReleaseIDs, spec.ID)
				break
			}
		}
	}
	sort.Slice(v.PossibleReleaseIDs, func(i, j int) bool { return v.PossibleReleaseIDs[i] < v.PossibleReleaseIDs[j] })
	if len(v.PossibleReleaseIDs) == 1 {
		v.ObservedReleaseID = v.PossibleReleaseIDs[0]
		v.ReleaseEvidence = "unique_image_match"
		if boundCode {
			v.ReleaseEvidence = "image_and_managed_bind_tree"
		}
		return
	}
	if currentTreeMatches && drift.State == "unchanged" && v.State == "matches_recorded_image" {
		for _, id := range v.PossibleReleaseIDs {
			if id == st.CurrentReleaseID {
				v.ObservedReleaseID = id
				v.ReleaseEvidence = "recorded_container_and_tree"
				return
			}
		}
	}
	if len(v.PossibleReleaseIDs) == 0 {
		v.AmbiguityReason = "no retained release matches observed image and managed bind tree"
	} else {
		v.AmbiguityReason = "the same observed image belongs to multiple releases; exact release is unknown"
	}
}
func (m *Manager) ReleaseEvidence(ctx context.Context, id, rid domain.ID) (transport.ReleaseEvidence, error) {
	v := transport.ReleaseEvidence{ReleaseID: rid, At: time.Now().UTC(), CanApply: true, Checks: map[string]string{}, Reasons: []string{}, Runs: []transport.ReleaseRun{}, LocalChecks: []transport.ReleaseCheck{}, ManualConfirmations: []transport.ManualReleaseConfirmation{}}
	s, err := m.Store.GetService(ctx, id)
	if err != nil {
		return v, err
	}
	st, err := m.state(ctx, s)
	if err != nil {
		return v, err
	}
	var release domain.Release
	if err := m.Store.Get(ctx, "release", rid, &release); err != nil {
		return v, err
	}
	spec := release.Spec()
	if spec.ServiceID != id {
		return v, fmt.Errorf("release belongs to another service")
	}
	v.Active = st.CurrentReleaseID == rid
	fail := func(key, reason string) {
		v.Checks[key] = "unavailable"
		v.Reasons = append(v.Reasons, reason)
		v.CanApply = false
	}
	retired, e := m.isRetired(ctx, "retired_release", rid)
	if e != nil {
		return v, e
	}
	if retired {
		fail("policy", "release has been retired")
	} else if spec.PolicyRevision != s.PolicyRevision || spec.FileMapRevision != s.FileMapRevision {
		fail("policy", "release policy is incompatible with the approved service")
	} else {
		v.Checks["policy"] = "available"
	}
	snap, e := m.loadSnapshot(ctx, spec.SnapshotID)
	if e != nil || snap.ServiceID != id || snap.ManifestDigest != spec.TreeDigest {
		fail("files", "verified release snapshot is unavailable")
	} else {
		v.Checks["files"] = "available"
	}
	if _, e = m.LoadConfiguration(ctx, spec.ConfigurationDigest); e != nil {
		fail("configuration", "frozen launch configuration unavailable")
	} else {
		v.Checks["configuration"] = "available"
	}
	v.Checks["secrets"] = "available"
	for _, ref := range spec.Secrets {
		if m.Vault == nil {
			fail("secrets", "release secret versions cannot be checked")
			break
		}
		if _, e = m.Vault.Read(ref); e != nil {
			fail("secrets", "one or more release secret versions are unavailable")
			break
		}
	}
	v.Checks["images"] = "available"
	if m.Engine == nil {
		fail("images", "Docker image inspection unavailable")
	} else {
		for _, image := range spec.Images {
			info, e := m.Engine.Client.ImageInspect(ctx, string(image.ImageID))
			if e != nil || info.ID != string(image.ImageID) {
				fail("images", "one or more exact local release images are unavailable")
				break
			}
		}
	}
	drift := m.driftObservation(ctx, s, st)
	v.Checks["active_tree"] = drift.State
	if drift.State != "unchanged" {
		fail("active_tree", "active tree drift must be resolved or observed before switching")
		v.Active = false
	}
	v.Checks["runtime"] = "unknown"
	if m.Engine != nil {
		inventory, e := m.Engine.Inventory(ctx, s.ComposeProject)
		if e != nil {
			fail("runtime", "actual runtime cannot be inspected")
			v.Active = false
		} else {
			observation := transport.ServiceDetails{Containers: inventory, CurrentReleaseID: st.CurrentReleaseID}
			m.detailObservations(ctx, s, st, &observation)
			if observation.CurrentReleaseID == "" {
				fail("runtime", "actual runtime does not match the last recorded active release")
				v.Active = false
			} else {
				v.Checks["runtime"] = "available"
			}
		}
	}
	codeBindLossAccepted := false
	for _, d := range s.DataPaths {
		codeBindLossAccepted = codeBindLossAccepted || d.AllowCodeUpdates
		if d.Significant {
			v.DataConfirmationRequired = true
		}
	}
	v.Checks["data"] = "unchanged_by_rollback"
	if v.DataConfirmationRequired {
		v.Checks["data"] = "confirmation_required"
	}
	if codeBindLossAccepted {
		v.Checks["data"] = "code_bind_loss_accepted"
		if v.DataConfirmationRequired {
			v.Checks["data"] = "confirmation_required_and_code_bind_loss_accepted"
		}
	}
	operations, e := m.Store.ListOperations(ctx)
	if e != nil {
		return v, e
	}
	for _, op := range operations {
		if op.Spec.ServiceID == id && op.Spec.ReleaseID == rid {
			v.Runs = append(v.Runs, transport.ReleaseRun{OperationID: op.Spec.ID, Action: op.Spec.Kind, State: op.State, At: op.UpdatedAt, Reason: op.Outcome.Reason})
		}
	}
	records, e := m.Store.List(ctx, "check_observation", id)
	if e != nil {
		return v, e
	}
	for _, record := range records {
		var check checkObservation
		if e = json.Unmarshal(record.Payload, &check); e != nil {
			return v, e
		}
		if check.ReleaseID == rid {
			v.LocalChecks = append(v.LocalChecks, transport.ReleaseCheck{At: record.CreatedAt, Signals: check.Signals})
		}
	}
	manual, e := m.Store.List(ctx, "manual_health", id)
	if e != nil {
		return v, e
	}
	for _, record := range manual {
		var check transport.ManualHealthView
		if e = json.Unmarshal(record.Payload, &check); e != nil {
			return v, e
		}
		if check.ReleaseID == rid {
			v.ManualConfirmations = append(v.ManualConfirmations, transport.ManualReleaseConfirmation{At: check.ObservedAt, Actor: check.Actor, Comment: check.Comment, State: check.State, ValidUntil: check.ValidUntil})
		}
	}
	if len(v.Runs) > 50 {
		v.Runs = v.Runs[len(v.Runs)-50:]
	}
	if len(v.LocalChecks) > 50 {
		v.LocalChecks = v.LocalChecks[len(v.LocalChecks)-50:]
	}
	if len(v.ManualConfirmations) > 50 {
		v.ManualConfirmations = v.ManualConfirmations[len(v.ManualConfirmations)-50:]
	}
	return v, nil
}
