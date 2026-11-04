package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/filesystem"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

type editableCompose struct {
	document transport.ComposeDocument
	snapshot domain.Snapshot
	root     string
}

func (m *Manager) ComposeDocument(ctx context.Context, id domain.ID) (transport.ComposeDocument, error) {
	s, err := m.Store.GetService(ctx, id)
	if err != nil {
		return transport.ComposeDocument{}, err
	}
	st, err := m.state(ctx, s)
	if err != nil {
		return transport.ComposeDocument{}, err
	}
	edited, err := m.editableCompose(ctx, s, st)
	return edited.document, err
}

func (m *Manager) editableCompose(ctx context.Context, s domain.Service, st runtimeState) (editableCompose, error) {
	var result editableCompose
	if st.CurrentReleaseID == "" {
		return result, &transport.ComposeEditorError{Message: "import a baseline release before editing Compose"}
	}
	if len(s.ComposeFiles) == 0 || slices.ContainsFunc(strings.Split(s.ComposeFiles[0], "/"), sensitiveRegistrationName) {
		return result, &transport.ComposeEditorError{Message: "the primary Compose input is not available for editing"}
	}
	approved, err := m.approvedComposeSnapshot(ctx, s, st)
	if err != nil {
		return result, err
	}
	name := s.ComposeFiles[0]
	entry := composeFileEntries(approved.Manifest, s.ComposeFiles)[name]
	if entry.Type != domain.EntryFile || entry.Size > transport.MaxComposeDraftBytes {
		return result, &transport.ComposeEditorError{Message: "the primary Compose input must be a managed regular file of at most 128 KiB"}
	}
	root, err := m.Snapshots.ContentPath(approved.ID)
	if err != nil {
		return result, err
	}
	data, err := filesystem.ReadVerifiedFile(ctx, root, entry, transport.MaxComposeDraftBytes)
	if err != nil {
		return result, err
	}
	if !utf8.Valid(data) || strings.ContainsRune(string(data), 0) {
		return result, &transport.ComposeEditorError{Message: "the primary Compose input must be UTF-8 text"}
	}
	revision := domain.Hash([]byte(fmt.Sprintf("%s\n%s\n%d\n%s", s.ID, st.CurrentReleaseID, s.PolicyRevision, approved.ManifestDigest)))
	return editableCompose{transport.ComposeDocument{Path: name, Content: string(data), Revision: revision}, approved, root}, nil
}

type reviewedComposeDraft struct {
	source        editableCompose
	manifest      domain.Manifest
	configuration Configuration
	digest        domain.Digest
	changes       []docker.ComposeResourceChange
}

func (m *Manager) reviewComposeDraft(ctx context.Context, s domain.Service, st runtimeState, draft transport.ComposeDraft, current Configuration, currentDigest domain.Digest) (reviewedComposeDraft, error) {
	var result reviewedComposeDraft
	source, err := m.editableCompose(ctx, s, st)
	if err != nil {
		return result, err
	}
	if source.document.Revision != draft.Revision {
		return result, transport.ErrComposeEditorStale
	}
	if source.document.Content == draft.Content {
		return result, &transport.ComposeEditorError{Message: "the draft matches the active Compose file"}
	}
	data := []byte(draft.Content)
	manifest, err := source.snapshot.Manifest.WithFileContents(source.document.Path, data)
	if err != nil {
		return result, err
	}
	overrides := map[string][]byte{source.document.Path: data}
	entries := composeFileEntries(source.snapshot.Manifest, s.ComposeFiles)
	for _, name := range s.ComposeFiles[1:] {
		entry := entries[name]
		if entry.Type != domain.EntryFile || entry.Size > 1<<20 {
			return result, &transport.ComposeEditorError{Message: "every additional Compose input must be a managed regular file of at most 1 MiB"}
		}
		content, err := filesystem.ReadVerifiedFile(ctx, source.root, entry, 1<<20)
		if err != nil {
			return result, err
		}
		overrides[name] = content
	}
	next, changes, err := m.reviewComposeConfiguration(ctx, s, current, overrides)
	if err != nil {
		var editorError *transport.ComposeEditorError
		var portConflict *transport.ComposePortConflict
		if errors.As(err, &editorError) || errors.As(err, &portConflict) {
			return result, err
		}
		return result, &transport.ComposeEditorError{Message: "Docker Compose could not validate the draft. Check the YAML syntax and supported settings"}
	}
	digest := currentDigest
	if len(changes) != 0 {
		if err := m.checkComposePorts(ctx, s, current.Model, next.Model, composeTargetIDs(s, st.Containers)); err != nil {
			return result, err
		}
		encoded, err := json.Marshal(next)
		if err != nil {
			return result, err
		}
		digest = domain.Hash(encoded)
	}
	return reviewedComposeDraft{source, manifest, next, digest, changes}, nil
}

func (m *Manager) previewComposeDraft(ctx context.Context, s domain.Service, st runtimeState, draft transport.ComposeDraft, result *transport.PreviewResult) (domain.Manifest, error) {
	currentDigest, err := m.activeConfigurationDigest(ctx, s, st)
	if err != nil {
		return domain.Manifest{}, err
	}
	current, err := m.LoadConfiguration(ctx, currentDigest)
	if err != nil {
		return domain.Manifest{}, err
	}
	review, err := m.reviewComposeDraft(ctx, s, st, draft, current, currentDigest)
	if err != nil {
		return domain.Manifest{}, err
	}
	result.ComposeSourceTree = review.manifest.Digest()
	result.ComposeDraftConfiguration = review.digest
	for _, change := range review.changes {
		result.ComposeChanges = append(result.ComposeChanges, transport.ComposeResourceChange(change))
	}
	return review.manifest, nil
}

func (m *Manager) prepareComposeDraftRelease(ctx context.Context, s domain.Service, st runtimeState, op domain.Operation, input operationInput, current Configuration, currentDigest domain.Digest) error {
	draft := *input.Request.ComposeDraft
	review, err := m.reviewComposeDraft(ctx, s, st, draft, current, currentDigest)
	if err != nil {
		return err
	}
	if review.digest != input.Plan.ComposeDraftConfiguration || review.manifest.Digest() != input.Plan.ComposeSourceTree {
		return errors.New("Compose draft or its effective configuration changed after review")
	}
	if review.digest != currentDigest {
		if _, err := m.storeComposeConfiguration(ctx, s, review.configuration); err != nil {
			return err
		}
	}
	metadataBytes, _ := json.Marshal(review.manifest)
	needed := uint64(review.manifest.TotalBytes()) + uint64(len(metadataBytes)) + 4096
	if err := m.preflightAllocation(ctx, filepath.Join(m.Config.StateDirectory, "snapshots"), needed, uint64(len(review.manifest.Entries())+3), m.Config.Storage.Effective().SnapshotMaxBytes); err != nil {
		return err
	}
	id := NewID("snap-")
	if err := m.Store.PutImmutable(ctx, "snapshot_allocation", id, s.ID, allocation{ID: id, OperationID: op.Spec.ID, CreatedAt: time.Now().UTC()}); err != nil {
		return err
	}
	metadata := domain.Snapshot{ID: id, ServiceID: s.ID, CreatedAt: time.Now().UTC(), Author: op.Spec.Initiator, Purpose: domain.SnapshotCandidate, FileMapRevision: s.FileMapRevision, Consistency: review.source.snapshot.Consistency}
	if git := review.source.snapshot.GitSource; git != nil {
		// The code still comes from the same Git commit. The edited file is
		// local to the host and must not enter a Git build context.
		origin := *git
		origin.ComposeRevision = true
		origin.HostComposeInputs = slices.Clone(git.HostComposeInputs)
		if !slices.Contains(origin.HostComposeInputs, review.source.document.Path) {
			origin.HostComposeInputs = append(origin.HostComposeInputs, review.source.document.Path)
		}
		metadata.GitSource = &origin
	}
	candidate, err := m.Snapshots.CloneWithFile(ctx, review.source.snapshot.ID, metadata, s.ManagedPaths, review.source.document.Path, []byte(draft.Content))
	if err != nil {
		return err
	}
	if candidate.ManifestDigest != input.Plan.ComposeSourceTree {
		return errors.New("Compose candidate differs from the reviewed draft")
	}
	if err := m.verifyCapturedQuota(ctx, candidate.ID); err != nil {
		return err
	}
	if err := m.Store.PutImmutable(ctx, "snapshot", candidate.ID, s.ID, candidate); err != nil {
		return err
	}
	return m.buildPreparedCompose(ctx, s, st, op, input, candidate, review.configuration, review.digest)
}
