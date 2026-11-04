package snapshots

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/filesystem"
)

// Clone creates a different immutable artifact from an existing verified one.
// It copies protected files, without materializing them into a workspace or an
// active tree. Original ownership and modes stay in the manifest, rather than
// being replaced with the normalized physical snapshot permissions.
func (s *Store) Clone(ctx context.Context, sourceID domain.ID, metadata domain.Snapshot, managed []domain.ManagedPath) (domain.Snapshot, error) {
	return s.clone(ctx, sourceID, metadata, managed, "", nil)
}

// CloneWithFile creates a new snapshot with one regular file replaced. Both the
// original snapshot and all captured ownership and permissions remain intact.
func (s *Store) CloneWithFile(ctx context.Context, sourceID domain.ID, metadata domain.Snapshot, managed []domain.ManagedPath, name string, data []byte) (domain.Snapshot, error) {
	if err := domain.ValidateRelativePath(name); err != nil {
		return domain.Snapshot{}, err
	}
	return s.clone(ctx, sourceID, metadata, managed, name, data)
}

func (s *Store) clone(ctx context.Context, sourceID domain.ID, metadata domain.Snapshot, managed []domain.ManagedPath, name string, data []byte) (domain.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return domain.Snapshot{}, err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	source, err := s.Load(ctx, sourceID)
	if err != nil {
		return domain.Snapshot{}, err
	}
	metadata.State = domain.SnapshotCreating
	if err := metadata.Validate(); err != nil {
		return domain.Snapshot{}, err
	}
	if metadata.ID == source.ID || metadata.ServiceID != source.ServiceID || metadata.FileMapRevision != source.FileMapRevision {
		return domain.Snapshot{}, errors.New("snapshot clone identity or file-map mismatch")
	}
	manifest := source.Manifest
	if name != "" {
		manifest, err = manifest.WithFileContents(name, data)
		if err != nil {
			return domain.Snapshot{}, err
		}
	}
	if err := s.root.Mkdir(string(metadata.ID), 0700); err != nil {
		return domain.Snapshot{}, err
	}
	from, _ := s.ContentPath(source.ID)
	to, _ := s.ContentPath(metadata.ID)
	physical, err := filesystem.Capture(ctx, from, to, managed, nil)
	if err != nil {
		return domain.Snapshot{}, err
	}
	// Capture validates the selected map, including literal exclusions. A clone
	// may neither widen that map nor silently discard historical paths.
	want, got := source.Manifest.Entries(), physical.Entries()
	if len(want) != len(got) {
		return domain.Snapshot{}, errors.New("snapshot is outside current managed file map")
	}
	for i, a := range want {
		b := got[i]
		if a.Path != b.Path || a.Type != b.Type || a.Size != b.Size || a.Digest != b.Digest || a.LinkTarget != b.LinkTarget {
			return domain.Snapshot{}, errors.New("snapshot clone content or managed paths changed")
		}
	}
	if name != "" {
		if err := replaceClonedFile(to, name, data); err != nil {
			return domain.Snapshot{}, err
		}
	}
	metadata.Manifest = manifest
	metadata.ManifestDigest = manifest.Digest()
	metadata.State = domain.SnapshotComplete
	if err := metadata.Validate(); err != nil {
		return domain.Snapshot{}, err
	}
	if err := filesystem.Verify(ctx, to, metadata.Manifest); err != nil {
		return domain.Snapshot{}, err
	}
	artifact, err := s.root.OpenRoot(string(metadata.ID))
	if err != nil {
		return domain.Snapshot{}, err
	}
	defer artifact.Close()
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return domain.Snapshot{}, err
	}
	temporary := ".metadata-" + hex.EncodeToString(random[:])
	file, err := artifact.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return domain.Snapshot{}, err
	}
	defer func() { file.Close(); _ = artifact.Remove(temporary) }()
	if err := json.NewEncoder(file).Encode(metadata); err != nil {
		return domain.Snapshot{}, err
	}
	if err := file.Chmod(0400); err != nil {
		return domain.Snapshot{}, err
	}
	if err := file.Sync(); err != nil {
		return domain.Snapshot{}, err
	}
	if err := file.Close(); err != nil {
		return domain.Snapshot{}, err
	}
	if err := artifact.Rename(temporary, "snapshot.json"); err != nil {
		return domain.Snapshot{}, err
	}
	if err := syncDirectory(artifact); err != nil {
		return domain.Snapshot{}, err
	}
	if err := syncDirectory(s.root); err != nil {
		return domain.Snapshot{}, err
	}
	return metadata, nil
}

func replaceClonedFile(content, name string, data []byte) error {
	// Capture created the private tree and verified this path as a regular file.
	root, err := os.OpenRoot(content)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.Remove(name); err != nil {
		return err
	}
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Chmod(0400); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	parent, err := root.OpenRoot(path.Dir(name))
	if err != nil {
		return err
	}
	defer parent.Close()
	return syncDirectory(parent)
}
