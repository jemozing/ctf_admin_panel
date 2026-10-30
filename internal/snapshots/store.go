// Package snapshots stores immutable, verified filesystem artifacts. SQLite
// references may be committed only after Create returns; incomplete directories
// are never accepted by Load as complete snapshots.
package snapshots

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/filesystem"
)

type Store struct {
	directory string
	root      *os.Root
	mutex     sync.Mutex
}

func NewStore(directory string) (*Store, error) {
	if err := domain.ValidateAbsolutePath(filepath.ToSlash(directory)); err != nil {
		return nil, err
	}
	if err := os.Mkdir(directory, 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	before, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("snapshot store must be a real directory")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	file, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, err
	}
	info, err := file.Stat()
	file.Close()
	if err != nil || !os.SameFile(before, info) {
		root.Close()
		return nil, fmt.Errorf("snapshot store replaced during open")
	}
	if err = protected(info, 0700); err != nil {
		root.Close()
		return nil, err
	}
	return &Store{directory: directory, root: root}, nil
}

func protected(info os.FileInfo, mode os.FileMode) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != mode {
		return fmt.Errorf("snapshot artifact must be executor-owned mode %04o", mode)
	}
	return nil
}

func (s *Store) Close() error { return s.root.Close() }

func (s *Store) ContentPath(id domain.ID) (string, error) {
	if err := id.Validate(); err != nil {
		return "", err
	}
	return filepath.Join(s.directory, string(id), "content"), nil
}

// Create reserves a new ID without replacement. Failures intentionally leave an
// incomplete directory for recovery; neither source files nor active data are
// deleted. The final snapshot.json appears only after content is synced.
func (s *Store) Create(ctx context.Context, metadata domain.Snapshot, source string, managed []domain.ManagedPath, exclusions []string) (domain.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return domain.Snapshot{}, err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	metadata.State = domain.SnapshotCreating
	if err := metadata.Validate(); err != nil {
		return domain.Snapshot{}, err
	}
	storePath, err := filepath.EvalSymlinks(s.directory)
	if err != nil {
		return domain.Snapshot{}, err
	}
	sourcePath, err := filepath.EvalSymlinks(source)
	if err != nil {
		return domain.Snapshot{}, err
	}
	if domain.PathsOverlap(filepath.ToSlash(storePath), filepath.ToSlash(sourcePath)) {
		return domain.Snapshot{}, fmt.Errorf("snapshot store overlaps managed source")
	}
	name := string(metadata.ID)
	if err = s.root.Mkdir(name, 0700); err != nil {
		return domain.Snapshot{}, err
	}
	content, _ := s.ContentPath(metadata.ID)
	manifest, err := filesystem.Capture(ctx, source, content, managed, exclusions)
	if err != nil {
		return domain.Snapshot{}, err
	}
	metadata.Manifest = manifest
	metadata.ManifestDigest = manifest.Digest()
	metadata.State = domain.SnapshotComplete
	if err = metadata.Validate(); err != nil {
		return domain.Snapshot{}, err
	}
	if err = filesystem.Verify(ctx, content, manifest); err != nil {
		return domain.Snapshot{}, err
	}
	artifact, err := s.root.OpenRoot(name)
	if err != nil {
		return domain.Snapshot{}, err
	}
	defer artifact.Close()
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return domain.Snapshot{}, err
	}
	temporary := ".metadata-" + hex.EncodeToString(random[:])
	file, err := artifact.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return domain.Snapshot{}, err
	}
	defer func() { file.Close(); _ = artifact.Remove(temporary) }()
	if err = json.NewEncoder(file).Encode(metadata); err != nil {
		return domain.Snapshot{}, err
	}
	if err = file.Chmod(0400); err != nil {
		return domain.Snapshot{}, err
	}
	if err = file.Sync(); err != nil {
		return domain.Snapshot{}, err
	}
	if err = file.Close(); err != nil {
		return domain.Snapshot{}, err
	}
	if err = artifact.Rename(temporary, "snapshot.json"); err != nil {
		return domain.Snapshot{}, err
	}
	if err = syncDirectory(artifact); err != nil {
		return domain.Snapshot{}, err
	}
	if err = syncDirectory(s.root); err != nil {
		return domain.Snapshot{}, err
	}
	return metadata, nil
}

func syncDirectory(root *os.Root) error {
	file, err := root.Open(".")
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func (s *Store) Load(ctx context.Context, id domain.ID) (domain.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return domain.Snapshot{}, err
	}
	if err := id.Validate(); err != nil {
		return domain.Snapshot{}, err
	}
	before, err := s.root.Lstat(string(id))
	if err != nil {
		return domain.Snapshot{}, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return domain.Snapshot{}, fmt.Errorf("invalid snapshot directory")
	}
	if err = protected(before, 0700); err != nil {
		return domain.Snapshot{}, err
	}
	artifact, err := s.root.OpenRoot(string(id))
	if err != nil {
		return domain.Snapshot{}, err
	}
	defer artifact.Close()
	info, err := artifact.Lstat("snapshot.json")
	if err != nil {
		return domain.Snapshot{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return domain.Snapshot{}, fmt.Errorf("invalid snapshot metadata file")
	}
	if info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return domain.Snapshot{}, fmt.Errorf("hard-linked snapshot metadata is not allowed")
	}
	if err = protected(info, 0400); err != nil {
		return domain.Snapshot{}, err
	}
	file, err := artifact.OpenFile("snapshot.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return domain.Snapshot{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return domain.Snapshot{}, err
	}
	if !os.SameFile(info, opened) {
		return domain.Snapshot{}, fmt.Errorf("snapshot metadata replaced")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 64<<20))
	decoder.DisallowUnknownFields()
	var snapshot domain.Snapshot
	if err = decoder.Decode(&snapshot); err != nil {
		return domain.Snapshot{}, err
	}
	var trailing any
	if err = decoder.Decode(&trailing); err != io.EOF {
		return domain.Snapshot{}, fmt.Errorf("trailing snapshot metadata")
	}
	if snapshot.ID != id || snapshot.State != domain.SnapshotComplete {
		return domain.Snapshot{}, fmt.Errorf("snapshot incomplete or wrong ID")
	}
	if err = snapshot.Validate(); err != nil {
		return domain.Snapshot{}, err
	}
	content, _ := s.ContentPath(id)
	if err = filesystem.Verify(ctx, content, snapshot.Manifest); err != nil {
		return domain.Snapshot{}, err
	}
	return snapshot, nil
}
