package snapshots

import (
	"context"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

// Remove removes an unreferenced snapshot after the caller has durably recorded
// its retention tombstone. The caller owns reference-graph checks and must hold
// its operation/retention lock. Complete artifacts are fully verified before a
// same-directory rename publishes a private, crash-resumable trash entry.
// Missing artifacts are success; incomplete or unsafe live artifacts are kept.
func (s *Store) Remove(ctx context.Context, id domain.ID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := id.Validate(); err != nil {
		return err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	name, trash := string(id), ".trash-"+string(id)
	live, liveErr := s.root.Lstat(name)
	trashed, trashErr := s.root.Lstat(trash)
	if liveErr != nil && !os.IsNotExist(liveErr) {
		return liveErr
	}
	if trashErr != nil && !os.IsNotExist(trashErr) {
		return trashErr
	}
	if liveErr == nil && trashErr == nil {
		return fmt.Errorf("snapshot and its trash entry both exist")
	}
	if os.IsNotExist(liveErr) && os.IsNotExist(trashErr) {
		return nil
	}
	if liveErr == nil {
		if !live.IsDir() || live.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("invalid snapshot directory")
		}
		if _, err := s.Load(ctx, id); err != nil {
			return fmt.Errorf("snapshot deletion verification: %w", err)
		}
		if err := s.inspectRemoval(ctx, name, false); err != nil {
			return err
		}
		after, err := s.root.Lstat(name)
		if err != nil || !os.SameFile(live, after) {
			return fmt.Errorf("snapshot directory changed before quarantine")
		}
		if err = s.root.Rename(name, trash); err != nil {
			return err
		}
		if err = syncDirectory(s.root); err != nil {
			return err
		}
	} else if !trashed.IsDir() || trashed.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("invalid snapshot trash directory")
	}
	// Validate the whole remaining tree before removing any of its entries. A
	// corruption error leaves the quarantine reachable for operator inspection.
	if err := s.inspectRemoval(ctx, trash, false); err != nil {
		return err
	}
	if err := s.inspectRemoval(ctx, trash, true); err != nil {
		return err
	}
	if err := s.root.Remove(trash); err != nil {
		return err
	}
	return syncDirectory(s.root)
}

type deletionIdentity struct {
	device uint64
	mount  uint64
}

func deletionCheck(file *os.File, before os.FileInfo, expected deletionIdentity) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(before, info) || before.Mode() != info.Mode() {
		return fmt.Errorf("snapshot deletion entry replaced")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("unsupported snapshot filesystem metadata")
	}
	mount, err := deletionMount(file)
	if err != nil {
		return err
	}
	if !sameDeletionFilesystem(uint64(stat.Dev), expected.device, mount, expected.mount) {
		return fmt.Errorf("snapshot deletion mount boundary")
	}
	mode := os.FileMode(0400)
	if info.IsDir() {
		mode = 0700
	} else if !info.Mode().IsRegular() || stat.Nlink != 1 {
		return fmt.Errorf("snapshot deletion rejects links and special files")
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("snapshot deletion rejects special permission bits")
	}
	return protected(info, mode)
}

func (s *Store) inspectRemoval(ctx context.Context, name string, remove bool) error {
	store, err := s.root.Open(".")
	if err != nil {
		return err
	}
	info, err := store.Stat()
	if err != nil {
		store.Close()
		return err
	}
	if err = protected(info, 0700); err != nil {
		store.Close()
		return err
	}
	mount, err := deletionMount(store)
	store.Close()
	if err != nil {
		return err
	}
	identity := deletionIdentity{device: uint64(info.Sys().(*syscall.Stat_t).Dev), mount: mount}
	before, err := s.root.Lstat(name)
	if err != nil {
		return err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("snapshot deletion requires a real directory")
	}
	artifact, err := s.root.OpenRoot(name)
	if err != nil {
		return err
	}
	defer artifact.Close()
	if err = walkRemoval(ctx, artifact, before, identity, remove); err != nil {
		return err
	}
	after, err := s.root.Lstat(name)
	if err != nil || !os.SameFile(before, after) {
		return fmt.Errorf("snapshot deletion root replaced")
	}
	return nil
}

func walkRemoval(ctx context.Context, root *os.Root, before os.FileInfo, identity deletionIdentity, remove bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	file, err := root.Open(".")
	if err != nil {
		return err
	}
	defer file.Close()
	if err = deletionCheck(file, before, identity); err != nil {
		return err
	}
	// Read all names first: deleting entries while advancing a directory stream
	// can otherwise skip entries on some filesystems. An entry list has no data.
	entries, err := file.ReadDir(-1)
	if err != nil && err != io.EOF {
		return err
	}
	for _, entry := range entries {
		if err = ctx.Err(); err != nil {
			return err
		}
		info, err := root.Lstat(entry.Name())
		if err != nil {
			return err
		}
		if info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			child, err := root.OpenRoot(entry.Name())
			if err != nil {
				return err
			}
			err = walkRemoval(ctx, child, info, identity, remove)
			child.Close()
			if err != nil {
				return err
			}
		} else {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("snapshot deletion rejects links and special files")
			}
			child, err := root.OpenFile(entry.Name(), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
			if err != nil {
				return err
			}
			err = deletionCheck(child, info, identity)
			child.Close()
			if err != nil {
				return err
			}
		}
		after, err := root.Lstat(entry.Name())
		if err != nil || !os.SameFile(info, after) || after.Mode() != info.Mode() {
			return fmt.Errorf("snapshot deletion entry replaced before unlink")
		}
		if remove {
			if err = root.Remove(entry.Name()); err != nil {
				return err
			}
		}
	}
	if remove {
		return file.Sync()
	}
	return nil
}
