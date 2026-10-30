package storage

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

// RemovePrivateTree removes one recorded executor allocation. Callers must hold
// their allocation/operation gate and prove from durable receipts that the child
// is unpublished and no writer or runtime bind references it. This function
// deliberately cannot infer that authorization from an orphan-looking name.
// Only owned 0700 directories and single-link 0400/0600 regular files are
// accepted. A private .trash-<name> entry makes cleanup restartable after a crash.
func RemovePrivateTree(ctx context.Context, directory, name string) error {
	return removePrivateTree(ctx, directory, name, false)
}

// RemoveStagingTree accepts recorded build contexts whose inner ordinary modes
// were restored from the manifest, including executable files. Its parent and
// allocation root must remain owned 0700; all descendants must remain owned by
// the executor and free of links, special files and privileged permissions.
// The same durable receipt and idle-writer preconditions as RemovePrivateTree
// apply. This function never changes file permissions to force deletion.
func RemoveStagingTree(ctx context.Context, directory, name string) error {
	return removePrivateTree(ctx, directory, name, true)
}

func removePrivateTree(ctx context.Context, directory, name string, ordinary bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := domain.ValidateAbsolutePath(directory); err != nil {
		return err
	}
	if err := domain.ID(name).Validate(); err != nil {
		return err
	}
	before, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: private allocation parent is not a real directory", ErrUnsafeTree)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := root.Open(".")
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}
	mount, err := mountIdentity(file)
	file.Close()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: unsupported filesystem metadata", ErrUnsafeTree)
	}
	identity := treeIdentity{device: uint64(stat.Dev), mount: mount}
	if !os.SameFile(before, info) {
		return fmt.Errorf("%w: private allocation parent replaced", ErrUnsafeTree)
	}
	if err = privateProtection(info, false); err != nil {
		return err
	}
	trash := ".trash-" + name
	live, liveErr := root.Lstat(name)
	trashed, trashErr := root.Lstat(trash)
	if liveErr != nil && !os.IsNotExist(liveErr) {
		return liveErr
	}
	if trashErr != nil && !os.IsNotExist(trashErr) {
		return trashErr
	}
	if liveErr == nil && trashErr == nil {
		return fmt.Errorf("private allocation and trash both exist")
	}
	if os.IsNotExist(liveErr) && os.IsNotExist(trashErr) {
		return nil
	}
	if liveErr == nil {
		if err = privateChild(ctx, root, name, live, identity, false, ordinary, true); err != nil {
			return err
		}
		after, err := root.Lstat(name)
		if err != nil || !os.SameFile(live, after) {
			return fmt.Errorf("%w: allocation replaced before quarantine", ErrUnsafeTree)
		}
		if err = root.Rename(name, trash); err != nil {
			return err
		}
		if err = syncPrivateDirectory(root); err != nil {
			return err
		}
		trashed, err = root.Lstat(trash)
		if err != nil {
			return err
		}
	}
	if err = privateChild(ctx, root, trash, trashed, identity, false, ordinary, true); err != nil {
		return err
	}
	if err = privateChild(ctx, root, trash, trashed, identity, true, ordinary, true); err != nil {
		return err
	}
	if err = root.Remove(trash); err != nil {
		return err
	}
	return syncPrivateDirectory(root)
}

func privateProtection(info os.FileInfo, ordinary bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("%w: allocation ownership or permissions", ErrUnsafeTree)
	}
	if ordinary && (info.IsDir() || info.Mode().IsRegular() && stat.Nlink == 1) {
		return nil
	}
	if info.IsDir() && info.Mode().Perm() == 0700 {
		return nil
	}
	if info.Mode().IsRegular() && stat.Nlink == 1 && (info.Mode().Perm() == 0400 || info.Mode().Perm() == 0600) {
		return nil
	}
	return fmt.Errorf("%w: allocation must contain private directories and regular files (mode %04o)", ErrUnsafeTree, info.Mode().Perm())
}

func privateOpened(file *os.File, before os.FileInfo, identity treeIdentity, ordinary bool) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(before, info) || before.Mode() != info.Mode() {
		return fmt.Errorf("%w: allocation entry replaced", ErrUnsafeTree)
	}
	if err = privateProtection(info, ordinary); err != nil {
		return err
	}
	if err = rejectCapabilities(file); err != nil {
		return err
	}
	mount, err := mountIdentity(file)
	if err != nil {
		return err
	}
	stat := info.Sys().(*syscall.Stat_t)
	if !sameFilesystem(uint64(stat.Dev), identity.device, mount, identity.mount) {
		return fmt.Errorf("%w: allocation filesystem or mount boundary", ErrUnsafeTree)
	}
	return nil
}

func privateChild(ctx context.Context, parent *os.Root, name string, before os.FileInfo, identity treeIdentity, remove, ordinary, top bool) error {
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: allocation root must be a real directory", ErrUnsafeTree)
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return err
	}
	defer root.Close()
	if err = walkPrivate(ctx, root, before, identity, remove, ordinary, top); err != nil {
		return err
	}
	after, err := parent.Lstat(name)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		return fmt.Errorf("%w: allocation root replaced", ErrUnsafeTree)
	}
	return nil
}

func walkPrivate(ctx context.Context, root *os.Root, before os.FileInfo, identity treeIdentity, remove, ordinary, top bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	file, err := root.Open(".")
	if err != nil {
		return err
	}
	defer file.Close()
	if err = privateOpened(file, before, identity, ordinary && !top); err != nil {
		return err
	}
	entries, err := file.ReadDir(-1)
	if err != nil {
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
			if err = privateChild(ctx, root, entry.Name(), info, identity, remove, ordinary, false); err != nil {
				return err
			}
		} else {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("%w: allocation symlink or special file", ErrUnsafeTree)
			}
			child, err := root.OpenFile(entry.Name(), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
			if err != nil {
				return err
			}
			err = privateOpened(child, info, identity, ordinary)
			child.Close()
			if err != nil {
				return err
			}
		}
		after, err := root.Lstat(entry.Name())
		if err != nil || !os.SameFile(info, after) || info.Mode() != after.Mode() {
			return fmt.Errorf("%w: allocation entry replaced before unlink", ErrUnsafeTree)
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

func syncPrivateDirectory(root *os.Root) error {
	file, err := root.Open(".")
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
