package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

var ErrUnsafeTree = errors.New("unsafe storage tree")

type treeIdentity struct {
	device uint64
	mount  uint64
}

func inspect(file *os.File, before os.FileInfo, identity *treeIdentity) (os.FileInfo, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	mount, err := mountIdentity(file)
	if err != nil {
		return nil, err
	}
	return inspectMetadata(before, info, identity, mount)
}

func inspectMetadata(before, info os.FileInfo, identity *treeIdentity, mount uint64) (os.FileInfo, error) {
	if !os.SameFile(before, info) || before.Mode() != info.Mode() || before.Size() != info.Size() || !before.ModTime().Equal(info.ModTime()) {
		return nil, fmt.Errorf("%w: entry changed during open", ErrUnsafeTree)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("%w: unsupported filesystem metadata", ErrUnsafeTree)
	}
	if info.Mode().IsRegular() && stat.Nlink != 1 {
		return nil, fmt.Errorf("%w: hard-linked file", ErrUnsafeTree)
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return nil, fmt.Errorf("%w: special permission bits", ErrUnsafeTree)
	}
	if !sameFilesystem(uint64(stat.Dev), identity.device, mount, identity.mount) {
		return nil, fmt.Errorf("%w: filesystem or mount boundary", ErrUnsafeTree)
	}
	return info, nil
}

// Measure counts logical regular-file bytes and all entries, including the root
// directory. Sparse files consume their full logical size. Symlinks, hard links,
// devices, sockets and nested mounts are rejected rather than underestimated.
// Every traversal is descriptor-relative; this function never modifies a tree.
func Measure(ctx context.Context, directory string) (Usage, error) {
	if err := ctx.Err(); err != nil {
		return Usage{}, err
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == string(filepath.Separator) {
		return Usage{}, fmt.Errorf("%w: absolute non-root directory required", ErrUnsafeTree)
	}
	before, err := os.Lstat(directory)
	if err != nil {
		return Usage{}, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return Usage{}, fmt.Errorf("%w: root is not a real directory", ErrUnsafeTree)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return Usage{}, err
	}
	defer root.Close()
	file, err := root.Open(".")
	if err != nil {
		return Usage{}, err
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok {
		file.Close()
		return Usage{}, fmt.Errorf("%w: unsupported filesystem metadata", ErrUnsafeTree)
	}
	mount, err := mountIdentity(file)
	file.Close()
	if err != nil {
		return Usage{}, err
	}
	return measure(ctx, root, before, treeIdentity{device: uint64(stat.Dev), mount: mount})
}

func measure(ctx context.Context, root *os.Root, before os.FileInfo, identity treeIdentity) (Usage, error) {
	if err := ctx.Err(); err != nil {
		return Usage{}, err
	}
	file, err := root.Open(".")
	if err != nil {
		return Usage{}, err
	}
	defer file.Close()
	if _, err = inspect(file, before, &identity); err != nil {
		return Usage{}, err
	}
	usage := Usage{Files: 1}
	for {
		entries, readErr := file.ReadDir(128)
		for _, entry := range entries {
			if err = ctx.Err(); err != nil {
				return Usage{}, err
			}
			info, err := root.Lstat(entry.Name())
			if err != nil {
				return Usage{}, err
			}
			if !info.IsDir() && !info.Mode().IsRegular() {
				return Usage{}, fmt.Errorf("%w: symlink or special file", ErrUnsafeTree)
			}
			var childUsage Usage
			if info.IsDir() {
				child, err := root.OpenRoot(entry.Name())
				if err != nil {
					return Usage{}, err
				}
				childUsage, err = measure(ctx, child, info, identity)
				child.Close()
				if err != nil {
					return Usage{}, err
				}
			} else {
				// Opening and closing an ordinary file descriptor here would
				// drop this process's POSIX locks on an active SQLite DB or SHM.
				opened, err := inspectRegularMetadata(root, entry.Name(), info, &identity)
				if err != nil {
					return Usage{}, err
				}
				if opened.Size() < 0 {
					return Usage{}, fmt.Errorf("%w: negative file size", ErrUnsafeTree)
				}
				childUsage = Usage{Bytes: uint64(opened.Size()), Files: 1}
			}
			after, err := root.Lstat(entry.Name())
			if err != nil || !os.SameFile(info, after) || info.Mode() != after.Mode() || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
				return Usage{}, fmt.Errorf("%w: entry replaced during traversal", ErrUnsafeTree)
			}
			usage.Bytes, err = add(usage.Bytes, childUsage.Bytes)
			if err != nil {
				return Usage{}, err
			}
			usage.Files, err = add(usage.Files, childUsage.Files)
			if err != nil {
				return Usage{}, err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return Usage{}, readErr
		}
	}
	if _, err = inspect(file, before, &identity); err != nil {
		return Usage{}, err
	}
	return usage, nil
}
