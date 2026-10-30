package storage

import (
	"errors"
	"fmt"
	"math"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func mountIdentity(file *os.File) (uint64, error) {
	var stat unix.Statx_t
	if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &stat); err != nil {
		return 0, fmt.Errorf("statx mount identity: %w", err)
	}
	if stat.Mask&unix.STATX_MNT_ID == 0 {
		return 0, fmt.Errorf("kernel does not report mount IDs")
	}
	return stat.Mnt_id, nil
}

func inspectRegularMetadata(root *os.Root, name string, before os.FileInfo, identity *treeIdentity) (os.FileInfo, error) {
	// O_PATH pins metadata without opening the inode for I/O. Linux does not
	// remove POSIX record locks when such a path descriptor is closed. Normal
	// O_RDONLY descriptors would silently strip SQLite DB/SHM locks owned by
	// this process, allowing another connection to unlink the live sidecars.
	file, err := root.OpenFile(name, unix.O_PATH|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return inspect(file, before, identity)
}

// OverlayFS can report differing st_dev values for entries on one mount.
// Mandatory statx mount IDs distinguish nested binds without this false reject.
func sameFilesystem(device, expectedDevice, mount, expectedMount uint64) bool {
	return mount == expectedMount
}

func rejectCapabilities(file *os.File) error {
	_, err := unix.Fgetxattr(int(file.Fd()), "security.capability", nil)
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("%w: allocation has file capabilities", ErrUnsafeTree)
}

func capacity(file *os.File) (Space, error) {
	var stat syscall.Statfs_t
	if err := syscall.Fstatfs(int(file.Fd()), &stat); err != nil {
		return Space{}, err
	}
	blockSize := stat.Frsize
	if blockSize <= 0 {
		blockSize = stat.Bsize
	}
	if blockSize <= 0 || stat.Bavail != 0 && uint64(blockSize) > math.MaxUint64/stat.Bavail {
		return Space{}, fmt.Errorf("invalid filesystem capacity")
	}
	return Space{AvailableBytes: stat.Bavail * uint64(blockSize), AvailableInodes: stat.Ffree, InodesKnown: stat.Files != 0}, nil
}
