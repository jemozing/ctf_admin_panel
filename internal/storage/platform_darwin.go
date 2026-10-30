package storage

import (
	"fmt"
	"math"
	"os"
	"syscall"
)

// Darwin supports development; production Linux also distinguishes bind mounts.
func mountIdentity(file *os.File) (uint64, error) { return 0, nil }

func inspectRegularMetadata(root *os.Root, name string, before os.FileInfo, identity *treeIdentity) (os.FileInfo, error) {
	// Darwin has no O_PATH. Root.Lstat remains descriptor-relative, never
	// follows the final symlink, and does not open/close the regular inode.
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	return inspectMetadata(before, info, identity, 0)
}

func sameFilesystem(device, expectedDevice, mount, expectedMount uint64) bool {
	return device == expectedDevice && mount == expectedMount
}

func rejectCapabilities(file *os.File) error { return nil }

func capacity(file *os.File) (Space, error) {
	var stat syscall.Statfs_t
	if err := syscall.Fstatfs(int(file.Fd()), &stat); err != nil {
		return Space{}, err
	}
	if stat.Bsize == 0 || stat.Bavail != 0 && uint64(stat.Bsize) > math.MaxUint64/stat.Bavail {
		return Space{}, fmt.Errorf("invalid filesystem capacity")
	}
	return Space{AvailableBytes: stat.Bavail * uint64(stat.Bsize), AvailableInodes: stat.Ffree, InodesKnown: stat.Files != 0}, nil
}
