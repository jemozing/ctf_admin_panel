package filesystem

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func changeTime(stat *syscall.Stat_t) int64 { return stat.Ctim.Sec*1e9 + stat.Ctim.Nsec }

// Unlike st_dev, a mount ID also distinguishes same-filesystem bind mounts.
// Unsupported kernels fail closed rather than silently traversing such mounts.
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

// OverlayFS may report a different st_dev for directories and regular files in
// one mount. Linux mount IDs identify the namespace boundary without rejecting
// those legitimate objects. Per-inode before/after checks still compare st_dev.
// https://www.kernel.org/doc/html/latest/filesystems/overlayfs.html
func sameBoundary(_, rootMount, _, fileMount uint64) bool {
	return rootMount != 0 && fileMount == rootMount
}
