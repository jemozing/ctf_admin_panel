package snapshots

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func deletionMount(file *os.File) (uint64, error) {
	var stat unix.Statx_t
	if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &stat); err != nil {
		return 0, fmt.Errorf("statx snapshot deletion mount: %w", err)
	}
	if stat.Mask&unix.STATX_MNT_ID == 0 {
		return 0, fmt.Errorf("kernel does not report snapshot deletion mount IDs")
	}
	return stat.Mnt_id, nil
}

func sameDeletionFilesystem(device, expectedDevice, mount, expectedMount uint64) bool {
	return mount == expectedMount
}
