package snapshots

import "os"

// Darwin is a development platform. Linux verifies statx mount IDs as well.
func deletionMount(file *os.File) (uint64, error) { return 0, nil }

func sameDeletionFilesystem(device, expectedDevice, mount, expectedMount uint64) bool {
	return device == expectedDevice && mount == expectedMount
}
