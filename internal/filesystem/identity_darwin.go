package filesystem

import (
	"os"
	"syscall"
)

func changeTime(stat *syscall.Stat_t) int64 { return stat.Ctimespec.Sec*1e9 + stat.Ctimespec.Nsec }

// Darwin is a development/test platform. Production Linux additionally checks
// statx mount IDs, including bind mounts which do not change device identity.
func mountIdentity(file *os.File) (uint64, error) { return 0, nil }

func sameBoundary(rootDevice, _, fileDevice, _ uint64) bool {
	return rootDevice == fileDevice
}
