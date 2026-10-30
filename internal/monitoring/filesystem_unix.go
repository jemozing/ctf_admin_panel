//go:build linux || darwin

package monitoring

import (
	"fmt"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"golang.org/x/sys/unix"
	"math"
	"syscall"
)

func filesystemCapacity(path string, result *transport.HostFilesystemMetrics) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var stat syscall.Statfs_t
	if err = syscall.Fstatfs(fd, &stat); err != nil {
		return err
	}
	block := uint64(stat.Bsize)
	if stat.Bsize <= 0 || stat.Blocks > math.MaxUint64/block || stat.Bavail > math.MaxUint64/block {
		return fmt.Errorf("invalid filesystem capacity")
	}
	total, available := stat.Blocks*block, stat.Bavail*block
	result.TotalBytes = &total
	result.AvailableBytes = &available
	if stat.Files != 0 {
		totalInodes, availableInodes := stat.Files, stat.Ffree
		result.TotalInodes = &totalInodes
		result.AvailableInodes = &availableInodes
	}
	return nil
}
