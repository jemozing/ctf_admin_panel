//go:build linux || darwin

package filesystem

import (
	"fmt"
	"os"
	"syscall"
)

type identity struct {
	device, inode, links    uint64
	uid, gid                uint32
	mode                    os.FileMode
	size, modified, changed int64
}

func identify(info os.FileInfo) (identity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return identity{}, fmt.Errorf("unsupported filesystem metadata")
	}
	return identity{device: uint64(stat.Dev), inode: uint64(stat.Ino), links: uint64(stat.Nlink),
		uid: stat.Uid, gid: stat.Gid, mode: info.Mode(), size: info.Size(),
		modified: info.ModTime().UnixNano(), changed: changeTime(stat)}, nil
}

const noFollowFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK
