//go:build linux

package transport

import (
	"golang.org/x/sys/unix"
)

func readPeer(fd int) (Principal, error) {
	credentials, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return Principal{}, err
	}
	return Principal{UID: credentials.Uid, GID: credentials.Gid, PID: credentials.Pid}, nil
}
