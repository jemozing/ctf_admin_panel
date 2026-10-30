//go:build darwin

package transport

import (
	"golang.org/x/sys/unix"
)

func readPeer(fd int) (Principal, error) {
	credentials, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return Principal{}, err
	}
	return Principal{UID: credentials.Uid, GID: credentials.Groups[0]}, nil
}
