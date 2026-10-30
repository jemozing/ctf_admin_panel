//go:build !linux && !darwin

package transport

import "fmt"

func readPeer(fd int) (Principal, error) {
	return Principal{}, fmt.Errorf("peer credentials unsupported on this operating system")
}
