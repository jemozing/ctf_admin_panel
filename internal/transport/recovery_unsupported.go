//go:build !linux && !darwin

package transport

import (
	"errors"
	"os"
)

func lockAndRecover(string) (*os.File, error) {
	return nil, errors.New("socket recovery is unsupported on this platform")
}
func releaseSocketLock(file *os.File) { _ = file.Close() }
