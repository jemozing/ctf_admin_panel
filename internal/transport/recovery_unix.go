//go:build linux || darwin

package transport

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

func lockAndRecover(name string) (*os.File, error) {
	f, err := os.OpenFile(name+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (*os.File, error) { f.Close(); return nil, e }
	info, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0600 || stat.Nlink != 1 {
		return fail(errors.New("executor lock must be a private regular file owned by executor"))
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fail(errors.New("another executor owns the socket lock"))
	}
	existing, err := os.Lstat(name)
	if os.IsNotExist(err) {
		return f, nil
	}
	if err != nil {
		return fail(err)
	}
	old, ok := existing.Sys().(*syscall.Stat_t)
	if !ok || existing.Mode()&os.ModeSocket == 0 || old.Uid != uint32(os.Geteuid()) {
		return fail(errors.New("existing executor socket is not an owned Unix socket"))
	}
	conn, err := net.DialTimeout("unix", name, 300*time.Millisecond)
	if err == nil {
		conn.Close()
		return fail(errors.New("executor socket is active"))
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fail(fmt.Errorf("cannot prove executor socket is stale: %w", err))
	}
	now, err := os.Lstat(name)
	if err != nil || !os.SameFile(existing, now) {
		return fail(errors.New("socket changed during recovery"))
	}
	if err := os.Remove(name); err != nil {
		return fail(err)
	}
	return f, nil
}
func releaseSocketLock(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}
