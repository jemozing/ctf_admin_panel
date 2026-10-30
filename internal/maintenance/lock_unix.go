//go:build linux || darwin

// Package maintenance coordinates offline exports with every process that opens
// panel state. Locks live outside SQLite so both databases can be frozen together.
package maintenance

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

var ErrActive = errors.New("panel state is in use; stop dashboard and executor before maintenance")

type Lock struct {
	file *os.File
	once sync.Once
	err  error
}

// Acquire never follows a lock-file symlink. Exclusive locks fail immediately
// while an application holds its lifetime shared lock; they never stop a job.
func Acquire(directory string, exclusive bool) (*Lock, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "/" {
		return nil, errors.New("maintenance state path must be canonical and absolute")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("maintenance state directory must be private and cannot be a symlink")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("state ownership is unavailable")
	}
	filename := filepath.Join(directory, ".maintenance.lock")
	fd, err := syscall.Open(filename, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), filename)
	fail := func(err error) (*Lock, error) { _ = f.Close(); return nil, err }
	stat, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	st, ok := stat.Sys().(*syscall.Stat_t)
	if !ok || !stat.Mode().IsRegular() || stat.Mode().Perm() != 0600 || st.Nlink != 1 {
		return fail(errors.New("maintenance lock must be a private regular file with one link"))
	}
	if st.Uid != owner.Uid {
		// A host root export may initialize a lock for the dashboard UID. Keep
		// that file usable by the unprivileged dashboard after maintenance.
		if os.Geteuid() != 0 || st.Uid != 0 {
			return fail(errors.New("maintenance lock owner does not match state owner"))
		}
		if err := f.Chown(int(owner.Uid), int(owner.Gid)); err != nil {
			return fail(err)
		}
	}
	operation := syscall.LOCK_SH
	if exclusive {
		operation = syscall.LOCK_EX
	}
	if err := syscall.Flock(fd, operation|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return fail(ErrActive)
		}
		return fail(fmt.Errorf("maintenance lock: %w", err))
	}
	return &Lock{file: f}, nil
}

func (l *Lock) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() { l.err = errors.Join(syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN), l.file.Close()) })
	return l.err
}
