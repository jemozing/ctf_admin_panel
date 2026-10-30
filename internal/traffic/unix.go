package traffic

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func validateUnixPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 || path == "/" {
		return errors.New("control socket must be a canonical bounded absolute path")
	}
	return nil
}

// ListenPrivateUnix only manages its own socket in an already-created private
// directory. The returned cleanup never removes a replacement socket/file.
func ListenPrivateUnix(path string) (net.Listener, func(), error) {
	noop := func() {}
	if err := validateUnixPath(path); err != nil {
		return nil, noop, err
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0700 {
		return nil, noop, errors.New("control socket directory must already be private")
	}
	if st, ok := parent.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() {
		return nil, noop, errors.New("control socket directory must belong to its process UID")
	}
	if before, err := os.Lstat(path); err == nil {
		st, ok := before.Sys().(*syscall.Stat_t)
		if !ok || before.Mode()&os.ModeSocket == 0 || int(st.Uid) != os.Geteuid() {
			return nil, noop, errors.New("refusing to replace a foreign control socket or file")
		}
		connection, dialErr := net.DialTimeout("unix", path, 200*time.Millisecond)
		if dialErr == nil {
			connection.Close()
			return nil, noop, errors.New("control socket already active")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) && !errors.Is(dialErr, syscall.ENOENT) {
			return nil, noop, errors.New("control socket liveness is unknown")
		}
		current, err := os.Lstat(path)
		if err != nil || !os.SameFile(before, current) {
			return nil, noop, errors.New("control socket changed during stale check")
		}
		if err := os.Remove(path); err != nil {
			return nil, noop, err
		}
	} else if !os.IsNotExist(err) {
		return nil, noop, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, noop, err
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, noop, err
	}
	original, err := os.Lstat(path)
	if err != nil {
		listener.Close()
		return nil, noop, err
	}
	cleanup := func() {
		listener.Close()
		if current, err := os.Lstat(path); err == nil && os.SameFile(original, current) && current.Mode()&os.ModeSocket != 0 {
			_ = os.Remove(path)
		}
	}
	return listener, cleanup, nil
}
