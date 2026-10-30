package traffic

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ReadTokenFile never returns token material in an error. Deployment gives each
// role its own private read-only bind; the ingest role cannot read history.
func ReadTokenFile(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("token file must be canonical and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", errors.New("token file unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("token file must be a private regular file")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Nlink != 1 || (int(st.Uid) != os.Geteuid() && os.Geteuid() != 0) {
		return "", errors.New("token ownership unavailable or invalid")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", errors.New("token file unavailable")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0077 != 0 {
		return "", errors.New("token file changed while opening")
	}
	if st, ok := opened.Sys().(*syscall.Stat_t); !ok || st.Nlink != 1 || (int(st.Uid) != os.Geteuid() && os.Geteuid() != 0) {
		return "", errors.New("token file metadata changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, 258))
	if err != nil {
		return "", errors.New("token file cannot be read")
	}
	value := strings.TrimSuffix(string(data), "\n")
	if !validSecret(value) {
		return "", errors.New("token must contain 32..256 non-whitespace bytes")
	}
	return value, nil
}
