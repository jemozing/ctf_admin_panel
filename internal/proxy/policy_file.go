package proxy

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ctf-service-manager/ctf-service-manager/internal/maintenance"
)

// LoadPolicyFile reads nonsecret, administrator-controlled desired policy. The
// runtime state/LKG reader remains stricter (private 0600 files).
func LoadPolicyFile(path string) (Policy, error) {
	var p Policy
	st, err := os.Lstat(path)
	if err != nil {
		return p, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || st.Size() > MaxPolicyBytes {
		return p, errors.New("desired policy must be a bounded non-writable regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return p, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(st, opened) {
		return p, errors.New("desired policy replaced while opening")
	}
	d := json.NewDecoder(io.LimitReader(f, MaxPolicyBytes+1))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF {
		return p, errors.New("invalid desired policy JSON")
	}
	return NormalizePolicy(p)
}

func LockPolicyDirectory(directory string) (func(), error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("absolute policy directory required")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("trusted policy parent required")
	}
	nested := filepath.Join(directory, ".control-lock")
	if err := os.Mkdir(nested, 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	lock, err := maintenance.Acquire(nested, true)
	if err != nil {
		return nil, err
	}
	return func() { _ = lock.Close() }, nil
}

// WriteDesiredPolicy preserves ownership/mode and refuses a changed input file.
// The caller holds LockPolicyDirectory for read/CAS/write as one transaction.
func WriteDesiredPolicy(path string, p Policy, expectedDigest string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("absolute desired policy path required")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 {
		return errors.New("unsafe desired policy file")
	}
	current, err := LoadPolicyFile(path)
	if err != nil || PolicyDigest(current) != expectedDigest {
		return errors.New("desired policy changed; inspect it again")
	}
	normalized, err := NormalizePolicy(p)
	if err != nil {
		return err
	}
	if normalized.Revision <= current.Revision {
		return errors.New("desired revision must increase")
	}
	dir := filepath.Dir(path)
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
		return errors.New("desired policy parent must be trusted and real")
	}
	f, err := os.CreateTemp(dir, ".proxy-emergency-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	owner, ok := before.Sys().(*syscall.Stat_t)
	if !ok {
		_ = f.Close()
		return errors.New("cannot preserve desired policy ownership")
	}
	if err = f.Chown(int(owner.Uid), int(owner.Gid)); err == nil {
		err = f.Chmod(before.Mode().Perm())
	}
	if err == nil {
		err = json.NewEncoder(f).Encode(normalized)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		return errors.New("desired policy changed during emergency edit")
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
