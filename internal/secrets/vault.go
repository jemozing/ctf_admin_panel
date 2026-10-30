// Package secrets stores immutable executor-owned secret versions. Values never
// belong in release manifests, public reports, or operation logs.
package secrets

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

type Vault struct{ root *os.Root }

func Open(directory string) (*Vault, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("secret directory must be private and must not be a symlink")
	}
	r, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	return &Vault{r}, nil
}
func (v *Vault) Close() error { return v.root.Close() }
func (v *Vault) Import(secretID domain.ID, data []byte) (domain.SecretVersionRef, error) {
	ref := domain.SecretVersionRef{SecretID: secretID}
	if err := secretID.Validate(); err != nil {
		return ref, err
	}
	if len(data) > 1<<20 {
		return ref, errors.New("secret exceeds 1 MiB")
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return ref, err
	}
	ref.Version = domain.ID(hex.EncodeToString(id))
	name := filename(ref)
	f, err := v.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ref, err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			_ = v.root.Remove(name)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return ref, err
	}
	if err := f.Chmod(0400); err != nil {
		return ref, err
	}
	if err := f.Sync(); err != nil {
		return ref, err
	}
	if err := f.Close(); err != nil {
		return ref, err
	}
	if err := v.sync(); err != nil {
		return ref, err
	}
	ok = true
	return ref, nil
}
func (v *Vault) Read(ref domain.SecretVersionRef) ([]byte, error) {
	if err := ref.SecretID.Validate(); err != nil {
		return nil, err
	}
	if err := ref.Version.Validate(); err != nil {
		return nil, err
	}
	if _, err := v.root.Lstat(filename(ref) + ".deleted"); err == nil {
		return nil, errors.New("secret version has been deleted")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if _, err := v.root.Lstat(filename(ref) + ".revoked"); err == nil {
		return nil, errors.New("secret version has been revoked")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	info, err := v.root.Lstat(filename(ref))
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("secret version is not a private regular file")
	}
	f, err := v.root.Open(filename(ref))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, errors.New("secret exceeds limit")
	}
	return data, nil
}
func (v *Vault) Revoke(ref domain.SecretVersionRef) error {
	if _, err := v.Read(ref); err != nil {
		return err
	}
	f, err := v.root.OpenFile(filename(ref)+".revoked", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0400)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return v.sync()
}
func (v *Vault) Path(ref domain.SecretVersionRef) (string, error) {
	if _, err := v.Read(ref); err != nil {
		return "", err
	}
	return filepath.Join(v.root.Name(), filename(ref)), nil
}
func (v *Vault) sync() error {
	f, err := v.root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func filename(ref domain.SecretVersionRef) string {
	return fmt.Sprintf("%s--%s.secret", ref.SecretID, ref.Version)
}
