package secrets

import (
	"errors"
	"os"
	"sort"
	"strings"
	"syscall"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

type VersionMetadata struct {
	Reference domain.SecretVersionRef `json:"reference"`
	Bytes     int64                   `json:"bytes"`
	Revoked   bool                    `json:"revoked"`
	Deleted   bool                    `json:"deleted"`
}

func validateReference(ref domain.SecretVersionRef) error {
	if err := ref.SecretID.Validate(); err != nil {
		return err
	}
	return ref.Version.Validate()
}

func (v *Vault) privateMetadata(name string) (os.FileInfo, error) {
	info, err := v.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0400 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return nil, errors.New("vault metadata must be an executor-owned private regular file")
	}
	return info, nil
}

func (v *Vault) Metadata(ref domain.SecretVersionRef) (VersionMetadata, error) {
	result := VersionMetadata{Reference: ref}
	if err := validateReference(ref); err != nil {
		return result, err
	}
	for _, marker := range []string{".revoked", ".deleted"} {
		if _, err := v.privateMetadata(filename(ref) + marker); err == nil {
			if marker == ".revoked" {
				result.Revoked = true
			} else {
				result.Deleted = true
			}
		} else if !os.IsNotExist(err) {
			return result, err
		}
	}
	info, err := v.privateMetadata(filename(ref))
	if err == nil {
		result.Bytes = info.Size()
	} else if !os.IsNotExist(err) || !result.Deleted {
		return result, err
	}
	return result, nil
}

func (v *Vault) Versions() ([]VersionMetadata, error) {
	file, err := v.root.Open(".")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	entries, err := file.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	refs := map[domain.SecretVersionRef]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".revoked") {
			name = strings.TrimSuffix(name, ".revoked")
		}
		if strings.HasSuffix(name, ".deleted") {
			name = strings.TrimSuffix(name, ".deleted")
		}
		if !strings.HasSuffix(name, ".secret") {
			return nil, errors.New("unrecognized vault entry")
		}
		base := strings.TrimSuffix(name, ".secret")
		separator := strings.LastIndex(base, "--")
		if separator <= 0 {
			return nil, errors.New("invalid vault version entry")
		}
		ref := domain.SecretVersionRef{SecretID: domain.ID(base[:separator]), Version: domain.ID(base[separator+2:])}
		if err := validateReference(ref); err != nil {
			return nil, err
		}
		refs[ref] = true
	}
	result := []VersionMetadata{}
	for ref := range refs {
		meta, err := v.Metadata(ref)
		if err != nil {
			return nil, err
		}
		result = append(result, meta)
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i].Reference, result[j].Reference
		return string(a.SecretID)+"/"+string(a.Version) < string(b.SecretID)+"/"+string(b.Version)
	})
	return result, nil
}

// Delete requires explicit prior revocation. A durable tombstone precedes unlink
// so a crash cannot make a deleted version appear usable or importable again.
func (v *Vault) Delete(ref domain.SecretVersionRef) error {
	meta, err := v.Metadata(ref)
	if err != nil {
		return err
	}
	if !meta.Revoked {
		return errors.New("revoke the secret version before deleting it")
	}
	if !meta.Deleted {
		file, err := v.root.OpenFile(filename(ref)+".deleted", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
		if err != nil {
			return err
		}
		if err := file.Sync(); err != nil {
			file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		if err := v.sync(); err != nil {
			return err
		}
	}
	if err := v.root.Remove(filename(ref)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return v.sync()
}
