// Package filesystem copies only registered managed paths. Source trees are
// untrusted; every component is checked against opened descriptors. The initial
// profile rejects all symlinks, special files and hard-linked regular files.
package filesystem

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

var (
	ErrSourceChanged = errors.New("source changed during copy")
	ErrUnsafePath    = errors.New("unsafe filesystem path")
	ErrDrift         = errors.New("active managed files differ from expected manifest")
)

type directory struct {
	root          *os.Root
	device, mount uint64
}

func openDirectory(name string) (*directory, error) {
	if err := domain.ValidateAbsolutePath(filepath.ToSlash(name)); err != nil {
		return nil, err
	}
	before, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: root must be a real directory", ErrUnsafePath)
	}
	root, err := os.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	f, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		root.Close()
		return nil, err
	}
	a, err := identify(before)
	if err != nil {
		root.Close()
		return nil, err
	}
	b, err := identify(info)
	if err != nil || a != b {
		root.Close()
		return nil, fmt.Errorf("%w: root replaced", ErrSourceChanged)
	}
	mount, err := mountIdentity(f)
	if err != nil {
		root.Close()
		return nil, err
	}
	return &directory{root: root, device: b.device, mount: mount}, nil
}

func (d *directory) close() { _ = d.root.Close() }

func (d *directory) check(file *os.File, before os.FileInfo) (identity, error) {
	info, err := file.Stat()
	if err != nil {
		return identity{}, err
	}
	a, err := identify(before)
	if err != nil {
		return identity{}, err
	}
	b, err := identify(info)
	if err != nil {
		return identity{}, err
	}
	if a != b {
		return identity{}, fmt.Errorf("%w: entry replaced before open", ErrSourceChanged)
	}
	mount, err := mountIdentity(file)
	if err != nil {
		return identity{}, err
	}
	if !sameBoundary(d.device, d.mount, b.device, mount) {
		return identity{}, fmt.Errorf("%w: mount boundary", ErrUnsafePath)
	}
	return b, nil
}

// parent returns an independently owned root for a path's parent. It pins each
// ancestor, rejects symlinks before opening and verifies the opened inode before
// any contents are read. os.Root provides confinement across concurrent renames.
func (d *directory) parent(name string) (*os.Root, string, error) {
	if err := domain.ValidateRelativePath(name); err != nil {
		return nil, "", err
	}
	current, err := d.root.OpenRoot(".")
	if err != nil {
		return nil, "", err
	}
	parts := strings.Split(name, "/")
	for _, part := range parts[:len(parts)-1] {
		before, err := current.Lstat(part)
		if err != nil {
			current.Close()
			return nil, "", err
		}
		if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			current.Close()
			return nil, "", fmt.Errorf("%w: non-directory ancestor %q", ErrUnsafePath, name)
		}
		child, err := current.OpenRoot(part)
		if err != nil {
			current.Close()
			return nil, "", err
		}
		file, err := child.Open(".")
		if err == nil {
			_, err = d.check(file, before)
			file.Close()
		}
		if err == nil {
			after, statErr := current.Lstat(part)
			if statErr != nil || !os.SameFile(before, after) || after.Mode()&os.ModeSymlink != 0 {
				err = fmt.Errorf("%w: ancestor replaced", ErrSourceChanged)
			}
		}
		current.Close()
		if err != nil {
			child.Close()
			return nil, "", err
		}
		current = child
	}
	return current, parts[len(parts)-1], nil
}

func (d *directory) open(name string) (*os.File, identity, error) {
	parent, leaf, err := d.parent(name)
	if err != nil {
		return nil, identity{}, err
	}
	defer parent.Close()
	before, err := parent.Lstat(leaf)
	if err != nil {
		return nil, identity{}, err
	}
	if !before.IsDir() && !before.Mode().IsRegular() {
		return nil, identity{}, fmt.Errorf("%w: symlink or special file %q", ErrUnsafePath, name)
	}
	file, err := parent.OpenFile(leaf, os.O_RDONLY|noFollowFlags, 0)
	if err != nil {
		return nil, identity{}, err
	}
	id, err := d.check(file, before)
	if err == nil && id.mode.IsRegular() && id.links != 1 {
		err = fmt.Errorf("%w: hard-linked file %q", ErrUnsafePath, name)
	}
	if err == nil && id.mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		err = fmt.Errorf("%w: special permission bits %q", ErrUnsafePath, name)
	}
	if err == nil {
		after, statErr := parent.Lstat(leaf)
		if statErr != nil || !os.SameFile(before, after) || after.Mode()&os.ModeSymlink != 0 {
			err = fmt.Errorf("%w: entry replaced", ErrSourceChanged)
		}
	}
	if err != nil {
		file.Close()
		return nil, identity{}, err
	}
	return file, id, nil
}

type policy struct {
	managed  []domain.ManagedPath
	excluded []string
}

func makePolicy(managed []domain.ManagedPath, exclusions []string) (policy, error) {
	if len(managed) == 0 {
		return policy{}, fmt.Errorf("managed paths are required")
	}
	p := policy{managed: managed, excluded: append([]string{}, exclusions...)}
	for i, m := range managed {
		if err := domain.ValidateRelativePath(m.Path); err != nil {
			return policy{}, err
		}
		if m.Kind != domain.ManagedCode && m.Kind != domain.ManagedConfig {
			return policy{}, fmt.Errorf("unclassified managed path")
		}
		for _, other := range managed[:i] {
			if domain.PathsOverlap(m.Path, other.Path) {
				return policy{}, fmt.Errorf("overlapping managed paths")
			}
		}
		for _, excluded := range m.Exclusions {
			if err := domain.ValidateRelativePath(excluded); err != nil {
				return policy{}, err
			}
			p.excluded = append(p.excluded, path.Join(m.Path, excluded))
		}
	}
	for _, name := range p.excluded {
		if err := domain.ValidateRelativePath(name); err != nil {
			return policy{}, err
		}
	}
	return p, nil
}

func (p policy) excludes(name string) bool {
	for _, part := range strings.Split(name, "/") {
		if part == ".git" || part == ".svn" || part == ".hg" {
			return true
		}
	}
	for _, excluded := range p.excluded {
		if name == excluded || strings.HasPrefix(name, excluded+"/") {
			return true
		}
	}
	return false
}

func (p policy) manages(name string) bool {
	if p.excludes(name) {
		return false
	}
	for _, m := range p.managed {
		if name == m.Path || strings.HasPrefix(name, m.Path+"/") {
			return true
		}
	}
	return false
}

func (p policy) allows(entry domain.ManifestEntry) bool {
	if p.manages(entry.Path) {
		return true
	}
	if entry.Type == domain.EntryDirectory && !p.excludes(entry.Path) {
		for _, m := range p.managed {
			if strings.HasPrefix(m.Path, entry.Path+"/") {
				return true
			}
		}
	}
	return false
}
