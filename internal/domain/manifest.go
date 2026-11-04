package domain

import (
	"encoding/json"
	"fmt"
	"math"
	"path"
	"sort"
)

type EntryType string

const (
	EntryFile      EntryType = "file"
	EntryDirectory EntryType = "directory"
	EntrySymlink   EntryType = "symlink"
)

type ManifestEntry struct {
	Path       string    `json:"path"`
	Type       EntryType `json:"type"`
	Size       int64     `json:"size"`
	Digest     Digest    `json:"digest,omitempty"`
	Mode       uint32    `json:"mode"`
	UID        uint32    `json:"uid"`
	GID        uint32    `json:"gid"`
	LinkTarget string    `json:"link_target,omitempty"`
}

type manifestDocument struct {
	SchemaVersion int             `json:"schema_version"`
	Entries       []ManifestEntry `json:"entries"`
}

// Manifest is immutable by construction. It owns its entries and returns copies.
// Its canonical JSON is a versioned struct with entries sorted by POSIX path.
type Manifest struct{ entries []ManifestEntry }

func NewManifest(entries []ManifestEntry) (Manifest, error) {
	if entries == nil {
		entries = []ManifestEntry{}
	}
	copyEntries := append([]ManifestEntry{}, entries...)
	sort.Slice(copyEntries, func(i, j int) bool { return copyEntries[i].Path < copyEntries[j].Path })
	types := map[string]EntryType{}
	var size int64
	for _, entry := range copyEntries {
		if err := ValidateRelativePath(entry.Path); err != nil {
			return Manifest{}, err
		}
		if _, exists := types[entry.Path]; exists {
			return Manifest{}, fmt.Errorf("duplicate manifest path %q", entry.Path)
		}
		if entry.Mode & ^uint32(0777) != 0 {
			return Manifest{}, fmt.Errorf("special permission bits are unsupported: %q", entry.Path)
		}
		if entry.Size < 0 || size > math.MaxInt64-entry.Size {
			return Manifest{}, fmt.Errorf("invalid manifest size")
		}
		size += entry.Size
		switch entry.Type {
		case EntryFile:
			if err := entry.Digest.Validate(); err != nil {
				return Manifest{}, err
			}
			if entry.LinkTarget != "" {
				return Manifest{}, fmt.Errorf("regular file has symlink target")
			}
		case EntryDirectory:
			if entry.Size != 0 || entry.Digest != "" || entry.LinkTarget != "" {
				return Manifest{}, fmt.Errorf("directory must not carry file content")
			}
		case EntrySymlink:
			if err := validateText(entry.LinkTarget, "symlink target", 4096); err != nil {
				return Manifest{}, err
			}
			if path.IsAbs(entry.LinkTarget) || entry.LinkTarget != path.Clean(entry.LinkTarget) {
				return Manifest{}, fmt.Errorf("symlink target must be canonical and relative")
			}
			resolved := path.Join(path.Dir(entry.Path), entry.LinkTarget)
			if err := ValidateRelativePath(resolved); err != nil {
				return Manifest{}, fmt.Errorf("symlink escapes snapshot root: %w", err)
			}
			if entry.Size != int64(len(entry.LinkTarget)) || entry.Digest != Hash([]byte(entry.LinkTarget)) {
				return Manifest{}, fmt.Errorf("symlink size or digest does not match target")
			}
		default:
			return Manifest{}, fmt.Errorf("unsupported file type %q", entry.Type)
		}
		for parent := path.Dir(entry.Path); parent != "."; parent = path.Dir(parent) {
			if kind, exists := types[parent]; exists && kind != EntryDirectory {
				return Manifest{}, fmt.Errorf("manifest entry descends through a non-directory %q", parent)
			}
		}
		types[entry.Path] = entry.Type
	}
	return Manifest{entries: copyEntries}, nil
}

func (m Manifest) Entries() []ManifestEntry { return append([]ManifestEntry{}, m.entries...) }

// WithFileContents replaces the recorded bytes of an existing regular file
// while retaining its registered owner, permissions and all other entries.
func (m Manifest) WithFileContents(name string, content []byte) (Manifest, error) {
	entries := m.Entries()
	for i := range entries {
		entry := &entries[i]
		if entry.Path == name && entry.Type == EntryFile {
			entry.Size = int64(len(content))
			entry.Digest = Hash(content)
			return NewManifest(entries)
		}
	}
	return Manifest{}, fmt.Errorf("replacement must name an existing regular manifest file")
}

func (m Manifest) CanonicalJSON() []byte {
	entries := m.Entries()
	data, _ := json.Marshal(manifestDocument{SchemaVersion: SchemaVersion, Entries: entries})
	return data
}

func (m Manifest) Digest() Digest { return Hash(m.CanonicalJSON()) }

func (m Manifest) TotalBytes() int64 {
	var total int64
	for _, entry := range m.entries {
		total += entry.Size
	}
	return total
}

func (m Manifest) MarshalJSON() ([]byte, error) { return m.CanonicalJSON(), nil }

func (m *Manifest) UnmarshalJSON(data []byte) error {
	var doc manifestDocument
	if err := decodeStrictJSON(data, &doc); err != nil {
		return err
	}
	if doc.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported manifest schema version")
	}
	result, err := NewManifest(doc.Entries)
	if err != nil {
		return err
	}
	*m = result
	return nil
}

func (m Manifest) Verify(expected Digest) error {
	if err := expected.Validate(); err != nil {
		return err
	}
	if m.Digest() != expected {
		return fmt.Errorf("manifest digest mismatch")
	}
	return nil
}
