package domain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

type SecretVersionRef struct {
	SecretID ID `json:"secret_id"`
	Version  ID `json:"version"`
}

func validateSecrets(refs []SecretVersionRef) error {
	seen := map[ID]bool{}
	for _, ref := range refs {
		if err := ref.SecretID.Validate(); err != nil {
			return err
		}
		if err := ref.Version.Validate(); err != nil {
			return err
		}
		if seen[ref.SecretID] {
			return fmt.Errorf("duplicate secret reference %q", ref.SecretID)
		}
		seen[ref.SecretID] = true
	}
	return nil
}

type ImageRef struct {
	Component       string   `json:"component"`
	ImageID         Digest   `json:"image_id"`
	RegistryDigests []string `json:"registry_digests,omitempty"`
	RetentionTag    string   `json:"retention_tag"`
}

type ReleaseSource string

const (
	ReleaseImported  ReleaseSource = "imported"
	ReleaseWorkspace ReleaseSource = "workspace"
	ReleaseGit       ReleaseSource = "git"
)

type DataCompatibility string

const (
	DataCompatible   DataCompatibility = "compatible"
	DataUnconfirmed  DataCompatibility = "unconfirmed"
	DataIncompatible DataCompatibility = "incompatible"
)

type DataReference struct {
	Name          string            `json:"name"`
	Identity      string            `json:"identity"`
	Compatibility DataCompatibility `json:"compatibility"`
	Evidence      string            `json:"evidence"`
}

// ReleaseSpec contains references to executor-owned immutable configuration and
// secret versions. It must never contain expanded environment or secret values.
type ReleaseSpec struct {
	SchemaVersion       int                `json:"schema_version"`
	ID                  ID                 `json:"id"`
	ServiceID           ID                 `json:"service_id"`
	CreatedAt           time.Time          `json:"created_at"`
	Author              ID                 `json:"author"`
	Source              ReleaseSource      `json:"source"`
	SnapshotID          ID                 `json:"snapshot_id"`
	TreeDigest          Digest             `json:"tree_digest"`
	ConfigurationDigest Digest             `json:"configuration_digest"`
	PolicyRevision      uint64             `json:"policy_revision"`
	FileMapRevision     uint64             `json:"file_map_revision"`
	Images              []ImageRef         `json:"images"`
	Secrets             []SecretVersionRef `json:"secrets,omitempty"`
	Data                []DataReference    `json:"data,omitempty"`
	BuildEvidenceDigest Digest             `json:"build_evidence_digest,omitempty"`
	GitSource           *GitProvenance     `json:"git_source,omitempty"`
}

// Release keeps an owned, canonical JSON payload. Decoding via Spec returns a deep
// copy, so callers cannot change a release by mutating slices after approval.
type Release struct{ canonical []byte }

func NewRelease(spec ReleaseSpec) (Release, error) {
	if spec.SchemaVersion != SchemaVersion {
		return Release{}, fmt.Errorf("unsupported release schema version")
	}
	for _, id := range []ID{spec.ID, spec.ServiceID, spec.Author, spec.SnapshotID} {
		if err := id.Validate(); err != nil {
			return Release{}, err
		}
	}
	if spec.CreatedAt.IsZero() || spec.PolicyRevision == 0 || spec.FileMapRevision == 0 {
		return Release{}, fmt.Errorf("release time and revisions are required")
	}
	if spec.Source != ReleaseImported && spec.Source != ReleaseWorkspace && spec.Source != ReleaseGit {
		return Release{}, fmt.Errorf("unsupported MVP release source")
	}
	if spec.GitSource != nil {
		if err := spec.GitSource.Validate(); err != nil {
			return Release{}, err
		}
	}
	if spec.Source == ReleaseGit && spec.GitSource == nil {
		return Release{}, fmt.Errorf("Git release requires exact source provenance")
	}
	for _, digest := range []Digest{spec.TreeDigest, spec.ConfigurationDigest} {
		if err := digest.Validate(); err != nil {
			return Release{}, err
		}
	}
	if spec.BuildEvidenceDigest != "" {
		if err := spec.BuildEvidenceDigest.Validate(); err != nil {
			return Release{}, err
		}
	}
	if len(spec.Images) == 0 {
		return Release{}, fmt.Errorf("release must retain at least one exact local image")
	}
	if err := validateSecrets(spec.Secrets); err != nil {
		return Release{}, err
	}
	// Copy before sorting to avoid modifying the caller's slices.
	encoded, err := json.Marshal(spec)
	if err != nil {
		return Release{}, err
	}
	if err := json.Unmarshal(encoded, &spec); err != nil {
		return Release{}, err
	}
	seen := map[string]bool{}
	tags := map[string]bool{}
	for _, image := range spec.Images {
		if err := validateComponent(image.Component); err != nil {
			return Release{}, err
		}
		if seen[image.Component] {
			return Release{}, fmt.Errorf("duplicate image component")
		}
		seen[image.Component] = true
		if err := image.ImageID.Validate(); err != nil {
			return Release{}, err
		}
		expectedTag := "ctf-manager/" + string(spec.ServiceID) + ":" + string(spec.ID) + "-" + image.Component
		if image.RetentionTag != expectedTag {
			return Release{}, fmt.Errorf("retention tag must be %q", expectedTag)
		}
		if tags[image.RetentionTag] {
			return Release{}, fmt.Errorf("duplicate image retention tag")
		}
		tags[image.RetentionTag] = true
		for _, digest := range image.RegistryDigests {
			repository, checksum, found := strings.Cut(digest, "@")
			if !found || repository == "" || strings.ContainsAny(repository, " \t\r\n") || Digest(checksum).Validate() != nil {
				return Release{}, fmt.Errorf("invalid registry digest")
			}
		}
	}
	dataNames := map[string]bool{}
	for _, data := range spec.Data {
		if err := validateComponent(data.Name); err != nil {
			return Release{}, err
		}
		if dataNames[data.Name] {
			return Release{}, fmt.Errorf("duplicate data reference")
		}
		dataNames[data.Name] = true
		if err := validateText(data.Identity, "storage identity", 4096); err != nil {
			return Release{}, err
		}
		switch data.Compatibility {
		case DataCompatible, DataUnconfirmed, DataIncompatible:
		default:
			return Release{}, fmt.Errorf("data compatibility must be explicit")
		}
		if err := validateText(data.Evidence, "compatibility evidence", 2048); err != nil {
			return Release{}, err
		}
	}
	sort.Slice(spec.Images, func(i, j int) bool { return spec.Images[i].Component < spec.Images[j].Component })
	for i := range spec.Images {
		sort.Strings(spec.Images[i].RegistryDigests)
	}
	sort.Slice(spec.Secrets, func(i, j int) bool { return spec.Secrets[i].SecretID < spec.Secrets[j].SecretID })
	sort.Slice(spec.Data, func(i, j int) bool { return spec.Data[i].Name < spec.Data[j].Name })
	spec.CreatedAt = spec.CreatedAt.UTC()
	encoded, err = json.Marshal(spec)
	if err != nil {
		return Release{}, err
	}
	return Release{canonical: encoded}, nil
}

func (r Release) Spec() ReleaseSpec {
	var spec ReleaseSpec
	_ = json.Unmarshal(r.canonical, &spec)
	return spec
}
func (r Release) CanonicalJSON() []byte { return append([]byte{}, r.canonical...) }
func (r Release) Digest() Digest        { return Hash(r.canonical) }
func (r Release) MarshalJSON() ([]byte, error) {
	if len(r.canonical) == 0 {
		return nil, fmt.Errorf("uninitialized release")
	}
	return r.CanonicalJSON(), nil
}
func (r *Release) UnmarshalJSON(data []byte) error {
	var spec ReleaseSpec
	if err := decodeStrictJSON(data, &spec); err != nil {
		return err
	}
	value, err := NewRelease(spec)
	if err != nil {
		return err
	}
	*r = value
	return nil
}

func decodeStrictJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("unexpected data after JSON document")
	}
	return nil
}
