package domain

import (
	"fmt"
	"time"
)

type SnapshotPurpose string
type SnapshotState string
type Consistency string

const (
	SnapshotBaseline       SnapshotPurpose = "baseline"
	SnapshotManual         SnapshotPurpose = "manual"
	SnapshotCandidate      SnapshotPurpose = "candidate_source"
	SnapshotRecovery       SnapshotPurpose = "recovery"
	SnapshotCreating       SnapshotState   = "creating"
	SnapshotComplete       SnapshotState   = "complete"
	SnapshotInvalid        SnapshotState   = "invalid"
	SnapshotDeleting       SnapshotState   = "deleting"
	ConsistencyCoordinated Consistency     = "coordinated_copy"
	ConsistencyQuiesced    Consistency     = "quiesced_copy"
)

// Snapshot status concerns file integrity, never application health or DB consistency.
type Snapshot struct {
	ID              ID              `json:"id"`
	ServiceID       ID              `json:"service_id"`
	CreatedAt       time.Time       `json:"created_at"`
	Author          ID              `json:"author"`
	Purpose         SnapshotPurpose `json:"purpose"`
	State           SnapshotState   `json:"state"`
	FileMapRevision uint64          `json:"file_map_revision"`
	Consistency     Consistency     `json:"consistency"`
	Manifest        Manifest        `json:"manifest"`
	ManifestDigest  Digest          `json:"manifest_digest"`
	PinReasons      []string        `json:"pin_reasons,omitempty"`
	GitSource       *GitProvenance  `json:"git_source,omitempty"`
}

func (s Snapshot) Validate() error {
	if s.GitSource != nil {
		if err := s.GitSource.Validate(); err != nil {
			return err
		}
	}
	for _, id := range []ID{s.ID, s.ServiceID, s.Author} {
		if err := id.Validate(); err != nil {
			return err
		}
	}
	if s.CreatedAt.IsZero() || s.FileMapRevision == 0 {
		return fmt.Errorf("snapshot time and file map revision are required")
	}
	switch s.Purpose {
	case SnapshotBaseline, SnapshotManual, SnapshotCandidate, SnapshotRecovery:
	default:
		return fmt.Errorf("unsupported snapshot purpose")
	}
	switch s.State {
	case SnapshotCreating, SnapshotComplete, SnapshotInvalid, SnapshotDeleting:
	default:
		return fmt.Errorf("unsupported snapshot state")
	}
	if s.Consistency != ConsistencyCoordinated && s.Consistency != ConsistencyQuiesced {
		return fmt.Errorf("snapshot consistency level must be explicit")
	}
	if s.State == SnapshotComplete {
		return s.Manifest.Verify(s.ManifestDigest)
	}
	return nil
}

// Protected snapshots cannot be selected by ordinary retention. Release and active
// operation references are supplied by the retention transaction, not by the UI.
func (s Snapshot) Protected(referencedByRelease, activeRecovery bool) bool {
	return s.Purpose == SnapshotBaseline || len(s.PinReasons) > 0 || referencedByRelease || activeRecovery
}
