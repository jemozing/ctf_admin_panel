package config

import "fmt"

// StoragePolicy is local administrator policy. Zero fields select conservative
// defaults, keeping old bootstrap files valid; browsers cannot change it.
type StoragePolicy struct {
	ManualSnapshots      uint32 `json:"manual_snapshots,omitempty"`
	CandidateSnapshots   uint32 `json:"candidate_snapshots,omitempty"`
	VerifiedReleases     uint32 `json:"verified_releases,omitempty"`
	CandidateMaxAgeHours uint32 `json:"candidate_max_age_hours,omitempty"`
	SnapshotMaxBytes     uint64 `json:"snapshot_max_bytes,omitempty"`
	StagingMaxBytes      uint64 `json:"staging_max_bytes,omitempty"`
	StateMaxBytes        uint64 `json:"state_max_bytes,omitempty"`
	DockerMaxBytes       uint64 `json:"docker_max_bytes,omitempty"`
	MinimumFreeBytes     uint64 `json:"minimum_free_bytes,omitempty"`
	MinimumFreeInodes    uint64 `json:"minimum_free_inodes,omitempty"`
	BuildReserveBytes    uint64 `json:"build_reserve_bytes,omitempty"`
}

func (p StoragePolicy) Effective() StoragePolicy {
	if p.ManualSnapshots == 0 {
		p.ManualSnapshots = 3
	}
	if p.CandidateSnapshots == 0 {
		p.CandidateSnapshots = 3
	}
	if p.VerifiedReleases == 0 {
		p.VerifiedReleases = 3
	}
	if p.CandidateMaxAgeHours == 0 {
		p.CandidateMaxAgeHours = 24
	}
	if p.SnapshotMaxBytes == 0 {
		p.SnapshotMaxBytes = 16 << 30
	}
	if p.StagingMaxBytes == 0 {
		p.StagingMaxBytes = 8 << 30
	}
	if p.StateMaxBytes == 0 {
		p.StateMaxBytes = 32 << 30
	}
	if p.DockerMaxBytes == 0 {
		p.DockerMaxBytes = 128 << 30
	}
	if p.MinimumFreeBytes == 0 {
		p.MinimumFreeBytes = 256 << 20
	}
	if p.MinimumFreeInodes == 0 {
		p.MinimumFreeInodes = 1024
	}
	if p.BuildReserveBytes == 0 {
		p.BuildReserveBytes = 64 << 20
	}
	return p
}
func (p StoragePolicy) Validate() error {
	p = p.Effective()
	if p.ManualSnapshots > 100 || p.CandidateSnapshots > 100 || p.VerifiedReleases > 100 || p.CandidateMaxAgeHours > 24*365 {
		return fmt.Errorf("storage retention counts/age exceed supported bounds")
	}
	for _, n := range []uint64{p.SnapshotMaxBytes, p.StagingMaxBytes, p.StateMaxBytes, p.DockerMaxBytes, p.MinimumFreeBytes, p.BuildReserveBytes} {
		if n > 1<<60 {
			return fmt.Errorf("storage byte limit exceeds supported bounds")
		}
	}
	return nil
}
