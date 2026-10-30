package config

import "testing"

func TestStoragePolicyDefaultsAndOverflowBounds(t *testing.T) {
	p := (StoragePolicy{}).Effective()
	if p.ManualSnapshots != 3 || p.VerifiedReleases != 3 || p.SnapshotMaxBytes == 0 || p.MinimumFreeInodes == 0 {
		t.Fatal(p)
	}
	for _, p := range []StoragePolicy{{ManualSnapshots: 101}, {CandidateMaxAgeHours: 1 << 30}, {StateMaxBytes: 1 << 63}, {MinimumFreeBytes: 1 << 63}} {
		if p.Validate() == nil {
			t.Fatalf("unbounded policy: %+v", p)
		}
	}
}
