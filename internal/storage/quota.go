// Package storage measures executor-owned storage without following links and
// checks logical quotas separately from the filesystem's remaining capacity.
package storage

import (
	"fmt"
	"math"
)

type Usage struct {
	Bytes uint64 `json:"bytes"`
	Files uint64 `json:"files"`
}

type Space struct {
	AvailableBytes  uint64 `json:"available_bytes"`
	AvailableInodes uint64 `json:"available_inodes"`
	InodesKnown     bool   `json:"inodes_known"`
}

// QuotaError deliberately contains quantities and no paths or file contents.
type QuotaError struct {
	Kind      string
	Requested uint64
	Available uint64
}

func (e *QuotaError) Error() string {
	return fmt.Sprintf("storage %s limit: requested %d, available %d", e.Kind, e.Requested, e.Available)
}

func add(a, b uint64) (uint64, error) {
	if math.MaxUint64-a < b {
		return 0, &QuotaError{Kind: "overflow", Requested: b, Available: math.MaxUint64 - a}
	}
	return a + b, nil
}

// CheckQuota is a preflight, not a reservation. Callers must serialize writes
// and recheck immediately before allocating storage. A zero maxBytes disables
// the logical quota; free space and inode reserves are always enforced.
func CheckQuota(used, additional, maxBytes uint64, space Space, reserveBytes, reserveInodes, additionalFiles uint64) error {
	total, err := add(used, additional)
	if err != nil {
		return err
	}
	if maxBytes != 0 && total > maxBytes {
		remaining := uint64(0)
		if used < maxBytes {
			remaining = maxBytes - used
		}
		return &QuotaError{Kind: "quota", Requested: additional, Available: remaining}
	}
	needed, err := add(additional, reserveBytes)
	if err != nil {
		return err
	}
	if needed > space.AvailableBytes {
		return &QuotaError{Kind: "capacity", Requested: needed, Available: space.AvailableBytes}
	}
	if space.InodesKnown {
		needed, err = add(additionalFiles, reserveInodes)
		if err != nil {
			return err
		}
		if needed > space.AvailableInodes {
			return &QuotaError{Kind: "inodes", Requested: needed, Available: space.AvailableInodes}
		}
	}
	return nil
}
