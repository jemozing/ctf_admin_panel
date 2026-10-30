//go:build linux || darwin

package storage

import (
	"context"
	"errors"
	"path/filepath"
	"syscall"
	"testing"
)

func TestMeasureRejectsFIFOWithoutOpeningIt(t *testing.T) {
	root := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Measure(context.Background(), root); !errors.Is(err, ErrUnsafeTree) {
		t.Fatalf("FIFO accepted: %v", err)
	}
}
