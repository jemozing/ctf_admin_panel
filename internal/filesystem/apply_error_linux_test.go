//go:build linux

package filesystem

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The file-size fault is a real kernel write error, isolated to a child process.
// It neither mounts filesystems nor changes the caller's process resource limit.
func TestApplyRealEFBIGAfterFirstReplacementCompensatesFromObservedTree(t *testing.T) {
	if os.Getenv("CTFM_EFBIG_CHILD") != "1" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		child := exec.CommandContext(ctx, binary, "-test.run=^TestApplyRealEFBIGAfterFirstReplacementCompensatesFromObservedTree$", "-test.v")
		child.Env = append(os.Environ(), "CTFM_EFBIG_CHILD=1")
		output, err := child.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated EFBIG child failed: %v\n%s", err, output)
		}
		t.Logf("%s", output)
		return
	}
	active := t.TempDir()
	write(t, active, "code/a-first", "baseline-first", 0644)
	write(t, active, "code/z-large", "baseline-last", 0644)
	write(t, active, "data/flag", "CTFM_TEST_FLAG_KEEP", 0600)
	baselineContent, baseline := captureFixture(t, active)
	nextSource := t.TempDir()
	write(t, nextSource, "code/a-first", "candidate-first", 0644)
	write(t, nextSource, "code/z-large", strings.Repeat("CANDIDATE_WRITE_LIMIT\n", 20000), 0644)
	nextContent, next := captureFixture(t, nextSource)
	var previous syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &previous); err != nil {
		t.Fatal(err)
	}
	limited := previous
	limited.Cur = 4096
	if previous.Max < limited.Cur {
		t.Fatalf("unexpected preexisting hard file-size limit: %d", previous.Max)
	}
	signal.Ignore(syscall.SIGXFSZ)
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limited); err != nil {
		t.Fatal(err)
	}
	err := Apply(context.Background(), nextContent, active, baseline, next, codePolicy, ApplyOptions{ApplicationsStopped: true})
	restoreLimitErr := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &previous)
	if restoreLimitErr != nil {
		t.Fatal(restoreLimitErr)
	}
	if !errors.Is(err, syscall.EFBIG) {
		t.Fatalf("expected actual kernel EFBIG after one replacement, got %v", err)
	}
	if read(t, active, "code/a-first") != "candidate-first" || read(t, active, "code/z-large") != "baseline-last" {
		t.Fatal("expected deterministic partially applied tree")
	}
	if read(t, active, "data/flag") != "CTFM_TEST_FLAG_KEEP" {
		t.Fatal("failed Apply changed unmanaged data")
	}
	entries, err := os.ReadDir(filepath.Join(active, "code"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".ctfm-") {
			t.Fatal("failed file replacement leaked a partial temporary file")
		}
	}
	if err := Verify(t.Context(), baselineContent, baseline); err != nil {
		t.Fatal("baseline damaged by failed Apply", err)
	}
	if err := Verify(t.Context(), nextContent, next); err != nil {
		t.Fatal("candidate damaged by failed Apply", err)
	}
	// Recovery cannot assume the pre-switch manifest still describes the tree.
	if err := Apply(t.Context(), baselineContent, active, baseline, baseline, codePolicy, ApplyOptions{ApplicationsStopped: true}); !errors.Is(err, ErrDrift) {
		t.Fatalf("stale recovery manifest accepted: %v", err)
	}
	partial, err := Observe(t.Context(), active, codePolicy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if partial.Digest() == baseline.Digest() || partial.Digest() == next.Digest() {
		t.Fatal("partial tree falsely matches a complete release")
	}
	if err := Apply(t.Context(), baselineContent, active, partial, baseline, codePolicy, ApplyOptions{ApplicationsStopped: true}); err != nil {
		t.Fatal("compensation from freshly observed partial tree failed", err)
	}
	observed, err := Observe(t.Context(), active, codePolicy, nil)
	if err != nil || observed.Digest() != baseline.Digest() {
		t.Fatal("compensation did not restore exact baseline", err)
	}
	if read(t, active, "data/flag") != "CTFM_TEST_FLAG_KEEP" {
		t.Fatal("compensation changed unmanaged game data")
	}
	t.Log("real EFBIG after first file replacement; partial tree observed; stale recovery rejected; exact baseline restored; game data preserved")
}
