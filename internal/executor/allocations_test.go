package executor

import (
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/jobs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJanitorChargesAndRemovesOnlyRecordedIdleAllocations(t *testing.T) {
	f := newPlanningFixture(t)
	if err := ensureStaging(f.m.Config.StateDirectory); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"build-finished", "build-active", "build-unrecorded"} {
		directory := filepath.Join(stagingPath(f.m.Config.StateDirectory), name)
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(directory, "src"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "src", "script"), []byte("#!/bin/sh\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	active := retentionOperation(t, f, "allocation-active", domain.OperationBuild, "", f.baseline.ID)
	done := retentionOperation(t, f, "allocation-done", domain.OperationBuild, "", f.baseline.ID)
	if _, err := jobs.New(f.m.Store).Transition(t.Context(), done.Spec.ID, domain.OperationFailed, domain.OutcomeEvidence{ActualStateKnown: true, ResultRecorded: true, Reason: "fixture failed before mutation"}); err != nil {
		t.Fatal(err)
	}
	for id, a := range map[domain.ID]allocation{"alloc-active": {OperationID: active.Spec.ID, Directory: "build-active", CreatedAt: time.Now()}, "alloc-done": {OperationID: done.Spec.ID, Directory: "build-finished", CreatedAt: time.Now()}} {
		if err := f.m.Store.PutImmutable(t.Context(), "build_allocation", id, f.s.ID, a); err != nil {
			t.Fatal(err)
		}
	}
	incomplete := "snap-incomplete"
	dir := filepath.Join(f.m.Config.StateDirectory, "snapshots", incomplete)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "content"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "content", "partial"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Store.PutImmutable(t.Context(), "snapshot_allocation", domain.ID(incomplete), f.s.ID, allocation{ID: domain.ID(incomplete), OperationID: done.Spec.ID, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := f.m.cleanupAllocations(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(stagingPath(f.m.Config.StateDirectory), "build-finished"), dir} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("idle recorded allocation remains %s: %v", p, err)
		}
	}
	for _, name := range []string{"build-active", "build-unrecorded"} {
		if _, err := os.Stat(filepath.Join(stagingPath(f.m.Config.StateDirectory), name)); err != nil {
			t.Fatalf("unsafe collection of %s: %v", name, err)
		}
	}
	if _, err := f.m.loadSnapshot(t.Context(), f.baseline.ID); err != nil {
		t.Fatal("published baseline removed", err)
	}
}
