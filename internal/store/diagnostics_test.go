package store

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

func diagnosticOperation(t *testing.T, s *Store, id string) domain.Operation {
	t.Helper()
	op := makeOperation(t, id, "service", id)
	if _, _, err := s.BeginOperation(t.Context(), op, domain.Hash([]byte(id))); err != nil {
		t.Fatal(err)
	}
	return op
}

func TestDiagnosticRetentionPreservesCriticalJournal(t *testing.T) {
	s := openTestStore(t)
	a := diagnosticOperation(t, s, "op-a")
	b := diagnosticOperation(t, s, "op-b")
	before, err := s.Events(t.Context(), a.Spec.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Small injected budgets exercise the same retention transaction without
	// writing hundreds of MiB in a unit test.
	for _, value := range []string{"first", "second", "third"} {
		if err := s.appendDiagnostic(t.Context(), a.Spec.ID, "compose_build", value, 11, 20); err != nil {
			t.Fatal(err)
		}
	}
	log, err := s.Diagnostics(t.Context(), a.Spec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if log.Bytes != 11 || log.DroppedBytes != 5 || !log.Truncated || len(log.Chunks) != 2 {
		t.Fatalf("wrong operation retention: %#v", log)
	}
	if err := s.appendDiagnostic(t.Context(), b.Spec.ID, "compose_up", "123456789012", 12, 20); err != nil {
		t.Fatal(err)
	}
	log, err = s.Diagnostics(t.Context(), a.Spec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if log.Bytes != 5 || log.DroppedBytes != 11 || log.Chunks[0].Content != "third" {
		t.Fatalf("wrong global retention: %#v", log)
	}
	after, err := s.Events(t.Context(), a.Spec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) || before[0].Sequence != after[0].Sequence || before[0].Message != after[0].Message {
		t.Fatal("diagnostic cleanup modified critical journal")
	}
}

func TestDiagnosticPagesAreBoundedAndCursorStable(t *testing.T) {
	s := openTestStore(t)
	op := diagnosticOperation(t, s, "op-pages")
	for i := 0; i < 40; i++ {
		if err := s.AppendDiagnostic(t.Context(), op.Spec.ID, "compose_build", fmt.Sprint(i)); err != nil {
			t.Fatal(err)
		}
	}
	first, err := s.Diagnostics(t.Context(), op.Spec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Chunks) != 32 || !first.HasMore || first.Truncated {
		t.Fatalf("unexpected first page: %#v", first)
	}
	second, err := s.DiagnosticsPage(t.Context(), op.Spec.ID, first.NextSequence)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Chunks) != 8 || second.HasMore || second.Chunks[0].Content != "32" {
		t.Fatalf("unexpected second page: %#v", second)
	}
	if err := s.AppendDiagnostic(t.Context(), op.Spec.ID, "compose_build", strings.Repeat("a", DiagnosticChunkLimit+1)); err == nil {
		t.Fatal("oversize chunk accepted")
	}
	if err := s.AppendDiagnostic(t.Context(), "missing-op", "compose_build", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing operation accepted: %v", err)
	}
}

func TestDiagnosticOutputSurvivesReopen(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "executor.db")
	s, err := Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	op := diagnosticOperation(t, s, "op-durable")
	if err := s.AppendDiagnostic(t.Context(), op.Spec.ID, "compose_build", "compiler error on stderr\n"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	log, err := s.Diagnostics(t.Context(), op.Spec.ID)
	if err != nil || len(log.Chunks) != 1 || log.Chunks[0].Content != "compiler error on stderr\n" {
		t.Fatalf("output not durable after reopen: %#v %v", log, err)
	}
}
