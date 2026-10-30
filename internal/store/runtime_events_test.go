package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRuntimeEventDurabilityDedupAndServiceIsolation(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	e := RuntimeEvent{ServiceID: "svc-a", ContainerID: strings.Repeat("a", 64), Component: "app", Kind: "oom", At: now, ObservedAt: now}
	if err := s.AppendRuntimeEvent(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendRuntimeEvent(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	items, err := s.RuntimeEvents(ctx, "svc-a")
	if err != nil || len(items) != 1 || items[0].Kind != "oom" {
		t.Fatalf("persisted events: %v %v", items, err)
	}
	other, err := s.RuntimeEvents(ctx, "svc-b")
	if err != nil || len(other) != 0 {
		t.Fatal("cross-service event leak")
	}
	cursor, err := s.RuntimeEventCursor(ctx)
	if err != nil || !cursor.Equal(now) {
		t.Fatalf("cursor: %v %v", cursor, err)
	}
	e.Kind = "arbitrary"
	if s.AppendRuntimeEvent(ctx, e) == nil {
		t.Fatal("unbounded kind accepted")
	}
}
