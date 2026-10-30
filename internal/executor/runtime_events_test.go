package executor

import (
	"github.com/moby/moby/api/types/events"
	"strings"
	"testing"
	"time"
)

func TestRuntimeEventsOnlyAttributeRegisteredProjectsAndComponents(t *testing.T) {
	f := newPlanningFixture(t)
	now := time.Now().UTC()
	e := events.Message{Type: events.ContainerEventType, Action: events.ActionOOM, TimeNano: now.UnixNano(), Actor: events.Actor{ID: strings.Repeat("b", 64), Attributes: map[string]string{"com.docker.compose.project": f.s.ComposeProject, "com.docker.compose.service": "unknown"}}}
	if err := f.m.recordRuntimeEvent(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	items, _ := f.m.Store.RuntimeEvents(t.Context(), f.s.ID)
	if len(items) != 0 {
		t.Fatal("unknown component attributed")
	}
	e.Actor.Attributes["com.docker.compose.service"] = "app"
	if err := f.m.recordRuntimeEvent(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	e.Actor.Attributes["com.docker.compose.project"] = "unrelated"
	if err := f.m.recordRuntimeEvent(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	items, err := f.m.Store.RuntimeEvents(t.Context(), f.s.ID)
	if err != nil || len(items) != 1 || items[0].Kind != "oom" {
		t.Fatalf("events: %v %v", items, err)
	}
}
