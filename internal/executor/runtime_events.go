package executor

import (
	"context"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
	"strconv"
	"time"
)

func (m *Manager) RuntimeEvents(ctx context.Context, id domain.ID) (transport.RuntimeEventsResponse, error) {
	if _, err := m.Store.GetService(ctx, id); err != nil {
		return transport.RuntimeEventsResponse{}, err
	}
	items, err := m.Store.RuntimeEvents(ctx, id)
	c := m.metricsCollector()
	c.mu.RLock()
	connected := c.eventsConnected
	at := c.eventsConnectedAt
	problem := c.eventsError
	c.mu.RUnlock()
	return transport.RuntimeEventsResponse{Events: items, Connected: connected, ConnectedAt: at, Error: problem, Storage: "sqlite", RetainedGlobal: store.RuntimeEventLimit, ReturnedLimit: 200, Continuity: "Docker retains a limited event buffer. Gaps while executor or daemon is offline cannot be excluded; start is not proof of an automatic restart."}, err
}

// RunRuntimeEvents is independent of page subscriptions and survives reconnects.
// Docker's bounded replay is best effort; we never reconstruct OOM from RAM=0.
func (m *Manager) RunRuntimeEvents(ctx context.Context) {
	for ctx.Err() == nil {
		cursor, err := m.Store.RuntimeEventCursor(ctx)
		if err != nil {
			m.eventStreamState(false, "Runtime event journal unavailable")
			return
		}
		if cursor.IsZero() {
			cursor = time.Now().UTC().Add(-time.Second)
		} else {
			cursor = cursor.Add(-time.Second)
		}
		streamCtx, cancel := context.WithCancel(ctx)
		stream := m.Engine.Client.Events(streamCtx, client.EventsListOptions{Since: strconv.FormatInt(cursor.Unix(), 10), Filters: client.Filters{}.Add("type", "container").Add("event", "oom", "restart", "die", "start", "destroy")})
		m.eventStreamState(true, "")
		connected := true
		for connected {
			select {
			case <-ctx.Done():
				cancel()
				return
			case _, ok := <-stream.Err:
				_ = ok
				connected = false
			case event := <-stream.Messages:
				if err := m.recordRuntimeEvent(ctx, event); err != nil {
					m.eventStreamState(false, "Runtime event journal write failed")
					connected = false
				}
			}
		}
		cancel()
		m.eventStreamState(false, "Docker event stream disconnected; replay is bounded")
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (m *Manager) eventStreamState(connected bool, problem string) {
	c := m.metricsCollector()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.eventsConnected = connected
	c.eventsError = problem
	if connected {
		c.eventsConnectedAt = time.Now().UTC()
	}
}

func (m *Manager) recordRuntimeEvent(ctx context.Context, event events.Message) error {
	if event.Type != events.ContainerEventType {
		return nil
	}
	kind := string(event.Action)
	switch kind {
	case "oom", "restart", "die", "start", "destroy":
	default:
		return nil
	}
	project := event.Actor.Attributes["com.docker.compose.project"]
	component := event.Actor.Attributes["com.docker.compose.service"]
	services, err := m.Store.ListServices(ctx)
	if err != nil {
		return err
	}
	for _, s := range services {
		if s.ComposeProject != project {
			continue
		}
		known := false
		for _, ref := range s.Containers {
			if ref.Component == component {
				known = true
				break
			}
		}
		if !known {
			return nil
		}
		at := time.Unix(event.Time, 0).UTC()
		if event.TimeNano != 0 {
			at = time.Unix(0, event.TimeNano).UTC()
		}
		return m.Store.AppendRuntimeEvent(ctx, store.RuntimeEvent{ServiceID: s.ID, ContainerID: event.Actor.ID, Component: component, Kind: kind, At: at, ObservedAt: time.Now().UTC()})
	}
	return nil
}
