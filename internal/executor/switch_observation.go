package executor

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

const maximumSwitchObservationComponents = 256

type runtimeSwitchComponent struct {
	Component   string `json:"component"`
	ContainerID string `json:"container_id"`
	ImageID     string `json:"image_id"`
	State       string `json:"state"`
}

// runtimeSwitchObservation is durable evidence, never an approved runtime state.
// In particular, partial/unrecognized components cannot authorize another action.
type runtimeSwitchObservation struct {
	OperationID            domain.ID                `json:"operation_id"`
	TargetReleaseID        domain.ID                `json:"target_release_id"`
	At                     time.Time                `json:"at"`
	ComposeSucceeded       bool                     `json:"compose_succeeded"`
	ExpectedComponentCount int                      `json:"expected_component_count"`
	ObservedComponentCount *int                     `json:"observed_component_count"`
	InventoryState         string                   `json:"inventory_state"`
	Components             []runtimeSwitchComponent `json:"components"`
	Truncated              bool                     `json:"truncated"`
	Reason                 string                   `json:"reason,omitempty"`
}

func boundedObservationText(value string, max int) string {
	if len(value) > max {
		value = value[:max]
	}
	return strings.ToValidUTF8(value, "?")
}

// recordRuntimeSwitchObservation runs after every Compose up outcome. A timeout
// or lost Compose response does not cancel the independent observation/journal
// budget. If inventory cannot be obtained, unknown is persisted (never count=0).
func (m *Manager) recordRuntimeSwitchObservation(ctx context.Context, s domain.Service, operation, target domain.ID, composeSucceeded bool) error {
	observation := runtimeSwitchObservation{OperationID: operation, TargetReleaseID: target, At: time.Now().UTC(), ComposeSucceeded: composeSucceeded, ExpectedComponentCount: len(s.Containers), InventoryState: "unknown", Components: []runtimeSwitchComponent{}}
	if err := operation.Validate(); err != nil {
		return err
	}
	if err := target.Validate(); err != nil {
		return err
	}
	inventoryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	var inventoryErr error
	if m.Engine == nil {
		inventoryErr = errors.New("Docker inventory unavailable")
	} else {
		items, err := m.Engine.Inventory(inventoryCtx, s.ComposeProject)
		inventoryErr = err
		if err == nil {
			count := len(items)
			observation.ObservedComponentCount = &count
			observation.InventoryState = "known"
			for i, item := range items {
				if i >= maximumSwitchObservationComponents {
					observation.Truncated = true
					break
				}
				observation.Components = append(observation.Components, runtimeSwitchComponent{Component: boundedObservationText(item.Component, 128), ContainerID: boundedObservationText(item.ID, 128), ImageID: boundedObservationText(item.ImageID, 160), State: boundedObservationText(item.State, 64)})
			}
			sort.Slice(observation.Components, func(i, j int) bool {
				a, b := observation.Components[i], observation.Components[j]
				if a.Component != b.Component {
					return a.Component < b.Component
				}
				return a.ContainerID < b.ContainerID
			})
		}
	}
	cancel()
	if inventoryErr != nil {
		observation.Reason = "Docker inventory unavailable; actual component identities are unknown"
	}
	if observation.Truncated {
		observation.Reason = "Runtime component list exceeds the bounded observation limit"
	}
	recording, stop := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer stop()
	if err := m.Store.PutImmutable(recording, "runtime_switch_observation", NewID("switch-observation-"), s.ID, observation); err != nil {
		return err
	}
	if inventoryErr != nil {
		return errors.New("runtime switch observation recorded as unknown; reconciliation required")
	}
	if observation.Truncated {
		return errors.New("runtime switch observation truncated; reconciliation required")
	}
	return nil
}
