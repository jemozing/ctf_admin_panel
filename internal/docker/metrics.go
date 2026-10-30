package docker

import (
	"context"
	"fmt"
	"github.com/moby/moby/client"
)

// MetricContainer is observation only, and carries no runtime approval evidence.
type MetricContainer struct {
	ID              string
	Component       string
	State           string
	RestartCount    *uint64
	OOMKilled       *bool
	CPULimitPercent *float64
	PidsLimit       *uint64
}

// MetricsInventory inspects only fixed approved container IDs, avoiding image,
// network and volume runtime-policy inspection on every observation.
func (e *Engine) MetricsInventory(ctx context.Context, project string, ids []string) ([]MetricContainer, error) {
	if e == nil || e.Client == nil {
		return nil, fmt.Errorf("Docker metric source unavailable")
	}
	if len(ids) > 128 {
		return nil, fmt.Errorf("metrics container budget exceeded")
	}
	result := make([]MetricContainer, 0, len(ids))
	for _, id := range ids {
		r, err := e.Client.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
		if err != nil {
			return nil, err
		}
		info := r.Container
		if info.ID != id || info.Config == nil || info.Config.Labels["com.docker.compose.project"] != project {
			return nil, fmt.Errorf("metric container identity mismatch")
		}
		item := MetricContainer{ID: id, Component: info.Config.Labels["com.docker.compose.service"], State: "unknown"}
		if info.RestartCount >= 0 {
			count := uint64(info.RestartCount)
			item.RestartCount = &count
		}
		if info.State != nil {
			item.State = string(info.State.Status)
			oom := info.State.OOMKilled
			item.OOMKilled = &oom
		}
		if info.HostConfig != nil {
			h := info.HostConfig
			if h.NanoCPUs > 0 {
				value := float64(h.NanoCPUs) / 1e9 * 100
				item.CPULimitPercent = &value
			} else if h.CPUQuota > 0 && h.CPUPeriod > 0 {
				value := float64(h.CPUQuota) / float64(h.CPUPeriod) * 100
				item.CPULimitPercent = &value
			}
			if h.PidsLimit != nil && *h.PidsLimit > 0 {
				value := uint64(*h.PidsLimit)
				item.PidsLimit = &value
			}
		}
		result = append(result, item)
	}
	return result, nil
}
