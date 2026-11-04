package docker

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

// LoopbackTCPPortReserved checks Docker publications that can conflict with
// the private backend. A host socket check alone misses Docker's NAT rules.
func (e *Engine) LoopbackTCPPortReserved(ctx context.Context, ports []int) (bool, error) {
	filters := client.Filters{}.Add("status", string(container.StateRunning), string(container.StatePaused), string(container.StateRestarting))
	listed, err := e.Client.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
	if err != nil {
		return false, err
	}
	for _, item := range listed.Items {
		result, err := e.Client.ContainerInspect(ctx, item.ID, client.ContainerInspectOptions{})
		if err != nil {
			return false, err
		}
		info := result.Container
		if info.State == nil || info.HostConfig == nil {
			return false, errors.New("Docker container port metadata is incomplete")
		}
		switch info.State.Status {
		case container.StateRunning, container.StatePaused, container.StateRestarting:
		case container.StateCreated, container.StateExited, container.StateDead:
			continue
		case container.StateRemoving:
			// A container that started removal may still hold its publications.
		default:
			return false, errors.New("Docker container port state is unknown")
		}
		reserved, err := loopbackTCPPortInBindings(info.HostConfig.PortBindings, ports)
		if err != nil || reserved {
			return reserved, err
		}
		if info.NetworkSettings != nil {
			reserved, err = loopbackTCPPortInBindings(info.NetworkSettings.Ports, ports)
			if err != nil || reserved {
				return reserved, err
			}
		}
	}
	return false, nil
}

func loopbackTCPPortInBindings(bindings network.PortMap, ports []int) (bool, error) {
	for target, publications := range bindings {
		if target.Proto() != "tcp" {
			continue
		}
		for _, publication := range publications {
			ip := publication.HostIP.Unmap()
			if ip.IsValid() && !ip.IsLoopback() && !ip.IsUnspecified() {
				continue
			}
			if publication.HostPort == "" || publication.HostPort == "0" {
				// Dynamic allocations appear as concrete observed bindings.
				continue
			}
			first, last, isRange := strings.Cut(publication.HostPort, "-")
			if !isRange {
				last = first
			}
			low, lowErr := strconv.Atoi(first)
			high, highErr := strconv.Atoi(last)
			if lowErr != nil || highErr != nil || low < 1 || high > 65535 || low > high {
				return false, errors.New("Docker reported an invalid host port binding")
			}
			for _, port := range ports {
				if low <= port && port <= high {
					return true, nil
				}
			}
		}
	}
	return false, nil
}
