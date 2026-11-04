package executor

import (
	"cmp"
	"context"
	"errors"
	"net/netip"
	"net/url"
	"strconv"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	proxyengine "github.com/ctf-service-manager/ctf-service-manager/internal/proxy"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"github.com/moby/moby/client"
)

func composeTargetIDs(s domain.Service, containers []domain.ContainerRef) []string {
	var ids []string
	for _, container := range containers {
		if hasTarget(s, container.Component) {
			ids = append(ids, container.ID)
		}
	}
	return ids
}

// Docker may reserve a port without a listening process in our network
// namespace. Use the daemon's publications plus managed proxy listeners.
// External listeners can still race this check; the release recovery point
// is committed before any container is stopped.
func (m *Manager) checkComposePorts(ctx context.Context, s domain.Service, before, after map[string]any, replaced []string) error {
	ports, err := docker.ComposeChangedPublishedPorts(before, after, s.Targets)
	if err != nil || len(ports) == 0 {
		return err
	}
	if m.Engine == nil || m.Engine.Client == nil {
		return errors.New("Docker port reservation inventory is unavailable")
	}
	inventory, err := m.Engine.Client.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return errors.New("Docker port reservation inventory is unavailable")
	}
	releasing := make(map[string]bool, len(replaced))
	for _, id := range replaced {
		releasing[id] = true
	}
	for _, container := range inventory.Items {
		if releasing[container.ID] {
			continue
		}
		switch container.State {
		case "running", "paused", "restarting", "removing":
		default:
			continue
		}
		for _, active := range container.Ports {
			if active.PublicPort == 0 {
				continue
			}
			binding := docker.PublishedPortBinding{HostIP: active.IP.Unmap(), Published: active.PublicPort, Protocol: active.Type}
			for _, port := range ports {
				if port.Overlaps(binding) {
					return composePortConflict(port, "host port is already published by another container")
				}
			}
		}
	}
	if m.Config.Proxy.Enabled {
		revision, _, _, err := m.effectiveProxyRevision(ctx)
		if err != nil {
			return errors.New("HTTP Proxy listener inventory is unavailable")
		}
		if m.Config.Proxy.AllowPublicBackendObservation {
			var status proxyengine.Status
			if err := m.proxyRPC(ctx, "GET", "/v1/status", nil, &status); err != nil ||
				status.AppliedRevision != revision.Policy.Revision || status.PolicyDigest != proxyengine.PolicyDigest(revision.Policy) {
				return composePortConflict(ports[0], "wait for the current HTTP Proxy policy to become active")
			}
		}
		for _, route := range revision.Policy.Routes {
			if m.Config.Proxy.AllowPublicBackendObservation {
				if route.ServiceID == string(s.ID) {
					return composePortConflict(ports[0], "remove this service's HTTP Proxy routes before changing its published ports")
				}
				upstream, err := url.Parse(route.Upstream)
				if err != nil {
					return errors.New("HTTP Proxy upstream inventory is unavailable")
				}
				ip, err := netip.ParseAddr(upstream.Hostname())
				if err != nil {
					return errors.New("HTTP Proxy upstream inventory is unavailable")
				}
				number, err := strconv.ParseUint(cmp.Or(upstream.Port(), "80"), 10, 16)
				if err != nil {
					return errors.New("HTTP Proxy upstream inventory is unavailable")
				}
				binding := docker.PublishedPortBinding{HostIP: ip.Unmap(), Published: uint16(number), Protocol: "tcp"}
				for _, port := range ports {
					if port.Overlaps(binding) {
						return composePortConflict(port, "host port is reserved by an HTTP Proxy backend")
					}
				}
			}
			listen, err := netip.ParseAddrPort(route.Listen)
			if err != nil {
				return errors.New("HTTP Proxy listener inventory is unavailable")
			}
			binding := docker.PublishedPortBinding{HostIP: listen.Addr().Unmap(), Published: listen.Port(), Protocol: "tcp"}
			for _, port := range ports {
				if port.Overlaps(binding) {
					return composePortConflict(port, "host port is reserved by HTTP Proxy")
				}
			}
		}
	}
	return nil
}

func (m *Manager) validateNewComposePorts(s domain.Service, before, after map[string]any) error {
	ports, err := docker.ComposeChangedPublishedPorts(before, after, s.Targets)
	if err != nil {
		return err
	}
	for _, port := range ports {
		if m.Config.Capture.HostPortProtected(int(port.Published)) {
			return composePortConflict(port, "host port is reserved for administration")
		}
	}
	return nil
}

func composePortConflict(port docker.PublishedPortBinding, reason string) error {
	return &transport.ComposePortConflict{Binding: port.String(), Reason: reason}
}
