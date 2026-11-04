package executor

import (
	"context"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func (m *Manager) serviceExternalPorts(ctx context.Context, id domain.ID, containers []docker.Container) []transport.ExternalPort {
	ports := make(map[transport.ExternalPort]struct{})
	for _, container := range containers {
		if container.State != "running" {
			continue
		}
		for _, binding := range container.Ports {
			host, port, _, protocol, ok := dockerPublication(binding)
			if ok && !host.IsLoopback() {
				ports[transport.ExternalPort{Port: port, Protocol: protocol}] = struct{}{}
			}
		}
	}
	if m.Config.Proxy.Enabled {
		var status struct {
			Available            bool             `json:"available"`
			PublicPortsByService map[string][]int `json:"public_ports_by_service"`
		}
		proxyCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		err := m.proxyRPC(proxyCtx, http.MethodGet, "/v1/status", nil, &status)
		cancel()
		if err == nil && status.Available && status.PublicPortsByService != nil {
			for _, port := range status.PublicPortsByService[string(id)] {
				if port >= 1 && port <= 65535 {
					ports[transport.ExternalPort{Port: port, Protocol: "tcp"}] = struct{}{}
				}
			}
		} else if len(ports) == 0 {
			return nil
		}
	}
	result := make([]transport.ExternalPort, 0, len(ports))
	for port := range ports {
		result = append(result, port)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Port == result[j].Port {
			return result[i].Protocol < result[j].Protocol
		}
		return result[i].Port < result[j].Port
	})
	return result
}

// dockerPublication parses the host binding reported by Docker inventory.
func dockerPublication(raw string) (host netip.Addr, published, target int, protocol string, ok bool) {
	left, right, found := strings.Cut(raw, "->")
	if !found {
		return
	}
	targetRaw, protocol, found := strings.Cut(right, "/")
	if !found || (protocol != "tcp" && protocol != "udp" && protocol != "sctp") {
		return
	}
	i := strings.LastIndex(left, ":")
	if i < 0 {
		return
	}
	var err error
	host, err = netip.ParseAddr(strings.Trim(left[:i], "[]"))
	if err != nil || host.Zone() != "" || host.IsMulticast() {
		return
	}
	published, err = strconv.Atoi(left[i+1:])
	if err != nil || published < 1 || published > 65535 {
		return
	}
	target, err = strconv.Atoi(targetRaw)
	if err != nil || target < 1 || target > 65535 {
		return
	}
	return host.Unmap(), published, target, protocol, true
}
