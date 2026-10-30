package docker

import (
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// CapturePoint is narrowly derived from private, reconciled Docker inspection.
// No environment, command, labels, host paths or arbitrary host IPs are exposed.
type CapturePoint struct {
	Interface string
	Addresses []string
	Protocol  string
	Port      int
	NetworkID string
}

func (c Container) CapturePoints() ([]CapturePoint, error) {
	r := c.runtime
	if r == nil || r.container.NetworkSettings == nil || r.container.Config == nil || r.container.ID != c.ID {
		return nil, errors.New("private network inspection unavailable")
	}
	if c.State != "running" || len(r.container.NetworkSettings.Networks) == 0 || len(r.container.NetworkSettings.Networks) > 8 {
		return nil, errors.New("capture supports 1..8 inspected Docker bridge networks")
	}
	type attachmentPoint struct {
		iface, id string
		addresses []string
	}
	attachments := []attachmentPoint{}
	names := []string{}
	for name := range r.container.NetworkSettings.Networks {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		attachment := r.container.NetworkSettings.Networks[name]
		info, ok := r.networks[name]
		if !ok || attachment == nil || info.ID != attachment.NetworkID || info.Driver != "bridge" || info.Ingress {
			return nil, errors.New("network is not an inspected local Docker bridge")
		}
		if len(info.ID) != 64 {
			return nil, errors.New("invalid Docker network identity")
		}
		for _, ch := range info.ID {
			if !strings.ContainsRune("0123456789abcdef", ch) {
				return nil, errors.New("invalid Docker network identity")
			}
		}
		iface := info.Options["com.docker.network.bridge.name"]
		if iface == "" {
			if name == "bridge" {
				iface = "docker0"
			} else {
				iface = "br-" + info.ID[:12]
			}
		}
		if iface == "" || len(iface) > 15 || strings.ContainsAny(iface, "/\\ \t\r\n\x00") || iface == "lo" {
			return nil, errors.New("unsupported Docker bridge interface")
		}
		addresses := []string{}
		for _, ip := range []netip.Addr{attachment.IPAddress, attachment.GlobalIPv6Address} {
			if !ip.IsValid() {
				continue
			}
			if ip.Zone() != "" || !ip.IsPrivate() || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
				return nil, errors.New("capture requires private container addresses")
			}
			addresses = append(addresses, ip.Unmap().String())
		}
		if len(addresses) == 0 {
			return nil, errors.New("container has no inspected private bridge address")
		}
		sort.Strings(addresses)
		attachments = append(attachments, attachmentPoint{iface, info.ID, addresses})
	}
	ports := []string{}
	for p := range r.container.Config.ExposedPorts {
		ports = append(ports, p.String())
	}
	sort.Strings(ports)
	out := []CapturePoint{}
	for _, raw := range ports {
		port, proto, ok := strings.Cut(raw, "/")
		n, e := strconv.Atoi(port)
		if !ok || e != nil || n < 1 || n > 65535 || (proto != "tcp" && proto != "udp") {
			continue
		}
		for _, a := range attachments {
			out = append(out, CapturePoint{Interface: a.iface, Addresses: append([]string{}, a.addresses...), Protocol: proto, Port: n, NetworkID: a.id})
		}
	}
	return out, nil
}
