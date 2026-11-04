package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/filesystem"
	"github.com/ctf-service-manager/ctf-service-manager/internal/packetcapture"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func (m *Manager) captureRPC(ctx context.Context, method, path string, input, out any) error {
	if !m.Config.Capture.Enabled {
		return proxyInput("Packet capture is not configured in this installation")
	}
	return localDataPlaneRPC(ctx, m.Config.Capture.ControlURL, m.Config.Capture.ControlTokenFile, method, path, input, out)
}
func (m *Manager) captureServiceTargets(ctx context.Context, s domain.Service, interfaces map[string]packetcapture.Interface) ([]transport.CaptureTarget, error) {
	st, e := m.state(ctx, s)
	if e != nil {
		return nil, e
	}
	if st.CurrentReleaseID == "" || st.BaselineID == "" {
		return nil, errors.New("Initialize the service baseline first")
	}
	model, e := m.observationConfiguration(ctx, s)
	if e != nil {
		return nil, e
	}
	release, e := m.loadRelease(ctx, s, st.CurrentReleaseID)
	if e != nil {
		return nil, e
	}
	pinModelImages(model, release.Spec().Images)
	actual, e := m.verifyRuntime(ctx, s, st, model)
	if e != nil {
		return nil, e
	}
	out := []transport.CaptureTarget{}
	var observedTree domain.Digest
	treeObserved := false
	for _, c := range actual {
		approved := false
		for _, ref := range s.Containers {
			if ref.Component == c.Component && ref.Role == domain.RoleApplication {
				approved = true
			}
		}
		if !approved {
			continue
		}
		points, e := c.CapturePoints()
		if e != nil {
			continue
		}
		versionVerified := true
		boundCode := false
		for _, mount := range c.Mounts {
			if mount.Type == "bind" {
				for _, managed := range s.ManagedPaths {
					if domain.PathsOverlap(filepath.Join(s.ProjectDirectory, managed.Path), mount.Source) {
						boundCode = true
					}
				}
			}
		}
		if boundCode {
			if !treeObserved {
				treeObserved = true
				observed, e := filesystem.Observe(ctx, s.ProjectDirectory, s.ManagedPaths, nil)
				if e == nil {
					observedTree = observed.Digest()
				}
			}
			versionVerified = observedTree != "" && observedTree == release.Spec().TreeDigest
		}
		networkIDs := map[string]bool{}
		for _, p := range points {
			networkIDs[p.NetworkID] = true
		}
		for _, p := range points {
			iface, ok := interfaces[p.Interface]
			if !ok || !iface.Up || !iface.Supported || iface.Loopback {
				continue
			}
			groupRaw, _ := json.Marshal([]any{s.ID, c.Component, p.Protocol, p.Port, p.NetworkID})
			group := "point-" + string(domain.Hash(groupRaw))[7:]
			base := transport.CaptureTarget{ServiceID: s.ID, ServiceName: s.Name, Component: c.Component, Protocol: p.Protocol, TargetPort: p.Port, Addresses: p.Addresses, Point: "container_bridge", PointGroup: group, ReleaseID: string(st.CurrentReleaseID), SourceDigest: string(release.Spec().TreeDigest)}
			if !versionVerified {
				base.ReleaseID = ""
				base.SourceDigest = ""
			}
			appendTarget := func(target transport.CaptureTarget) {
				raw, _ := json.Marshal(struct {
					Target             transport.CaptureTarget
					Container, Network string
					Policy, Sequence   uint64
					Release            domain.ID
				}{target, c.ID, p.NetworkID, s.PolicyRevision, st.Sequence, st.CurrentReleaseID})
				target.ID = "target-" + string(domain.Hash(raw))[7:]
				out = append(out, target)
			}
			if m.captureInterfaceApproved(iface.Name) {
				t := base
				t.Interface = iface.Name
				t.IfIndex = iface.Index
				appendTarget(t)
			}
			for _, point := range interfaces {
				if point.Up && point.Supported && point.Kind == "veth" && point.MasterIndex == iface.Index && m.captureInterfaceApproved(point.Name) {
					t := base
					t.Interface = point.Name
					t.IfIndex = point.Index
					t.Point = "container_veth"
					appendTarget(t)
				}
			}
			// Host NAT-leg alternatives are offered only with one unambiguous
			// container network. All mappings still originate in fresh inspect.
			if len(networkIDs) != 1 {
				continue
			}
			for _, raw := range c.Ports {
				host, port, target, proto, valid := capturePublication(raw)
				if !valid || target != p.Port || proto != p.Protocol || m.Config.Capture.HostPortProtected(port) {
					continue
				}
				for _, point := range interfaces {
					if !m.captureInterfaceApproved(point.Name) || !point.Up || !point.Supported || point.Kind == "bridge" || point.Kind == "veth" {
						continue
					}
					addresses := capturePublicationAddresses(host, point)
					if len(addresses) == 0 {
						continue
					}
					t := base
					t.Interface = point.Name
					t.IfIndex = point.Index
					t.Addresses = addresses
					t.ObservedPort = port
					t.Point = "host_publication"
					appendTarget(t)
				}
			}
		}
	}
	return out, nil
}
func (m *Manager) CaptureTargets(ctx context.Context) (transport.CaptureTargets, error) {
	v := transport.CaptureTargets{Targets: []transport.CaptureTarget{}, Unavailable: []transport.ProxyUnavailableTarget{}, AllowedInterfaces: append([]string{}, m.Config.Capture.AllowedInterfaces...)}
	if !m.Config.Capture.Enabled {
		return v, nil
	}
	var available []packetcapture.Interface
	if e := m.captureRPC(ctx, "GET", "/v1/interfaces", nil, &available); e != nil {
		return v, e
	}
	approved := map[string]packetcapture.Interface{}
	for _, iface := range available {
		approved[iface.Name] = iface
	}
	services, e := m.Store.ListServices(ctx)
	if e != nil {
		return v, e
	}
	for _, s := range services {
		targets, e := m.captureServiceTargets(ctx, s, approved)
		if e == nil {
			v.Targets = append(v.Targets, targets...)
		}
		for _, c := range s.Containers {
			if c.Role != domain.RoleApplication {
				continue
			}
			found := false
			for _, t := range targets {
				found = found || t.Component == c.Component
			}
			if found {
				continue
			}
			reason := "A running application with verified private Docker bridges, approved observation interfaces and explicit TCP/UDP exposed ports is required"
			if e != nil {
				reason = "Approved runtime could not be verified; resolve drift or initialize the baseline"
			}
			v.Unavailable = append(v.Unavailable, transport.ProxyUnavailableTarget{ServiceID: s.ID, Component: c.Component, Reason: reason})
		}
	}
	sort.Slice(v.Targets, func(i, j int) bool { return v.Targets[i].ID < v.Targets[j].ID })
	if len(v.Targets) > 256 {
		v.Targets = v.Targets[:256]
	}
	return v, nil
}
func captureSelection(targets transport.CaptureTargets, ids []string) ([]transport.CaptureTarget, error) {
	if len(ids) > 256 {
		return nil, proxyInput("Capture target budget exceeded")
	}
	wanted := map[string]bool{}
	groups := map[string]string{}
	out := []transport.CaptureTarget{}
	for _, id := range ids {
		if wanted[id] {
			return nil, proxyInput("Duplicate capture target")
		}
		wanted[id] = true
		found := false
		for _, t := range targets.Targets {
			if t.ID == id {
				if t.PointGroup != "" {
					previous := groups[t.PointGroup]
					if previous != "" && (previous != "host_publication" || t.Point != "host_publication") {
						return nil, proxyInput("Choose one canonical bridge, veth or host observation leg per target")
					}
					groups[t.PointGroup] = t.Point
				}
				out = append(out, t)
				found = true
				break
			}
		}
		if !found {
			return nil, proxyInput("Capture target runtime changed; refresh and review a new preview")
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func capturePolicyFor(revision uint64, in transport.CapturePreviewRequest, selected []transport.CaptureTarget) (packetcapture.Policy, error) {
	p := packetcapture.Policy{SchemaVersion: 1, Revision: revision, Enabled: in.Enabled, Snaplen: in.Snaplen, MaxPacketsPerSecond: in.MaxPacketsPerSecond, Interfaces: []packetcapture.InterfacePolicy{}}
	if !in.Enabled && len(selected) > 0 {
		return p, proxyInput("Disabled capture must have no selected targets")
	}
	grouped := map[string]*packetcapture.InterfacePolicy{}
	for _, t := range selected {
		key := fmt.Sprintf("%s/%d", t.Interface, t.IfIndex)
		v := grouped[key]
		if v == nil {
			v = &packetcapture.InterfacePolicy{Name: t.Interface, Index: t.IfIndex, Endpoints: []packetcapture.Endpoint{}}
			grouped[key] = v
		}
		for _, ip := range t.Addresses {
			v.Endpoints = append(v.Endpoints, packetcapture.Endpoint{ServiceID: string(t.ServiceID), Component: t.Component, Protocol: t.Protocol, Address: ip, Port: captureObservedPort(t), ReleaseID: t.ReleaseID, SourceDigest: t.SourceDigest})
		}
	}
	for _, v := range grouped {
		p.Interfaces = append(p.Interfaces, *v)
	}
	normalized, e := packetcapture.NormalizePolicy(captureLease(p))
	normalized.LeaseUntil = p.LeaseUntil
	if e != nil {
		return p, proxyInput(e.Error())
	}
	return normalized, nil
}

func (m *Manager) captureInterfaceApproved(name string) bool {
	for _, v := range m.Config.Capture.AllowedInterfaces {
		if v == name {
			return true
		}
	}
	return false
}
func captureObservedPort(t transport.CaptureTarget) int {
	if t.ObservedPort > 0 {
		return t.ObservedPort
	}
	return t.TargetPort
}
func capturePublication(raw string) (netip.Addr, int, int, string, bool) {
	host, published, target, protocol, ok := dockerPublication(raw)
	return host, published, target, protocol, ok && (protocol == "tcp" || protocol == "udp")
}
func capturePublicationAddresses(host netip.Addr, point packetcapture.Interface) []string {
	out := []string{}
	for _, raw := range point.Addresses {
		prefix, e := netip.ParsePrefix(raw)
		if e != nil {
			continue
		}
		ip := prefix.Addr().Unmap()
		if host.Is4() != ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		if host.IsUnspecified() {
			if !point.Loopback && ip.IsGlobalUnicast() {
				out = append(out, ip.String())
			}
		} else if ip == host || point.Loopback && host.IsLoopback() && prefix.Contains(host) {
			out = append(out, host.String())
		}
	}
	sort.Strings(out)
	dedup := out[:0]
	for _, v := range out {
		if len(dedup) == 0 || dedup[len(dedup)-1] != v {
			dedup = append(dedup, v)
		}
	}
	return dedup
}
