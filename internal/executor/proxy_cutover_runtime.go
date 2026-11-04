package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"sort"
	"strconv"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

// A port overlay is independent of release/configuration identities. Releases
// retain their immutable images and Compose input, while every future runtime
// recreation receives the administrator-approved publication change.
type runtimePortOverlayEntry struct {
	Component   string           `json:"component"`
	Original    []map[string]any `json:"original"`
	Replacement []map[string]any `json:"replacement"`
	Active      bool             `json:"active"`
}

type runtimePortOverlay struct {
	SchemaVersion       int                       `json:"schema_version,omitempty"`
	Entries             []runtimePortOverlayEntry `json:"entries,omitempty"`
	ServiceID           domain.ID                 `json:"service_id"`
	PolicyRevision      uint64                    `json:"policy_revision"`
	ConfigurationDigest domain.Digest             `json:"configuration_digest"`
	Sequence            uint64                    `json:"sequence"`
	CutoverID           domain.ID                 `json:"cutover_id"`
	Component           string                    `json:"component"`
	Original            []map[string]any          `json:"original"`
	Replacement         []map[string]any          `json:"replacement"`
	Active              bool                      `json:"active"`
}

func (m *Manager) runtimePortOverlay(ctx context.Context, id domain.ID) (runtimePortOverlay, error) {
	var latest runtimePortOverlay
	records, err := m.Store.List(ctx, "runtime_port_overlay", id)
	if err != nil {
		return latest, err
	}
	for _, record := range records {
		var v runtimePortOverlay
		if err := json.Unmarshal(record.Payload, &v); err != nil {
			return latest, err
		}
		if v.ServiceID != id || v.Sequence == 0 {
			return latest, errors.New("invalid runtime publication history")
		}
		if v.Sequence > latest.Sequence {
			latest = v
		}
	}
	return latest, nil
}

func (m *Manager) applyRuntimePorts(ctx context.Context, s domain.Service, model map[string]any) error {
	v, err := m.runtimePortOverlay(ctx, s.ID)
	if err != nil || !v.Active {
		return err
	}
	digest, err := m.currentConfigurationDigest(ctx, s)
	if err != nil {
		return err
	}
	if v.PolicyRevision != s.PolicyRevision || v.ConfigurationDigest != digest {
		return errors.New("approved publication overlay requires registration reconciliation")
	}
	entries, err := cutoverOverlayEntries(v)
	if err != nil {
		return err
	}
	services, _ := model["services"].(map[string]any)
	for _, entry := range entries {
		component, ok := services[entry.Component].(map[string]any)
		if !ok {
			return errors.New("publication overlay component disappeared")
		}
		actual, e := cutoverModelPorts(component)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(actual, entry.Original) && !reflect.DeepEqual(actual, entry.Replacement) {
			return errors.New("frozen publication differs from approved port overlay")
		}
		ports := entry.Original
		if entry.Active {
			ports = entry.Replacement
		}
		component["ports"] = cutoverPortValues(ports)
	}

	return nil
}

func (m *Manager) runtimeConfiguration(ctx context.Context, s domain.Service, c Configuration) (map[string]any, error) {
	model, err := m.materializedConfiguration(c)
	if err == nil {
		err = m.applyRuntimePorts(ctx, s, model)
	}
	return model, err
}

func cutoverModelPorts(component map[string]any) ([]map[string]any, error) {
	ports, ok := component["ports"].([]any)
	if !ok || len(ports) == 0 || len(ports) > 32 {
		return nil, errors.New("cutover requires a bounded set of fixed TCP publications")
	}
	out := make([]map[string]any, 0, len(ports))
	for _, raw := range ports {
		p, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("frozen publication is not normalized")
		}
		copy := map[string]any{}
		for k, value := range p {
			if k != "target" && k != "published" && k != "host_ip" && k != "protocol" && k != "mode" {
				return nil, errors.New("named or extended port profiles require explicit reconciliation")
			}
			copy[k] = value
		}
		target, err := cutoverPortNumber(p["target"])
		if err != nil {
			return nil, err
		}
		published, err := cutoverPortNumber(p["published"])
		if err != nil {
			return nil, err
		}
		protocol, _ := p["protocol"].(string)
		if protocol != "" && protocol != "tcp" {
			return nil, errors.New("UDP publication cannot be moved by HTTP proxy cutover")
		}
		mode, _ := p["mode"].(string)
		if mode != "" && mode != "ingress" {
			return nil, errors.New("unsupported publication mode")
		}
		copy["target"] = float64(target)
		copy["published"] = strconv.Itoa(published)
		copy["protocol"] = "tcp"
		if raw, exists := copy["host_ip"]; exists {
			ip, ok := raw.(string)
			if !ok {
				return nil, errors.New("publication host_ip must be a literal address or omitted")
			}
			if ip == "" {
				delete(copy, "host_ip")
			}
		}
		delete(copy, "mode")
		out = append(out, copy)
	}
	return out, nil
}

func cutoverPortNumber(v any) (int, error) {
	var text string
	switch n := v.(type) {
	case float64:
		if n != float64(int(n)) {
			return 0, errors.New("port must be an integer")
		}
		text = strconv.Itoa(int(n))
	case int:
		text = strconv.Itoa(n)
	case json.Number:
		text = n.String()
	case string:
		text = n
	default:
		return 0, errors.New("explicit port number required")
	}
	n, err := strconv.Atoi(text)
	if err != nil || n < 1 || n > 65535 {
		return 0, errors.New("port is outside 1..65535")
	}
	return n, nil
}

func cutoverPortValues(ports []map[string]any) []any {
	out := make([]any, 0, len(ports))
	for _, p := range ports {
		copy := map[string]any{}
		for key, value := range p {
			copy[key] = value
		}
		out = append(out, copy)
	}
	return out
}

func cutoverRuntimeDigest(actual []docker.Container) domain.Digest {
	copy := append([]docker.Container{}, actual...)
	sort.Slice(copy, func(i, j int) bool { return copy[i].Component < copy[j].Component })
	raw, _ := json.Marshal(copy)
	return domain.Hash(raw)
}

func cutoverVerifyContainers(s domain.Service, before, after []docker.Container, component string, model map[string]any) ([]domain.ContainerRef, error) {
	if len(before) != len(after) || (len(before) == 0 && component == "") {
		return nil, errors.New("cutover component count changed")
	}
	refs := make([]domain.ContainerRef, 0, len(before))
	seen := map[string]bool{}
	for _, current := range after {
		if seen[current.Component] {
			return nil, errors.New("duplicate component after cutover")
		}
		seen[current.Component] = true
		var old *docker.Container
		for i := range before {
			if before[i].Component == current.Component {
				old = &before[i]
				break
			}
		}
		if old == nil || old.ImageID != current.ImageID || !reflect.DeepEqual(old.Mounts, current.Mounts) {
			return nil, errors.New("cutover changed image or persistent mount identity")
		}
		if current.Component != component && current.ID != old.ID {
			return nil, errors.New("cutover recreated a dependency or another application")
		}
		if issues := current.RuntimeIssues(model, s.ComposeProject); len(issues) > 0 {
			return nil, fmt.Errorf("cutover runtime settings differ in %s (%s)", current.Component, issues[0].Code)
		}
		role := domain.ComponentRole("")
		for _, ref := range s.Containers {
			if ref.Component == current.Component {
				role = ref.Role
			}
		}
		if role == "" {
			return nil, errors.New("cutover observed an unregistered component")
		}
		refs = append(refs, domain.ContainerRef{Component: current.Component, ID: current.ID, ImageID: domain.Digest(current.ImageID), Role: role})
	}
	return refs, nil
}

func cutoverOverlayEntries(v runtimePortOverlay) ([]runtimePortOverlayEntry, error) {
	if v.SchemaVersion != 0 && v.SchemaVersion != 1 && v.SchemaVersion != 2 {
		return nil, errors.New("unsupported runtime port overlay schema")
	}
	if len(v.Entries) > 0 {
		if v.SchemaVersion != 2 {
			return nil, errors.New("group overlay requires schema version 2")
		}
		return append([]runtimePortOverlayEntry{}, v.Entries...), nil
	}
	if v.Component == "" {
		return nil, errors.New("empty runtime port overlay")
	}
	return []runtimePortOverlayEntry{{Component: v.Component, Original: v.Original, Replacement: v.Replacement, Active: v.Active}}, nil
}

func cutoverProposalEntries(p proxyCutoverProposal) ([]runtimePortOverlayEntry, error) {
	if p.SchemaVersion != 0 && p.SchemaVersion != 1 && p.SchemaVersion != 2 {
		return nil, errors.New("unsupported port transfer schema")
	}
	if len(p.Entries) > 0 {
		if p.SchemaVersion != 2 {
			return nil, errors.New("group transfer requires schema version 2")
		}
		return append([]runtimePortOverlayEntry{}, p.Entries...), nil
	}
	if p.Component == "" || len(p.OriginalPorts) == 0 || len(p.ReplacementPorts) == 0 {
		return nil, errors.New("empty port transfer")
	}
	return []runtimePortOverlayEntry{{Component: p.Component, Original: p.OriginalPorts, Replacement: p.ReplacementPorts}}, nil
}

func cutoverComponents(p proxyCutoverProposal) []string {
	entries, err := cutoverProposalEntries(p)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Component)
	}
	sort.Strings(out)
	return out
}

func cutoverPortStrings(ports []map[string]any) []string {
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		target, _ := cutoverPortNumber(p["target"])
		pub, _ := cutoverPortNumber(p["published"])
		ip, _ := p["host_ip"].(string)
		if address, e := netip.ParseAddr(ip); e == nil {
			ip = address.Unmap().String()
		}
		out = append(out, fmt.Sprintf("%s:%d->%d/tcp", ip, pub, target))
	}
	sort.Strings(out)
	return out
}

func cutoverContainerPortsEqual(c docker.Container, ports []map[string]any) bool {
	return cutoverObservedPortsEqual(c, cutoverPortStrings(ports))
}

// Docker may realize one implicit publication as IPv4 and IPv6 listeners.
// Keep the original Compose shape for recreation and verify its exact
// effective listener set using the separately frozen Docker evidence.
func cutoverOriginalPortsEqual(c docker.Container, entry runtimePortOverlayEntry, targets []transport.ProxyCutoverTargetPlan) bool {
	implicit := slices.ContainsFunc(entry.Original, func(port map[string]any) bool {
		ip, _ := port["host_ip"].(string)
		return ip == ""
	})
	if !implicit {
		// Historical proposals contain literal host_ip values and need no
		// separate Targets evidence to check their exact publication set.
		return cutoverContainerPortsEqual(c, entry.Original)
	}
	expected := []string{}
	for _, target := range targets {
		if target.Component != entry.Component {
			continue
		}
		for _, binding := range target.OriginalBindings {
			host, published, err := net.SplitHostPort(binding)
			if err != nil {
				return false
			}
			expected = append(expected, fmt.Sprintf("%s:%s->%d/tcp", host, published, target.UpstreamPort))
		}
	}
	sort.Strings(expected)
	return len(expected) > 0 && cutoverObservedPortsEqual(c, expected)
}

func cutoverObservedPortsEqual(c docker.Container, expected []string) bool {
	actual := make([]string, 0, len(c.Ports))
	for _, raw := range c.Ports {
		ip, pub, target, _, ok := privatePublication(raw)
		if !ok {
			return false
		}
		actual = append(actual, fmt.Sprintf("%s:%d->%d/tcp", ip, pub, target))
	}
	sort.Strings(actual)
	return reflect.DeepEqual(actual, expected)
}

// Group verification retains the baseline image/mount evidence for every
// selected application. Only selected application IDs may differ; dependencies
// retain their exact IDs. The driver rechecks private Docker inspect settings.
func (m *Manager) verifyCutoverGroup(ctx context.Context, s domain.Service, before, after []docker.Container, selected []string, model map[string]any) ([]domain.ContainerRef, error) {
	expectedComponents := map[string]bool{}
	for _, ref := range s.Containers {
		expectedComponents[ref.Component] = true
	}
	if len(before) != len(expectedComponents) {
		return nil, errors.New("recovery baseline does not cover the registered service")
	}
	baselineSeen := map[string]bool{}
	for _, c := range before {
		if !expectedComponents[c.Component] || baselineSeen[c.Component] {
			return nil, errors.New("recovery baseline component set is ambiguous")
		}
		baselineSeen[c.Component] = true
	}
	allowed := map[string]bool{}
	for _, c := range selected {
		allowed[c] = true
	}
	current := map[string]docker.Container{}
	for _, c := range after {
		if _, ok := current[c.Component]; ok {
			return nil, errors.New("duplicate runtime component")
		}
		current[c.Component] = c
	}
	filtered := make([]docker.Container, 0, len(before))
	for _, old := range before {
		now, exists := current[old.Component]
		if !exists {
			if !allowed[old.Component] {
				return nil, errors.New("unselected dependency disappeared")
			}
			continue
		}
		if allowed[old.Component] {
			old.ID = now.ID
		}
		filtered = append(filtered, old)
	}
	if len(filtered) == 0 && len(after) == 0 && len(before) > 0 {
		return []domain.ContainerRef{}, nil
	}
	// IDs have been normalized only for the explicitly selected set. Images,
	// mounts and effective runtime settings still come from approved evidence.
	return m.cutoverDriver().Verify(ctx, s, filtered, after, "", model)
}

// Health transitions during application warmup are observations, not runtime
// configuration changes. All identity, state, image, mount and port fields stay
// in this between-step checkpoint; final local checks still evaluate health.
func cutoverStepDigest(actual []docker.Container) domain.Digest {
	value := append([]docker.Container{}, actual...)
	for i := range value {
		value[i].Health = ""
	}
	return cutoverRuntimeDigest(value)
}
