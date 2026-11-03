package docker

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

const maxChangedPublishedPorts = 128

// PublishedPortBinding is a fixed host publication. An invalid HostIP is the
// implicit Docker binding on all available addresses.
type PublishedPortBinding struct {
	Component string
	HostIP    netip.Addr
	Published uint16
	Target    uint16
	Protocol  string
}

// Overlaps compares host endpoints, independently of the container target.
func (p PublishedPortBinding) Overlaps(other PublishedPortBinding) bool {
	if p.Published == 0 || p.Published != other.Published || p.Protocol != other.Protocol {
		return false
	}
	left, right := p.HostIP.Unmap(), other.HostIP.Unmap()
	return !left.IsValid() || !right.IsValid() ||
		left.BitLen() == right.BitLen() && (left == right || left.IsUnspecified() || right.IsUnspecified())
}

func (p PublishedPortBinding) hostPort() string {
	host := "*"
	if p.HostIP.IsValid() {
		host = p.HostIP.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(p.Published)))
}

func (p PublishedPortBinding) String() string {
	return p.hostPort() + "/" + p.Protocol
}

// ComposeChangedPublishedPorts compares only port publications on approved
// targets and returns newly claimed fixed bindings for host preflight.
func ComposeChangedPublishedPorts(current, proposed map[string]any, targets []string) ([]PublishedPortBinding, error) {
	before, _ := current["services"].(map[string]any)
	after, _ := proposed["services"].(map[string]any)
	_, desired, err := composePublishedPortChanges(before, after, targets)
	return desired, err
}

func composePublishedPortChanges(before, after map[string]any, targets []string) ([]ComposeResourceChange, []PublishedPortBinding, error) {
	var changes []ComposeResourceChange
	var desired []PublishedPortBinding
	for _, component := range slices.Sorted(slices.Values(targets)) {
		left, _ := before[component].(map[string]any)
		right, _ := after[component].(map[string]any)
		if reflect.DeepEqual(left["ports"], right["ports"]) {
			continue
		}
		previous, next, err := changedComposeBindings(component, left["ports"], right["ports"])
		if err != nil {
			return nil, nil, err
		}
		if slices.Equal(previous, next) {
			continue
		}
		changes = append(changes, ComposeResourceChange{Component: component, Setting: "ports", Before: formatPublishedPorts(previous), After: formatPublishedPorts(next)})
		oldCount := map[PublishedPortBinding]int{}
		for _, old := range previous {
			oldCount[old]++
		}
		for _, binding := range next {
			if oldCount[binding] > 0 {
				oldCount[binding]--
			} else {
				desired = append(desired, binding)
			}
		}
	}
	if err := checkComposePublishedPortConflicts(after, desired); err != nil {
		return nil, nil, err
	}
	return changes, desired, nil
}

func formatPublishedPorts(bindings []PublishedPortBinding) string {
	values := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		values = append(values, fmt.Sprintf("%s → %d/%s", binding.hostPort(), binding.Target, binding.Protocol))
	}
	return strings.Join(values, ", ")
}

type composePortShape struct {
	target    uint16
	protocol  string
	unchanged string
}

func changedComposeBindings(component string, before, after any) ([]PublishedPortBinding, []PublishedPortBinding, error) {
	old, oldShape, err := composePortBindings(component, before)
	if err != nil {
		return nil, nil, err
	}
	next, nextShape, err := composePortBindings(component, after)
	if err != nil {
		return nil, nil, err
	}
	if !slices.Equal(oldShape, nextShape) {
		return nil, nil, fmt.Errorf("Compose component %q must keep existing container ports, protocols, and non-fixed publications", component)
	}
	return old, next, nil
}

func composePortBindings(component string, raw any) ([]PublishedPortBinding, []composePortShape, error) {
	if raw == nil {
		return nil, nil, nil
	}
	ports, ok := raw.([]any)
	if !ok || len(ports) > maxChangedPublishedPorts {
		return nil, nil, fmt.Errorf("Compose component %q has an unsupported publication list", component)
	}
	bindings := make([]PublishedPortBinding, 0, len(ports))
	shapes := make([]composePortShape, 0, len(ports))
	for _, raw := range ports {
		port, ok := raw.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("Compose component %q has a non-normalized publication", component)
		}
		if !sameSettingsExcept(port, nil, []string{"target", "published", "host_ip", "protocol", "mode"}) ||
			port["mode"] != nil && port["mode"] != "" && port["mode"] != "ingress" {
			return nil, nil, fmt.Errorf("Compose component %q has unsupported publication settings", component)
		}
		binding, err := parseComposePortBinding(component, port)
		if err != nil {
			return nil, nil, err
		}
		shape := composePortShape{target: binding.Target, protocol: binding.Protocol}
		if binding.Published == 0 {
			// Preserve an existing Docker-assigned port or range verbatim.
			encoded, err := json.Marshal(port)
			if err != nil {
				return nil, nil, err
			}
			shape.unchanged = string(encoded)
		} else {
			bindings = append(bindings, binding)
		}
		shapes = append(shapes, shape)
	}
	slices.SortFunc(shapes, func(a, b composePortShape) int {
		return cmp.Or(cmp.Compare(a.target, b.target), cmp.Compare(a.protocol, b.protocol), cmp.Compare(a.unchanged, b.unchanged))
	})
	slices.SortFunc(bindings, func(a, b PublishedPortBinding) int {
		return cmp.Or(cmp.Compare(a.Target, b.Target), cmp.Compare(a.Protocol, b.Protocol), cmp.Compare(a.Published, b.Published), a.HostIP.Compare(b.HostIP))
	})
	return bindings, shapes, nil
}

func parseComposePortBinding(component string, port map[string]any) (PublishedPortBinding, error) {
	binding := PublishedPortBinding{Component: component, Protocol: "tcp"}
	target, ok := integer(port["target"])
	if !ok || target < 1 || target > 65535 {
		return binding, fmt.Errorf("Compose component %q has an invalid container port", component)
	}
	binding.Target = uint16(target)
	if protocol := port["protocol"]; protocol != nil && protocol != "" {
		if protocol != "tcp" && protocol != "udp" {
			return binding, fmt.Errorf("Compose component %q must publish TCP or UDP", component)
		}
		binding.Protocol = protocol.(string)
	}
	if host := port["host_ip"]; host != nil && host != "" {
		raw, ok := host.(string)
		if !ok {
			return binding, fmt.Errorf("Compose component %q has an invalid publication address", component)
		}
		ip, err := netip.ParseAddr(raw)
		if err != nil || ip.Zone() != "" || ip.Is4In6() {
			return binding, fmt.Errorf("Compose component %q has an invalid publication address", component)
		}
		binding.HostIP = ip
	}
	// Compose emits published ports as strings. A range or an omitted value
	// does not identify a fixed host endpoint and is handled by the shape.
	if raw, ok := port["published"].(string); ok {
		if published, err := strconv.ParseUint(raw, 10, 16); err == nil && strconv.FormatUint(published, 10) == raw {
			binding.Published = uint16(published)
		}
	}
	return binding, nil
}

func checkComposePublishedPortConflicts(components map[string]any, desired []PublishedPortBinding) error {
	if len(desired) == 0 {
		return nil
	}
	if len(desired) > maxChangedPublishedPorts {
		return fmt.Errorf("Compose change exceeds %d fixed port publications", maxChangedPublishedPorts)
	}
	overlaps := make([]int, len(desired))
	for component, raw := range components {
		service, _ := raw.(map[string]any)
		rows, _ := service["ports"].([]any)
		for _, raw := range rows {
			port, _ := raw.(map[string]any)
			binding, err := parseComposePortBinding(component, port)
			if err != nil {
				continue
			}
			for i, want := range desired {
				if !want.Overlaps(binding) {
					continue
				}
				overlaps[i]++
				if overlaps[i] > 1 {
					return fmt.Errorf("Compose component %q has a conflicting publication on %s", want.Component, want)
				}
			}
		}
	}
	return nil
}
