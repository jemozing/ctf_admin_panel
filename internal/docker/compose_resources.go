package docker

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"sort"
	"strconv"
)

type ComposeResourceChange struct {
	Component string `json:"component"`
	Setting   string `json:"setting"`
	Before    string `json:"before"`
	After     string `json:"after"`
}

var composeResourceSettings = []string{"cpus", "mem_limit", "pids_limit"}
var composeRevisionSettings = []string{"cpus", "mem_limit", "pids_limit", "ports"}

// ComposeResourceChanges accepts supported resource limits and changes to the
// published addresses and port numbers of existing target bindings.
func ComposeResourceChanges(current, proposed map[string]any, targets []string) ([]ComposeResourceChange, error) {
	if !sameSettingsExcept(current, proposed, []string{"services"}) {
		return nil, errors.New("Compose project settings differ outside supported resource limits and published ports")
	}
	before, _ := current["services"].(map[string]any)
	after, _ := proposed["services"].(map[string]any)
	if len(before) == 0 || len(before) != len(after) {
		return nil, errors.New("Compose component set changed")
	}
	names := make([]string, 0, len(before))
	for name := range before {
		names = append(names, name)
	}
	sort.Strings(names)

	changes := []ComposeResourceChange{}
	for _, name := range names {
		left, leftOK := before[name].(map[string]any)
		right, rightOK := after[name].(map[string]any)
		if !leftOK || !rightOK {
			return nil, errors.New("Compose component set changed")
		}
		if !slices.Contains(targets, name) {
			if !reflect.DeepEqual(left, right) {
				return nil, fmt.Errorf("non-target Compose component %q changed", name)
			}
			continue
		}
		if !sameSettingsExcept(left, right, composeRevisionSettings) {
			return nil, fmt.Errorf("Compose component %q changed outside supported resource limits and published ports", name)
		}
		firstChange := len(changes)
		for _, setting := range composeResourceSettings {
			oldValue, oldExists := left[setting]
			newValue, newExists := right[setting]
			if oldExists == newExists && reflect.DeepEqual(oldValue, newValue) {
				continue
			}
			old, oldOK := composeResourceValue(setting, oldValue, oldExists)
			next, nextOK := composeResourceValue(setting, newValue, newExists)
			if !oldOK || !nextOK {
				return nil, fmt.Errorf("invalid Compose resource limit %s for component %q", setting, name)
			}
			if old != next {
				changes = append(changes, ComposeResourceChange{Component: name, Setting: setting, Before: old, After: next})
			}
		}
		if firstChange != len(changes) && !resourceLimitsCompatible(right) {
			return nil, fmt.Errorf("Compose resource limits conflict for component %q", name)
		}
	}
	portChanges, _, err := composePublishedPortChanges(before, after, targets)
	if err != nil {
		return nil, err
	}
	return append(changes, portChanges...), nil
}

// Compose config normalizes each setting, but the Docker Engine checks their
// combinations at container creation. Reject contradictions before cutover.
func resourceLimitsCompatible(component map[string]any) bool {
	limit, _ := composeMemory(component["mem_limit"])
	reserve, _ := composeMemory(component["mem_reservation"])
	swap, _ := composeMemory(component["memswap_limit"])
	if limit > 0 && reserve > limit || swap > 0 && (limit == 0 || swap < limit) {
		return false
	}
	cpus, _ := strconv.ParseFloat(fmt.Sprint(component["cpus"]), 64)
	period, _ := integer(component["cpu_period"])
	quota, _ := integer(component["cpu_quota"])
	return cpus == 0 || period <= 0 && quota <= 0
}

func sameSettingsExcept(left, right map[string]any, ignored []string) bool {
	for key, value := range left {
		if slices.Contains(ignored, key) {
			continue
		}
		other, exists := right[key]
		if !exists || !reflect.DeepEqual(value, other) {
			return false
		}
	}
	for key := range right {
		if _, exists := left[key]; !exists && !slices.Contains(ignored, key) {
			return false
		}
	}
	return true
}

func composeResourceValue(setting string, value any, exists bool) (string, bool) {
	if !exists {
		return "", true
	}
	if number, ok := value.(json.Number); ok {
		value = number.String()
	}
	switch setting {
	case "cpus":
		n, err := strconv.ParseFloat(fmt.Sprint(value), 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n >= float64(math.MaxInt64)/1e9 || n > 0 && n*1e9 < 1 {
			return "", false
		}
		return strconv.FormatFloat(n, 'f', -1, 64), true
	case "mem_limit":
		// Docker requires at least 6 MiB for a positive memory limit. Bound
		// accepted bytes to integers that Compose JSON represents exactly.
		n, ok := composeMemory(value)
		if !ok || n < 0 || n > 1<<53-1 || n > 0 && n < 6<<20 {
			return "", false
		}
		return strconv.FormatInt(n, 10), true
	case "pids_limit":
		n, ok := integer(value)
		if !ok || n < -1 || n > 1<<53-1 {
			return "", false
		}
		return strconv.FormatInt(n, 10), true
	default:
		return "", false
	}
}

func composeMemory(value any) (int64, bool) {
	if n, ok := integer(value); ok {
		return n, true
	}
	return memory(value)
}

// normalizeDeployLimits maps the Docker local-engine shorthand emitted by
// Compose for a limits-only deploy block to the equivalent service settings.
// Other deploy semantics remain visible to the runtime profile validator.
func normalizeDeployLimits(document map[string]any) error {
	services, _ := document["services"].(map[string]any)
	for _, raw := range services {
		service, _ := raw.(map[string]any)
		deploy, _ := service["deploy"].(map[string]any)
		limits := deployResourceLimits(deploy)
		if len(limits) == 0 {
			continue
		}
		for _, setting := range []struct{ from, to string }{{"cpus", "cpus"}, {"memory", "mem_limit"}} {
			value, exists := limits[setting.from]
			if !exists {
				continue
			}
			limit, valid := composeResourceValue(setting.to, value, true)
			if !valid {
				return fmt.Errorf("invalid Compose deploy resource limit %s", setting.from)
			}
			if direct, ok := service[setting.to]; ok {
				normalized, valid := composeResourceValue(setting.to, direct, true)
				if !valid || limit != normalized {
					return fmt.Errorf("Compose deploy resource limit %s conflicts with %s", setting.from, setting.to)
				}
				continue
			}
			if setting.to == "cpus" {
				service[setting.to], _ = strconv.ParseFloat(limit, 64)
			} else {
				service[setting.to] = limit
			}
		}
		delete(service, "deploy")
	}
	return nil
}

func deployResourceLimits(deploy map[string]any) map[string]any {
	for key, value := range deploy {
		placement, isMap := value.(map[string]any)
		if key != "resources" && (key != "placement" || !isMap || len(placement) != 0) {
			return nil
		}
	}
	resources, _ := deploy["resources"].(map[string]any)
	if len(resources) != 1 {
		return nil
	}
	limits, _ := resources["limits"].(map[string]any)
	for key := range limits {
		if key != "cpus" && key != "memory" {
			return nil
		}
	}
	return limits
}
