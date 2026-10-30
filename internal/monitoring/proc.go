// Package monitoring reads a fixed, explicitly mounted set of host observations.
// It never substitutes the executor's own namespace for host evidence.
package monitoring

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

type cpuCounters struct{ total, idle, cores uint64 }

func add(a, b uint64) (uint64, error) {
	if math.MaxUint64-a < b {
		return 0, errors.New("counter overflow")
	}
	return a + b, nil
}

func parseCPU(data string) (cpuCounters, error) {
	var result cpuCounters
	found := false
	s := bufio.NewScanner(strings.NewReader(data))
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) == 0 {
			continue
		}
		if fields[0] != "cpu" {
			if strings.HasPrefix(fields[0], "cpu") {
				if _, err := strconv.ParseUint(strings.TrimPrefix(fields[0], "cpu"), 10, 32); err == nil {
					result.cores++
				}
			}
			continue
		}
		if found || len(fields) < 5 {
			return result, errors.New("invalid CPU counters")
		}
		found = true
		// guest and guest_nice are already included in user/nice by Linux.
		for i, raw := range fields[1:] {
			value, err := strconv.ParseUint(raw, 10, 64)
			if err != nil {
				return result, errors.New("invalid CPU counter")
			}
			if i >= 8 {
				continue
			}
			result.total, err = add(result.total, value)
			if err != nil {
				return result, err
			}
			if i == 3 || i == 4 {
				result.idle, err = add(result.idle, value)
				if err != nil {
					return result, err
				}
			}
		}
	}
	if err := s.Err(); err != nil {
		return result, err
	}
	if !found || result.cores == 0 || result.idle > result.total {
		return result, errors.New("missing CPU counters")
	}
	return result, nil
}

func parseMemory(data string) (map[string]uint64, error) {
	required := map[string]bool{"MemTotal:": true, "MemAvailable:": true, "SwapTotal:": true, "SwapFree:": true}
	result := map[string]uint64{}
	s := bufio.NewScanner(strings.NewReader(data))
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) == 0 || !required[fields[0]] {
			continue
		}
		if len(fields) != 3 || fields[2] != "kB" {
			return nil, errors.New("invalid memory unit")
		}
		if _, duplicate := result[fields[0]]; duplicate {
			return nil, errors.New("duplicate memory field")
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || value > math.MaxUint64/1024 {
			return nil, errors.New("invalid memory counter")
		}
		result[fields[0]] = value * 1024
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	// MemAvailable is deliberately not approximated on old/unsupported kernels.
	if len(result) != len(required) || result["MemTotal:"] == 0 || result["MemAvailable:"] > result["MemTotal:"] || result["SwapFree:"] > result["SwapTotal:"] {
		return nil, errors.New("missing or inconsistent memory counters")
	}
	return result, nil
}

func nonnegative(raw string) (float64, error) {
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || value < 0 || math.IsInf(value, 0) || math.IsNaN(value) {
		return 0, errors.New("invalid numeric observation")
	}
	return value, nil
}

func parseLoad(data string) ([3]float64, error) {
	var result [3]float64
	fields := strings.Fields(data)
	if len(fields) < 5 {
		return result, errors.New("missing load averages")
	}
	for i := range result {
		value, err := nonnegative(fields[i])
		if err != nil {
			return result, err
		}
		result[i] = value
	}
	return result, nil
}

func parseUptime(data string) (float64, error) {
	fields := strings.Fields(data)
	if len(fields) != 2 {
		return 0, errors.New("missing uptime")
	}
	return nonnegative(fields[0])
}

func parseNetwork(data string) ([]transport.HostNetworkMetrics, uint64, uint64, error) {
	result := []transport.HostNetworkMetrics{}
	var rx, tx uint64
	seen := map[string]bool{}
	s := bufio.NewScanner(strings.NewReader(data))
	for s.Scan() {
		line := s.Text()
		colon := strings.LastIndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		if name == "" || len(name) > 64 || strings.ContainsAny(name, " \t\r\n/\\") || seen[name] {
			return nil, 0, 0, errors.New("invalid network interface")
		}
		seen[name] = true
		fields := strings.Fields(line[colon+1:])
		if len(fields) != 16 {
			return nil, 0, 0, errors.New("invalid network counters")
		}
		values := make([]uint64, 16)
		for i, raw := range fields {
			value, err := strconv.ParseUint(raw, 10, 64)
			if err != nil {
				return nil, 0, 0, err
			}
			values[i] = value
		}
		if len(result) >= 128 {
			return nil, 0, 0, errors.New("network interface limit exceeded")
		}
		result = append(result, transport.HostNetworkMetrics{Name: name, RxBytes: values[0], TxBytes: values[8]})
		if name == "lo" {
			continue
		}
		var err error
		rx, err = add(rx, values[0])
		if err != nil {
			return nil, 0, 0, err
		}
		tx, err = add(tx, values[8])
		if err != nil {
			return nil, 0, 0, err
		}
	}
	if err := s.Err(); err != nil {
		return nil, 0, 0, err
	}
	if len(result) == 0 {
		return nil, 0, 0, fmt.Errorf("missing network interfaces")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, rx, tx, nil
}
