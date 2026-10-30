package packetcapture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"syscall"
	"time"
)

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

func NormalizePolicy(input Policy) (Policy, error) {
	p := input
	if p.SchemaVersion != SchemaVersion || p.Revision == 0 || p.Snaplen < 0 || p.Snaplen > 65535 || (p.Snaplen > 0 && p.Snaplen < 64) || p.MaxPacketsPerSecond < 1 || p.MaxPacketsPerSecond > 100000 || len(p.Interfaces) > MaxInterfaces {
		return Policy{}, errors.New("invalid capture policy bounds")
	}
	if p.Enabled && (p.LeaseUntil.IsZero() || !p.LeaseUntil.After(time.Now()) || p.LeaseUntil.After(time.Now().Add(60*time.Second))) {
		return Policy{}, errors.New("enabled capture requires an unexpired runtime lease of at most 60 seconds")
	}
	if !p.LeaseUntil.IsZero() {
		p.LeaseUntil = p.LeaseUntil.UTC()
	}
	p.Interfaces = append([]InterfacePolicy(nil), input.Interfaces...)
	seenNames, seenIndices, pointInterfaces := map[string]bool{}, map[int]bool{}, map[string]string{}
	count := 0
	for n := range p.Interfaces {
		v := &p.Interfaces[n]
		if !interfaceName.MatchString(v.Name) || v.Index < 1 || v.Index > 1<<30 || seenNames[v.Name] || seenIndices[v.Index] {
			return Policy{}, errors.New("capture interfaces must have unique explicit names and indices")
		}
		seenNames[v.Name], seenIndices[v.Index] = true, true
		v.Endpoints = append([]Endpoint(nil), v.Endpoints...)
		if len(v.Endpoints) == 0 {
			return Policy{}, errors.New("capture interface requires approved endpoints")
		}
		seen := map[string]bool{}
		for m := range v.Endpoints {
			e := &v.Endpoints[m]
			addr, err := netip.ParseAddr(e.Address)
			if err != nil || addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() || !identifier.MatchString(e.ServiceID) || !identifier.MatchString(e.Component) || (e.Protocol != "tcp" && e.Protocol != "udp") || e.Port < 1 || e.Port > 65535 {
				return Policy{}, errors.New("invalid capture endpoint")
			}
			if e.ReleaseID != "" && !identifier.MatchString(e.ReleaseID) {
				return Policy{}, errors.New("invalid captured release identity")
			}
			if e.SourceDigest != "" && !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(e.SourceDigest) {
				return Policy{}, errors.New("invalid captured source digest")
			}
			e.Address = addr.Unmap().String()
			point := e.Protocol + "/" + net.JoinHostPort(e.Address, strconv.Itoa(e.Port))
			if previous, ok := pointInterfaces[point]; ok && previous != v.Name {
				return Policy{}, errors.New("a capture endpoint must use one canonical interface")
			}
			pointInterfaces[point] = v.Name
			key := point + "/" + e.ServiceID + "/" + e.Component
			if seen[key] {
				return Policy{}, errors.New("duplicate capture endpoint")
			}
			seen[key] = true
			count++
		}
		sort.Slice(v.Endpoints, func(i, j int) bool {
			a, _ := json.Marshal(v.Endpoints[i])
			b, _ := json.Marshal(v.Endpoints[j])
			return string(a) < string(b)
		})
	}
	if count > MaxEndpoints || (p.Enabled && count == 0) {
		return Policy{}, errors.New("capture endpoint budget exceeded or enabled policy is empty")
	}
	sort.Slice(p.Interfaces, func(i, j int) bool { return p.Interfaces[i].Name < p.Interfaces[j].Name })
	b, _ := json.Marshal(p)
	if len(b) > MaxPolicyBytes {
		return Policy{}, errors.New("capture policy too large")
	}
	return p, nil
}

// PolicyDigest identifies configuration; a fresh runtime lease can be renewed
// at the same revision without approving a different capture scope.
func PolicyDigest(p Policy) string {
	p.LeaseUntil = time.Time{}
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func LoadPolicyFile(path string) (Policy, error) {
	var p Policy
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return p, errors.New("absolute capture policy path required")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return p, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 || before.Size() > MaxPolicyBytes {
		return p, errors.New("capture policy must be a bounded trusted regular file")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return p, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm()&0022 != 0 || after.Size() > MaxPolicyBytes {
		return p, errors.New("capture policy replaced during open")
	}
	d := json.NewDecoder(io.LimitReader(f, MaxPolicyBytes+1))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF {
		return p, errors.New("invalid capture policy JSON")
	}
	return NormalizePolicy(p)
}

func ListInterfaces() ([]Interface, error) {
	list, err := net.Interfaces()
	if err != nil {
		return nil, errors.New("capture interfaces unavailable")
	}
	out := make([]Interface, 0, len(list))
	for _, v := range list {
		ips, err := v.Addrs()
		if err != nil {
			return nil, errors.New("capture interface addresses unavailable")
		}
		item := Interface{Name: v.Name, Index: v.Index, MTU: v.MTU, HardwareAddr: v.HardwareAddr.String(), Addresses: []string{}, Loopback: v.Flags&net.FlagLoopback != 0, Up: v.Flags&net.FlagUp != 0}
		item.Supported = item.Loopback || len(v.HardwareAddr) == 6
		for _, ip := range ips {
			item.Addresses = append(item.Addresses, ip.String())
		}
		sort.Strings(item.Addresses)
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return enrichInterfaces(out), nil
}
