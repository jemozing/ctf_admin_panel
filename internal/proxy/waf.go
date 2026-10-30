package proxy

import (
	"errors"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type ipState struct {
	tokens                      float64
	last, seen, window, expires time.Time
	violations                  int
}
type wafState struct {
	mu         sync.Mutex
	directory  string
	maxStates  int
	states     map[string]*ipState
	bans       map[string]Ban
	lastSweep  time.Time
	stateError bool
}
type wafDecision struct {
	blocked          bool
	decision, reason string
	retryAfter       int
}
type persistedBans struct {
	SchemaVersion int   `json:"schema_version"`
	Bans          []Ban `json:"bans"`
}

func newWAF(directory string, max int, lkgExists bool, now time.Time) *wafState {
	w := &wafState{directory: directory, maxStates: max, states: map[string]*ipState{}, bans: map[string]Ban{}}
	var saved persistedBans
	err := readJSON(filepath.Join(directory, "bans.json"), &saved)
	if os.IsNotExist(err) && !lkgExists {
		err = atomicJSON(directory, "bans.json", persistedBans{SchemaVersion: 1, Bans: []Ban{}})
		saved.SchemaVersion = 1
	}
	if err != nil || saved.SchemaVersion != 1 || len(saved.Bans) > minInt(max, 4096) {
		w.stateError = true
		return w
	}
	for _, b := range saved.Bans {
		ip, e := normalizedIP(b.IP)
		if e != nil || !identifier.MatchString(b.ServiceID) || (b.RouteID != "" && !identifier.MatchString(b.RouteID)) || b.ExpiresAt.Sub(b.CreatedAt) > time.Hour || !b.ExpiresAt.After(b.CreatedAt) || len(b.Reason) > 500 || b.CreatedAt.After(now.Add(time.Minute)) || (b.Source != "manual" && b.Source != "automatic" && b.Source != "observe_only") {
			w.stateError = true
			continue
		}
		if now.Before(b.ExpiresAt) {
			b.IP = ip.String()
			w.bans[banKey(b.ServiceID, b.RouteID, b.IP)] = b
		}
	}
	return w
}

func banKey(service, route, ip string) string { return service + "\x00" + route + "\x00" + ip }
func scopeRoute(r Route) string {
	if r.WAF.RouteSpecific {
		return r.ID
	}
	return ""
}
func (w *wafState) persist() error {
	bans := make([]Ban, 0, len(w.bans))
	for _, b := range w.bans {
		bans = append(bans, b)
	}
	sort.Slice(bans, func(i, j int) bool {
		return banKey(bans[i].ServiceID, bans[i].RouteID, bans[i].IP) < banKey(bans[j].ServiceID, bans[j].RouteID, bans[j].IP)
	})
	err := atomicJSON(w.directory, "bans.json", persistedBans{SchemaVersion: 1, Bans: bans})
	if err != nil {
		w.stateError = true
	}
	return err
}

func (w *wafState) check(r Route, ip string, now time.Time) wafDecision {
	p := r.WAF
	if p.Mode == "off" {
		return wafDecision{decision: "off"}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	deny := func(reason string, retry int) wafDecision {
		d := wafDecision{decision: "would_block", reason: reason, retryAfter: retry}
		if p.Mode == "enforce" {
			d.blocked = true
			d.decision = "blocked"
		}
		return d
	}
	if w.stateError {
		return deny("waf_state_unavailable", 1)
	}
	a, _ := netip.ParseAddr(ip)
	bypassRate, bypassBan := false, false
	for _, ex := range p.Exceptions {
		prefix, _ := normalizedPrefix(ex.CIDR)
		if prefix.Contains(a) || prefix.Contains(a.Unmap()) {
			bypassRate = bypassRate || ex.BypassRate
			bypassBan = bypassBan || ex.BypassBan
		}
	}
	key := banKey(r.ServiceID, scopeRoute(r), ip)
	if now.Sub(w.lastSweep) >= time.Second {
		changed := false
		for k, b := range w.bans {
			if !now.Before(b.ExpiresAt) {
				delete(w.bans, k)
				changed = true
			}
		}
		for k, s := range w.states {
			if !now.Before(s.expires) {
				if _, active := w.bans[k]; !active {
					delete(w.states, k)
				}
			}
		}
		w.lastSweep = now
		if changed {
			if err := w.persist(); err != nil {
				return deny("waf_state_unavailable", 1)
			}
		}
	}
	if b, ok := w.bans[key]; ok && now.Before(b.ExpiresAt) && !bypassBan {
		return deny("active_ban", maxInt(1, int(math.Ceil(b.ExpiresAt.Sub(now).Seconds()))))
	}
	if bypassRate {
		return wafDecision{decision: "exception", reason: "checker_rate_exception"}
	}
	s := w.states[key]
	if s == nil {
		scopeCount := 0
		prefix := r.ServiceID + "\x00" + scopeRoute(r) + "\x00"
		for k := range w.states {
			if strings.HasPrefix(k, prefix) {
				scopeCount++
			}
		}
		if len(w.states) >= w.maxStates || scopeCount >= p.MaxIPStates {
			return deny("ip_state_capacity", 1)
		}
		s = &ipState{tokens: float64(p.Burst), last: now, seen: now, window: now, expires: now.Add(time.Duration(p.StateTTLSeconds) * time.Second)}
		w.states[key] = s
	}
	elapsed := now.Sub(s.last).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	s.tokens = math.Min(float64(p.Burst), s.tokens+elapsed*p.RatePerSecond)
	s.last = now
	s.seen = now
	s.expires = now.Add(time.Duration(p.StateTTLSeconds) * time.Second)
	if s.tokens >= 1 {
		s.tokens--
		return wafDecision{decision: "allowed"}
	}
	if now.Sub(s.window) >= time.Duration(p.ViolationWindowSeconds)*time.Second {
		s.window = now
		s.violations = 0
	}
	s.violations++
	retry := maxInt(1, int(math.Ceil((1-s.tokens)/p.RatePerSecond)))
	if s.violations >= p.ViolationThreshold && !bypassBan {
		b := Ban{ServiceID: r.ServiceID, RouteID: scopeRoute(r), IP: ip, Reason: "request_rate_repeated", Source: "automatic", CreatedAt: now, ExpiresAt: now.Add(time.Duration(p.BanTTLSeconds) * time.Second)}
		if len(w.bans) >= minInt(w.maxStates, 4096) {
			return deny("ban_state_capacity", 1)
		}
		if p.Mode == "observe_only" {
			b.Source = "observe_only"
		}
		w.bans[key] = b
		if err := w.persist(); err != nil {
			return deny("waf_state_unavailable", 1)
		}
		return deny("autoban", p.BanTTLSeconds)
	}
	return deny("request_rate", retry)
}

func (w *wafState) list(service string, now time.Time) []Ban {
	w.mu.Lock()
	defer w.mu.Unlock()
	result := []Ban{}
	for _, b := range w.bans {
		if now.Before(b.ExpiresAt) && (service == "" || service == b.ServiceID) {
			result = append(result, b)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ExpiresAt.Before(result[j].ExpiresAt) })
	return result
}
func (w *wafState) add(b Ban) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stateError {
		return errors.New("WAF state is unavailable")
	}
	if len(w.bans) >= minInt(w.maxStates, 4096) {
		return errors.New("ban state capacity exhausted")
	}
	w.bans[banKey(b.ServiceID, b.RouteID, b.IP)] = b
	return w.persist()
}
func (w *wafState) remove(q UnbanRequest) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stateError {
		return errors.New("WAF state is unavailable")
	}
	delete(w.bans, banKey(q.ServiceID, q.RouteID, q.IP))
	return w.persist()
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
