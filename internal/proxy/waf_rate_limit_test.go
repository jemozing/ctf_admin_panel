package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestWAFSimpleRateLimitPolicyCoversEveryRoute(t *testing.T) {
	r := DefaultRoute()
	r.ID, r.ServiceID, r.Component = "game-v4", "game", "app"
	r.Listen, r.Upstream = "127.0.0.1:18080", "http://127.0.0.1:29080"
	r.WAF.Mode, r.WAF.RatePerSecond = wafRateLimitMode, 100000
	r.WAF.RouteSpecific = true
	other := r
	other.ID, other.Listen = "game-v6", "[::1]:18080"
	other.WAF = WAFPolicy{Mode: wafRateLimitMode, RatePerSecond: r.WAF.RatePerSecond}
	p := Policy{SchemaVersion: 1, Revision: 1, Routes: []Route{r, other}}
	normalized, err := NormalizePolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	w := normalized.Routes[0].WAF
	if w.RouteSpecific || w.Burst != 0 || w.BanTTLSeconds != 0 || w.MaxIPStates != 4096 {
		t.Fatalf("unexpected simple WAF policy: %+v", w)
	}
	if PolicyDigest(p) != PolicyDigest(normalized) {
		t.Fatal("simple WAF normalization changed the policy digest")
	}
	for _, rate := range []float64{0, 0.5, 1.5, 100001, 99999} {
		p.Routes[1].WAF.RatePerSecond = rate
		if _, err := NormalizePolicy(p); err == nil {
			t.Errorf("accepted invalid or inconsistent service rate %g", rate)
		}
	}
	p.Routes[1].WAF = DefaultRoute().WAF
	p.Routes[1].WAF.RouteSpecific = true
	if _, err := NormalizePolicy(p); err == nil {
		t.Fatal("accepted a separate route with a different WAF mode on the same service")
	}
}

func TestWAFSimpleRateLimitExpiresWithoutExtendingAndKeepsScopes(t *testing.T) {
	now := time.Date(2026, 10, 30, 1, 0, 0, 0, time.UTC)
	w := newWAF(t.TempDir(), 3, false, now)
	r := DefaultRoute()
	r.ID, r.ServiceID = "first-route", "game"
	r.WAF = defaultWAFPolicy(WAFPolicy{Mode: wafRateLimitMode, RatePerSecond: 2}, r.WAF)
	alias := r
	alias.ID = "second-route"
	other := r
	other.ServiceID = "other-game"
	const ip = "192.0.2.1"
	if w.check(r, ip, now).blocked || w.check(alias, ip, now.Add(500*time.Millisecond)).blocked {
		t.Fatal("first two requests inside the second should be allowed across both routes")
	}
	trigger := now.Add(999 * time.Millisecond)
	if d := w.check(r, ip, trigger); !d.blocked || d.reason != "request_rate" || d.retryAfter != 5 {
		t.Fatalf("first excess request did not start a five-second cooldown: %+v", d)
	}
	if w.check(r, "192.0.2.2", trigger).blocked || w.check(other, ip, trigger).blocked {
		t.Fatal("another client IP or service inherited the cooldown")
	}
	if d := w.check(alias, "192.0.2.3", trigger); !d.blocked || d.reason != "ip_state_capacity" {
		t.Fatalf("global IP state limit did not cover the simple mode: %+v", d)
	}
	if d := w.check(alias, ip, trigger.Add(4900*time.Millisecond)); !d.blocked || d.reason != "rate_limit_cooldown" || d.retryAfter != 1 {
		t.Fatalf("cooldown did not hold until its original expiry: %+v", d)
	}
	if w.check(r, ip, trigger.Add(5*time.Second)).blocked || w.check(alias, ip, trigger.Add(5*time.Second)).blocked {
		t.Fatal("cooldown expiry did not restore the full allowance")
	}
	if len(w.list("game", trigger)) != 0 {
		t.Fatal("the five-second cooldown appeared as a separate ban")
	}
	if w.check(r, "192.0.2.4", trigger.Add(5*time.Second)).blocked {
		t.Fatal("expired entries still occupy IP capacity")
	}
}

func TestWAFSimpleRateLimitHTTPAcrossRoutes(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	listeners := map[string]net.Listener{}
	var routes []Route
	for _, id := range []string{"first-route", "second-route"} {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		r := DefaultRoute()
		r.ID, r.ServiceID, r.Component = id, "game", "app"
		r.Listen, r.Upstream = listener.Addr().String(), upstream.URL
		r.WAF = WAFPolicy{Mode: wafRateLimitMode, RatePerSecond: 1}
		listeners[r.Listen] = listener
		routes = append(routes, r)
	}
	var clock atomic.Int64
	base := time.Date(2026, 10, 30, 1, 0, 0, 0, time.UTC)
	e, err := NewEngine(Options{
		StateDirectory: filepath.Join(t.TempDir(), "state"),
		Now:            func() time.Time { return base.Add(time.Duration(clock.Load())) },
		Listen:         func(_, addr string) (net.Listener, error) { return listeners[addr], nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = e.Close(ctx)
	})
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 1, Routes: routes}); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := request(t, routes[0], "GET", "/", "", nil); status != http.StatusNoContent {
		t.Fatalf("first request returned %d", status)
	}
	status, _, headers := request(t, routes[1], "GET", "/", "", http.Header{"X-Forwarded-For": {"203.0.113.4"}})
	if status != http.StatusTooManyRequests || headers.Get("Retry-After") != "5" || upstreamCalls.Load() != 1 {
		t.Fatalf("second route bypassed the limiter or returned wrong headers: status=%d, headers=%v", status, headers)
	}
	clock.Store(int64(4 * time.Second))
	status, _, headers = request(t, routes[0], "GET", "/", "", nil)
	if status != http.StatusTooManyRequests || headers.Get("Retry-After") != "1" || upstreamCalls.Load() != 1 {
		t.Fatalf("cooldown response did not reflect remaining time: status=%d, headers=%v", status, headers)
	}
	clock.Store(int64(5 * time.Second))
	if status, _, _ := request(t, routes[1], "GET", "/", "", nil); status != http.StatusNoContent || upstreamCalls.Load() != 2 {
		t.Fatalf("first request after expiry returned %d", status)
	}
}
