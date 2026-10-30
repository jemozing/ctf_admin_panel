package proxy

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGroupCutoverPreflightUsesBoundedExactExceptionsAndNormalPostflight(t *testing.T) {
	directory := t.TempDir()
	now := time.Now()
	testCertificate(t, directory, "group-tls", []string{"game.test"}, now.Add(-time.Hour), now.Add(time.Hour))
	e, err := NewEngine(Options{StateDirectory: filepath.Join(t.TempDir(), "state"), TLSDirectory: directory})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(context.Background())
	old, future := []net.Listener{}, []net.Listener{}
	defer func() {
		for _, listener := range append(old, future...) {
			_ = listener.Close()
		}
	}()
	q := CutoverPreflightRequest{Policy: Policy{SchemaVersion: 1, Revision: 1, Routes: []Route{}}}
	for i := 0; i < MaxCutoverUpstreams; i++ {
		backend, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		future = append(future, backend)
		origin := "http://" + backend.Addr().String()
		q.PendingUpstreams = append(q.PendingUpstreams, origin)
		for family := 0; family < 2; family++ {
			publication, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			old = append(old, publication)
			route := DefaultRoute()
			route.ID, route.ServiceID, route.Component = fmt.Sprintf("route-%d-%d", i, family), "group-game", fmt.Sprintf("app-%d", i/2)
			route.Listen, route.Upstream = publication.Addr().String(), origin
			if i == 0 && family == 0 {
				route.Protocol, route.Host, route.TLS = "https1", "game.test", &TLSRoutePolicy{CertificateID: "group-tls"}
			}
			q.ReleasedListeners = append(q.ReleasedListeners, route.Listen)
			q.Policy.Routes = append(q.Policy.Routes, route)
		}
	}
	for _, listener := range future {
		_ = listener.Close()
	}
	if len(q.ReleasedListeners) != MaxCutoverListeners || len(q.PendingUpstreams) != MaxCutoverUpstreams {
		t.Fatal("fixture did not exercise full group budgets")
	}
	if err := e.PreflightCutover(q); err != nil {
		t.Fatal("bounded multi-component/port preflight rejected", err)
	}
	clone := func() CutoverPreflightRequest {
		out := q
		out.Policy.Routes = append([]Route{}, q.Policy.Routes...)
		out.ReleasedListeners = append([]string{}, q.ReleasedListeners...)
		out.PendingUpstreams = append([]string{}, q.PendingUpstreams...)
		return out
	}
	tests := []struct {
		name string
		edit func(*CutoverPreflightRequest)
	}{
		{"too_many_listeners", func(v *CutoverPreflightRequest) { v.ReleasedListeners = append(v.ReleasedListeners, "127.0.0.1:1") }},
		{"too_many_upstreams", func(v *CutoverPreflightRequest) {
			v.PendingUpstreams = append(v.PendingUpstreams, "http://127.0.0.1:1")
		}},
		{"duplicate_listener", func(v *CutoverPreflightRequest) { v.ReleasedListeners[1] = v.ReleasedListeners[0] }},
		{"duplicate_upstream", func(v *CutoverPreflightRequest) { v.PendingUpstreams[1] = v.PendingUpstreams[0] }},
		{"unrelated_listener", func(v *CutoverPreflightRequest) { v.ReleasedListeners[0] = "127.0.0.1:1" }},
		{"unrelated_upstream", func(v *CutoverPreflightRequest) { v.PendingUpstreams[0] = "http://127.0.0.1:1" }},
		{"pending_origin_without_released_route", func(v *CutoverPreflightRequest) { v.ReleasedListeners = v.ReleasedListeners[2:] }},
		{"missing_tls_profile", func(v *CutoverPreflightRequest) { v.Policy.Routes[0].TLS = &TLSRoutePolicy{CertificateID: "missing"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := clone()
			test.edit(&changed)
			if e.PreflightCutover(changed) == nil {
				t.Fatal("group exceptions bypassed a required bound or policy check")
			}
		})
	}
	if e.Preflight(q.Policy) == nil {
		t.Fatal("normal preflight silently retained released-listener exceptions")
	}
	for _, listener := range old {
		_ = listener.Close()
	}
	if e.Preflight(q.Policy) == nil {
		t.Fatal("normal preflight silently retained pending-upstream exceptions")
	}
	for i, listener := range future {
		replacement, err := net.Listen("tcp4", listener.Addr().String())
		if err != nil {
			t.Fatal("group preflight retained a future port reservation", err)
		}
		future[i] = replacement
	}
	if err := e.Preflight(q.Policy); err != nil {
		t.Fatal("normal post-stage preflight rejected all now-ready group origins", err)
	}
	if status := e.Status(); status.AppliedRevision != 0 || status.Routes != 0 {
		t.Fatal("group preflight activated policy")
	}
	for _, name := range []string{"policy.json", "tls-profiles.json"} {
		if _, err := os.Stat(filepath.Join(e.options.StateDirectory, name)); !os.IsNotExist(err) {
			t.Fatal("group preflight wrote runtime or immutable TLS state")
		}
	}
}
