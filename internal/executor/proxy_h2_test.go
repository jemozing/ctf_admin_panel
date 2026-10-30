package executor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	proxyengine "github.com/ctf-service-manager/ctf-service-manager/internal/proxy"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

type cutoverH2Spy struct {
	calls    atomic.Int32
	requests chan proxyengine.HTTP2ProbeRequest
	reject   bool
}

func newCutoverH2Spy(t *testing.T, reject bool) (*Manager, *cutoverH2Spy) {
	t.Helper()
	const token = "isolated-cutover-h2-control-000000000000000000"
	spy := &cutoverH2Spy{requests: make(chan proxyengine.HTTP2ProbeRequest, 4), reject: reject}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spy.calls.Add(1)
		if r.Method != "POST" || r.URL.Path != "/v1/h2-preflight" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected control request: %s %s", r.Method, r.URL.String())
			w.WriteHeader(400)
			return
		}
		var input proxyengine.HTTP2ProbeRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		spy.requests <- input
		if spy.reject {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"code":"not_http2","message":"fixture rejection"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(server.Close)
	credential := filepath.Join(t.TempDir(), "control-token")
	if err := os.WriteFile(credential, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	// No Docker Engine, store, service filesystem or worker exists in this fixture.
	// An accidental attempt to mutate runtime cannot be hidden by a test adapter.
	manager := &Manager{Config: config.Config{Development: true, Proxy: config.ProxyPolicy{Enabled: true, ControlURL: server.URL, ControlTokenFile: credential}}}
	return manager, spy
}
func cutoverH2Policy(component, private string) proxyengine.Policy {
	return proxyengine.Policy{SchemaVersion: 1, Revision: 2, Routes: []proxyengine.Route{{ID: "game-h2", ServiceID: "game", Component: component, Protocol: "https2", Upstream: "http://" + private}}}
}
func cutoverH2Target(component, private string, bindings ...string) transport.ProxyCutoverTargetPlan {
	return transport.ProxyCutoverTargetPlan{Component: component, UpstreamPort: 7000, PrivatePort: 29080, PrivateBinding: private, OriginalBindings: bindings}
}

func TestCutoverHTTP2PreflightProbesOnlyFrozenCurrentLiteralOrigins(t *testing.T) {
	for _, tc := range []struct {
		name     string
		bindings []string
		want     string
	}{
		{"wildcard4", []string{"0.0.0.0:18000"}, "http://127.0.0.1:18000"},
		{"wildcard6", []string{"[::]:18001"}, "http://[::1]:18001"},
		{"loopback4", []string{"127.0.0.1:18002"}, "http://127.0.0.1:18002"},
		{"loopback6", []string{"[::1]:18003"}, "http://[::1]:18003"},
		{"exactLAN4", []string{"192.168.50.19:18004"}, "http://192.168.50.19:18004"},
		{"exactLAN6", []string{"[fd00::19]:18005"}, "http://[fd00::19]:18005"},
		{"mappedIPv4", []string{"[::ffff:127.0.0.1]:18006"}, "http://127.0.0.1:18006"},
		{"preferFrozenLoopback", []string{"192.168.50.19:18007", "127.0.0.1:18007"}, "http://127.0.0.1:18007"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, spy := newCutoverH2Spy(t, false)
			target := cutoverH2Target("api", "127.0.0.1:29080", tc.bindings...)
			before := append([]string{}, target.OriginalBindings...)
			if err := m.preflightCutoverHTTP2(context.Background(), cutoverH2Policy("api", target.PrivateBinding), []transport.ProxyCutoverTargetPlan{target}); err != nil {
				t.Fatal(err)
			}
			if spy.calls.Load() != 1 {
				t.Fatal("expected one authenticated control probe")
			}
			request := <-spy.requests
			if !request.AllowHostAddresses || !reflect.DeepEqual(request.Upstreams, []string{tc.want}) {
				t.Fatalf("probe did not use frozen current origin: %+v", request)
			}
			if !reflect.DeepEqual(before, target.OriginalBindings) {
				t.Fatal("preflight changed immutable binding order")
			}
			if strings.Contains(request.Upstreams[0], "29080") {
				t.Fatal("pending private port was probed before creation")
			}
		})
	}
}
func TestCutoverHTTP2PreflightSkipsH1AndUnmatchedTargetsWithoutRPC(t *testing.T) {
	m, spy := newCutoverH2Spy(t, false)
	target := cutoverH2Target("api", "127.0.0.1:29080", "not-a-publication")
	cases := []proxyengine.Policy{
		{SchemaVersion: 1, Revision: 2},
		{SchemaVersion: 1, Revision: 2, Routes: []proxyengine.Route{{Component: "api", Protocol: "https1", Upstream: "http://127.0.0.1:29080"}}},
		cutoverH2Policy("unrelated", target.PrivateBinding),
		cutoverH2Policy("api", "127.0.0.1:29081"),
		{SchemaVersion: 1, Revision: 2, Routes: []proxyengine.Route{{Component: "api", Protocol: "https2", Upstream: "http://untrusted.example:29080"}}},
	}
	for _, policy := range cases {
		if err := m.preflightCutoverHTTP2(context.Background(), policy, []transport.ProxyCutoverTargetPlan{target}); err != nil {
			t.Fatalf("non-H2 pair unexpectedly inspected malformed unrelated bindings: %v", err)
		}
	}
	if spy.calls.Load() != 0 {
		t.Fatal("H1/unmatched route caused a control probe")
	}
}
func TestCutoverHTTP2PreflightRejectsInvalidFrozenBindingBeforeControlRPC(t *testing.T) {
	for _, bindings := range [][]string{nil, {"broken"}, {"localhost:18000"}, {"untrusted.example:18000"}, {"127.0.0.1:0"}, {"127.0.0.1:65536"}, {"127.0.0.1:not-a-port"}, {"[::1]"}, {"127.0.0.1:18000/path"}} {
		m, spy := newCutoverH2Spy(t, false)
		target := cutoverH2Target("api", "127.0.0.1:29080", bindings...)
		if err := m.preflightCutoverHTTP2(context.Background(), cutoverH2Policy("api", target.PrivateBinding), []transport.ProxyCutoverTargetPlan{target}); err == nil {
			t.Fatalf("invalid binding accepted: %+v", bindings)
		}
		if spy.calls.Load() != 0 {
			t.Fatalf("invalid frozen binding reached proxy control: %+v", bindings)
		}
	}
}
func TestCutoverHTTP2PreflightIsolatesComponentAndPrivateTargetPair(t *testing.T) {
	m, spy := newCutoverH2Spy(t, false)
	h2 := cutoverH2Target("api", "127.0.0.1:29080", "0.0.0.0:18000")
	h1SameOrigin := cutoverH2Target("web", h2.PrivateBinding, "invalid-web-binding")
	sameComponentOtherPort := cutoverH2Target("api", "127.0.0.1:29081", "invalid-other-port")
	policy := cutoverH2Policy("api", h2.PrivateBinding)
	policy.Routes = append(policy.Routes, proxyengine.Route{ID: "h1", Component: "web", Protocol: "http1", Upstream: "http://" + h2.PrivateBinding})
	if err := m.preflightCutoverHTTP2(context.Background(), policy, []transport.ProxyCutoverTargetPlan{h1SameOrigin, sameComponentOtherPort, h2}); err != nil {
		t.Fatal(err)
	}
	if spy.calls.Load() != 1 {
		t.Fatal("wrong number of selected pair probes")
	}
	request := <-spy.requests
	if !reflect.DeepEqual(request.Upstreams, []string{"http://127.0.0.1:18000"}) {
		t.Fatalf("unrelated targets were probed: %+v", request)
	}
}
func TestCutoverHTTP2PreflightDeduplicatesFrozenOriginAndPropagatesRejection(t *testing.T) {
	for _, reject := range []bool{false, true} {
		m, spy := newCutoverH2Spy(t, reject)
		target := cutoverH2Target("api", "127.0.0.1:29080", "0.0.0.0:18000")
		policy := cutoverH2Policy("api", target.PrivateBinding)
		policy.Routes = append(policy.Routes, policy.Routes[0])
		err := m.preflightCutoverHTTP2(context.Background(), policy, []transport.ProxyCutoverTargetPlan{target, target})
		if (err != nil) != reject {
			t.Fatalf("control rejection not propagated: reject=%v err=%v", reject, err)
		}
		if spy.calls.Load() != 1 {
			t.Fatal("deduplicated request count changed")
		}
		request := <-spy.requests
		if len(request.Upstreams) != 1 || request.Upstreams[0] != "http://127.0.0.1:18000" {
			t.Fatalf("same selected H2 pair probed multiple times: %+v", request)
		}
		if m.Engine != nil || m.Store != nil {
			t.Fatal("pure probe acquired runtime mutation dependencies")
		}
	}
}
