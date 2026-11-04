package executor

import (
	"slices"
	"testing"

	proxyengine "github.com/ctf-service-manager/ctf-service-manager/internal/proxy"
)

func TestProxyPolicyKeepsActiveCutoverRoutes(t *testing.T) {
	f := newCutoverFixture(t)
	plan := f.preview(t)
	if active := f.confirm(t, plan); active.State != "active" {
		t.Fatalf("cutover did not activate: %+v", active)
	}

	wanted := plan.Policy
	wanted.Routes = slices.Clone(plan.Policy.Routes)
	wanted.Routes[0].Capture.Mode = "bounded_body"
	if err := f.m.validateActiveCutoverRoutes(t.Context(), wanted); err != nil {
		t.Fatalf("capture setting should remain editable: %v", err)
	}

	for name, change := range map[string]func(*proxyengine.Policy){
		"removed":    func(policy *proxyengine.Policy) { policy.Routes = nil },
		"moved":      func(policy *proxyengine.Policy) { policy.Routes[0].Listen = "127.0.0.1:18081" },
		"retargeted": func(policy *proxyengine.Policy) { policy.Routes[0].Upstream = "http://127.0.0.1:29081" },
	} {
		t.Run(name, func(t *testing.T) {
			wanted := plan.Policy
			wanted.Routes = slices.Clone(plan.Policy.Routes)
			change(&wanted)
			if err := f.m.validateActiveCutoverRoutes(t.Context(), wanted); err == nil {
				t.Fatal("ordinary policy may not change an active cutover binding")
			}
		})
	}
}
