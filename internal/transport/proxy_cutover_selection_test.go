package transport

import (
	"testing"

	proxyengine "github.com/ctf-service-manager/ctf-service-manager/internal/proxy"
)

func TestGroupedCutoverSelectionHasIndependentBoundedTargetPorts(t *testing.T) {
	if MaxProxyCutoverListeners != proxyengine.MaxCutoverListeners || MaxProxyCutoverTargets != proxyengine.MaxCutoverUpstreams {
		t.Fatal("control-plane and engine budgets diverge")
	}
	legacy := ProxyCutoverPreviewRequest{Component: "app", UpstreamPort: 8080, PrivatePort: 29080}
	if err := ValidateProxyCutoverSelection(legacy); err != nil {
		t.Fatal(err)
	}
	group := ProxyCutoverPreviewRequest{Targets: []ProxyCutoverSelection{{Component: "api", UpstreamPort: 8080, PrivatePort: 29080}, {Component: "api", UpstreamPort: 9090, PrivatePort: 29081}, {Component: "frontend", UpstreamPort: 8080, PrivatePort: 29082}}}
	if err := ValidateProxyCutoverSelection(group); err != nil {
		t.Fatal(err)
	}
	upper := group
	upper.Targets = append([]ProxyCutoverSelection{}, group.Targets...)
	upper.Targets[2].Component = "Front.API"
	if err := ValidateProxyCutoverSelection(upper); err != nil {
		t.Fatalf("registered Compose component rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		change func(*ProxyCutoverPreviewRequest)
	}{
		{"mix legacy component", func(v *ProxyCutoverPreviewRequest) { v.Component = "app" }},
		{"mix legacy target port", func(v *ProxyCutoverPreviewRequest) { v.UpstreamPort = 8080 }},
		{"mix legacy private port", func(v *ProxyCutoverPreviewRequest) { v.PrivatePort = 29080 }},
		{"empty group", func(v *ProxyCutoverPreviewRequest) { v.Targets = []ProxyCutoverSelection{} }},
		{"duplicate pair", func(v *ProxyCutoverPreviewRequest) { v.Targets[1].UpstreamPort = v.Targets[0].UpstreamPort }},
		{"duplicate private port across components", func(v *ProxyCutoverPreviewRequest) { v.Targets[2].PrivatePort = v.Targets[0].PrivatePort }},
		{"unsafe component", func(v *ProxyCutoverPreviewRequest) { v.Targets[0].Component = "../api" }},
		{"component colon", func(v *ProxyCutoverPreviewRequest) { v.Targets[0].Component = "api:8080" }},
		{"TCP port zero", func(v *ProxyCutoverPreviewRequest) { v.Targets[0].UpstreamPort = 0 }},
		{"privileged backend", func(v *ProxyCutoverPreviewRequest) { v.Targets[0].PrivatePort = 443 }},
		{"port overflow", func(v *ProxyCutoverPreviewRequest) { v.Targets[0].PrivatePort = 65536 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			v := group
			v.Targets = append([]ProxyCutoverSelection{}, group.Targets...)
			test.change(&v)
			if ValidateProxyCutoverSelection(v) == nil {
				t.Fatal("unsafe group accepted")
			}
		})
	}
	legacy.Targets = []ProxyCutoverSelection{}
	if ValidateProxyCutoverSelection(legacy) == nil {
		t.Fatal("explicit empty group can masquerade as legacy")
	}
}

func TestGroupedCutoverSelectionRejectsComponentAndTargetBudgetOverflow(t *testing.T) {
	var group ProxyCutoverPreviewRequest
	for i := 0; i < MaxProxyCutoverComponents; i++ {
		for j := 0; j < 2; j++ {
			group.Targets = append(group.Targets, ProxyCutoverSelection{Component: string(rune('a' + i)), UpstreamPort: 8080 + j, PrivatePort: 29080 + i*2 + j})
		}
	}
	if ValidateProxyCutoverSelection(group) != nil {
		t.Fatal("maximum bounded group rejected")
	}
	group.Targets = append(group.Targets, ProxyCutoverSelection{Component: "a", UpstreamPort: 8082, PrivatePort: 29110})
	if ValidateProxyCutoverSelection(group) == nil {
		t.Fatal("target budget overflow accepted")
	}
	group.Targets = group.Targets[:MaxProxyCutoverComponents+1]
	for i := range group.Targets {
		group.Targets[i].Component = string(rune('a' + i))
		group.Targets[i].PrivatePort = 29080 + i
	}
	if ValidateProxyCutoverSelection(group) == nil {
		t.Fatal("component budget overflow accepted")
	}
}
