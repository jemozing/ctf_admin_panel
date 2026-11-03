package docker

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
)

func decodeComposeResourceTest(t *testing.T, raw string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestNormalizeDeployLimitsMatchesFilestorageRuntime(t *testing.T) {
	doc := decodeComposeResourceTest(t, `{"services":{"cleaner":{"image":"alpine:3.21.3","deploy":{"resources":{"limits":{"cpus":0.1,"memory":"134217728"}},"placement":{}}}}}`)
	if err := normalizeDeployLimits(doc); err != nil {
		t.Fatal(err)
	}
	component := doc["services"].(map[string]any)["cleaner"].(map[string]any)
	if _, ok := component["deploy"]; ok {
		t.Fatal("limits-only deploy block was not normalized")
	}
	if !limitsMatch(component, container.Resources{NanoCPUs: 100000000, Memory: 134217728, MemorySwap: 268435456}) {
		t.Fatalf("normalized limits do not match the running cleaner: %#v", component)
	}
}

func TestNormalizeDeployLimitsDoesNotWeakenOtherDeploySemantics(t *testing.T) {
	for _, extra := range []string{
		`"replicas": 2`,
		`"placement": {"constraints":["node.role==manager"]}`,
		`"resources": {"reservations":{"memory":"128M"},"limits":{"cpus":0.1}}`,
		`"resources": {"limits":{"pids":10}}`,
	} {
		t.Run(extra, func(t *testing.T) {
			deploy := decodeComposeResourceTest(t, "{"+extra+"}")
			if _, ok := deploy["resources"]; !ok {
				deploy["resources"] = map[string]any{"limits": map[string]any{"cpus": 0.1}}
			}
			component := map[string]any{"image": "alpine:3.21.3", "deploy": deploy}
			doc := map[string]any{"services": map[string]any{"web": component}}
			if err := normalizeDeployLimits(doc); err != nil {
				t.Fatal(err)
			}
			if len(component) != 2 || component["deploy"] == nil {
				t.Fatalf("unsupported deploy input was rewritten: %#v", component)
			}
		})
	}
}

func TestNormalizeDeployLimitsRequiresEquivalentDirectSettings(t *testing.T) {
	doc := decodeComposeResourceTest(t, `{"services":{"app":{"cpus":0.5,"mem_limit":"128M","deploy":{"resources":{"limits":{"cpus":"0.50","memory":"134217728"}}}}}}`)
	if err := normalizeDeployLimits(doc); err != nil {
		t.Fatalf("equivalent settings rejected: %v", err)
	}
	doc = decodeComposeResourceTest(t, `{"services":{"app":{"cpus":1,"deploy":{"resources":{"limits":{"cpus":0.5}}}}}}`)
	if err := normalizeDeployLimits(doc); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("conflicting limits accepted: %v", err)
	}
}

func TestComposeResourceChanges(t *testing.T) {
	base := `{"name":"files","services":{"web":{"image":"app:latest","ports":[{"target":5000,"published":"5000"}],"environment":{"PASSWORD":"private-value"},"cpus":0.5,"mem_limit":"128M"},"db":{"image":"db:latest"}}}`
	current := decodeComposeResourceTest(t, base)
	proposed := decodeComposeResourceTest(t, base)
	web := proposed["services"].(map[string]any)["web"].(map[string]any)
	web["cpus"], web["mem_limit"], web["pids_limit"] = "0.75", "134217728", 250
	want := []ComposeResourceChange{
		{Component: "web", Setting: "cpus", Before: "0.5", After: "0.75"},
		{Component: "web", Setting: "pids_limit", After: "250"},
	}
	changes, err := ComposeResourceChanges(current, proposed, []string{"web"})
	if err != nil || !reflect.DeepEqual(changes, want) {
		t.Fatalf("unexpected changes: %+v, %v", changes, err)
	}
	delete(web, "pids_limit")
	delete(web, "mem_limit")
	web["cpus"] = "0.5"
	changes, err = ComposeResourceChanges(current, proposed, []string{"web"})
	if err != nil || !reflect.DeepEqual(changes, []ComposeResourceChange{{Component: "web", Setting: "mem_limit", Before: "134217728"}}) {
		t.Fatalf("removed limit not represented: %+v, %v", changes, err)
	}
	for name, change := range map[string]func(doc, web, db map[string]any){
		"project": func(doc, _, _ map[string]any) { doc["name"] = "other" },
		"container set": func(doc, _, _ map[string]any) {
			delete(doc["services"].(map[string]any), "db")
		},
		"port":    func(_, web, _ map[string]any) { delete(web, "ports") },
		"mount":   func(_, web, _ map[string]any) { web["volumes"] = []any{"db:/data"} },
		"network": func(doc, _, _ map[string]any) { doc["networks"] = map[string]any{"foreign": nil} },
		"environment": func(_, web, _ map[string]any) {
			web["environment"].(map[string]any)["PASSWORD"] = "new-secret"
		},
		"non-target":       func(_, _, db map[string]any) { db["cpus"] = 2 },
		"NaN CPU":          func(_, web, _ map[string]any) { web["cpus"] = "NaN" },
		"too small memory": func(_, web, _ map[string]any) { web["mem_limit"] = "1m" },
		"fractional pids":  func(_, web, _ map[string]any) { web["pids_limit"] = 3.5 },
	} {
		t.Run(name, func(t *testing.T) {
			other := decodeComposeResourceTest(t, base)
			items := other["services"].(map[string]any)
			change(other, items["web"].(map[string]any), items["db"].(map[string]any))
			_, err := ComposeResourceChanges(current, other, []string{"web"})
			if err == nil || strings.Contains(err.Error(), "private-value") || strings.Contains(err.Error(), "new-secret") {
				t.Fatalf("unsafe changes or details: %v", err)
			}
		})
	}
}

func TestComposeResourceChangesRejectsDockerLimitContradictions(t *testing.T) {
	for _, tt := range []struct {
		name    string
		current string
		next    string
	}{
		{"reservation", `"mem_limit":"128M","mem_reservation":"64M"`, `"mem_limit":"32M","mem_reservation":"64M"`},
		{"swap lower than memory", `"mem_limit":"128M","memswap_limit":"256M"`, `"mem_limit":"512M","memswap_limit":"256M"`},
		{"swap without memory", `"mem_limit":"128M","memswap_limit":"256M"`, `"memswap_limit":"256M"`},
		{"CPU period", `"cpu_period":100000`, `"cpu_period":100000,"cpus":1`},
		{"CPU quota", `"cpu_quota":100000`, `"cpu_quota":100000,"cpus":1`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			current := decodeComposeResourceTest(t, `{"services":{"web":{`+tt.current+`}}}`)
			next := decodeComposeResourceTest(t, `{"services":{"web":{`+tt.next+`}}}`)
			if _, err := ComposeResourceChanges(current, next, []string{"web"}); err == nil {
				t.Fatal("incompatible resource limit accepted")
			}
		})
	}
}
