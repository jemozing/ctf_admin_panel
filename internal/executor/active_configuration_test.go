package executor

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/moby/moby/client"
)

func TestActiveConfigurationTracksReleaseSelection(t *testing.T) {
	f := newPlanningFixture(t)
	ctx := t.Context()
	baseline := f.release.Spec()
	next := baseline
	next.ID = "release-updated-config"
	next.ConfigurationDigest = domain.Hash([]byte("reviewed new configuration"))
	next.Images[0].RetentionTag = retentionTag(f.s, next.ID, "app")
	release, err := domain.NewRelease(next)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.m.Store.PutImmutable(ctx, "release", next.ID, f.s.ID, release); err != nil {
		t.Fatal(err)
	}

	if got, err := f.m.activeConfigurationDigest(ctx, f.s, runtimeState{}); err != nil || got != baseline.ConfigurationDigest {
		t.Fatalf("initial approved configuration: got %s, err %v", got, err)
	}
	st, err := f.m.state(ctx, f.s)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range []domain.ReleaseSpec{baseline, next, baseline} {
		st.CurrentReleaseID = spec.ID
		if err := f.m.saveState(ctx, &st); err != nil {
			t.Fatal(err)
		}
		if got, err := f.m.currentConfigurationDigest(ctx, f.s); err != nil || got != spec.ConfigurationDigest {
			t.Fatalf("configuration for %s: got %s, err %v", spec.ID, got, err)
		}
	}
}

func TestRecoveryRuntimeRequiresImageAndResourceSettingsFromSameRelease(t *testing.T) {
	const project = "flags"
	const component = "app"
	id := strings.Repeat("a", 64)
	oldImage := domain.Hash([]byte("old-image"))
	newImage := domain.Hash([]byte("new-image"))
	model := func(cpus float64) map[string]any {
		return map[string]any{"services": map[string]any{component: map[string]any{"network_mode": "none", "cpus": cpus}}}
	}
	prior := recoveryRuntime{model: model(0.5), images: []domain.ImageRef{{Component: component, ImageID: oldImage}}}
	target := recoveryRuntime{model: model(0.75), images: []domain.ImageRef{{Component: component, ImageID: newImage}}}
	for _, tc := range []struct {
		name          string
		image         domain.Digest
		nanocpus      int64
		prior, target bool
	}{
		{"previous release", oldImage, 500000000, true, false},
		{"target release", newImage, 750000000, false, true},
		{"previous image with target limits", oldImage, 750000000, false, false},
		{"target image with previous limits", newImage, 500000000, false, false},
		{"unexpected limit", newImage, 950000000, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api, err := client.New(client.WithHost("http://docker.invalid"), client.WithAPIVersion("1.56"), client.WithHTTPClient(&http.Client{Transport: statsRoundTripper(func(r *http.Request) (*http.Response, error) {
				var body string
				switch {
				case strings.HasSuffix(r.URL.Path, "/containers/json"):
					body = fmt.Sprintf(`[{"Id":%q,"Labels":{"com.docker.compose.project":%q,"com.docker.compose.service":%q}}]`, id, project, component)
				case strings.Contains(r.URL.Path, "/containers/"):
					body = fmt.Sprintf(`{
						"Id":%q,"Image":%q,"Name":"/flags-app-1","State":{"Status":"exited"},
						"Config":{"Hostname":%q,"Env":["PATH=/usr/bin"],"Labels":{"com.docker.compose.project":%q,"com.docker.compose.service":%q}},
						"HostConfig":{"NetworkMode":"none","NanoCpus":%d,
							"MaskedPaths":["/proc/acpi","/proc/asound","/proc/interrupts","/proc/kcore","/proc/keys","/proc/latency_stats","/proc/sched_debug","/proc/scsi","/proc/timer_list","/proc/timer_stats","/sys/devices/virtual/powercap","/sys/firmware"],
							"ReadonlyPaths":["/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"]},
						"NetworkSettings":{"Networks":{"none":{}}}
					}`, id, tc.image, id[:12], project, component, tc.nanocpus)
				case strings.Contains(r.URL.Path, "/images/"):
					body = fmt.Sprintf(`{"Id":%q,"Os":"linux","Config":{"Env":["PATH=/usr/bin"]}}`, tc.image)
				case strings.Contains(r.URL.Path, "/networks/"):
					body = `{"Name":"none","Driver":"null","Scope":"local"}`
				default:
					return nil, fmt.Errorf("unexpected Docker request: %s", r.URL.Path)
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}))
			if err != nil {
				t.Fatal(err)
			}
			defer api.Close()
			engine := docker.Engine{Client: api}
			items, err := engine.Inventory(t.Context(), project)
			if err != nil || len(items) != 1 {
				t.Fatalf("inventory failed: %v, %v", items, err)
			}
			c := items[0]
			if a, b := prior.matches(c, project), target.matches(c, project); a != tc.prior || b != tc.target {
				t.Fatalf("prior=%t target=%t, previous issues %v, target issues %v", a, b, c.RuntimeIssues(prior.model, project), c.RuntimeIssues(target.model, project))
			}
		})
	}
}

func TestComposeRecoveryOnlyRecreatesMissingMountFreeApplications(t *testing.T) {
	s := domain.Service{Targets: []string{"app"}}
	app := map[string]any{}
	model := map[string]any{"services": map[string]any{"app": app, "db": map[string]any{}}}
	if !missingComposeTargetRecoverable(s, model, "app") || missingComposeTargetRecoverable(s, model, "db") {
		t.Fatal("only registered application targets may be recreated when missing")
	}
	app["volumes"] = []any{map[string]any{"source": "flag-data", "target": "/data"}}
	if missingComposeTargetRecoverable(s, model, "app") {
		t.Fatal("recovery must not let Compose silently create an empty replacement volume")
	}
}

func TestComposeRecoveryConfirmsOnlyKnownUnstartedTargets(t *testing.T) {
	s := domain.Service{Targets: []string{"app", "absent"}}
	before := []docker.Container{{ID: "known-id", ImageID: "known-image", Component: "app", State: "created"}}
	after := append([]docker.Container{}, before...)
	if err := confirmStoppedIdentities(s, before, after, true); err != nil {
		t.Fatal(err)
	}
	if err := confirmStoppedIdentities(s, before, after, false); err == nil {
		t.Fatal("ordinary release switch must not accept a partial runtime")
	}
	after[0].State = "running"
	if err := confirmStoppedIdentities(s, before, after, true); err == nil {
		t.Fatal("running target accepted as stopped")
	}
	after[0].State, after[0].ID = "created", "unknown-id"
	if err := confirmStoppedIdentities(s, before, after, true); err == nil {
		t.Fatal("changed identity accepted as a confirmed stop")
	}
}
