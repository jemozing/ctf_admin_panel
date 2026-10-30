package executor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"github.com/moby/moby/client"
)

func healthFixture(t *testing.T) (*planningFixture, *atomic.Int32) {
	t.Helper()
	f := gitPlanningFixture(t)
	generation := &atomic.Int32{}
	api, err := client.New(client.WithHost("http://docker.invalid"), client.WithAPIVersion("1.56"), client.WithHTTPClient(&http.Client{Transport: statsRoundTripper(func(r *http.Request) (*http.Response, error) {
		id := f.s.Containers[0].ID
		image := string(f.s.Containers[0].ImageID)
		body := ""
		switch {
		case strings.HasSuffix(r.URL.Path, "/containers/json"):
			body = fmt.Sprintf(`[{"Id":%q,"Names":["/fixture"],"Labels":{"com.docker.compose.project":%q,"com.docker.compose.service":"app"}}]`, id, f.s.ComposeProject)
		case strings.Contains(r.URL.Path, "/containers/") && strings.HasSuffix(r.URL.Path, "/json"):
			body = fmt.Sprintf(`{"Id":%q,"Name":"/fixture","Image":%q,"State":{"Status":"running","StartedAt":"2026-10-19T12:00:%02dZ"},"Config":{"Labels":{}},"HostConfig":{},"NetworkSettings":{}}`, id, image, generation.Load())
		case strings.Contains(r.URL.Path, "/images/") && strings.HasSuffix(r.URL.Path, "/json"):
			body = fmt.Sprintf(`{"Id":%q,"Config":{}}`, image)
		default:
			t.Errorf("unexpected Docker endpoint: %s", r.URL.Path)
			body = `{}`
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { api.Close() })
	f.m.Engine = &docker.Engine{Client: api}
	return f, generation
}

func TestHealthConfigurationVaultOnlyCASAndIdleBoundary(t *testing.T) {
	f, _ := healthFixture(t)
	const privateInput = "private-health-secret-f80b"
	input := transport.HealthChecksRequest{ExpectedRevision: 0, Confirmed: true, Actor: "admin", Policy: domain.HealthCheckPolicy{Checks: []domain.HTTPCheck{{ID: "ready", Source: domain.HealthReadiness, URL: "http://service:8080/private?token=" + privateInput, ExpectedStatus: 200, BodyContains: privateInput, TimeoutSeconds: 2}}, Attempts: 2, ValiditySeconds: 120}}
	view, err := f.m.ConfigureHealthChecks(t.Context(), f.s.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	if view.Revision != 1 || len(view.Checks) != 1 || len(view.Settings.Checks) != 0 || view.Checks[0].Targets[0] != "http://service:8080" {
		t.Fatalf("public summary: %#v", view)
	}
	encoded, _ := json.Marshal(view)
	if strings.Contains(string(encoded), privateInput) {
		t.Fatal("check input leaked through API")
	}
	records, err := f.m.Store.List(t.Context(), "health_policy", f.s.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if strings.Contains(string(record.Payload), privateInput) {
			t.Fatal("private input persisted in SQLite instead of vault")
		}
	}
	policy, revision, err := f.m.healthPolicy(t.Context(), f.s)
	if err != nil || revision != 1 || policy.Checks[0].BodyContains != privateInput {
		t.Fatal("vault policy not recovered", err)
	}
	if _, err := f.m.ConfigureHealthChecks(t.Context(), f.s.ID, input); !errors.Is(err, store.ErrConflict) {
		t.Fatal("stale configuration revision accepted", err)
	}
	req := transport.SubmitRequest{ServiceID: f.s.ID, Action: domain.OperationStop, IdempotencyKey: "stop-before-health-change", Initiator: "admin"}
	plan, err := f.m.Preview(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	req.PlanDigest = plan.PlanDigest
	input.ExpectedRevision = 1
	if _, err := f.m.ConfigureHealthChecks(t.Context(), f.s.ID, input); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Submit(t.Context(), transport.Principal{}, req); !errors.Is(err, store.ErrConflict) {
		t.Fatal("changed health policy did not invalidate reviewed plan", err)
	}
	plan, err = f.m.Preview(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	req.PlanDigest = plan.PlanDigest
	if _, err := f.m.Submit(t.Context(), transport.Principal{}, req); err != nil {
		t.Fatal(err)
	}
	input.ExpectedRevision = 2
	if _, err := f.m.ConfigureHealthChecks(t.Context(), f.s.ID, input); !errors.Is(err, store.ErrBusy) {
		t.Fatal("health policy changed while a prepared operation was queued", err)
	}
}

func TestManualHealthBindsAuthorReleaseRuntimeAndTTL(t *testing.T) {
	f, generation := healthFixture(t)
	view, err := f.m.HealthChecks(t.Context(), f.s.ID)
	if err != nil {
		t.Fatal(err)
	}
	input := transport.ManualHealthRequest{ExpectedReleaseID: view.CurrentReleaseID, ExpectedStateSequence: view.StateSequence, ExpectedRuntimeDigest: view.RuntimeDigest, TTLSeconds: 300, Healthy: true, Comment: "Synthetic patient workflow checked", Actor: "defender"}
	manual, err := f.m.ConfirmManualHealth(t.Context(), f.s.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	if manual.Actor != "defender" || manual.ReleaseID != view.CurrentReleaseID || manual.State != domain.HealthHealthy || manual.ValidUntil.Sub(manual.ObservedAt) != 300*time.Second {
		t.Fatal("provenance lost", manual)
	}
	current, err := f.m.HealthChecks(t.Context(), f.s.ID)
	if err != nil || current.ManualConfirmations[0].State != domain.HealthHealthy {
		t.Fatal(current, err)
	}
	generation.Add(1)
	changed, err := f.m.HealthChecks(t.Context(), f.s.ID)
	if err != nil || changed.ManualConfirmations[0].State != domain.HealthStale {
		t.Fatal("same-ID Docker restart did not invalidate manual proof", changed, err)
	}
	if _, err := f.m.ConfirmManualHealth(t.Context(), f.s.ID, input); !errors.Is(err, store.ErrConflict) {
		t.Fatal("old browser runtime evidence accepted", err)
	}
	st, err := f.m.state(t.Context(), f.s)
	if err != nil {
		t.Fatal(err)
	}
	if result := effectiveManual(manual, st, manual.RuntimeDigest, manual.ValidUntil); result.State != domain.HealthStale {
		t.Fatal("expired manual confirmation is green")
	}
	signals, err := f.m.recordedChecks(t.Context(), f.s, st, healthSignals(nil))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, signal := range signals {
		if signal.Source == domain.HealthManual {
			found = true
			if signal.State != domain.HealthStale {
				t.Fatal(signal)
			}
		}
	}
	if !found {
		t.Fatal("manual signal absent from overview")
	}
}

func TestPositiveManualHealthRejectsUnregisteredRuntimeIdentity(t *testing.T) {
	f, _ := healthFixture(t)
	st, err := f.m.state(t.Context(), f.s)
	if err != nil {
		t.Fatal(err)
	}
	st.Containers[0].ID = strings.Repeat("c", 64)
	if err := f.m.saveState(t.Context(), &st); err != nil {
		t.Fatal(err)
	}
	view, err := f.m.HealthChecks(t.Context(), f.s.ID)
	if err != nil {
		t.Fatal(err)
	}
	input := transport.ManualHealthRequest{ExpectedReleaseID: view.CurrentReleaseID, ExpectedStateSequence: view.StateSequence, ExpectedRuntimeDigest: view.RuntimeDigest, TTLSeconds: 300, Healthy: true, Comment: "reviewed but unknown container", Actor: "defender"}
	if _, err := f.m.ConfirmManualHealth(t.Context(), f.s.ID, input); err == nil {
		t.Fatal("unknown runtime identity attached positive proof to immutable release")
	}
}
