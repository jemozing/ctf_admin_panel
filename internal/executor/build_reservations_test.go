package executor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/jobs"
	"github.com/ctf-service-manager/ctf-service-manager/internal/storage"
	"github.com/moby/moby/client"
)

func TestParallelBuildBudgetChargesOtherReservationsAndInterruptedOwners(t *testing.T) {
	f := newPlanningFixture(t)
	api, err := client.New(client.WithHost("http://docker.invalid"), client.WithAPIVersion("1.56"), client.WithHTTPClient(&http.Client{Transport: statsRoundTripper(func(r *http.Request) (*http.Response, error) {
		if !strings.HasSuffix(r.URL.Path, "/system/df") {
			t.Fatalf("unexpected Docker call: %s", r.URL.Path)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"ImageUsage":{"TotalSize":100},"BuildCacheUsage":{"TotalSize":0},"ContainerUsage":{"TotalSize":0},"VolumeUsage":{"TotalSize":0}}`))}, nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	f.m.Engine = &docker.Engine{Client: api}
	f.m.Config.Storage.DockerMaxBytes = 1000
	f.m.Config.Storage.BuildReserveBytes = 600
	one := schedulerOperation(t, f, "build-owner", "one", domain.OperationBuild)
	two := schedulerOperation(t, f, "build-other", "two", domain.OperationBuild)
	manager := jobs.New(f.m.Store)
	if _, err := manager.Start(t.Context(), one.Spec.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Start(t.Context(), two.Spec.ID); err != nil {
		t.Fatal(err)
	}
	ctx1 := context.WithValue(t.Context(), operationContextKey{}, one.Spec.ID)
	ctx2 := context.WithValue(t.Context(), operationContextKey{}, two.Spec.ID)
	model := map[string]any{"services": map[string]any{"app": map[string]any{"image": "irrelevant"}}}
	if err := f.m.reserveDockerBuild(ctx1, "one", one.Spec.ID, "release-one", model); err != nil {
		t.Fatal(err)
	}
	if err := f.m.checkDockerBudget(ctx1, 0); err != nil {
		t.Fatal("current build reservation charged twice", err)
	}
	var quota *storage.QuotaError
	if err := f.m.reserveDockerBuild(ctx2, "two", two.Spec.ID, "release-two", model); !errors.As(err, &quota) {
		t.Fatal("parallel build oversubscribed budget", err)
	}
	if _, err := manager.Transition(t.Context(), one.Spec.ID, domain.OperationInterrupted, domain.OutcomeEvidence{Reason: "crash"}); err != nil {
		t.Fatal(err)
	}
	total, tags, err := f.m.dockerBuildReservations(t.Context(), "")
	if err != nil || total != 600 || !tags["ctf-manager/one:release-one-app"] {
		t.Fatal("interrupted build lost reservation/tag guard", total, tags, err)
	}
	if err := f.m.reserveDockerBuild(ctx2, "two", two.Spec.ID, "release-two", model); !errors.As(err, &quota) {
		t.Fatal("unresolved build reservation ignored", err)
	}
	if _, err := manager.Transition(t.Context(), one.Spec.ID, domain.OperationFailed, domain.OutcomeEvidence{ActualStateKnown: true, ResultRecorded: true, Reason: "reconciled"}); err != nil {
		t.Fatal(err)
	}
	if err := f.m.reserveDockerBuild(ctx2, "two", two.Spec.ID, "release-two", model); err != nil {
		t.Fatal("terminal build did not release reservation", err)
	}
}
