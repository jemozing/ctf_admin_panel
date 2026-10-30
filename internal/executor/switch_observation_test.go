package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/moby/moby/client"
)

func TestSwitchObservationPersistsPartialActualIDsAfterLostComposeResponse(t *testing.T) {
	f := newPlanningFixture(t)
	appID := strings.Repeat("c", 64)
	dbID := strings.Repeat("b", 64)
	newImage := string(domain.Hash([]byte("new-app-image")))
	oldImage := string(f.s.Containers[0].ImageID)
	api, err := client.New(client.WithHost("http://docker.invalid"), client.WithAPIVersion("1.56"), client.WithHTTPClient(&http.Client{Transport: statsRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.Context().Err() != nil {
			t.Fatal("cancelled operation context leaked into final observation")
		}
		body := ""
		switch {
		case strings.HasSuffix(r.URL.Path, "/containers/json"):
			body = fmt.Sprintf(`[{"Id":%q,"Labels":{"com.docker.compose.project":"flags","com.docker.compose.service":"app"}},{"Id":%q,"Labels":{"com.docker.compose.project":"flags","com.docker.compose.service":"db"}}]`, appID, dbID)
		case strings.Contains(r.URL.Path, "/containers/"):
			id, image, state := appID, newImage, "running"
			if strings.Contains(r.URL.Path, dbID) {
				id, image, state = dbID, oldImage, "exited"
			}
			body = fmt.Sprintf(`{"Id":%q,"Image":%q,"State":{"Status":%q},"Config":{},"HostConfig":{},"NetworkSettings":{}}`, id, image, state)
		case strings.Contains(r.URL.Path, "/images/"):
			body = fmt.Sprintf(`{"Id":%q,"Config":{}}`, newImage)
		default:
			t.Fatalf("unexpected Docker request %s", r.URL.Path)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	f.m.Engine = &docker.Engine{Client: api}
	policy := f.s
	policy.Containers = append(append([]domain.ContainerRef{}, policy.Containers...), domain.ContainerRef{Component: "db", ID: dbID, ImageID: domain.Digest(oldImage), Role: domain.RoleDatabase})
	before, err := f.m.Store.List(t.Context(), "runtime_state", f.s.ID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := f.m.recordRuntimeSwitchObservation(ctx, policy, "partial-operation", "target-release", false); err != nil {
		t.Fatal(err)
	}
	records, err := f.m.Store.List(t.Context(), "runtime_switch_observation", f.s.ID)
	if err != nil || len(records) != 1 {
		t.Fatal(records, err)
	}
	var observation runtimeSwitchObservation
	if err := json.Unmarshal(records[0].Payload, &observation); err != nil {
		t.Fatal(err)
	}
	if observation.ComposeSucceeded || observation.InventoryState != "known" || observation.ExpectedComponentCount != 2 || observation.ObservedComponentCount == nil || *observation.ObservedComponentCount != 2 || len(observation.Components) != 2 {
		t.Fatal("partial result was lost or declared approved", observation)
	}
	if observation.Components[0].ContainerID != appID || observation.Components[0].ImageID != newImage || observation.Components[1].ContainerID != dbID || observation.Components[1].State != "exited" {
		t.Fatal("actual mixed identities were not recorded", observation.Components)
	}
	after, err := f.m.Store.List(t.Context(), "runtime_state", f.s.ID)
	if err != nil || len(after) != len(before) || after[0].Digest != before[0].Digest {
		t.Fatal("observation modified trusted runtime state", err)
	}
}

func TestSwitchObservationJournalsUnknownWhenDockerUnavailableEvenAfterCancellation(t *testing.T) {
	f := newPlanningFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := f.m.recordRuntimeSwitchObservation(ctx, f.s, "unknown-operation", "target-release", true); err == nil {
		t.Fatal("unavailable inventory declared confirmed")
	}
	records, err := f.m.Store.List(t.Context(), "runtime_switch_observation", f.s.ID)
	if err != nil || len(records) != 1 {
		t.Fatal("unknown outcome not durable", err)
	}
	var observation runtimeSwitchObservation
	if err := json.Unmarshal(records[0].Payload, &observation); err != nil {
		t.Fatal(err)
	}
	if observation.InventoryState != "unknown" || observation.ObservedComponentCount != nil || len(observation.Components) != 0 || observation.ExpectedComponentCount != 1 || !observation.ComposeSucceeded {
		t.Fatal("unknown inventory replaced by fake empty success", observation)
	}
	if strings.Contains(observation.Reason, "private") || observation.At.IsZero() {
		t.Fatal("invalid diagnostic evidence")
	}
}
