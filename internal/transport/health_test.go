package transport

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

type healthTestBackend struct {
	testBackend
	writes atomic.Int32
}

func (*healthTestBackend) HealthChecks(context.Context, domain.ID) (HealthChecksView, error) {
	return HealthChecksView{Revision: 1}, nil
}
func (b *healthTestBackend) ConfigureHealthChecks(_ context.Context, _ domain.ID, r HealthChecksRequest) (HealthChecksView, error) {
	b.writes.Add(1)
	return HealthChecksView{Revision: r.ExpectedRevision + 1}, nil
}
func (b *healthTestBackend) ConfirmManualHealth(_ context.Context, id domain.ID, r ManualHealthRequest) (ManualHealthView, error) {
	b.writes.Add(1)
	return ManualHealthView{ServiceID: id, ReleaseID: r.ExpectedReleaseID, Actor: r.Actor}, nil
}

func TestHealthTypedRoutesRejectCommandsUnboundedInputsAndForeignMethods(t *testing.T) {
	b := &healthTestBackend{}
	_, c := runServer(t, Options{Backend: b})
	view, err := c.HealthChecks(t.Context(), "game")
	if err != nil || view.Revision != 1 {
		t.Fatal(view, err)
	}
	view, err = c.ConfigureHealthChecks(t.Context(), "game", HealthChecksRequest{ExpectedRevision: 1, Confirmed: true, Actor: "admin", Policy: domain.HealthCheckPolicy{Checks: []domain.HTTPCheck{{ID: "tcp", Source: domain.HealthReadiness, Kind: domain.CheckTCP, Address: "service:8080", TimeoutSeconds: 2}}}})
	if err != nil || view.Revision != 2 {
		t.Fatal(view, err)
	}
	for _, body := range []string{
		`{"confirmed":true,"policy":{"command":"id"}}`,
		`{"confirmed":false,"policy":{}}`,
		`{"confirmed":true,"policy":{"attempts":11}}`,
		`{"confirmed":true,"policy":{"checks":[{"id":"exec","source":"readiness","kind":"shell","timeout_seconds":2}]}}`,
		`{"confirmed":true,"policy":{"checks":[{"id":"http","source":"readiness","url":"file:///etc/passwd","expected_status":200,"timeout_seconds":2}]}}`,
		`{"confirmed":true,"policy":{}} {}`,
	} {
		r, _ := http.NewRequest("POST", "http://executor/v1/services/game/checks", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		response, err := c.http.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 400 {
			t.Fatalf("unsafe check input accepted: %d", response.StatusCode)
		}
	}
	if b.writes.Load() != 1 {
		t.Fatal("invalid input reached backend")
	}
}
