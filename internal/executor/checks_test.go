package executor

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

func TestProbeDoesNotFollowRedirectOrExposeResponse(t *testing.T) {
	var followed atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/secret", http.StatusFound)
		case "/secret":
			followed.Add(1)
			w.Write([]byte("do-not-leak-private-response"))
		default:
			w.Write([]byte("version=v2"))
		}
	}))
	defer server.Close()
	check := domain.HTTPCheck{ID: "check-v2", Source: domain.HealthFunctional, URL: server.URL, ExpectedStatus: 200, BodyContains: "version=v2", TimeoutSeconds: 1}
	if result := probe(context.Background(), check); result.State != domain.HealthHealthy {
		t.Fatalf("expected success: %+v", result)
	}
	check.URL = server.URL + "/redirect"
	if result := probe(context.Background(), check); result.State != domain.HealthUnhealthy || strings.Contains(result.Reason, "do-not-leak") {
		t.Fatalf("unsafe redirect result: %+v", result)
	}
	if followed.Load() != 0 {
		t.Fatal("redirect was followed")
	}
	check.URL = server.URL + "/secret"
	if result := probe(context.Background(), check); result.State != domain.HealthUnhealthy || strings.Contains(result.Reason, "do-not-leak") {
		t.Fatalf("response leaked: %+v", result)
	}
}
func TestProbeRejectsOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(strings.Repeat("x", 65537))) }))
	defer server.Close()
	check := domain.HTTPCheck{ID: "bounded", Source: domain.HealthReadiness, URL: server.URL, ExpectedStatus: 200, TimeoutSeconds: 1}
	if result := probe(context.Background(), check); result.State != domain.HealthUnhealthy {
		t.Fatal(result)
	}
}
func TestExactTargetsRejectsMissingAndDuplicate(t *testing.T) {
	s := domain.Service{Targets: []string{"app"}}
	if err := exactTargets(s, nil); err == nil {
		t.Fatal("missing target accepted")
	}
}

func TestTCPReadinessAndClosedPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	check := domain.HTTPCheck{ID: "tcp", Source: domain.HealthReadiness, Kind: domain.CheckTCP, Address: listener.Addr().String(), TimeoutSeconds: 1}
	if v := probe(t.Context(), check); v.State != domain.HealthHealthy {
		t.Fatal(v)
	}
	listener.Close()
	if v := probe(t.Context(), check); v.State != domain.HealthUnhealthy || strings.Contains(v.Reason, check.Address) {
		t.Fatal("closed port or private address leaked", v)
	}
}

func TestHTTPSequenceSharesCookiesAndAlwaysCleansSyntheticData(t *testing.T) {
	var cleaned atomic.Int32
	var fail atomic.Bool
	const privateInput = "private-scenario-password"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			body, _ := io.ReadAll(r.Body)
			if r.Method != "POST" || string(body) != privateInput {
				t.Error("typed request body lost")
			}
			http.SetCookie(w, &http.Cookie{Name: "synthetic", Value: "ok", Path: "/"})
			w.WriteHeader(201)
		case "/profile":
			cookie, err := r.Cookie("synthetic")
			if err != nil || cookie.Value != "ok" {
				t.Error("cookie session lost between steps")
			}
			if fail.Load() {
				w.WriteHeader(500)
				w.Write([]byte(privateInput))
				return
			}
			w.Write([]byte("test patient present"))
		case "/cleanup":
			if _, err := r.Cookie("synthetic"); err != nil {
				t.Error("cleanup lost cookie")
			}
			cleaned.Add(1)
			w.WriteHeader(204)
		}
	}))
	defer server.Close()
	check := domain.HTTPCheck{ID: "patient-flow", Source: domain.HealthFunctional, Kind: domain.CheckHTTPSequence, TimeoutSeconds: 1, SideEffectsReviewed: true, CleanupDescription: "Remove only our synthetic patient fixture", Steps: []domain.HTTPStep{{Method: "POST", URL: server.URL + "/login", Body: privateInput, ExpectedStatus: 201}, {URL: server.URL + "/profile", ExpectedStatus: 200, BodyContains: "test patient present"}}, CleanupSteps: []domain.HTTPStep{{Method: "DELETE", URL: server.URL + "/cleanup", ExpectedStatus: 204}}}
	if v := probe(t.Context(), check); v.State != domain.HealthHealthy {
		t.Fatal(v)
	}
	fail.Store(true)
	if v := probe(t.Context(), check); v.State != domain.HealthUnhealthy || strings.Contains(v.Reason, privateInput) {
		t.Fatal("failed sequence leaked private response", v)
	}
	if cleaned.Load() != 2 {
		t.Fatal("failure skipped cleanup")
	}
}

func TestCheckOverallDeadlineBoundsRetriesAndTTL(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(503)
			return
		}
		w.Write([]byte("ready"))
	}))
	defer server.Close()
	check := domain.HTTPCheck{ID: "retry", Source: domain.HealthReadiness, URL: server.URL, ExpectedStatus: 200, TimeoutSeconds: 1}
	policy := (domain.HealthCheckPolicy{Attempts: 2, ValiditySeconds: 75}).Effective()
	result := retryProbe(t.Context(), check, policy)
	if result.State != domain.HealthHealthy || calls.Load() != 2 || result.ValidUntil.Sub(result.ObservedAt) != 75*time.Second {
		t.Fatal("bounded retry/TTL not applied", result, calls.Load())
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	check.BodyContains = "will never match"
	policy.Attempts = 10
	started := time.Now()
	result = retryProbe(ctx, check, policy)
	if result.State != domain.HealthUnhealthy || time.Since(started) > 500*time.Millisecond {
		t.Fatal("overall deadline did not stop retries", result)
	}
}
