package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

type checkObservation struct {
	StateSequence        uint64                `json:"state_sequence"`
	ReleaseID            domain.ID             `json:"release_id"`
	Signals              []domain.HealthSignal `json:"signals"`
	HealthPolicyRevision uint64                `json:"health_policy_revision,omitempty"`
}

func probe(ctx context.Context, check domain.HTTPCheck) domain.HealthSignal {
	now := time.Now().UTC()
	signal := domain.HealthSignal{Source: check.Source, State: domain.HealthUnhealthy, ObservedAt: now, ValidUntil: now.Add(30 * time.Second), Reason: "local check failed: " + string(check.ID)}
	if err := check.Validate(); err != nil {
		return signal
	}
	if check.EffectiveKind() == domain.CheckTCP {
		deadline, cancel := context.WithTimeout(ctx, time.Duration(check.TimeoutSeconds)*time.Second)
		defer cancel()
		conn, err := (&net.Dialer{}).DialContext(deadline, "tcp", check.Address)
		if err != nil {
			return signal
		}
		_ = conn.Close()
	} else {
		tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, TLSHandshakeTimeout: 3 * time.Second, MaxResponseHeaderBytes: 16384, DisableKeepAlives: true}
		defer tr.CloseIdleConnections()
		jar, _ := cookiejar.New(nil)
		client := &http.Client{Transport: tr, Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		steps := check.Steps
		if check.EffectiveKind() == domain.CheckHTTP {
			steps = []domain.HTTPStep{{URL: check.URL, ExpectedStatus: check.ExpectedStatus, BodyContains: check.BodyContains}}
		}
		passed := true
		for _, step := range steps {
			if !probeHTTP(ctx, client, step, check.TimeoutSeconds) {
				passed = false
				break
			}
		}
		// Cleanup requests run even after a failed functional step, under the same
		// bounded overall context. A cleanup failure must not produce a green signal.
		for _, step := range check.CleanupSteps {
			if !probeHTTP(ctx, client, step, check.TimeoutSeconds) {
				passed = false
				signal.Reason = "local check cleanup could not be confirmed: " + string(check.ID)
			}
		}
		if !passed {
			return signal
		}
	}
	signal.State = domain.HealthHealthy
	signal.Reason = "local " + string(check.EffectiveKind()) + " check passed: " + string(check.ID)
	return signal
}
func probeHTTP(ctx context.Context, client *http.Client, step domain.HTTPStep, timeout uint32) bool {
	deadline, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()
	method := step.Method
	if method == "" {
		method = http.MethodGet
	}
	request, err := http.NewRequestWithContext(deadline, method, step.URL, strings.NewReader(step.Body))
	if err != nil {
		return false
	}
	for name, value := range step.Headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	defer clear(body)
	return err == nil && len(body) <= 65536 && response.StatusCode == step.ExpectedStatus && strings.Contains(string(body), step.BodyContains)
}
func retryProbe(ctx context.Context, check domain.HTTPCheck, policy domain.HealthCheckPolicy) domain.HealthSignal {
	var signal domain.HealthSignal
	for attempt := uint32(0); attempt < policy.Attempts; attempt++ {
		signal = probe(ctx, check)
		signal.ValidUntil = signal.ObservedAt.Add(time.Duration(policy.ValiditySeconds) * time.Second)
		if signal.State == domain.HealthHealthy || ctx.Err() != nil {
			return signal
		}
		if attempt+1 < policy.Attempts {
			timer := time.NewTimer(time.Duration(policy.RetryIntervalSeconds) * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return signal
			case <-timer.C:
			}
		}
	}
	return signal
}
func (m *Manager) runChecksObserved(ctx context.Context, s domain.Service, opID domain.ID) error {
	policy, revision, err := m.healthPolicy(ctx, s)
	if err != nil {
		return err
	}
	if len(policy.Checks) == 0 {
		return m.event(ctx, opID, "checks_not_configured", "local readiness and functional probes are not configured; external checker is independent")
	}
	if err := m.stage(ctx, opID, domain.StageFunctionalCheck); err != nil {
		return err
	}
	st, err := m.state(ctx, s)
	if err != nil {
		return err
	}
	healthRelease, err := m.healthReleaseID(ctx, s, st)
	if err != nil {
		return err
	}
	results := checkObservation{StateSequence: st.Sequence, ReleaseID: healthRelease, HealthPolicyRevision: revision, Signals: []domain.HealthSignal{}}
	overall, cancel := context.WithTimeout(ctx, time.Duration(policy.OverallTimeoutSeconds)*time.Second)
	defer cancel()
	failed := false
	for _, check := range policy.Checks {
		signal := retryProbe(overall, check, policy)
		results.Signals = append(results.Signals, signal)
		failed = failed || signal.State != domain.HealthHealthy
	}
	if err := m.Store.PutImmutable(ctx, "check_observation", NewID("check-"), s.ID, results); err != nil {
		return err
	}
	if failed {
		return errors.New("one or more configured local checks failed")
	}
	return m.event(ctx, opID, "local_checks_passed", "configured local typed checks passed; external checker state is independent")
}
func (m *Manager) recordedChecks(ctx context.Context, s domain.Service, st runtimeState, signals []domain.HealthSignal) ([]domain.HealthSignal, error) {
	policy, revision, err := m.healthPolicy(ctx, s)
	if err != nil {
		for i := range signals {
			if signals[i].Source == domain.HealthReadiness || signals[i].Source == domain.HealthFunctional {
				signals[i].State = domain.HealthUnknown
				signals[i].Reason = "configured check inputs unavailable"
			}
		}
		return m.recordedManualHealth(ctx, s, st, signals)
	}
	for i := range signals {
		for _, c := range policy.Checks {
			if c.Source == signals[i].Source {
				signals[i].State = domain.HealthUnknown
			}
		}
	}
	records, err := m.Store.List(ctx, "check_observation", s.ID)
	if err != nil {
		return nil, err
	}
	var newest time.Time
	var observed *checkObservation
	healthRelease, err := m.healthReleaseID(ctx, s, st)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		var v checkObservation
		if err := json.Unmarshal(record.Payload, &v); err != nil {
			return nil, err
		}
		if v.StateSequence == st.Sequence && v.ReleaseID == healthRelease && v.HealthPolicyRevision == revision && record.CreatedAt.After(newest) {
			copy := v
			observed = &copy
			newest = record.CreatedAt
		}
	}
	if observed == nil {
		return m.recordedManualHealth(ctx, s, st, signals)
	}
	for i := range signals {
		source := signals[i].Source
		var found *domain.HealthSignal
		for _, v := range observed.Signals {
			if v.Source != source {
				continue
			}
			copy := v
			copy.State = v.EffectiveState(time.Now())
			if found == nil || copy.State != domain.HealthHealthy {
				found = &copy
			}
		}
		if found != nil {
			signals[i] = *found
		}
	}
	return m.recordedManualHealth(ctx, s, st, signals)
}
