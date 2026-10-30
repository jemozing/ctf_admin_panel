package domain

import (
	"encoding/json"
	"testing"
)

func TestHTTPCheckBoundary(t *testing.T) {
	valid := HTTPCheck{ID: "ready", Source: HealthReadiness, URL: "http://127.0.0.1:8080/health", ExpectedStatus: 200, TimeoutSeconds: 2}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, url := range []string{"file:///etc/passwd", "http://user:password@localhost/", "http://localhost/#hidden", "http:///no-host"} {
		v := valid
		v.URL = url
		if err := v.Validate(); err == nil {
			t.Fatalf("accepted %q", url)
		}
	}
	v := valid
	v.Source = HealthExternal
	if err := v.Validate(); err == nil {
		t.Fatal("local check impersonated external checker")
	}
}

func TestTypedCheckPoliciesRejectUnsafeOrUnboundedScenarios(t *testing.T) {
	tcp := HTTPCheck{ID: "tcp", Source: HealthReadiness, Kind: CheckTCP, Address: "127.0.0.1:8080", TimeoutSeconds: 2}
	if err := tcp.Validate(); err != nil {
		t.Fatal(err)
	}
	tcp.Source = HealthFunctional
	if err := tcp.Validate(); err == nil {
		t.Fatal("TCP connect impersonated functional proof")
	}
	step := HTTPStep{URL: "http://service:8080/login", Method: "POST", Body: "test=synthetic", ExpectedStatus: 200}
	sequence := HTTPCheck{ID: "scenario", Source: HealthFunctional, Kind: CheckHTTPSequence, TimeoutSeconds: 2, Steps: []HTTPStep{step}}
	if err := sequence.Validate(); err == nil {
		t.Fatal("unreviewed mutating request accepted")
	}
	sequence.SideEffectsReviewed = true
	sequence.CleanupDescription = "Delete only the synthetic fixture after the scenario"
	if err := sequence.Validate(); err != nil {
		t.Fatal(err)
	}
	sequence.Steps = append(sequence.Steps, HTTPStep{URL: "http://other:8080/private", ExpectedStatus: 200})
	if err := sequence.Validate(); err == nil {
		t.Fatal("cross-origin scenario accepted")
	}
	for _, header := range []string{"Host", "Proxy-Authorization", "Transfer-Encoding", "Connection"} {
		step.Headers = map[string]string{header: "private"}
		if err := step.Validate(); err == nil {
			t.Fatalf("transport header %q accepted", header)
		}
	}
	policy := HealthCheckPolicy{Attempts: 11}
	if err := policy.Validate(); err == nil {
		t.Fatal("unbounded retries accepted")
	}
	policy = HealthCheckPolicy{Checks: []HTTPCheck{{ID: "ready", Source: HealthReadiness, URL: "http://service/", ExpectedStatus: 200, TimeoutSeconds: 1}, {ID: "ready", Source: HealthReadiness, URL: "http://service/", ExpectedStatus: 200, TimeoutSeconds: 1}}}
	if err := policy.Validate(); err == nil {
		t.Fatal("duplicate check identifiers accepted")
	}
}

func TestLegacyHTTPCheckJSONRemainsValid(t *testing.T) {
	var check HTTPCheck
	if err := json.Unmarshal([]byte(`{"id":"legacy","source":"local_functional","url":"http://service/status","expected_status":200,"body_contains":"version","timeout_seconds":2}`), &check); err != nil {
		t.Fatal(err)
	}
	if check.EffectiveKind() != CheckHTTP || check.Validate() != nil {
		t.Fatal("legacy single GET check no longer supported", check)
	}
}
