package domain

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type CheckKind string

const (
	CheckHTTP         CheckKind = "http"
	CheckTCP          CheckKind = "tcp"
	CheckHTTPSequence CheckKind = "http_sequence"
)

// HTTPStep is an administrator-reviewed request. Bodies and headers can contain
// credentials: the health policy API stores complete checks only in the vault.
type HTTPStep struct {
	Method         string            `json:"method,omitempty"`
	URL            string            `json:"url"`
	Headers        map[string]string `json:"headers,omitempty"`
	Body           string            `json:"body,omitempty"`
	ExpectedStatus int               `json:"expected_status"`
	BodyContains   string            `json:"body_contains,omitempty"`
}

// HTTPCheck retains the original single-GET JSON contract. An omitted kind means
// http; tcp and http_sequence add bounded, typed probes without host commands.
type HTTPCheck struct {
	ID                  ID           `json:"id"`
	Source              HealthSource `json:"source"`
	Kind                CheckKind    `json:"kind,omitempty"`
	URL                 string       `json:"url,omitempty"`
	ExpectedStatus      int          `json:"expected_status,omitempty"`
	BodyContains        string       `json:"body_contains,omitempty"`
	TimeoutSeconds      uint32       `json:"timeout_seconds"`
	Address             string       `json:"address,omitempty"`
	Steps               []HTTPStep   `json:"steps,omitempty"`
	CleanupSteps        []HTTPStep   `json:"cleanup_steps,omitempty"`
	SideEffectsReviewed bool         `json:"side_effects_reviewed,omitempty"`
	CleanupDescription  string       `json:"cleanup_description,omitempty"`
}

func (c HTTPCheck) EffectiveKind() CheckKind {
	if c.Kind == "" {
		return CheckHTTP
	}
	return c.Kind
}

func parseCheckURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u == nil || u.Host == "" || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || strings.IndexFunc(raw, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return nil, fmt.Errorf("check requires an absolute HTTP(S) URL without credentials, controls or fragment")
	}
	if u.Port() != "" {
		if p, err := strconv.Atoi(u.Port()); err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid check port")
		}
	}
	return u, nil
}

func (s HTTPStep) Validate() error {
	if _, err := parseCheckURL(s.URL); err != nil {
		return err
	}
	method := s.Method
	if method == "" {
		method = http.MethodGet
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return fmt.Errorf("unsupported HTTP check method")
	}
	if s.ExpectedStatus < 200 || s.ExpectedStatus > 499 || len(s.BodyContains) > 256 || len(s.Body) > 4096 || len(s.Headers) > 8 {
		return fmt.Errorf("invalid bounded HTTP expectation or input")
	}
	if (method == http.MethodGet || method == http.MethodHead) && s.Body != "" {
		return fmt.Errorf("GET/HEAD check cannot contain a request body")
	}
	total := 0
	for name, value := range s.Headers {
		total += len(name) + len(value)
		if name == "" || len(name) > 128 || len(value) > 2048 || strings.IndexFunc(name, func(r rune) bool {
			return !strings.ContainsRune("!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", r)
		}) >= 0 || strings.IndexFunc(value, func(r rune) bool { return r < 0x20 && r != '\t' || r == 0x7f }) >= 0 {
			return fmt.Errorf("invalid bounded HTTP header")
		}
		lower := strings.ToLower(name)
		if lower == "host" || lower == "connection" || lower == "content-length" || lower == "transfer-encoding" || lower == "upgrade" || lower == "trailer" || strings.HasPrefix(lower, "proxy-") {
			return fmt.Errorf("HTTP transport headers cannot be overridden")
		}
	}
	if total > 4096 {
		return fmt.Errorf("HTTP headers exceed limit")
	}
	return nil
}

func (c HTTPCheck) Validate() error {
	if err := c.ID.Validate(); err != nil {
		return err
	}
	if c.Source != HealthReadiness && c.Source != HealthFunctional {
		return fmt.Errorf("only readiness and local functional checks are supported")
	}
	if c.TimeoutSeconds == 0 || c.TimeoutSeconds > 10 {
		return fmt.Errorf("check request timeout must be 1..10 seconds")
	}
	switch c.EffectiveKind() {
	case CheckHTTP:
		if c.Address != "" || len(c.Steps) != 0 || len(c.CleanupSteps) != 0 {
			return fmt.Errorf("single HTTP check has incompatible fields")
		}
		return (HTTPStep{URL: c.URL, ExpectedStatus: c.ExpectedStatus, BodyContains: c.BodyContains}).Validate()
	case CheckTCP:
		if c.Source != HealthReadiness || c.URL != "" || c.ExpectedStatus != 0 || c.BodyContains != "" || len(c.Steps) != 0 || len(c.CleanupSteps) != 0 {
			return fmt.Errorf("TCP connect is a readiness check without HTTP fields")
		}
		host, port, err := net.SplitHostPort(c.Address)
		p, parseErr := strconv.Atoi(port)
		if err != nil || host == "" || strings.ContainsAny(host, "/\\ \t\r\n\x00%") || len(host) > 253 || parseErr != nil || p < 1 || p > 65535 {
			return fmt.Errorf("TCP check requires host:port with port 1..65535")
		}
		return nil
	case CheckHTTPSequence:
		if c.Source != HealthFunctional || c.Address != "" || c.URL != "" || c.ExpectedStatus != 0 || c.BodyContains != "" || len(c.Steps) == 0 || len(c.Steps) > 8 || len(c.CleanupSteps) > 4 {
			return fmt.Errorf("HTTP sequence requires 1..8 functional steps and at most 4 cleanup steps")
		}
		origin := ""
		mutates := false
		for _, step := range append(append([]HTTPStep{}, c.Steps...), c.CleanupSteps...) {
			if err := step.Validate(); err != nil {
				return err
			}
			u, _ := parseCheckURL(step.URL)
			current := strings.ToLower(u.Scheme + "://" + u.Host)
			if origin == "" {
				origin = current
			} else if origin != current {
				return fmt.Errorf("HTTP sequence must remain on its approved origin")
			}
			mutates = mutates || step.Method != "" && step.Method != http.MethodGet && step.Method != http.MethodHead
		}
		if mutates && (!c.SideEffectsReviewed || len(strings.TrimSpace(c.CleanupDescription)) < 8 || len(c.CleanupDescription) > 512) {
			return fmt.Errorf("mutating checks require reviewed test data and a cleanup procedure")
		}
		return nil
	default:
		return fmt.Errorf("unsupported typed check kind")
	}
}

type HealthCheckPolicy struct {
	Checks                []HTTPCheck `json:"checks"`
	WarmupSeconds         uint32      `json:"warmup_seconds"`
	OverallTimeoutSeconds uint32      `json:"overall_timeout_seconds"`
	Attempts              uint32      `json:"attempts"`
	RetryIntervalSeconds  uint32      `json:"retry_interval_seconds"`
	ValiditySeconds       uint32      `json:"validity_seconds"`
}

func (p HealthCheckPolicy) Effective() HealthCheckPolicy {
	if p.WarmupSeconds == 0 {
		p.WarmupSeconds = 45
	}
	if p.OverallTimeoutSeconds == 0 {
		p.OverallTimeoutSeconds = 60
	}
	if p.Attempts == 0 {
		p.Attempts = 1
	}
	if p.RetryIntervalSeconds == 0 {
		p.RetryIntervalSeconds = 1
	}
	if p.ValiditySeconds == 0 {
		p.ValiditySeconds = 30
	}
	if p.Checks == nil {
		p.Checks = []HTTPCheck{}
	}
	return p
}

func (p HealthCheckPolicy) Validate() error {
	p = p.Effective()
	if len(p.Checks) > 16 || p.WarmupSeconds > 300 || p.OverallTimeoutSeconds > 300 || p.Attempts > 10 || p.RetryIntervalSeconds > 30 || p.ValiditySeconds > 3600 {
		return fmt.Errorf("health policy exceeds bounded limits")
	}
	seen := map[ID]bool{}
	for _, check := range p.Checks {
		if err := check.Validate(); err != nil {
			return err
		}
		if seen[check.ID] {
			return fmt.Errorf("duplicate check ID")
		}
		seen[check.ID] = true
	}
	return nil
}
