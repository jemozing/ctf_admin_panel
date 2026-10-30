package transport

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

type HealthChecksRequest struct {
	ExpectedRevision uint64                   `json:"expected_revision"`
	Confirmed        bool                     `json:"confirmed"`
	Actor            domain.ID                `json:"actor,omitempty"`
	Policy           domain.HealthCheckPolicy `json:"policy"`
}

func (r HealthChecksRequest) Validate() error {
	if !r.Confirmed {
		return errors.New("confirm approved probe destinations, test data and cleanup before saving")
	}
	if r.Actor != "" {
		if err := r.Actor.Validate(); err != nil {
			return err
		}
	}
	return r.Policy.Validate()
}

type CheckSummary struct {
	ID             domain.ID           `json:"id"`
	Kind           domain.CheckKind    `json:"kind"`
	Source         domain.HealthSource `json:"source"`
	Targets        []string            `json:"targets"`
	Steps          int                 `json:"steps"`
	CleanupSteps   int                 `json:"cleanup_steps"`
	TimeoutSeconds uint32              `json:"timeout_seconds"`
}
type ManualHealthRequest struct {
	ExpectedReleaseID     domain.ID     `json:"expected_release_id"`
	ExpectedStateSequence uint64        `json:"expected_state_sequence"`
	ExpectedRuntimeDigest domain.Digest `json:"expected_runtime_digest"`
	TTLSeconds            uint32        `json:"ttl_seconds"`
	Healthy               bool          `json:"healthy"`
	Comment               string        `json:"comment"`
	Actor                 domain.ID     `json:"actor,omitempty"`
}

func (r ManualHealthRequest) Validate() error {
	if err := r.ExpectedReleaseID.Validate(); err != nil {
		return err
	}
	if err := r.ExpectedRuntimeDigest.Validate(); err != nil {
		return err
	}
	if r.ExpectedStateSequence == 0 || r.TTLSeconds == 0 || r.TTLSeconds > 3600 || len(strings.TrimSpace(r.Comment)) < 3 || len(r.Comment) > 1024 || strings.ContainsRune(r.Comment, '\x00') {
		return errors.New("manual confirmation requires observed state, a comment and TTL 1..3600 seconds")
	}
	if r.Actor != "" {
		return r.Actor.Validate()
	}
	return nil
}

type ManualHealthView struct {
	ID            domain.ID          `json:"id"`
	ServiceID     domain.ID          `json:"service_id"`
	ReleaseID     domain.ID          `json:"release_id"`
	StateSequence uint64             `json:"state_sequence"`
	RuntimeDigest domain.Digest      `json:"runtime_digest"`
	Actor         domain.ID          `json:"actor"`
	Comment       string             `json:"comment"`
	ObservedAt    time.Time          `json:"observed_at"`
	ValidUntil    time.Time          `json:"valid_until"`
	State         domain.HealthState `json:"state"`
}
type HealthChecksView struct {
	Warning               string `json:"warning,omitempty"`
	Revision              uint64 `json:"revision"`
	ServicePolicyRevision uint64 `json:"service_policy_revision"`
	// Settings has no Checks: complete request inputs are write-only vault data.
	Settings            domain.HealthCheckPolicy `json:"settings"`
	Checks              []CheckSummary           `json:"checks"`
	CurrentReleaseID    domain.ID                `json:"current_release_id,omitempty"`
	StateSequence       uint64                   `json:"state_sequence"`
	RuntimeDigest       domain.Digest            `json:"runtime_digest"`
	ManualConfirmations []ManualHealthView       `json:"manual_confirmations"`
}
type HealthBackend interface {
	HealthChecks(context.Context, domain.ID) (HealthChecksView, error)
	ConfigureHealthChecks(context.Context, domain.ID, HealthChecksRequest) (HealthChecksView, error)
	ConfirmManualHealth(context.Context, domain.ID, ManualHealthRequest) (ManualHealthView, error)
}

func (s *Server) healthCheckRoutes(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/services/"), "/")
	if (len(parts) != 2 && len(parts) != 3) || parts[1] != "checks" || len(parts) == 3 && parts[2] != "manual" || r.URL.RawQuery != "" {
		writeError(w, 400, "invalid_path", "invalid health check endpoint")
		return
	}
	id, err := domain.ParseID(parts[0])
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service ID")
		return
	}
	backend, ok := s.options.Backend.(HealthBackend)
	if !ok {
		writeError(w, 501, "not_implemented", "health configuration unavailable")
		return
	}
	if len(parts) == 2 && r.Method == http.MethodGet {
		out, err := backend.HealthChecks(r.Context(), id)
		if err != nil {
			backendError(w, err)
			return
		}
		writeJSON(w, 200, out)
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "GET, POST")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		writeError(w, 415, "invalid_content_type", "JSON required")
		return
	}
	decode := func(out any) bool {
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16*1024))
		if err != nil {
			writeError(w, 413, "body_too_large", "health configuration exceeds limit")
			return false
		}
		if err := DecodeRegistrationJSON(data, out); err != nil {
			writeError(w, 400, "invalid_request", "invalid health configuration")
			return false
		}
		return true
	}
	if len(parts) == 3 {
		var input ManualHealthRequest
		if !decode(&input) {
			return
		}
		if err := input.Validate(); err != nil {
			writeError(w, 400, "invalid_request", err.Error())
			return
		}
		out, err := backend.ConfirmManualHealth(r.Context(), id, input)
		if err != nil {
			backendError(w, err)
			return
		}
		writeJSON(w, 200, out)
		return
	}
	var input HealthChecksRequest
	if !decode(&input) {
		return
	}
	if err := input.Validate(); err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	out, err := backend.ConfigureHealthChecks(r.Context(), id, input)
	if err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, 200, out)
}
func (c *Client) HealthChecks(ctx context.Context, id domain.ID) (HealthChecksView, error) {
	var out HealthChecksView
	if err := id.Validate(); err != nil {
		return out, err
	}
	err := c.request(ctx, http.MethodGet, "/v1/services/"+string(id)+"/checks", nil, &out)
	return out, err
}
func (c *Client) ConfigureHealthChecks(ctx context.Context, id domain.ID, input HealthChecksRequest) (HealthChecksView, error) {
	var out HealthChecksView
	if err := id.Validate(); err != nil {
		return out, err
	}
	if err := input.Validate(); err != nil {
		return out, err
	}
	err := c.request(ctx, http.MethodPost, "/v1/services/"+string(id)+"/checks", input, &out)
	return out, err
}
func (c *Client) ConfirmManualHealth(ctx context.Context, id domain.ID, input ManualHealthRequest) (ManualHealthView, error) {
	var out ManualHealthView
	if err := id.Validate(); err != nil {
		return out, err
	}
	if err := input.Validate(); err != nil {
		return out, err
	}
	err := c.request(ctx, http.MethodPost, "/v1/services/"+string(id)+"/checks/manual", input, &out)
	return out, err
}
