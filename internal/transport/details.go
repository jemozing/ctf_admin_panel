package transport

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
)

type SnapshotSummary struct {
	ID         domain.ID              `json:"id"`
	Purpose    domain.SnapshotPurpose `json:"purpose"`
	CreatedAt  time.Time              `json:"created_at"`
	TreeDigest domain.Digest          `json:"tree_digest"`
	Bytes      int64                  `json:"bytes"`
	GitSource  *domain.GitProvenance  `json:"git_source,omitempty"`
}
type ServiceDetails struct {
	Service           domain.Service        `json:"service"`
	Containers        []docker.Container    `json:"containers"`
	CurrentReleaseID  domain.ID             `json:"current_release_id,omitempty"`
	CandidateID       domain.ID             `json:"candidate_id,omitempty"`
	Releases          []domain.Release      `json:"releases"`
	Snapshots         []SnapshotSummary     `json:"snapshots"`
	Capabilities      map[string]bool       `json:"capabilities"`
	ObservedState     string                `json:"observed_state"`
	Health            []domain.HealthSignal `json:"health"`
	Drift             DriftObservation      `json:"drift"`
	ComponentVersions []ComponentVersion    `json:"component_versions"`
}
type LogResult struct {
	Content   string `json:"content"`
	Truncated bool   `json:"truncated"`
}
type FileChange struct {
	Path   string `json:"path"`
	Change string `json:"change"`
}
type PreviewResult struct {
	Space                     PreviewSpace             `json:"space"`
	RecoveryOperationID       domain.ID                `json:"recovery_operation_id,omitempty"`
	ServiceID                 domain.ID                `json:"service_id"`
	Action                    domain.OperationKind     `json:"action"`
	ActiveReleaseID           domain.ID                `json:"active_release_id,omitempty"`
	CandidateID               domain.ID                `json:"candidate_id,omitempty"`
	SnapshotID                domain.ID                `json:"snapshot_id,omitempty"`
	TargetReleaseID           domain.ID                `json:"target_release_id,omitempty"`
	Targets                   []string                 `json:"targets"`
	ChangedFiles              []FileChange             `json:"changed_files"`
	PlanDigest                domain.Digest            `json:"plan_digest"`
	PolicyRevision            uint64                   `json:"policy_revision"`
	CurrentTreeDigest         domain.Digest            `json:"current_tree_digest"`
	DataCompatibilityRequired bool                     `json:"data_compatibility_required"`
	HasRollback               bool                     `json:"has_rollback"`
	Images                    []domain.ImageRef        `json:"images,omitempty"`
	GitSource                 *GitSourceView           `json:"git_source,omitempty"`
	HealthCheckRevision       uint64                   `json:"health_check_revision"`
	HealthSettings            domain.HealthCheckPolicy `json:"health_settings"`
	CheckSummaries            []CheckSummary           `json:"check_summaries"`
	ActiveFileDrift           bool                     `json:"active_file_drift"`
	AcceptedFileDrift         bool                     `json:"accepted_file_drift"`
	DriftChangedFiles         []FileChange             `json:"drift_changed_files"`
}
type PreviewSpace struct {
	EstimateKnown        bool    `json:"estimate_known"`
	SnapshotBytes        uint64  `json:"snapshot_bytes"`
	StagingBytes         uint64  `json:"staging_bytes"`
	ApplyTemporaryBytes  uint64  `json:"apply_temporary_bytes"`
	DockerReserveBytes   uint64  `json:"docker_reserve_bytes"`
	MinimumFreeBytes     uint64  `json:"minimum_free_bytes"`
	MinimumFreeInodes    uint64  `json:"minimum_free_inodes"`
	StateAvailableBytes  *uint64 `json:"state_available_bytes"`
	StateAvailableInodes *uint64 `json:"state_available_inodes"`
}
type DetailBackend interface {
	ServiceDetails(context.Context, domain.ID) (ServiceDetails, error)
	OperationEvents(context.Context, domain.ID) ([]store.Event, error)
	Logs(context.Context, domain.ID, string, int) (LogResult, error)
	Preview(context.Context, SubmitRequest) (PreviewResult, error)
}

func (s *Server) serviceEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	tail := strings.TrimPrefix(r.URL.Path, "/v1/services/")
	parts := strings.Split(tail, "/")
	id, err := domain.ParseID(parts[0])
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service ID")
		return
	}
	backend, ok := s.options.Backend.(DetailBackend)
	if !ok {
		writeError(w, 501, "not_implemented", "details unavailable")
		return
	}
	if len(parts) == 1 {
		result, err := backend.ServiceDetails(r.Context(), id)
		if err != nil {
			backendError(w, err)
			return
		}
		writeJSON(w, 200, result)
		return
	}
	if len(parts) == 2 && parts[1] == "metrics" {
		s.metricsEndpoint(w, r, id)
		return
	}
	if len(parts) == 2 && parts[1] == "log-records" {
		s.logRecordsEndpoint(w, r, id)
		return
	}
	if len(parts) == 2 && parts[1] == "files" {
		s.filesEndpoint(w, r, id)
		return
	}
	if len(parts) == 4 && parts[1] == "releases" && parts[3] == "evidence" {
		s.releaseEvidenceEndpoint(w, r, id, parts[2])
		return
	}
	if len(parts) == 2 && parts[1] == "logs" {
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || len(query) > 2 || len(query["component"]) != 1 || len(query["tail"]) != 1 {
			writeError(w, 400, "invalid_query", "component and tail are required")
			return
		}
		for k := range query {
			if k != "component" && k != "tail" {
				writeError(w, 400, "invalid_query", "unknown log option")
				return
			}
		}
		n, err := strconv.Atoi(query.Get("tail"))
		if err != nil || n < 1 || n > 500 {
			writeError(w, 400, "invalid_tail", "tail must be between 1 and 500")
			return
		}
		result, err := backend.Logs(r.Context(), id, query.Get("component"), n)
		if err != nil {
			backendError(w, err)
			return
		}
		writeJSON(w, 200, result)
		return
	}
	writeError(w, 404, "not_found", "unknown service endpoint")
}
func (s *Server) preview(w http.ResponseWriter, r *http.Request) {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		writeError(w, 415, "invalid_content_type", "JSON required")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err != nil {
		writeError(w, 413, "body_too_large", "request too large")
		return
	}
	var req SubmitRequest
	if err := decodeSubmit(data, &req); err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	if req.IdempotencyKey == "" {
		req.IdempotencyKey = "preview"
	}
	if err := req.Validate(); err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	backend, ok := s.options.Backend.(DetailBackend)
	if !ok {
		writeError(w, 501, "not_implemented", "preview unavailable")
		return
	}
	result, err := backend.Preview(r.Context(), req)
	if err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (c *Client) ServiceDetails(ctx context.Context, id domain.ID) (ServiceDetails, error) {
	var v ServiceDetails
	if err := id.Validate(); err != nil {
		return v, err
	}
	err := c.request(ctx, http.MethodGet, "/v1/services/"+string(id), nil, &v)
	return v, err
}
func (c *Client) OperationEvents(ctx context.Context, id domain.ID) ([]store.Event, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	var v []store.Event
	err := c.request(ctx, http.MethodGet, "/v1/operations/"+string(id)+"/events", nil, &v)
	return v, err
}
func (c *Client) Logs(ctx context.Context, id domain.ID, component string, tail int) (LogResult, error) {
	var v LogResult
	if err := id.Validate(); err != nil {
		return v, err
	}
	q := url.Values{"component": []string{component}, "tail": []string{strconv.Itoa(tail)}}
	err := c.request(ctx, http.MethodGet, "/v1/services/"+string(id)+"/logs?"+q.Encode(), nil, &v)
	return v, err
}
func (c *Client) Preview(ctx context.Context, req SubmitRequest) (PreviewResult, error) {
	var v PreviewResult
	err := c.request(ctx, http.MethodPost, "/v1/preview", req, &v)
	return v, err
}
