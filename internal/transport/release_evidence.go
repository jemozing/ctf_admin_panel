package transport

import (
	"context"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"net/http"
	"time"
)

type DriftObservation struct {
	State          string        `json:"state"`
	Reason         string        `json:"reason,omitempty"`
	ExpectedDigest domain.Digest `json:"expected_digest,omitempty"`
	CurrentDigest  domain.Digest `json:"current_digest,omitempty"`
	At             time.Time     `json:"at"`
}
type ComponentVersion struct {
	Component          string        `json:"component"`
	ContainerID        string        `json:"container_id,omitempty"`
	ImageID            string        `json:"image_id,omitempty"`
	RecordedImageID    domain.Digest `json:"recorded_image_id,omitempty"`
	RecordedReleaseID  domain.ID     `json:"recorded_release_id,omitempty"`
	State              string        `json:"state"`
	ObservedReleaseID  domain.ID     `json:"observed_release_id,omitempty"`
	PossibleReleaseIDs []domain.ID   `json:"possible_release_ids"`
	ReleaseEvidence    string        `json:"release_evidence,omitempty"`
	AmbiguityReason    string        `json:"ambiguity_reason,omitempty"`
}
type ReleaseRun struct {
	OperationID domain.ID             `json:"operation_id"`
	Action      domain.OperationKind  `json:"action"`
	State       domain.OperationState `json:"state"`
	At          time.Time             `json:"at"`
	Reason      string                `json:"reason,omitempty"`
}
type ReleaseCheck struct {
	At      time.Time             `json:"at"`
	Signals []domain.HealthSignal `json:"signals"`
}
type ManualReleaseConfirmation struct {
	At         time.Time          `json:"at"`
	Actor      domain.ID          `json:"actor"`
	Comment    string             `json:"comment"`
	State      domain.HealthState `json:"state"`
	ValidUntil time.Time          `json:"valid_until"`
}
type ReleaseEvidence struct {
	ReleaseID                domain.ID                   `json:"release_id"`
	At                       time.Time                   `json:"at"`
	Active                   bool                        `json:"active"`
	CanApply                 bool                        `json:"can_apply"`
	DataConfirmationRequired bool                        `json:"data_confirmation_required"`
	Checks                   map[string]string           `json:"checks"`
	Reasons                  []string                    `json:"reasons"`
	Runs                     []ReleaseRun                `json:"runs"`
	LocalChecks              []ReleaseCheck              `json:"local_checks"`
	ManualConfirmations      []ManualReleaseConfirmation `json:"manual_confirmations"`
}
type ReleaseEvidenceBackend interface {
	ReleaseEvidence(context.Context, domain.ID, domain.ID) (ReleaseEvidence, error)
}

func (s *Server) releaseEvidenceEndpoint(w http.ResponseWriter, r *http.Request, id domain.ID, release string) {
	rid, err := domain.ParseID(release)
	if err != nil || r.URL.RawQuery != "" {
		writeError(w, 400, "invalid_query", "valid release ID and no query are required")
		return
	}
	b, ok := s.options.Backend.(ReleaseEvidenceBackend)
	if !ok {
		writeError(w, 501, "not_implemented", "release evidence unavailable")
		return
	}
	v, err := b.ReleaseEvidence(r.Context(), id, rid)
	if err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, 200, v)
}
func (c *Client) ReleaseEvidence(ctx context.Context, id, release domain.ID) (ReleaseEvidence, error) {
	var v ReleaseEvidence
	if err := id.Validate(); err != nil {
		return v, err
	}
	if err := release.Validate(); err != nil {
		return v, err
	}
	err := c.request(ctx, http.MethodGet, "/v1/services/"+string(id)+"/releases/"+string(release)+"/evidence", nil, &v)
	return v, err
}
