package transport

import (
	"context"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"net/http"
	"strings"
	"time"
)

type RuntimeEventsResponse struct {
	Events         []store.RuntimeEvent `json:"events"`
	Connected      bool                 `json:"connected"`
	ConnectedAt    time.Time            `json:"connected_at,omitempty"`
	Error          string               `json:"error,omitempty"`
	Storage        string               `json:"storage"`
	RetainedGlobal int                  `json:"retained_global"`
	ReturnedLimit  int                  `json:"returned_limit"`
	Continuity     string               `json:"continuity"`
}
type RuntimeEventsBackend interface {
	RuntimeEvents(context.Context, domain.ID) (RuntimeEventsResponse, error)
}

func (s *Server) runtimeEventsEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	id, err := domain.ParseID(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/services/"), "/runtime-events"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service ID")
		return
	}
	b, ok := s.options.Backend.(RuntimeEventsBackend)
	if !ok {
		writeError(w, 501, "not_implemented", "runtime events unavailable")
		return
	}
	v, err := b.RuntimeEvents(r.Context(), id)
	if err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, 200, v)
}
func (c *Client) RuntimeEvents(ctx context.Context, id domain.ID) (RuntimeEventsResponse, error) {
	var v RuntimeEventsResponse
	if err := id.Validate(); err != nil {
		return v, err
	}
	err := c.request(ctx, http.MethodGet, "/v1/services/"+string(id)+"/runtime-events", nil, &v)
	return v, err
}
