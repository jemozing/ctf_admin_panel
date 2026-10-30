package transport

import (
	"context"
	"net/http"
	"strings"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

type CancelBackend interface {
	CancelOperation(context.Context, domain.ID, domain.ID) (domain.Operation, error)
}
type CancelRequest struct {
	Actor domain.ID `json:"actor"`
}

func (s *Server) cancelEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	id, err := domain.ParseID(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/operations/"), "/cancel"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid operation ID")
		return
	}
	var input CancelRequest
	if !decodeRegistrationBody(w, r, &input) {
		return
	}
	if input.Actor.Validate() != nil {
		writeError(w, 400, "invalid_request", "actor is required")
		return
	}
	b, ok := s.options.Backend.(CancelBackend)
	if !ok {
		writeError(w, 501, "not_implemented", "cancellation unavailable")
		return
	}
	op, err := b.CancelOperation(r.Context(), id, input.Actor)
	if err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, 200, op)
}

func (c *Client) CancelOperation(ctx context.Context, id, actor domain.ID) (domain.Operation, error) {
	var op domain.Operation
	if err := id.Validate(); err != nil {
		return op, err
	}
	err := c.request(ctx, http.MethodPost, "/v1/operations/"+string(id)+"/cancel", CancelRequest{Actor: actor}, &op)
	return op, err
}
