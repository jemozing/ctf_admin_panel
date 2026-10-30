package dashboard

import (
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"net/http"
	"strings"
)

func (s *Server) cancelOperation(w http.ResponseWriter, r *http.Request, current session) {
	if !method(w, r, "POST") {
		return
	}
	if current.User.Role == RoleViewer {
		s.deny(w, r, current.User.ID)
		return
	}
	if r.URL.RawQuery != "" {
		apiError(w, 400, "invalid_query", "No query is supported")
		return
	}
	id, err := domain.ParseID(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/operations/"), "/cancel"))
	if err != nil {
		apiError(w, 400, "invalid_id", "Invalid operation ID")
		return
	}
	var input struct{}
	if !decodeBody(w, r, &input) {
		return
	}
	if err := s.audit(r.Context(), current.User.ID, "operation.cancel", string(id), "requested", string(id)); err != nil {
		internalError(w)
		return
	}
	op, err := s.executor.CancelOperation(r.Context(), id, domain.ID(current.User.ID))
	if err != nil {
		_ = s.audit(r.Context(), current.User.ID, "operation.cancel", string(id), "rejected", string(id))
		executorError(w, err)
		return
	}
	if err := s.audit(r.Context(), current.User.ID, "operation.cancel", string(id), "accepted", string(id)); err != nil {
		apiError(w, 502, "audit_incomplete", "Request may have been saved; refresh operation")
		return
	}
	writeJSON(w, 200, op)
}
