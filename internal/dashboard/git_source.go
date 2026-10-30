package dashboard

import (
	"net/http"
	"strings"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func (s *Server) gitSourceRoutes(w http.ResponseWriter, r *http.Request, current session) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/services/"), "/")
	if len(parts) != 2 || parts[1] != "source" || r.URL.RawQuery != "" {
		apiError(w, 400, "invalid_path", "Invalid source endpoint")
		return
	}
	id, err := domain.ParseID(parts[0])
	if err != nil {
		apiError(w, 400, "invalid_id", "Invalid service ID")
		return
	}
	if r.Method == http.MethodGet {
		v, err := s.executor.GitSource(r.Context(), id)
		if err != nil {
			executorError(w, err)
			return
		}
		writeJSON(w, 200, v)
		return
	}
	if !method(w, r, "POST") {
		return
	}
	if current.User.Role != RoleAdmin {
		s.deny(w, r, current.User.ID)
		return
	}
	var input transport.GitSourceRequest
	if !decodeBody(w, r, &input) {
		return
	}
	if err := input.Validate(); err != nil {
		apiError(w, 400, "invalid_request", err.Error())
		return
	}
	if err := s.audit(r.Context(), current.User.ID, "source.configure", string(id), "requested", ""); err != nil {
		internalError(w)
		return
	}
	v, err := s.executor.ConfigureGitSource(r.Context(), id, input)
	if err != nil {
		_ = s.audit(r.Context(), current.User.ID, "source.configure", string(id), "rejected", "")
		executorError(w, err)
		return
	}
	if err := s.audit(r.Context(), current.User.ID, "source.configure", string(id), "succeeded", ""); err != nil {
		apiError(w, 502, "audit_incomplete", "Source may have been saved; refresh configuration")
		return
	}
	writeJSON(w, 200, v)
}
