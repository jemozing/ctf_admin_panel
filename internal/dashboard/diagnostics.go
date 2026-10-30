package dashboard

import (
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"net/http"
)

func (s *Server) diagnostics(w http.ResponseWriter, r *http.Request, current session, id domain.ID) {
	if !method(w, r, "GET") {
		return
	}
	if !current.User.SensitiveAccess {
		s.deny(w, r, current.User.ID)
		return
	}
	after, err := transport.ParseDiagnosticsCursor(r.URL.RawQuery)
	if err != nil {
		apiError(w, 400, "invalid_query", err.Error())
		return
	}
	v, err := s.executor.OperationDiagnostics(r.Context(), id, after)
	if err != nil {
		executorError(w, err)
		return
	}
	writeJSON(w, 200, v)
}
