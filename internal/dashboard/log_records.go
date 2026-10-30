package dashboard

import (
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"net/http"
)

func (s *Server) logRecords(w http.ResponseWriter, r *http.Request, current session, id domain.ID) {
	if !current.User.SensitiveAccess {
		s.deny(w, r, current.User.ID)
		return
	}
	q, err := transport.ParseLogQuery(r.URL.RawQuery)
	if err != nil {
		apiError(w, 400, "invalid_query", err.Error())
		return
	}
	v, err := s.executor.LogRecords(r.Context(), id, q)
	if err != nil {
		executorError(w, err)
		return
	}
	writeJSON(w, 200, v)
}
