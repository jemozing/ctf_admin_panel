package dashboard

import (
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"net/http"
	"strings"
)

func (s *Server) runtimeEvents(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	if r.URL.RawQuery != "" {
		apiError(w, 400, "invalid_query", "No query is supported")
		return
	}
	id, err := domain.ParseID(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/services/"), "/runtime-events"))
	if err != nil {
		apiError(w, 400, "invalid_id", "Invalid service ID")
		return
	}
	v, err := s.executor.RuntimeEvents(r.Context(), id)
	if err != nil {
		executorError(w, err)
		return
	}
	writeJSON(w, 200, v)
}
