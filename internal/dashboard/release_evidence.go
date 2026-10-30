package dashboard

import (
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"net/http"
)

func (s *Server) releaseEvidence(w http.ResponseWriter, r *http.Request, current session, id domain.ID, release string) {
	rid, err := domain.ParseID(release)
	if err != nil || r.URL.RawQuery != "" {
		apiError(w, 400, "invalid_query", "valid release ID and no query are required")
		return
	}
	v, err := s.executor.ReleaseEvidence(r.Context(), id, rid)
	if err != nil {
		executorError(w, err)
		return
	}
	if !current.User.SensitiveAccess {
		v.ManualConfirmations = nil
		for i := range v.Runs {
			v.Runs[i].Reason = ""
		}
	}
	writeJSON(w, 200, v)
}
