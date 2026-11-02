package dashboard

import (
	"io"
	"mime"
	"net/http"

	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func (s *Server) gitProbeRoute(w http.ResponseWriter, r *http.Request, current session) {
	if current.User.Role != RoleAdmin {
		s.deny(w, r, current.User.ID)
		return
	}
	if r.URL.RawQuery != "" {
		apiError(w, 400, "invalid_query", "Git check does not accept query parameters")
		return
	}
	if !method(w, r, "POST") {
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		apiError(w, 415, "invalid_content_type", "Content-Type must be application/json")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16*1024))
	if err != nil {
		apiError(w, 413, "body_too_large", "Git check request exceeds limit")
		return
	}
	var input transport.GitProbeRequest
	if err := transport.DecodeRegistrationJSON(data, &input); err != nil {
		apiError(w, 400, "invalid_request", "Git check contains invalid fields")
		return
	}
	if err := input.Validate(); err != nil {
		apiError(w, 400, "invalid_request", err.Error())
		return
	}
	target := string(input.ServiceID)
	if err := s.audit(r.Context(), current.User.ID, "source.probe", target, "requested", ""); err != nil {
		internalError(w)
		return
	}
	result, probeErr := s.executor.ProbeGitSource(r.Context(), input)
	// Private branch names must not outlive the initiating Admin session.
	cookie, err := r.Cookie(s.cookieName())
	if err != nil {
		apiError(w, 401, "unauthenticated", "Sign in to continue")
		return
	}
	fresh, err := s.getSession(r.Context(), cookie.Value)
	if err != nil {
		apiError(w, 401, "unauthenticated", "Session has expired")
		return
	}
	if fresh.User.ID != current.User.ID || fresh.User.Role != RoleAdmin {
		s.deny(w, r, fresh.User.ID)
		return
	}
	if probeErr != nil {
		if err := s.audit(r.Context(), current.User.ID, "source.probe", target, "failed", ""); err != nil {
			internalError(w)
			return
		}
		executorError(w, probeErr)
		return
	}
	if err := s.audit(r.Context(), current.User.ID, "source.probe", target, "completed", ""); err != nil {
		internalError(w)
		return
	}
	writeJSON(w, 200, result)
}
