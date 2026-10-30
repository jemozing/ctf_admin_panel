package dashboard

import (
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func decodeHealthBody(w http.ResponseWriter, r *http.Request, out any) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		apiError(w, 415, "invalid_content_type", "JSON required")
		return false
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16*1024))
	if err != nil {
		apiError(w, 413, "body_too_large", "Health configuration exceeds limit")
		return false
	}
	if transport.DecodeRegistrationJSON(data, out) != nil {
		apiError(w, 400, "invalid_request", "Health configuration contains invalid or duplicate fields")
		return false
	}
	return true
}

func (s *Server) healthCheckRoutes(w http.ResponseWriter, r *http.Request, current session) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/services/"), "/")
	if (len(parts) != 2 && len(parts) != 3) || parts[1] != "checks" || len(parts) == 3 && parts[2] != "manual" || r.URL.RawQuery != "" {
		apiError(w, 400, "invalid_path", "Invalid health check endpoint")
		return
	}
	id, err := domain.ParseID(parts[0])
	if err != nil {
		apiError(w, 400, "invalid_id", "Invalid service ID")
		return
	}
	if len(parts) == 2 && r.Method == http.MethodGet {
		v, err := s.executor.HealthChecks(r.Context(), id)
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
	if len(parts) == 3 {
		if current.User.Role == RoleViewer {
			s.deny(w, r, current.User.ID)
			return
		}
		var input transport.ManualHealthRequest
		if !decodeHealthBody(w, r, &input) {
			return
		}
		input.Actor = domain.ID(current.User.ID)
		if err := input.Validate(); err != nil {
			apiError(w, 400, "invalid_request", err.Error())
			return
		}
		if err := s.audit(r.Context(), current.User.ID, "health.manual", string(id), "requested", ""); err != nil {
			internalError(w)
			return
		}
		out, err := s.executor.ConfirmManualHealth(r.Context(), id, input)
		if err != nil {
			_ = s.audit(r.Context(), current.User.ID, "health.manual", string(id), "rejected", "")
			executorError(w, err)
			return
		}
		if err := s.audit(r.Context(), current.User.ID, "health.manual", string(id), "succeeded", ""); err != nil {
			apiError(w, 502, "audit_incomplete", "Confirmation may have been saved; refresh")
			return
		}
		writeJSON(w, 200, out)
		return
	}
	if current.User.Role != RoleAdmin {
		s.deny(w, r, current.User.ID)
		return
	}
	var input transport.HealthChecksRequest
	if !decodeHealthBody(w, r, &input) {
		return
	}
	input.Actor = domain.ID(current.User.ID)
	if err := input.Validate(); err != nil {
		apiError(w, 400, "invalid_request", err.Error())
		return
	}
	if err := s.audit(r.Context(), current.User.ID, "health.configure", string(id), "requested", ""); err != nil {
		internalError(w)
		return
	}
	out, err := s.executor.ConfigureHealthChecks(r.Context(), id, input)
	if err != nil {
		_ = s.audit(r.Context(), current.User.ID, "health.configure", string(id), "rejected", "")
		executorError(w, err)
		return
	}
	if err := s.audit(r.Context(), current.User.ID, "health.configure", string(id), "succeeded", ""); err != nil {
		apiError(w, 502, "audit_incomplete", "Health policy may have been saved; refresh")
		return
	}
	writeJSON(w, 200, out)
}
