package dashboard

import (
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

// Registration expands executor policy only for authenticated Admins, inside
// roots approved at installation. All POST routes share the global CSRF gate.
func (s *Server) registrationRoutes(w http.ResponseWriter, r *http.Request, current session) {
	if current.User.Role != RoleAdmin {
		s.deny(w, r, current.User.ID)
		return
	}
	if r.URL.RawQuery != "" {
		apiError(w, 400, "invalid_query", "Registration does not accept query parameters")
		return
	}
	if r.URL.Path == "/api/registration/options" {
		if !method(w, r, "GET") {
			return
		}
		v, err := s.executor.RegistrationOptions(r.Context())
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
	switch r.URL.Path {
	case "/api/registration/directories":
		var input transport.RegistrationBrowseRequest
		if !decodeRegistrationInput(w, r, &input) {
			return
		}
		v, err := s.executor.BrowseRegistrationDirectories(r.Context(), input)
		if err != nil {
			executorError(w, err)
			return
		}
		writeJSON(w, 200, v)
	case "/api/registration/inspect":
		var input transport.RegistrationInspectRequest
		if !decodeRegistrationInput(w, r, &input) {
			return
		}
		v, err := s.executor.InspectRegistration(r.Context(), input)
		if err != nil {
			executorError(w, err)
			return
		}
		writeJSON(w, 200, v)
	case "/api/registration/proposals":
		// Initiator is deliberately absent from the browser DTO.
		var input struct {
			Service domain.Service `json:"service"`
		}
		if !decodeRegistrationInput(w, r, &input) {
			return
		}
		if err := s.audit(r.Context(), current.User.ID, "registration_propose", string(input.Service.ID), "requested", ""); err != nil {
			internalError(w)
			return
		}
		v, err := s.executor.ProposeRegistration(r.Context(), transport.RegistrationProposalRequest{Service: input.Service, Initiator: domain.ID(current.User.ID)})
		if err != nil {
			_ = s.audit(r.Context(), current.User.ID, "registration_propose", string(input.Service.ID), "rejected", "")
			executorError(w, err)
			return
		}
		writeJSON(w, 200, v)
	case "/api/registration/approve":
		var input struct {
			ProposalID domain.ID     `json:"proposal_id"`
			Digest     domain.Digest `json:"digest"`
		}
		if !decodeRegistrationInput(w, r, &input) {
			return
		}
		if err := s.audit(r.Context(), current.User.ID, "registration_approve", string(input.ProposalID), "requested", ""); err != nil {
			internalError(w)
			return
		}
		v, err := s.executor.ApproveRegistration(r.Context(), transport.RegistrationApproveRequest{ProposalID: input.ProposalID, Digest: input.Digest, Initiator: domain.ID(current.User.ID)})
		if err != nil {
			_ = s.audit(r.Context(), current.User.ID, "registration_approve", string(input.ProposalID), "rejected", "")
			executorError(w, err)
			return
		}
		if err := s.audit(r.Context(), current.User.ID, "registration_approve", string(v.Service.ID), "succeeded", ""); err != nil {
			internalError(w)
			return
		}
		writeJSON(w, 200, v)
	default:
		apiError(w, 404, "not_found", "Unknown registration endpoint")
	}
}

func decodeRegistrationInput(w http.ResponseWriter, r *http.Request, out any) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		apiError(w, 415, "invalid_content_type", "Content-Type must be application/json")
		return false
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, transport.MaxBodyBytes))
	if err != nil {
		apiError(w, 413, "body_too_large", "Registration request exceeds limit")
		return false
	}
	if err := transport.DecodeRegistrationJSON(data, out); err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			apiError(w, 413, "body_too_large", "Registration request exceeds limit")
		} else {
			apiError(w, 400, "invalid_request", "Registration contains invalid fields")
		}
		return false
	}
	return true
}
