package dashboard

import (
	"net/http"
	"strings"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func (s *Server) serviceRoutes(w http.ResponseWriter, r *http.Request, current session) {
	if strings.Contains(r.URL.Path, "/checks") {
		s.healthCheckRoutes(w, r, current)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/runtime-events") {
		s.runtimeEvents(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/source") {
		s.gitSourceRoutes(w, r, current)
		return
	}
	if !method(w, r, "GET") {
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/services/"), "/")
	id, err := domain.ParseID(parts[0])
	if err != nil {
		apiError(w, 400, "invalid_id", "Invalid service ID")
		return
	}
	if len(parts) == 1 {
		if r.URL.RawQuery != "" {
			apiError(w, 400, "invalid_query", "No query is supported")
			return
		}
		v, err := s.executor.ServiceDetails(r.Context(), id)
		if err != nil {
			executorError(w, err)
			return
		}
		writeJSON(w, 200, v)
		return
	}
	if len(parts) == 2 && parts[1] == "metrics" {
		component, valid := transport.MetricsComponentQuery(r.URL.RawQuery)
		if !valid {
			apiError(w, 400, "invalid_query", "Only one component selector is supported")
			return
		}
		v, err := s.executor.MetricsComponent(r.Context(), id, component)
		if err != nil {
			executorError(w, err)
			return
		}
		writeJSON(w, 200, v)
		return
	}
	if len(parts) == 2 && parts[1] == "log-records" {
		s.logRecords(w, r, current, id)
		return
	}
	if len(parts) == 2 && parts[1] == "files" {
		s.files(w, r, current, id)
		return
	}
	if len(parts) == 4 && parts[1] == "releases" && parts[3] == "evidence" {
		s.releaseEvidence(w, r, current, id, parts[2])
		return
	}
	if len(parts) == 2 && parts[1] == "logs" {
		if !current.User.SensitiveAccess {
			s.deny(w, r, current.User.ID)
			return
		}
		query := r.URL.Query()
		if len(query) > 2 || len(query["component"]) != 1 || len(query["tail"]) > 1 {
			apiError(w, 400, "invalid_query", "component is required; only component and tail are supported")
			return
		}
		for key := range query {
			if key != "component" && key != "tail" {
				apiError(w, 400, "invalid_query", "Unknown log option")
				return
			}
		}
		tail, err := parseTail(query.Get("tail"))
		if err != nil {
			apiError(w, 400, "invalid_query", err.Error())
			return
		}
		v, err := s.executor.Logs(r.Context(), id, query.Get("component"), tail)
		if err != nil {
			executorError(w, err)
			return
		}
		writeJSON(w, 200, v)
		return
	}
	apiError(w, 404, "not_found", "Unknown service endpoint")
}

func (s *Server) operationRoutes(w http.ResponseWriter, r *http.Request, current session) {
	if strings.HasSuffix(r.URL.Path, "/diagnostics") {
		id, err := domain.ParseID(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/operations/"), "/diagnostics"))
		if err != nil {
			apiError(w, 400, "invalid_id", "Invalid operation ID")
			return
		}
		s.diagnostics(w, r, current, id)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/cancel") {
		s.cancelOperation(w, r, current)
		return
	}
	if !method(w, r, "GET") {
		return
	}
	if r.URL.RawQuery != "" {
		apiError(w, 400, "invalid_query", "No query is supported")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/operations/"), "/")
	id, err := domain.ParseID(parts[0])
	if err != nil {
		apiError(w, 400, "invalid_id", "Invalid operation ID")
		return
	}
	if len(parts) == 1 {
		v, err := s.executor.GetOperation(r.Context(), id)
		if err != nil {
			executorError(w, err)
			return
		}
		writeJSON(w, 200, v)
		return
	}
	if len(parts) == 2 && parts[1] == "events" {
		if !current.User.SensitiveAccess {
			s.deny(w, r, current.User.ID)
			return
		}
		v, err := s.executor.OperationEvents(r.Context(), id)
		if err != nil {
			executorError(w, err)
			return
		}
		writeJSON(w, 200, v)
		return
	}
	apiError(w, 404, "not_found", "Unknown operation endpoint")
}

func (s *Server) preview(w http.ResponseWriter, r *http.Request, current session) {
	if !method(w, r, "POST") {
		return
	}
	if current.User.Role == RoleViewer {
		s.deny(w, r, current.User.ID)
		return
	}
	var input transport.SubmitRequest
	if !decodeBody(w, r, &input) {
		return
	}
	input.Initiator = domain.ID(current.User.ID)
	if input.AcceptFileDrift && !current.User.SensitiveAccess {
		s.deny(w, r, current.User.ID)
		return
	}
	if err := input.Validate(); err != nil {
		apiError(w, 400, "invalid_request", err.Error())
		return
	}
	v, err := s.executor.Preview(r.Context(), input)
	if err != nil {
		executorError(w, err)
		return
	}
	if !current.User.SensitiveAccess {
		v.ChangedFiles = nil
		v.DriftChangedFiles = nil
	}
	writeJSON(w, 200, v)
}
