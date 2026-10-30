package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/coder/websocket"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

// stream is a read-only, bounded WebSocket. Authorization is rechecked before
// every message, so role changes/revocation also terminate existing connections.
func (s *Server) stream(w http.ResponseWriter, r *http.Request, current session, token string) {
	if !method(w, r, "GET") {
		return
	}
	if !s.validOrigin(r, r.Header.Get("Origin")) {
		apiError(w, 403, "invalid_origin", "Same-origin Origin is required")
		return
	}
	query, queryErr := url.ParseQuery(r.URL.RawQuery)
	if queryErr != nil {
		apiError(w, 400, "invalid_query", "Malformed stream query")
		return
	}
	recordMode := query.Get("format") == "records"
	var logQuery transport.LogQuery
	if recordMode {
		if len(query["format"]) != 1 {
			apiError(w, 400, "invalid_query", "Duplicate stream format")
			return
		}
		options := r.URL.Query()
		options.Del("service_id")
		options.Del("format")
		var err error
		logQuery, err = transport.ParseLogQuery(options.Encode())
		if err != nil {
			apiError(w, 400, "invalid_query", err.Error())
			return
		}
	}
	for key := range query {
		if key != "service_id" && key != "component" && !(recordMode && (key == "format" || key == "tail" || key == "since" || key == "until" || key == "search" || key == "include" || key == "exclude")) {
			apiError(w, 400, "invalid_query", "Unknown stream option")
			return
		}
	}
	if len(query["service_id"]) > 1 || len(query["component"]) > 1 {
		apiError(w, 400, "invalid_query", "Duplicate stream option")
		return
	}
	var serviceID domain.ID
	component := query.Get("component")
	if recordMode {
		component = logQuery.Component
	}
	if raw := query.Get("service_id"); raw != "" {
		var err error
		serviceID, err = domain.ParseID(raw)
		if err != nil {
			apiError(w, 400, "invalid_id", "Invalid service ID")
			return
		}
	}
	if component != "" && (serviceID == "" || !current.User.SensitiveAccess) {
		s.deny(w, r, current.User.ID)
		return
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer conn.CloseNow()
	parent, cancel := context.WithCancel(r.Context())
	defer cancel()
	stop := context.AfterFunc(s.stopCtx, cancel)
	defer stop()
	ctx := conn.CloseRead(parent)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		fresh, err := s.getSession(ctx, token)
		if err != nil || fresh.User.Role != current.User.Role || fresh.User.SensitiveAccess != current.User.SensitiveAccess {
			_ = conn.Close(websocket.StatusPolicyViolation, "Session was revoked")
			return
		}
		payload := map[string]any{"at": time.Now().UTC()}
		operations, err := s.executor.ListOperations(ctx)
		if err != nil {
			payload["executor"] = "unavailable"
		} else {
			if operations == nil {
				operations = []domain.Operation{}
			}
			payload["operations"] = operations
			payload["executor"] = "ok"
		}
		if recordMode {
			logs, err := s.executor.LogRecords(ctx, serviceID, logQuery)
			if err != nil {
				payload["logs_error"] = "Structured logs are unavailable"
			} else {
				payload["log_records"] = logs
			}
		} else if component != "" {
			logs, err := s.executor.Logs(ctx, serviceID, component, 200)
			if err != nil {
				payload["logs_error"] = "Logs are unavailable"
			} else {
				payload["logs"] = logs
			}
		}
		// A revocation during the executor round trip must not leak the result.
		fresh, err = s.getSession(ctx, token)
		if err != nil || fresh.User.Role != current.User.Role || fresh.User.SensitiveAccess != current.User.SensitiveAccess {
			return
		}
		data, err := json.Marshal(payload)
		if err != nil {
			return
		}
		if len(data) > 1024*1024 {
			data = []byte(`{"truncated":true,"message":"Stream payload exceeds 1 MiB; use the paged HTTP view"}`)
		}
		writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = conn.Write(writeCtx, websocket.MessageText, data)
		cancel()
		if err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
