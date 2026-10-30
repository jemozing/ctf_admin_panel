package transport

import (
	"context"
	"fmt"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"net/http"
	"net/url"
	"strconv"
)

type DiagnosticsBackend interface {
	OperationDiagnostics(context.Context, domain.ID, uint64) (store.DiagnosticLog, error)
}

func ParseDiagnosticsCursor(raw string) (uint64, error) {
	v, err := url.ParseQuery(raw)
	if err != nil || len(v) > 1 {
		return 0, fmt.Errorf("only one after cursor is supported")
	}
	if len(v) == 0 {
		return 0, nil
	}
	if len(v["after"]) != 1 {
		return 0, fmt.Errorf("only one after cursor is supported")
	}
	after, err := strconv.ParseUint(v.Get("after"), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid after cursor")
	}
	return after, nil
}
func (s *Server) diagnosticsEndpoint(w http.ResponseWriter, r *http.Request, id domain.ID) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	after, err := ParseDiagnosticsCursor(r.URL.RawQuery)
	if err != nil {
		writeError(w, 400, "invalid_query", err.Error())
		return
	}
	b, ok := s.options.Backend.(DiagnosticsBackend)
	if !ok {
		writeError(w, 501, "not_implemented", "operation diagnostics unavailable")
		return
	}
	v, err := b.OperationDiagnostics(r.Context(), id, after)
	if err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, 200, v)
}
func (c *Client) OperationDiagnostics(ctx context.Context, id domain.ID, after uint64) (store.DiagnosticLog, error) {
	var v store.DiagnosticLog
	if err := id.Validate(); err != nil {
		return v, err
	}
	err := c.request(ctx, http.MethodGet, "/v1/operations/"+string(id)+"/diagnostics?after="+strconv.FormatUint(after, 10), nil, &v)
	return v, err
}
