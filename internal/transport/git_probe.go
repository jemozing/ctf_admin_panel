package transport

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/sourcegit"
)

type GitProbeRequest struct {
	Source    GitSourceRequest `json:"source"`
	ServiceID domain.ID        `json:"service_id,omitempty"`
}

func (v GitProbeRequest) Validate() error {
	if v.ServiceID != "" {
		if err := v.ServiceID.Validate(); err != nil {
			return err
		}
	}
	return v.Source.Validate()
}

type GitProbeResult = sourcegit.ProbeResult

type GitProbeBackend interface {
	ProbeGitSource(context.Context, GitProbeRequest) (GitProbeResult, error)
}

func (s *Server) gitProbeEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, 400, "invalid_query", "Git check does not accept query parameters")
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		writeError(w, 415, "invalid_content_type", "JSON required")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16*1024))
	if err != nil {
		writeError(w, 413, "body_too_large", "Git check request exceeds limit")
		return
	}
	var input GitProbeRequest
	if err := DecodeRegistrationJSON(data, &input); err != nil {
		writeError(w, 400, "invalid_request", "Invalid Git check request")
		return
	}
	if err := input.Validate(); err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	backend, ok := s.options.Backend.(GitProbeBackend)
	if !ok {
		writeError(w, 501, "not_implemented", "Git checks unavailable")
		return
	}
	result, err := backend.ProbeGitSource(r.Context(), input)
	if err != nil {
		var probe *sourcegit.ProbeError
		if errors.As(err, &probe) {
			status := http.StatusBadGateway
			if probe.Code == "git_timeout" {
				status = http.StatusGatewayTimeout
			}
			writeError(w, status, probe.Code, probe.Message)
		} else {
			backendError(w, err)
		}
		return
	}
	writeJSON(w, 200, result)
}

func (c *Client) ProbeGitSource(ctx context.Context, input GitProbeRequest) (GitProbeResult, error) {
	var result GitProbeResult
	if err := input.Validate(); err != nil {
		return result, err
	}
	// The remote check alone gets a longer budget. Keep the fixed Unix dialer,
	// nil proxy and redirect policy; leave ordinary RPC timeouts unchanged.
	transport := c.transport.Clone()
	transport.ResponseHeaderTimeout = 25 * time.Second
	defer transport.CloseIdleConnections()
	client := *c.http
	client.Transport = transport
	client.Timeout = 28 * time.Second
	probe := &Client{http: &client, transport: transport}
	err := probe.requestLimits(ctx, http.MethodPost, "/v1/git/probe", input, &result, 16*1024, 256*1024)
	return result, err
}
