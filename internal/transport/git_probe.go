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

type GitDirectoriesRequest struct {
	Source    GitSourceRequest `json:"source"`
	ServiceID domain.ID        `json:"service_id,omitempty"`
	Directory string           `json:"directory"`
}

func (v GitDirectoriesRequest) Validate() error {
	v.Source.Subdirectory = ""
	if err := (GitProbeRequest{Source: v.Source, ServiceID: v.ServiceID}).Validate(); err != nil {
		return err
	}
	return sourcegit.ValidateBrowseDirectory(v.Directory)
}

type GitDirectoryListing = sourcegit.DirectoryListing

type GitDirectoriesBackend interface {
	BrowseGitDirectories(context.Context, GitDirectoriesRequest) (GitDirectoryListing, error)
}

func (s *Server) gitProbeEndpoint(w http.ResponseWriter, r *http.Request) {
	var input GitProbeRequest
	if !decodeGitRequest(w, r, &input) {
		return
	}
	backend, ok := s.options.Backend.(GitProbeBackend)
	if !ok {
		writeError(w, 501, "not_implemented", "Git checks unavailable")
		return
	}
	result, err := backend.ProbeGitSource(r.Context(), input)
	writeGitResult(w, result, err)
}

func (s *Server) gitDirectoriesEndpoint(w http.ResponseWriter, r *http.Request) {
	var input GitDirectoriesRequest
	if !decodeGitRequest(w, r, &input) {
		return
	}
	backend, ok := s.options.Backend.(GitDirectoriesBackend)
	if !ok {
		writeError(w, 501, "not_implemented", "Git directory browsing unavailable")
		return
	}
	result, err := backend.BrowseGitDirectories(r.Context(), input)
	writeGitResult(w, result, err)
}

func decodeGitRequest(w http.ResponseWriter, r *http.Request, input interface{ Validate() error }) bool {
	if r.URL.RawQuery != "" {
		writeError(w, 400, "invalid_query", "Git check does not accept query parameters")
		return false
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return false
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		writeError(w, 415, "invalid_content_type", "JSON required")
		return false
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16*1024))
	if err != nil {
		writeError(w, 413, "body_too_large", "Git check request exceeds limit")
		return false
	}
	if err := DecodeRegistrationJSON(data, input); err != nil {
		writeError(w, 400, "invalid_request", "Invalid Git check request")
		return false
	}
	if err := input.Validate(); err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return false
	}
	return true
}

func writeGitResult(w http.ResponseWriter, result any, err error) {
	if err != nil {
		var probe *sourcegit.ProbeError
		if errors.As(err, &probe) {
			status := http.StatusBadGateway
			switch probe.Code {
			case "git_timeout":
				status = http.StatusGatewayTimeout
			case "git_directory_missing":
				status = http.StatusNotFound
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
	err := c.gitRequest(ctx, "/v1/git/probe", input, &result)
	return result, err
}

func (c *Client) BrowseGitDirectories(ctx context.Context, input GitDirectoriesRequest) (GitDirectoryListing, error) {
	var result GitDirectoryListing
	err := c.gitRequest(ctx, "/v1/git/directories", input, &result)
	return result, err
}

func (c *Client) gitRequest(ctx context.Context, path string, input interface{ Validate() error }, result any) error {
	if err := input.Validate(); err != nil {
		return err
	}
	// Remote Git requests have their own budget and keep the fixed Unix
	// dialer, nil proxy, and redirect policy.
	transport := c.transport.Clone()
	transport.ResponseHeaderTimeout = 25 * time.Second
	defer transport.CloseIdleConnections()
	client := *c.http
	client.Transport = transport
	client.Timeout = 28 * time.Second
	remote := &Client{http: &client, transport: transport}
	return remote.requestLimits(ctx, http.MethodPost, path, input, result, 16*1024, 256*1024)
}
