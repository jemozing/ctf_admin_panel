package transport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/sourcegit"
)

type GitSourceRequest struct {
	URL              string `json:"url"`
	Ref              string `json:"ref"`
	Subdirectory     string `json:"subdirectory,omitempty"`
	Username         string `json:"username,omitempty"`
	Token            string `json:"token,omitempty"`
	ClearCredentials bool   `json:"clear_credentials,omitempty"`
}

func (v GitSourceRequest) Configuration() sourcegit.Config {
	ref := v.Ref
	if ref == "" {
		ref = "HEAD"
	}
	return sourcegit.Config{URL: v.URL, Ref: ref, Subdirectory: sourcegit.CleanSubdirectory(v.Subdirectory), Username: v.Username}
}
func (v GitSourceRequest) Validate() error {
	if err := v.Configuration().Validate(); err != nil {
		return err
	}
	if len(v.Token) > 4096 || strings.ContainsAny(v.Token, "\x00\r\n") {
		return errors.New("Git token exceeds limit or contains control characters")
	}
	for _, ch := range v.Token {
		if ch < 0x21 || ch > 0x7e {
			return errors.New("Git token must use printable ASCII")
		}
	}
	if v.ClearCredentials && v.Token != "" {
		return errors.New("cannot set and clear Git credentials together")
	}
	return nil
}

type GitFetchSummary struct {
	Commit     string    `json:"commit"`
	SnapshotID domain.ID `json:"snapshot_id"`
	At         time.Time `json:"at"`
}
type GitSourceView struct {
	Configured     bool             `json:"configured"`
	URL            string           `json:"url,omitempty"`
	Ref            string           `json:"ref,omitempty"`
	Subdirectory   string           `json:"subdirectory,omitempty"`
	Username       string           `json:"username,omitempty"`
	HasCredentials bool             `json:"has_credentials"`
	Revision       uint64           `json:"revision"`
	LastFetch      *GitFetchSummary `json:"last_fetch,omitempty"`
}
type GitSourceBackend interface {
	GitSource(context.Context, domain.ID) (GitSourceView, error)
	ConfigureGitSource(context.Context, domain.ID, GitSourceRequest) (GitSourceView, error)
}

func (s *Server) gitSourceRoutes(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/services/"), "/")
	if len(parts) != 2 || parts[1] != "source" || r.URL.RawQuery != "" {
		writeError(w, 400, "invalid_path", "invalid source endpoint")
		return
	}
	id, err := domain.ParseID(parts[0])
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service ID")
		return
	}
	backend, ok := s.options.Backend.(GitSourceBackend)
	if !ok {
		writeError(w, 501, "not_implemented", "Git sources unavailable")
		return
	}
	var result GitSourceView
	switch r.Method {
	case http.MethodGet:
		result, err = backend.GitSource(r.Context(), id)
	case http.MethodPost:
		media, _, parseErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if parseErr != nil || media != "application/json" {
			writeError(w, 415, "invalid_content_type", "JSON required")
			return
		}
		var input GitSourceRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
		decoder.DisallowUnknownFields()
		if decodeErr := decoder.Decode(&input); decodeErr != nil {
			writeError(w, 400, "invalid_request", "invalid source configuration")
			return
		}
		if decoder.Decode(new(any)) != io.EOF {
			writeError(w, 400, "invalid_request", "one JSON object required")
			return
		}
		if err := input.Validate(); err != nil {
			writeError(w, 400, "invalid_request", err.Error())
			return
		}
		result, err = backend.ConfigureGitSource(r.Context(), id, input)
	default:
		methodNotAllowed(w, "GET, POST")
		return
	}
	if err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (c *Client) GitSource(ctx context.Context, id domain.ID) (GitSourceView, error) {
	var out GitSourceView
	if err := id.Validate(); err != nil {
		return out, err
	}
	err := c.request(ctx, http.MethodGet, "/v1/services/"+string(id)+"/source", nil, &out)
	return out, err
}
func (c *Client) ConfigureGitSource(ctx context.Context, id domain.ID, input GitSourceRequest) (GitSourceView, error) {
	var out GitSourceView
	if err := id.Validate(); err != nil {
		return out, err
	}
	if err := input.Validate(); err != nil {
		return out, err
	}
	err := c.request(ctx, http.MethodPost, "/v1/services/"+string(id)+"/source", input, &out)
	return out, err
}
