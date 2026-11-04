package transport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

// The maximum UTF-8 file size leaves room for JSON escaping in MaxBodyBytes.
const MaxComposeDraftBytes = 128 * 1024

type ComposeDocument struct {
	Path     string        `json:"path"`
	Content  string        `json:"content"`
	Revision domain.Digest `json:"revision"`
}

type ComposeDraft struct {
	Content  string        `json:"content"`
	Revision domain.Digest `json:"revision"`
}

var ErrComposeEditorStale = errors.New("the active Compose revision changed; reopen the editor and review the latest file")

// ComposeEditorError carries a user-facing message without raw YAML, environment
// values or Docker command output.
type ComposeEditorError struct{ Message string }

func (e *ComposeEditorError) Error() string { return e.Message }

func (d ComposeDraft) validate() error {
	if strings.TrimSpace(d.Content) == "" || len(d.Content) > MaxComposeDraftBytes || !utf8.ValidString(d.Content) || strings.ContainsRune(d.Content, 0) {
		return errors.New("compose_draft content must be non-empty UTF-8 text of at most 128 KiB")
	}
	if err := d.Revision.Validate(); err != nil {
		return errors.New("compose_draft revision must be a valid digest")
	}
	return nil
}

func decodeComposeDraft(d *json.Decoder) (ComposeDraft, error) {
	var draft ComposeDraft
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return draft, errors.New("compose_draft must be a JSON object")
	}
	seen := map[string]bool{}
	for d.More() {
		field, err := d.Token()
		key, ok := field.(string)
		if err != nil || !ok || seen[key] || (key != "content" && key != "revision") {
			return draft, errors.New("invalid or duplicate compose_draft field")
		}
		seen[key] = true
		token, err := d.Token()
		value, ok := token.(string)
		if err != nil || !ok {
			return draft, errors.New("compose_draft fields must be strings")
		}
		if key == "content" {
			draft.Content = value
		} else {
			draft.Revision = domain.Digest(value)
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return draft, errors.New("malformed compose_draft")
	}
	return draft, nil
}

type ComposeDocumentBackend interface {
	ComposeDocument(context.Context, domain.ID) (ComposeDocument, error)
}

func (s *Server) composeDocumentEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	id, err := domain.ParseID(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/services/"), "/compose"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service ID")
		return
	}
	backend, ok := s.options.Backend.(ComposeDocumentBackend)
	if !ok {
		writeError(w, http.StatusNotImplemented, "not_implemented", "Compose editor unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	result, err := backend.ComposeDocument(r.Context(), id)
	if err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (c *Client) ComposeDocument(ctx context.Context, id domain.ID) (ComposeDocument, error) {
	var result ComposeDocument
	if err := id.Validate(); err != nil {
		return result, err
	}
	err := c.requestBounded(ctx, http.MethodGet, "/v1/services/"+string(id)+"/compose", nil, &result, MaxBodyBytes)
	return result, err
}
