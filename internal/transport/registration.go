package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"reflect"
	"strings"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/policy"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
)

type RegistrationOptions struct {
	DiscoveryRoots []string `json:"discovery_roots"`
	WorkspaceRoots []string `json:"workspace_roots"`
}
type RegistrationBrowseRequest struct {
	Directory string `json:"directory"`
}
type RegistrationDirectoryEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
}
type RegistrationDirectoryListing struct {
	Directory    string                       `json:"directory"`
	Parent       string                       `json:"parent,omitempty"`
	Directories  []RegistrationDirectoryEntry `json:"directories"`
	ComposeFiles []string                     `json:"compose_files"`
	Truncated    bool                         `json:"truncated"`
}
type RegistrationInspectRequest struct {
	ProjectDirectory string `json:"project_directory"`
}
type RegistrationInspection struct {
	Service  domain.Service `json:"service"`
	Warnings []string       `json:"warnings"`
}
type RegistrationManagedPathsRequest struct {
	ServiceID    domain.ID `json:"service_id"`
	CodeBindings []string  `json:"code_bindings"`
}
type RegistrationManagedPathsResult struct {
	ManagedPaths []domain.ManagedPath `json:"managed_paths"`
}

// RegistrationManagedPathsBackend is optional so older registration adapters
// keep their existing routes while code-bind classification remains opt-in.
type RegistrationManagedPathsBackend interface {
	ResolveRegistrationManagedPaths(context.Context, RegistrationManagedPathsRequest) (RegistrationManagedPathsResult, error)
}

func ValidateRegistrationManagedPathsRequest(input RegistrationManagedPathsRequest) error {
	if input.ServiceID.Validate() != nil || len(input.CodeBindings) > 128 {
		return errors.New("valid draft service and at most 128 code bindings are required")
	}
	seen := map[string]bool{}
	for _, name := range input.CodeBindings {
		if domain.ValidateComponent(name) != nil || seen[name] {
			return errors.New("code bindings must be unique discovered storage names")
		}
		seen[name] = true
	}
	return nil
}

type RegistrationProposalRequest struct {
	Service   domain.Service `json:"service"`
	Initiator domain.ID      `json:"initiator,omitempty"`
}
type RegistrationApproveRequest struct {
	ProposalID domain.ID     `json:"proposal_id"`
	Digest     domain.Digest `json:"digest"`
	Initiator  domain.ID     `json:"initiator,omitempty"`
}
type RegistrationApproval struct {
	Service             domain.Service    `json:"service"`
	Initialized         bool              `json:"initialized"`
	InitializationError string            `json:"initialization_error,omitempty"`
	Operation           *domain.Operation `json:"operation,omitempty"`
}
type RegistrationBackend interface {
	RegistrationOptions(context.Context) (RegistrationOptions, error)
	BrowseRegistrationDirectories(context.Context, RegistrationBrowseRequest) (RegistrationDirectoryListing, error)
	InspectRegistration(context.Context, RegistrationInspectRequest) (RegistrationInspection, error)
	ProposeRegistration(context.Context, RegistrationProposalRequest) (store.Proposal, error)
	ApproveRegistration(context.Context, RegistrationApproveRequest) (RegistrationApproval, error)
}

// RegistrationInputError contains only safe, user-actionable diagnostics.
type RegistrationInputError struct{ Message string }

func (e *RegistrationInputError) Error() string { return e.Message }

func (s *Server) registrationEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, 400, "invalid_query", "registration does not accept query parameters")
		return
	}
	b, ok := s.options.Backend.(RegistrationBackend)
	if !ok {
		writeError(w, 501, "not_implemented", "registration unavailable")
		return
	}
	if r.URL.Path == "/v1/registration/options" {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		v, err := b.RegistrationOptions(r.Context())
		if err != nil {
			registrationError(w, err)
			return
		}
		writeJSON(w, 200, v)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/v1/registration/") {
		writeError(w, 404, "not_found", "unknown registration endpoint")
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	var v any
	var err error
	switch r.URL.Path {
	case "/v1/registration/directories":
		var input RegistrationBrowseRequest
		if !decodeRegistrationBody(w, r, &input) {
			return
		}
		v, err = b.BrowseRegistrationDirectories(r.Context(), input)
	case "/v1/registration/inspect":
		var input RegistrationInspectRequest
		if !decodeRegistrationBody(w, r, &input) {
			return
		}
		v, err = b.InspectRegistration(r.Context(), input)
	case "/v1/registration/managed-paths":
		var input RegistrationManagedPathsRequest
		if !decodeRegistrationBody(w, r, &input) {
			return
		}
		if ValidateRegistrationManagedPathsRequest(input) != nil {
			writeError(w, 400, "invalid_request", "valid draft service and unique discovered code bindings are required")
			return
		}
		resolver, available := s.options.Backend.(RegistrationManagedPathsBackend)
		if !available {
			writeError(w, 501, "not_implemented", "code-bind classification unavailable")
			return
		}
		v, err = resolver.ResolveRegistrationManagedPaths(r.Context(), input)
	case "/v1/registration/proposals":
		var input RegistrationProposalRequest
		if !decodeRegistrationBody(w, r, &input) {
			return
		}
		if input.Initiator.Validate() != nil {
			writeError(w, 400, "invalid_actor", "authenticated actor is required")
			return
		}
		v, err = b.ProposeRegistration(r.Context(), input)
	case "/v1/registration/approve":
		var input RegistrationApproveRequest
		if !decodeRegistrationBody(w, r, &input) {
			return
		}
		if input.Initiator.Validate() != nil || input.ProposalID.Validate() != nil || input.Digest.Validate() != nil {
			writeError(w, 400, "invalid_request", "valid proposal, digest and authenticated actor are required")
			return
		}
		v, err = b.ApproveRegistration(r.Context(), input)
	default:
		writeError(w, 404, "not_found", "unknown registration endpoint")
		return
	}
	if err != nil {
		registrationError(w, err)
		return
	}
	writeJSON(w, 200, v)
}
func decodeRegistrationBody(w http.ResponseWriter, r *http.Request, out any) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		writeError(w, 415, "invalid_content_type", "JSON required")
		return false
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err != nil {
		writeError(w, 413, "body_too_large", "registration request exceeds limit")
		return false
	}
	if err := DecodeRegistrationJSON(data, out); err != nil {
		writeError(w, 400, "invalid_request", "invalid registration object")
		return false
	}
	return true
}

// DecodeRegistrationJSON rejects duplicate keys recursively and requires exact
// JSON field names. encoding/json alone accepts both duplicates and case aliases.
func DecodeRegistrationJSON(data []byte, out any) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("JSON object required")
	}
	t := reflect.TypeOf(out)
	if t == nil || t.Kind() != reflect.Pointer {
		return errors.New("destination must be a pointer")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := registrationJSONValue(d, t.Elem()); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("exactly one JSON object required")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(out)
}
func registrationJSONValue(d *json.Decoder, t reflect.Type) error {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return nil
	}
	switch token {
	case json.Delim('{'):
		fields := map[string]reflect.Type{}
		if t != nil && t.Kind() == reflect.Struct {
			for i := 0; i < t.NumField(); i++ {
				field := t.Field(i)
				tag := strings.Split(field.Tag.Get("json"), ",")[0]
				if tag == "-" || field.PkgPath != "" {
					continue
				}
				if tag == "" {
					tag = field.Name
				}
				fields[tag] = field.Type
			}
		}
		seen := map[string]bool{}
		for d.More() {
			keyToken, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return errors.New("duplicate or invalid JSON key")
			}
			seen[key] = true
			var child reflect.Type
			if t != nil && t.Kind() == reflect.Struct {
				var exists bool
				child, exists = fields[key]
				if !exists {
					return fmt.Errorf("unknown JSON field %q", key)
				}
			} else if t != nil && t.Kind() == reflect.Map {
				child = t.Elem()
			}
			if err := registrationJSONValue(d, child); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case json.Delim('['):
		var child reflect.Type
		if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
			child = t.Elem()
		}
		for d.More() {
			if err := registrationJSONValue(d, child); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	case json.Delim('}'), json.Delim(']'):
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
func registrationError(w http.ResponseWriter, err error) {
	var input *RegistrationInputError
	var invalid *policy.RegistrationError
	switch {
	case errors.As(err, &input):
		writeError(w, 400, "invalid_registration", input.Message)
	case errors.As(err, &invalid):
		messages := []string{invalid.Error()}
		for i, issue := range invalid.Issues {
			if i == 8 {
				break
			}
			messages = append(messages, issue.Code+" "+issue.Path+": "+issue.Message)
		}
		writeJSON(w, 400, struct {
			Code    string         `json:"code"`
			Message string         `json:"message"`
			Issues  []policy.Issue `json:"issues"`
		}{"invalid_registration", strings.Join(messages, "; "), invalid.Issues})
	default:
		backendError(w, err)
	}
}
func (c *Client) RegistrationOptions(ctx context.Context) (RegistrationOptions, error) {
	var v RegistrationOptions
	err := c.request(ctx, "GET", "/v1/registration/options", nil, &v)
	return v, err
}
func (c *Client) BrowseRegistrationDirectories(ctx context.Context, input RegistrationBrowseRequest) (RegistrationDirectoryListing, error) {
	var v RegistrationDirectoryListing
	err := c.request(ctx, "POST", "/v1/registration/directories", input, &v)
	return v, err
}
func (c *Client) InspectRegistration(ctx context.Context, input RegistrationInspectRequest) (RegistrationInspection, error) {
	var v RegistrationInspection
	err := c.request(ctx, "POST", "/v1/registration/inspect", input, &v)
	return v, err
}
func (c *Client) ResolveRegistrationManagedPaths(ctx context.Context, input RegistrationManagedPathsRequest) (RegistrationManagedPathsResult, error) {
	var v RegistrationManagedPathsResult
	err := c.request(ctx, "POST", "/v1/registration/managed-paths", input, &v)
	return v, err
}
func (c *Client) ProposeRegistration(ctx context.Context, input RegistrationProposalRequest) (store.Proposal, error) {
	var v store.Proposal
	err := c.request(ctx, "POST", "/v1/registration/proposals", input, &v)
	return v, err
}
func (c *Client) ApproveRegistration(ctx context.Context, input RegistrationApproveRequest) (RegistrationApproval, error) {
	var v RegistrationApproval
	err := c.request(ctx, "POST", "/v1/registration/approve", input, &v)
	return v, err
}
