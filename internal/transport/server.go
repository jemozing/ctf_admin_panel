// Package transport provides the local typed executor protocol over a Unix socket.
package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
)

const MaxBodyBytes = 1024 * 1024

type Principal struct {
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
	PID int32  `json:"pid,omitempty"`
}

type Backend interface {
	ListServices(context.Context) ([]domain.Service, error)
	ListOperations(context.Context) ([]domain.Operation, error)
	GetOperation(context.Context, domain.ID) (domain.Operation, error)
}

type SubmitRequest struct {
	ServiceID                domain.ID            `json:"service_id"`
	Action                   domain.OperationKind `json:"action"`
	ReleaseID                domain.ID            `json:"release_id,omitempty"`
	IdempotencyKey           string               `json:"idempotency_key"`
	Initiator                domain.ID            `json:"initiator,omitempty"`
	CandidateID              domain.ID            `json:"candidate_id,omitempty"`
	SnapshotID               domain.ID            `json:"snapshot_id,omitempty"`
	PlanDigest               domain.Digest        `json:"plan_digest,omitempty"`
	ConfirmDataCompatibility bool                 `json:"confirm_data_compatibility,omitempty"`
	AcceptFileDrift          bool                 `json:"accept_file_drift,omitempty"`
	ComposeFromGit           bool                 `json:"compose_from_git,omitempty"`
	ComposeDraft             *ComposeDraft        `json:"compose_draft,omitempty"`
	ConfirmComposeChange     bool                 `json:"confirm_compose_change,omitempty"`
	RecoveryOperationID      domain.ID            `json:"recovery_operation_id,omitempty"`
}

func (r SubmitRequest) Validate() error {
	if err := r.ServiceID.Validate(); err != nil {
		return err
	}
	if r.ReleaseID != "" {
		if err := r.ReleaseID.Validate(); err != nil {
			return err
		}
	}
	for _, id := range []domain.ID{r.Initiator, r.CandidateID, r.RecoveryOperationID, r.SnapshotID} {
		if id != "" {
			if err := id.Validate(); err != nil {
				return err
			}
		}
	}
	if r.PlanDigest != "" {
		if err := r.PlanDigest.Validate(); err != nil {
			return err
		}
	}
	switch r.Action {
	case domain.OperationStart, domain.OperationStop, domain.OperationRestart, domain.OperationPrepare, domain.OperationPrepareCompose, domain.OperationFetchSource, domain.OperationBuild, domain.OperationDeploy, domain.OperationSnapshot, domain.OperationRestoreSnapshot, domain.OperationRollback, domain.OperationRecover:
	default:
		return fmt.Errorf("unsupported operation action")
	}
	if (r.Action == domain.OperationDeploy || r.Action == domain.OperationRollback) && r.ReleaseID == "" {
		return fmt.Errorf("release_id is required for deploy and rollback")
	}
	if r.Action == domain.OperationRecover && r.RecoveryOperationID == "" {
		return errors.New("recovery_operation_id is required")
	}
	if r.Action == domain.OperationRestoreSnapshot && r.SnapshotID == "" {
		return errors.New("snapshot_id is required")
	}
	if r.Action != domain.OperationRestoreSnapshot && r.SnapshotID != "" {
		return errors.New("snapshot_id is only supported for restore_snapshot")
	}
	if r.AcceptFileDrift && r.Action != domain.OperationDeploy && r.Action != domain.OperationRollback {
		return errors.New("accept_file_drift is only supported for deploy and rollback")
	}
	if r.ComposeFromGit && r.Action != domain.OperationPrepareCompose {
		return errors.New("compose_from_git is only supported for prepare_compose")
	}
	if r.ComposeDraft != nil {
		if r.Action != domain.OperationPrepareCompose || r.ComposeFromGit {
			return errors.New("compose_draft is only supported for prepare_compose without compose_from_git")
		}
		if err := r.ComposeDraft.validate(); err != nil {
			return err
		}
	}
	if r.ConfirmComposeChange && r.Action != domain.OperationDeploy && r.Action != domain.OperationRollback {
		return errors.New("confirm_compose_change is only supported for deploy and rollback")
	}
	if len(r.IdempotencyKey) == 0 || len(r.IdempotencyKey) > 128 || strings.TrimSpace(r.IdempotencyKey) != r.IdempotencyKey {
		return fmt.Errorf("idempotency_key must contain 1..128 bytes without surrounding whitespace")
	}
	for _, c := range []byte(r.IdempotencyKey) {
		if c < 0x21 || c > 0x7e {
			return fmt.Errorf("idempotency_key must use printable ASCII without whitespace")
		}
	}
	return nil
}

type SubmitFunc func(context.Context, Principal, SubmitRequest) (domain.Operation, error)

type Options struct {
	SocketPath         string
	AllowedUIDs        []uint32
	Backend            Backend
	Submit             SubmitFunc
	Development        bool
	RecoverStaleSocket bool
}

type Server struct {
	options    Options
	listener   *net.UnixListener
	http       *http.Server
	socketInfo os.FileInfo
	closeOnce  sync.Once
	closeErr   error
	lock       *os.File
}

type principalKey struct{}

// NewServer safely binds a new socket. With RecoverStaleSocket enabled, an
// executor-owned socket is reclaimed only under an exclusive file lock after
// ECONNREFUSED proves it stale. Active, foreign-owned and replaced paths survive.
func NewServer(options Options) (*Server, error) {
	if runtime.GOOS != "linux" && !options.Development {
		return nil, fmt.Errorf("production executor transport requires Linux; development must be explicitly enabled")
	}
	if !filepath.IsAbs(options.SocketPath) || filepath.Clean(options.SocketPath) != options.SocketPath {
		return nil, fmt.Errorf("socket path must be canonical and absolute")
	}
	if len(options.AllowedUIDs) == 0 || options.Backend == nil {
		return nil, fmt.Errorf("explicit allowed peer UIDs and backend are required")
	}
	parent := filepath.Dir(options.SocketPath)
	if err := os.MkdirAll(parent, 0750); err != nil {
		return nil, err
	}
	info, err := os.Lstat(parent)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("socket directory must not be a symlink or writable by group/others")
	}
	var lock *os.File
	if options.RecoverStaleSocket {
		var err error
		lock, err = lockAndRecover(options.SocketPath)
		if err != nil {
			return nil, err
		}
	}
	locked := false
	defer func() {
		if !locked && lock != nil {
			releaseSocketLock(lock)
		}
	}()
	if _, err := os.Lstat(options.SocketPath); err == nil {
		return nil, fmt.Errorf("socket path already exists; refusing to unlink it")
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: options.SocketPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(false)
	s := &Server{options: options, listener: listener, lock: lock}
	if err := os.Chmod(options.SocketPath, 0660); err != nil {
		listener.Close()
		os.Remove(options.SocketPath)
		return nil, err
	}
	s.socketInfo, err = os.Lstat(options.SocketPath)
	if err != nil {
		listener.Close()
		return nil, err
	}
	s.options.AllowedUIDs = append([]uint32{}, options.AllowedUIDs...)
	s.http = &http.Server{Handler: http.HandlerFunc(s.handle), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024, ConnContext: func(ctx context.Context, connection net.Conn) context.Context {
		unixConnection, ok := connection.(*net.UnixConn)
		if !ok {
			return ctx
		}
		raw, err := unixConnection.SyscallConn()
		if err != nil {
			return ctx
		}
		var p Principal
		var credentialErr error
		if err := raw.Control(func(fd uintptr) { p, credentialErr = readPeer(int(fd)) }); err != nil || credentialErr != nil {
			return ctx
		}
		return context.WithValue(ctx, principalKey{}, p)
	}}
	locked = true
	return s, nil
}

func (s *Server) Serve(ctx context.Context) error {
	finished := make(chan struct{})
	shutdownFinished := make(chan struct{})
	go func() {
		defer close(shutdownFinished)
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.http.Shutdown(shutdownCtx)
		case <-finished:
		}
	}()
	err := s.http.Serve(s.listener)
	close(finished)
	<-shutdownFinished
	_ = s.Close()
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		_ = s.http.Close()
		err := s.listener.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			s.closeErr = err
		}
		if current, err := os.Lstat(s.options.SocketPath); err == nil && os.SameFile(s.socketInfo, current) {
			if err := os.Remove(s.options.SocketPath); err != nil {
				s.closeErr = err
			}
		}
		if s.lock != nil {
			releaseSocketLock(s.lock)
		}
	})
	return s.closeErr
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	principal, ok := r.Context().Value(principalKey{}).(Principal)
	allowed := false
	if ok {
		for _, uid := range s.options.AllowedUIDs {
			allowed = allowed || uid == principal.UID
		}
	}
	if !allowed {
		writeError(w, http.StatusForbidden, "peer_not_allowed", "executor peer UID is not allowed")
		return
	}
	if r.Host != "executor" && r.Host != "localhost" || r.Header.Get("Origin") != "" {
		writeError(w, http.StatusForbidden, "invalid_origin", "unexpected Host or Origin")
		return
	}
	metricsPath := strings.HasPrefix(r.URL.Path, "/v1/services/") && strings.HasSuffix(r.URL.Path, "/metrics")
	if (r.URL.RawQuery != "" && !strings.HasSuffix(r.URL.Path, "/logs") && !strings.HasSuffix(r.URL.Path, "/diagnostics") && !strings.HasSuffix(r.URL.Path, "/log-records") && !strings.HasSuffix(r.URL.Path, "/files") && !metricsPath && r.URL.Path != "/v1/traffic" && r.URL.Path != "/v1/packets" && r.URL.Path != "/v1/flows") || r.URL.RawPath != "" {
		writeError(w, http.StatusBadRequest, "invalid_path", "query parameters and encoded paths are not supported")
		return
	}
	if r.Method == http.MethodGet && (r.ContentLength > 0 || len(r.TransferEncoding) > 0) {
		writeError(w, http.StatusBadRequest, "unexpected_body", "GET request must not have a body")
		return
	}
	switch {
	case r.URL.Path == "/v1/flows" || strings.HasPrefix(r.URL.Path, "/v1/flows/") || r.URL.Path == "/v1/descriptors" || strings.HasPrefix(r.URL.Path, "/v1/descriptors/") || r.URL.Path == "/v1/exchange/decode":
		s.analysisEndpoint(w, r)
		return
	case r.URL.Path == "/v1/packets" || strings.HasPrefix(r.URL.Path, "/v1/packets/") || strings.HasPrefix(r.URL.Path, "/v1/capture/"):
		s.packetEndpoint(w, r)
		return
	case strings.HasPrefix(r.URL.Path, "/v1/proxy/") || r.URL.Path == "/v1/traffic" || strings.HasPrefix(r.URL.Path, "/v1/traffic/"):
		s.proxyControlEndpoint(w, r)
		return
	case strings.HasPrefix(r.URL.Path, "/v1/operations/") && strings.HasSuffix(r.URL.Path, "/diagnostics"):
		id, err := domain.ParseID(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/operations/"), "/diagnostics"))
		if err != nil {
			writeError(w, 400, "invalid_id", "invalid operation ID")
			return
		}
		s.diagnosticsEndpoint(w, r, id)
		return
	case strings.HasPrefix(r.URL.Path, "/v1/services/") && strings.Count(r.URL.Path, "/") == 4 && strings.HasSuffix(r.URL.Path, "/compose"):
		s.composeDocumentEndpoint(w, r)
		return
	case strings.HasPrefix(r.URL.Path, "/v1/services/") && strings.Contains(r.URL.Path, "/checks"):
		s.healthCheckRoutes(w, r)
		return
	case strings.HasPrefix(r.URL.Path, "/v1/services/") && strings.HasSuffix(r.URL.Path, "/runtime-events"):
		s.runtimeEventsEndpoint(w, r)
		return
	case strings.HasPrefix(r.URL.Path, "/v1/operations/") && strings.HasSuffix(r.URL.Path, "/cancel"):
		s.cancelEndpoint(w, r)
		return
	case r.URL.Path == "/v1/git/probe":
		s.gitProbeEndpoint(w, r)
		return
	case r.URL.Path == "/v1/git/directories":
		s.gitDirectoriesEndpoint(w, r)
		return
	case strings.HasPrefix(r.URL.Path, "/v1/registration/"):
		s.registrationEndpoint(w, r)
		return
	case strings.HasPrefix(r.URL.Path, "/v1/services/") && strings.HasSuffix(r.URL.Path, "/source"):
		s.gitSourceRoutes(w, r)
		return
	case r.URL.Path == "/v1/metrics/host":
		s.hostMetricsEndpoint(w, r)
		return
	case r.URL.Path == "/v1/storage" || strings.HasPrefix(r.URL.Path, "/v1/storage/"):
		s.storageEndpoint(w, r, principal)
		return
	case r.URL.Path == "/v1/preview":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		s.preview(w, r)
		return
	case strings.HasPrefix(r.URL.Path, "/v1/services/"):
		s.serviceEndpoint(w, r)
		return
	case strings.HasPrefix(r.URL.Path, "/v1/operations/") && strings.HasSuffix(r.URL.Path, "/events"):
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		id, err := domain.ParseID(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/operations/"), "/events"))
		if err != nil {
			writeError(w, 400, "invalid_id", "invalid operation ID")
			return
		}
		backend, ok := s.options.Backend.(DetailBackend)
		if !ok {
			writeError(w, 501, "not_implemented", "details unavailable")
			return
		}
		events, err := backend.OperationEvents(r.Context(), id)
		if err != nil {
			backendError(w, err)
			return
		}
		writeJSON(w, 200, events)
		return
	case r.URL.Path == "/v1/health":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "schema_version": domain.SchemaVersion})
	case r.URL.Path == "/v1/services":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		result, err := s.options.Backend.ListServices(r.Context())
		if err != nil {
			backendError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	case r.URL.Path == "/v1/operations":
		switch r.Method {
		case http.MethodGet:
			result, err := s.options.Backend.ListOperations(r.Context())
			if err != nil {
				backendError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, result)
		case http.MethodPost:
			s.submit(w, r, principal)
		default:
			methodNotAllowed(w, "GET, POST")
		}
	case strings.HasPrefix(r.URL.Path, "/v1/operations/"):
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		id, err := domain.ParseID(strings.TrimPrefix(r.URL.Path, "/v1/operations/"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_id", "invalid operation ID")
			return
		}
		result, err := s.options.Backend.GetOperation(r.Context(), id)
		if err != nil {
			backendError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	default:
		writeError(w, http.StatusNotFound, "not_found", "unknown executor endpoint")
	}
}

func (s *Server) submit(w http.ResponseWriter, r *http.Request, p Principal) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "invalid_content_type", "Content-Type must be application/json")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request exceeds body limit")
		} else {
			writeError(w, http.StatusBadRequest, "invalid_body", "request body cannot be read")
		}
		return
	}
	var request SubmitRequest
	if err := decodeSubmit(data, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := request.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if s.options.Submit == nil {
		writeError(w, http.StatusNotImplemented, "not_implemented", "operation submission is not enabled")
		return
	}
	result, err := s.options.Submit(r.Context(), p, request)
	if err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, result)
}

func decodeSubmit(data []byte, out *SubmitRequest) error {
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return fmt.Errorf("request must be a JSON object")
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return fmt.Errorf("malformed request")
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("malformed request")
		}
		if seen[key] {
			return fmt.Errorf("duplicate request field")
		}
		seen[key] = true
		switch key {
		case "service_id", "action", "release_id", "idempotency_key", "initiator", "candidate_id", "snapshot_id", "plan_digest", "confirm_data_compatibility", "accept_file_drift", "compose_from_git", "confirm_compose_change", "recovery_operation_id":
		case "compose_draft":
			draft, err := decodeComposeDraft(d)
			if err != nil {
				return err
			}
			out.ComposeDraft = &draft
			continue
		default:
			return fmt.Errorf("unknown request field")
		}
		token, err = d.Token()
		if err != nil {
			return fmt.Errorf("malformed request")
		}
		switch key {
		case "confirm_data_compatibility", "accept_file_drift", "compose_from_git", "confirm_compose_change":
			value, ok := token.(bool)
			if !ok {
				return fmt.Errorf("confirmation must be a boolean")
			}
			switch key {
			case "accept_file_drift":
				out.AcceptFileDrift = value
			case "compose_from_git":
				out.ComposeFromGit = value
			case "confirm_compose_change":
				out.ConfirmComposeChange = value
			default:
				out.ConfirmDataCompatibility = value
			}
			continue
		}
		value, ok := token.(string)
		if !ok {
			return fmt.Errorf("request fields must be strings")
		}
		switch key {
		case "service_id":
			out.ServiceID = domain.ID(value)
		case "action":
			out.Action = domain.OperationKind(value)
		case "release_id":
			out.ReleaseID = domain.ID(value)
		case "idempotency_key":
			out.IdempotencyKey = value
		case "initiator":
			out.Initiator = domain.ID(value)
		case "candidate_id":
			out.CandidateID = domain.ID(value)
		case "snapshot_id":
			out.SnapshotID = domain.ID(value)
		case "recovery_operation_id":
			out.RecoveryOperationID = domain.ID(value)
		case "plan_digest":
			out.PlanDigest = domain.Digest(value)
		}
	}
	if _, err := d.Token(); err != nil {
		return fmt.Errorf("malformed request")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("unexpected data after request")
	}
	return nil
}

type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, ErrorResponse{code, message})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"code":"serialization_error","message":"response cannot be encoded"}`))
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(append(payload, '\n'))
}
func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method is not supported")
}
func backendError(w http.ResponseWriter, err error) {
	var portConflict *ComposePortConflict
	var composeEditor *ComposeEditorError
	switch {
	case errors.As(err, &portConflict):
		writeError(w, http.StatusConflict, "compose_port_conflict", portConflict.Error())
	case errors.Is(err, ErrComposeEditorStale):
		writeError(w, http.StatusConflict, "compose_editor_stale", ErrComposeEditorStale.Error())
	case errors.As(err, &composeEditor):
		writeError(w, http.StatusUnprocessableEntity, "compose_editor_error", composeEditor.Message)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "requested object not found")
	case errors.Is(err, store.ErrIdempotencyConflict), errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrBusy):
		writeError(w, http.StatusConflict, "conflict", "request conflicts with executor state")
	default:
		writeError(w, http.StatusInternalServerError, "executor_error", "executor could not complete the request")
	}
}
