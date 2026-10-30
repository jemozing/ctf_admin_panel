// Package dashboard serves an unprivileged UI. All privileged actions pass through
// fixed, typed methods of the executor Unix client; this package never uses Docker.
package dashboard

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/maintenance"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	webui "github.com/ctf-service-manager/ctf-service-manager/web"
)

type Config struct {
	Listen         string
	StateDirectory string
	ExecutorSocket string
	AllowedHosts   []string
	SecureCookies  bool
}

type Server struct {
	config        Config
	db            *sql.DB
	executor      *transport.Client
	http          *http.Server
	hosts         map[string]bool
	assets        fs.FS
	dummyPassword string
	passwordSlots chan struct{}
	limiter       loginLimiter
	closeOnce     sync.Once
	closeErr      error
	stopCtx       context.Context
	stop          context.CancelFunc
	maintenance   *maintenance.Lock
}

func Open(config Config) (*Server, error) {
	if config.Listen == "" {
		config.Listen = "127.0.0.1:8765"
	}
	_, port, err := net.SplitHostPort(config.Listen)
	if err != nil {
		return nil, fmt.Errorf("invalid dashboard listen address: %w", err)
	}
	if len(config.AllowedHosts) == 0 {
		config.AllowedHosts = []string{"localhost:" + port, "127.0.0.1:" + port, "[::1]:" + port}
	}
	hosts := map[string]bool{}
	for _, host := range config.AllowedHosts {
		if host == "" || strings.ContainsAny(host, " /\\\t\r\n@?#*") {
			return nil, fmt.Errorf("allowed hosts must contain exact host[:port] values")
		}
		u, err := url.Parse("http://" + host)
		if err != nil || u.Host != host || u.Hostname() == "" {
			return nil, fmt.Errorf("invalid allowed host")
		}
		hosts[strings.ToLower(host)] = true
	}
	client, err := transport.NewClient(config.ExecutorSocket)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(config.StateDirectory, 0700); err != nil {
		client.Close()
		return nil, err
	}
	stateLock, err := maintenance.Acquire(config.StateDirectory, false)
	if err != nil {
		client.Close()
		return nil, err
	}
	opened := false
	defer func() {
		if !opened {
			_ = stateLock.Close()
		}
	}()
	db, err := openAuth(config.StateDirectory)
	if err != nil {
		client.Close()
		return nil, err
	}
	assets, err := fs.Sub(webui.Assets, "dist")
	if err != nil {
		db.Close()
		client.Close()
		return nil, err
	}
	dummy, err := hashPassword("invalid-account-placeholder-password")
	if err != nil {
		db.Close()
		client.Close()
		return nil, err
	}
	s := &Server{config: config, db: db, executor: client, hosts: hosts, assets: assets, dummyPassword: dummy, passwordSlots: make(chan struct{}, 2), maintenance: stateLock}
	s.stopCtx, s.stop = context.WithCancel(context.Background())
	s.http = &http.Server{Addr: config.Listen, Handler: http.HandlerFunc(s.handle), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	opened = true
	return s, nil
}

func (s *Server) Serve(ctx context.Context) error {
	// Restarting the serving process invalidates restored or previously issued sessions.
	// Opening metadata for a local bootstrap command does not revoke live sessions.
	listener, err := net.Listen("tcp", s.config.Listen)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM sessions"); err != nil {
		listener.Close()
		return err
	}
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			s.stop()
			c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.http.Shutdown(c)
		case <-finished:
		}
	}()
	err = s.http.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.stop()
		s.http.Close()
		s.executor.Close()
		s.closeErr = errors.Join(s.db.Close(), s.maintenance.Close())
	})
	return s.closeErr
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("Cache-Control", "no-store")
	if !s.hosts[strings.ToLower(r.Host)] {
		apiError(w, 403, "invalid_host", "Host is not allowed")
		return
	}
	if r.URL.RawPath != "" || strings.Contains(r.URL.Path, "\\") {
		apiError(w, 400, "invalid_path", "encoded paths are not accepted")
		return
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		apiError(w, 403, "invalid_origin", "cross-site requests are not accepted")
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && !s.validOrigin(r, origin) {
		apiError(w, 403, "invalid_origin", "Origin is not allowed")
		return
	}
	if r.URL.Path == "/healthz" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		writeJSON(w, 200, map[string]string{"status": "ok"})
		return
	}
	if r.URL.Path == "/api/auth/login" {
		if !method(w, r, "POST") {
			return
		}
		if !s.validOrigin(r, r.Header.Get("Origin")) {
			apiError(w, 403, "invalid_origin", "same-origin Origin is required")
			return
		}
		s.login(w, r)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			apiError(w, 405, "method_not_allowed", "method is not supported")
			return
		}
		s.static(w, r)
		return
	}
	cookie, err := r.Cookie(s.cookieName())
	if err != nil {
		apiError(w, 401, "unauthenticated", "Sign in to continue")
		return
	}
	session, err := s.getSession(r.Context(), cookie.Value)
	if err != nil {
		apiError(w, 401, "unauthenticated", "Session has expired")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if !s.validOrigin(r, r.Header.Get("Origin")) || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(session.CSRF)) != 1 {
			apiError(w, 403, "csrf_failed", "CSRF token and same-origin Origin are required")
			return
		}
	}
	switch {
	case r.URL.Path == "/api/flows" || strings.HasPrefix(r.URL.Path, "/api/flows/") || r.URL.Path == "/api/descriptors" || strings.HasPrefix(r.URL.Path, "/api/descriptors/") || strings.HasPrefix(r.URL.Path, "/api/traffic/") && strings.HasSuffix(r.URL.Path, "/decode"):
		s.analysisRoutes(w, r, session)
	case r.URL.Path == "/api/packets" || strings.HasPrefix(r.URL.Path, "/api/packets/") || strings.HasPrefix(r.URL.Path, "/api/capture/"):
		s.packetRoutes(w, r, session)
	case strings.HasPrefix(r.URL.Path, "/api/proxy/"):
		s.httpProxyRoutes(w, r, session)
	case r.URL.Path == "/api/traffic" || strings.HasPrefix(r.URL.Path, "/api/traffic/"):
		s.trafficRoutes(w, r, session)
	case r.URL.Path == "/api/storage":
		if !method(w, r, "GET") {
			return
		}
		if r.URL.RawQuery != "" {
			apiError(w, 400, "invalid_query", "No query is supported")
			return
		}
		v, err := s.executor.StorageStatus(r.Context())
		if err != nil {
			executorError(w, err)
			return
		}
		writeJSON(w, 200, v)
	case strings.HasPrefix(r.URL.Path, "/api/registration/"):
		s.registrationRoutes(w, r, session)
	case r.URL.Path == "/api/metrics/host":
		if !method(w, r, "GET") {
			return
		}
		if r.URL.RawQuery != "" {
			apiError(w, 400, "invalid_query", "No query is supported")
			return
		}
		v, err := s.executor.HostMetrics(r.Context())
		if err != nil {
			executorError(w, err)
			return
		}
		writeJSON(w, 200, v)
	case r.URL.Path == "/api/auth/session":
		if !method(w, r, "GET") {
			return
		}
		writeJSON(w, 200, map[string]any{"user": session.User, "csrf_token": session.CSRF, "expires_at": session.Expires})
	case r.URL.Path == "/api/auth/logout":
		if !method(w, r, "POST") {
			return
		}
		if _, err := s.db.ExecContext(r.Context(), "DELETE FROM sessions WHERE token_hash=?", session.Hash); err != nil {
			internalError(w)
			return
		}
		s.clearCookie(w)
		writeJSON(w, 200, map[string]bool{"ok": true})
	case r.URL.Path == "/api/status":
		if !method(w, r, "GET") {
			return
		}
		health, err := s.executor.Health(r.Context())
		if err != nil {
			writeJSON(w, 200, map[string]any{"executor": "unavailable"})
			return
		}
		writeJSON(w, 200, map[string]any{"executor": health.Status, "schema_version": health.SchemaVersion})
	case r.URL.Path == "/api/services":
		if !method(w, r, "GET") {
			return
		}
		result, err := s.executor.ListServices(r.Context())
		if err != nil {
			executorError(w, err)
			return
		}
		if result == nil {
			result = []domain.Service{}
		}
		writeJSON(w, 200, result)
	case r.URL.Path == "/api/operations":
		if r.Method == http.MethodPost {
			s.submit(w, r, session)
			return
		}
		if !method(w, r, "GET") {
			return
		}
		result, err := s.executor.ListOperations(r.Context())
		if err != nil {
			executorError(w, err)
			return
		}
		if result == nil {
			result = []domain.Operation{}
		}
		writeJSON(w, 200, result)
	case r.URL.Path == "/api/preview":
		s.preview(w, r, session)
	case r.URL.Path == "/api/stream":
		s.stream(w, r, session, cookie.Value)
	case r.URL.Path == "/api/users":
		if session.User.Role != RoleAdmin {
			s.deny(w, r, session.User.ID)
			return
		}
		s.users(w, r, session)
	case strings.HasPrefix(r.URL.Path, "/api/users/"):
		if session.User.Role != RoleAdmin {
			s.deny(w, r, session.User.ID)
			return
		}
		s.user(w, r, session)
	case r.URL.Path == "/api/audit":
		if !method(w, r, "GET") {
			return
		}
		if session.User.Role != RoleAdmin {
			s.deny(w, r, session.User.ID)
			return
		}
		s.auditList(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/services/"):
		s.serviceRoutes(w, r, session)
	case strings.HasPrefix(r.URL.Path, "/api/operations/"):
		s.operationRoutes(w, r, session)
	default:
		apiError(w, 404, "not_found", "unknown endpoint")
	}
}

func (s *Server) validOrigin(r *http.Request, origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	scheme := "http"
	if s.config.SecureCookies || r.TLS != nil {
		scheme = "https"
	}
	return u.Scheme == scheme && strings.EqualFold(u.Host, r.Host) && s.hosts[strings.ToLower(u.Host)]
}

func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if name == "" || !strings.HasPrefix(name, "assets/") {
		name = "index.html"
	}
	data, err := fs.ReadFile(s.assets, name)
	if err != nil {
		apiError(w, 404, "not_found", "asset not found")
		return
	}
	if strings.HasPrefix(name, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	w.Header().Set("Content-Type", mime.TypeByExtension(path.Ext(name)))
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}

func (s *Server) cookieName() string {
	if s.config.SecureCookies {
		return "__Host-ctfsm_session"
	}
	return "ctfsm_session"
}
func (s *Server) setCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: token, Path: "/", Expires: expires, MaxAge: int(time.Until(expires).Seconds()), HttpOnly: true, Secure: s.config.SecureCookies, SameSite: http.SameSiteStrictMode})
}
func (s *Server) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.config.SecureCookies, SameSite: http.SameSiteStrictMode})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	if !s.limiter.allow(ip, input.Username, time.Now()) {
		w.Header().Set("Retry-After", "60")
		apiError(w, 429, "rate_limited", "Too many sign-in attempts; try again later")
		return
	}
	if len(input.Username) > 64 || len(input.Password) > 1024 {
		apiError(w, 401, "invalid_credentials", "Invalid username or password")
		return
	}
	select {
	case s.passwordSlots <- struct{}{}:
		defer func() { <-s.passwordSlots }()
	default:
		w.Header().Set("Retry-After", "2")
		apiError(w, 429, "rate_limited", "Authentication is busy; try again shortly")
		return
	}
	var u User
	var hash string
	var created int64
	err = s.db.QueryRowContext(r.Context(), "SELECT "+userColumns+",password_hash FROM users WHERE username=?", input.Username).Scan(&u.ID, &u.Username, &u.Role, &u.Disabled, &u.SensitiveAccess, &created, &hash)
	if err != nil && !dbNotFound(err) {
		internalError(w)
		return
	}
	if err != nil {
		hash = s.dummyPassword
	}
	valid := verifyPassword(hash, input.Password)
	if err != nil || u.Disabled || !valid {
		// Do not record arbitrary submitted usernames, passwords or cookie values.
		if auditErr := s.audit(r.Context(), "anonymous", "login", "", "denied", ""); auditErr != nil {
			internalError(w)
			return
		}
		apiError(w, 401, "invalid_credentials", "Invalid username or password")
		return
	}
	u.CreatedAt = time.Unix(created, 0).UTC()
	token, err := randomToken()
	if err != nil {
		internalError(w)
		return
	}
	csrf, err := randomToken()
	if err != nil {
		internalError(w)
		return
	}
	expires := time.Now().Add(8 * time.Hour).UTC()
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		internalError(w)
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE expires_at<=?", time.Now().Unix()); err != nil {
		internalError(w)
		return
	}
	// Bound per-user sessions and rotate any session supplied during login.
	if c, e := r.Cookie(s.cookieName()); e == nil {
		if _, err = tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE token_hash=?", tokenHash(c.Value)); err != nil {
			internalError(w)
			return
		}
	}
	if _, err = tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE token_hash IN (SELECT token_hash FROM sessions WHERE user_id=? ORDER BY expires_at DESC LIMIT -1 OFFSET 4)", u.ID); err != nil {
		internalError(w)
		return
	}
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO sessions(token_hash,user_id,csrf,expires_at) VALUES(?,?,?,?)", tokenHash(token), u.ID, csrf, expires.Unix()); err != nil {
		internalError(w)
		return
	}
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO audit(at,actor,action,target,result) VALUES(?,?,?,?,?)", time.Now().UTC().Format(time.RFC3339Nano), u.ID, "login", "", "succeeded"); err != nil {
		internalError(w)
		return
	}
	if err = tx.Commit(); err != nil {
		internalError(w)
		return
	}
	s.setCookie(w, token, expires)
	writeJSON(w, 200, map[string]any{"user": u, "csrf_token": csrf, "expires_at": expires})
}

func (s *Server) submit(w http.ResponseWriter, r *http.Request, current session) {
	if current.User.Role == RoleViewer {
		s.deny(w, r, current.User.ID)
		return
	}
	var input transport.SubmitRequest
	if !decodeBody(w, r, &input) {
		return
	}
	// The executor receives authenticated user identity only from the server.
	input.Initiator = domain.ID(current.User.ID)
	if err := input.Validate(); err != nil {
		apiError(w, 400, "invalid_request", err.Error())
		return
	}
	if err := s.audit(r.Context(), current.User.ID, string(input.Action), string(input.ServiceID), "requested", ""); err != nil {
		internalError(w)
		return
	}
	if input.AcceptFileDrift && !current.User.SensitiveAccess {
		s.deny(w, r, current.User.ID)
		return
	}
	result, err := s.executor.Submit(r.Context(), input)
	if err != nil {
		_ = s.audit(r.Context(), current.User.ID, string(input.Action), string(input.ServiceID), "rejected", "")
		executorError(w, err)
		return
	}
	if err = s.audit(r.Context(), current.User.ID, string(input.Action), string(input.ServiceID), "accepted", string(result.Spec.ID)); err != nil {
		apiError(w, 502, "audit_incomplete", "Operation may have been accepted; retry with the same idempotency key")
		return
	}
	writeJSON(w, 202, result)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func apiError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"code": code, "message": message})
}
func internalError(w http.ResponseWriter) {
	apiError(w, 500, "dashboard_error", "Dashboard could not complete the request")
}
func (s *Server) deny(w http.ResponseWriter, r *http.Request, actor string) {
	target := r.URL.Path
	if len(target) > 256 {
		target = target[:256]
	}
	if err := s.audit(r.Context(), actor, "authorization.denied", target, "denied", ""); err != nil {
		internalError(w)
		return
	}
	apiError(w, 403, "forbidden", "This account cannot perform this action")
}
func executorError(w http.ResponseWriter, err error) {
	var p *transport.ProtocolError
	if errors.As(err, &p) {
		status := p.Status
		if status < 400 || status > 599 {
			status = 502
		}
		apiError(w, status, p.Code, p.Message)
		return
	}
	apiError(w, 502, "executor_unavailable", "Executor is unavailable")
}
func method(w http.ResponseWriter, r *http.Request, want string) bool {
	if r.Method == want {
		return true
	}
	w.Header().Set("Allow", want)
	apiError(w, 405, "method_not_allowed", "method is not supported")
	return false
}
func decodeBody(w http.ResponseWriter, r *http.Request, out any) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		apiError(w, 415, "invalid_content_type", "Content-Type must be application/json")
		return false
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	d.DisallowUnknownFields()
	if err = d.Decode(out); err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			apiError(w, 413, "body_too_large", "Request body exceeds limit")
		} else {
			apiError(w, 400, "invalid_request", "Request contains invalid fields")
		}
		return false
	}
	if err = d.Decode(new(any)); err != io.EOF {
		apiError(w, 400, "invalid_request", "Request must contain one JSON object")
		return false
	}
	return true
}

type rateWindow struct {
	Count int
	Until time.Time
}
type loginLimiter struct {
	mu      sync.Mutex
	windows map[string]rateWindow
}

func (l *loginLimiter) allow(ip, username string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.windows == nil {
		l.windows = map[string]rateWindow{}
	}
	if len(l.windows) > 2000 {
		for key, value := range l.windows {
			if !now.Before(value.Until) {
				delete(l.windows, key)
			}
		}
		if len(l.windows) > 10000 {
			return false
		}
	}
	allowed := true
	for key, limit := range map[string]int{"ip:" + ip: 30, "account:" + tokenHash(username): 5} {
		window := l.windows[key]
		if !now.Before(window.Until) {
			window = rateWindow{Until: now.Add(time.Minute)}
		}
		window.Count++
		l.windows[key] = window
		if window.Count > limit {
			allowed = false
		}
	}
	return allowed
}

func parseTail(raw string) (int, error) {
	if raw == "" {
		return 200, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 || v > 500 {
		return 0, fmt.Errorf("tail must be between 1 and 500")
	}
	return v, nil
}

func (s *Server) acquirePasswordSlot(w http.ResponseWriter) bool {
	select {
	case s.passwordSlots <- struct{}{}:
		return true
	default:
		w.Header().Set("Retry-After", "2")
		apiError(w, 429, "rate_limited", "Password processing is busy; retry shortly")
		return false
	}
}
