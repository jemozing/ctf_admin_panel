package proxy

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type BanPage struct {
	Bans      []Ban `json:"bans"`
	Truncated bool  `json:"truncated"`
	Total     int   `json:"total"`
}

// Preflight performs no policy/state writes or application HTTP requests.
func (e *Engine) Preflight(input Policy) error {
	return e.preflight(CutoverPreflightRequest{Policy: input})
}

// PreflightCutover validates a staged, administrator-approved publication
// change. It does not prove that the old owner has released its listener:
// callers must repeat normal Preflight after changing Docker publications.
func (e *Engine) PreflightCutover(input CutoverPreflightRequest) error {
	return e.preflight(input)
}

func (e *Engine) preflight(input CutoverPreflightRequest) error {
	p, err := NormalizePolicy(input.Policy)
	if err != nil {
		return err
	}
	if len(input.ReleasedListeners) > MaxCutoverListeners || len(input.PendingUpstreams) > MaxCutoverUpstreams {
		return errors.New("cutover preflight exception budget exceeded")
	}
	released, pending := map[string]bool{}, map[string]bool{}
	knownListeners, knownUpstreams := map[string]bool{}, map[string]bool{}
	for _, route := range p.Routes {
		knownListeners[route.Listen] = true
		knownUpstreams[route.Upstream] = true
	}
	for _, listener := range input.ReleasedListeners {
		if !knownListeners[listener] || released[listener] {
			return errors.New("released listener must uniquely match a proposed route")
		}
		released[listener] = true
	}
	for _, upstream := range input.PendingUpstreams {
		belongsToReleased := false
		for _, route := range p.Routes {
			belongsToReleased = belongsToReleased || (released[route.Listen] && route.Upstream == upstream)
		}
		if !knownUpstreams[upstream] || pending[upstream] || !belongsToReleased {
			return errors.New("pending upstream must uniquely match a cutover route")
		}
		pending[upstream] = true
	}
	e.mu.Lock()
	if e.ctx.Err() != nil {
		e.mu.Unlock()
		return errors.New("proxy is closed")
	}
	if _, err := e.prepareTLS(p); err != nil {
		e.mu.Unlock()
		return err
	}
	listeners := []net.Listener{}
	cleanup := func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
		e.mu.Unlock()
	}
	for _, r := range p.Routes {
		if e.listeners[r.Listen] != nil {
			if released[r.Listen] {
				cleanup()
				return errors.New("an active proxy listener cannot be marked released")
			}
			if err := e.validateListenerReuse(r); err != nil {
				cleanup()
				return err
			}
			continue
		}
		if released[r.Listen] {
			continue
		}
		l, err := e.options.Listen(listenNetwork(r.Listen), r.Listen)
		if err != nil {
			cleanup()
			return errors.New("external listener is unavailable")
		}
		listeners = append(listeners, l)
	}
	for upstream := range pending {
		address := upstreamAddress(upstream)
		l, err := e.options.Listen(listenNetwork(address), address)
		if err != nil {
			cleanup()
			return errors.New("future loopback upstream port is unavailable")
		}
		listeners = append(listeners, l)
	}
	cleanup()
	ctx, cancel := context.WithTimeout(e.ctx, 5*time.Second)
	defer cancel()
	h2Targets := map[string]bool{}
	for _, route := range p.Routes {
		if route.Protocol == "https2" && !pending[route.Upstream] {
			h2Targets[upstreamAddress(route.Upstream)] = true
		}
	}
	jobs := make(chan string)
	var wg sync.WaitGroup
	var first error
	var mu sync.Mutex
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				dialCtx, stop := context.WithTimeout(ctx, 2*time.Second)
				var err error
				if h2Targets[target] {
					err = probeHTTP2Address(dialCtx, target)
				} else {
					var conn net.Conn
					conn, err = (&net.Dialer{}).DialContext(dialCtx, "tcp", target)
					if conn != nil {
						_ = conn.Close()
					}
				}
				stop()
				if err != nil {
					mu.Lock()
					if first == nil {
						first = errors.New("approved upstream is unreachable")
					}
					mu.Unlock()
					cancel()
				}
			}
		}()
	}
	seen := map[string]bool{}
	for _, r := range p.Routes {
		if pending[r.Upstream] {
			continue
		}
		target := upstreamAddress(r.Upstream)
		if seen[target] {
			continue
		}
		seen[target] = true
		select {
		case jobs <- target:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()
	if first != nil {
		return first
	}
	if ctx.Err() != nil {
		return errors.New("upstream preflight deadline exceeded")
	}
	return nil
}

func upstreamAddress(origin string) string {
	u, _ := url.Parse(origin)
	port := u.Port()
	if port == "" {
		port = "80"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// ControlHandler is served only on a separate private loopback/Unix listener.
// It is never mounted on any game listener.
func (e *Engine) ControlHandler(token string) (http.Handler, error) {
	if len(token) < 32 || len(token) > 4096 || strings.ContainsAny(token, " \r\n\t") {
		return nil, errors.New("private control token must contain 32..4096 non-whitespace bytes")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		emit := func(status int, v any) { w.WriteHeader(status); _ = json.NewEncoder(w).Encode(v) }
		fail := func(status int, code, message string) {
			emit(status, map[string]string{"code": code, "message": message})
		}
		if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
			emit(200, map[string]string{"status": "ok"})
			return
		}
		if len(r.Header.Values("Authorization")) != 1 || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			fail(401, "unauthorized", "Authentication required")
			return
		}
		if r.Method == http.MethodPost && r.URL.RawQuery != "" {
			fail(400, "invalid_request", "Unknown control options")
			return
		}
		decode := func(v any) bool {
			d := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxPolicyBytes))
			d.DisallowUnknownFields()
			if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
				fail(400, "invalid_request", "A bounded typed JSON request is required")
				return false
			}
			return true
		}
		switch {
		case r.URL.Path == "/v1/status" && r.Method == http.MethodGet:
			if r.URL.RawQuery != "" {
				fail(400, "invalid_request", "Unknown status options")
				return
			}
			emit(200, e.statusSnapshot(true))
		case r.URL.Path == "/v1/h2-preflight" && r.Method == http.MethodPost:
			var input HTTP2ProbeRequest
			if !decode(&input) {
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			if err := probeHTTP2Origins(ctx, input.Upstreams, input.AllowHostAddresses); err != nil {
				fail(409, "h2_preflight_failed", "Approved origins do not support bounded plaintext HTTP/2 preflight")
				return
			}
			emit(200, map[string]bool{"ok": true})
		case r.URL.Path == "/v1/preflight" && r.Method == http.MethodPost:
			var p Policy
			if !decode(&p) {
				return
			}
			if err := e.Preflight(p); err != nil {
				fail(409, "preflight_failed", "Policy, listener or approved upstream preflight failed")
				return
			}
			emit(200, map[string]bool{"ok": true})
		case r.URL.Path == "/v1/preflight-cutover" && r.Method == http.MethodPost:
			var q CutoverPreflightRequest
			if !decode(&q) {
				return
			}
			if err := e.PreflightCutover(q); err != nil {
				fail(409, "preflight_failed", "Cutover policy, TLS profile or host port preflight failed")
				return
			}
			emit(200, map[string]bool{"ok": true})
		case r.URL.Path == "/v1/tls/certificates" && r.Method == http.MethodGet:
			if r.URL.RawQuery != "" {
				fail(400, "invalid_request", "Unknown certificate inventory options")
				return
			}
			page, err := e.TLSCertificates()
			if err != nil {
				fail(503, "tls_inventory_unavailable", "Local certificate inventory unavailable")
				return
			}
			emit(200, page)
		case r.URL.Path == "/v1/bans" && r.Method == http.MethodGet:
			query, err := url.ParseQuery(r.URL.RawQuery)
			if err != nil || len(query) > 1 || len(query["service_id"]) > 1 {
				fail(400, "invalid_request", "Invalid ban filter")
				return
			}
			for key := range query {
				if key != "service_id" {
					fail(400, "invalid_request", "Unknown ban filter")
					return
				}
			}
			service := query.Get("service_id")
			if service != "" && !identifier.MatchString(service) {
				fail(400, "invalid_request", "Invalid service filter")
				return
			}
			bans := e.ListBans(service)
			sort.Slice(bans, func(i, j int) bool { return bans[i].ExpiresAt.Before(bans[j].ExpiresAt) })
			page := BanPage{Bans: bans, Total: len(bans)}
			if len(page.Bans) > 1000 {
				page.Bans = page.Bans[:1000]
				page.Truncated = true
			}
			emit(200, page)
		case r.URL.Path == "/v1/bans" && r.Method == http.MethodPost:
			var q BanRequest
			if !decode(&q) {
				return
			}
			b, err := e.AddBan(q)
			if err != nil {
				fail(409, "ban_rejected", "Ban scope, TTL, comment or WAF state is invalid")
				return
			}
			emit(200, b)
		case r.URL.Path == "/v1/unban" && r.Method == http.MethodPost:
			var q UnbanRequest
			if !decode(&q) {
				return
			}
			if err := e.RemoveBan(q); err != nil {
				fail(409, "unban_rejected", "Unban scope, comment or WAF state is invalid")
				return
			}
			emit(200, map[string]bool{"ok": true})
		default:
			fail(404, "not_found", "Unknown control method")
		}
	}), nil
}
