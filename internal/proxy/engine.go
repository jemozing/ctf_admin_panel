package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/maintenance"
	"github.com/ctf-service-manager/ctf-service-manager/internal/traffic"
)

type compiledRoute struct {
	route      Route
	redact     *redactor
	proxy      *httputil.ReverseProxy
	slots      chan struct{}
	transport  idleTransport
	tlsProfile *certificateProfile
	tlsConfig  *tls.Config
}
type activePolicy struct {
	policy Policy
	digest string
	routes map[string]*compiledRoute
}
type liveListener struct {
	server   *http.Server
	listener net.Listener
}

type Engine struct {
	options                                                                                                 Options
	mu                                                                                                      sync.Mutex
	active                                                                                                  atomic.Pointer[activePolicy]
	listeners                                                                                               map[string]*liveListener
	ctx                                                                                                     context.Context
	cancel                                                                                                  context.CancelFunc
	waf                                                                                                     *wafState
	status                                                                                                  Status
	sequence                                                                                                atomic.Uint64
	queue                                                                                                   chan traffic.Exchange
	accepted, forwarded, rejected, wouldReject, upstreamErrors, captureDropped, requestBytes, responseBytes atomic.Uint64
	stateLock                                                                                               *maintenance.Lock
	connectionSlots                                                                                         chan struct{}
	pendingCaptureDrops                                                                                     atomic.Uint64
	recorderUnavailable                                                                                     atomic.Bool
	auditMu                                                                                                 sync.Mutex
	tlsPins                                                                                                 tlsPinState
}

func NewEngine(options Options) (*Engine, error) {
	if options.StateDirectory == "" || !filepath.IsAbs(options.StateDirectory) || filepath.Clean(options.StateDirectory) != options.StateDirectory || options.StateDirectory == "/" {
		return nil, errors.New("private absolute proxy state directory required")
	}
	if err := os.MkdirAll(options.StateDirectory, 0700); err != nil {
		return nil, err
	}
	st, err := os.Lstat(options.StateDirectory)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("proxy state directory must be private and real")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Listen == nil {
		options.Listen = net.Listen
	}
	if options.GlobalMaxIPStates == 0 {
		options.GlobalMaxIPStates = 65536
	}
	if options.GlobalMaxIPStates < 1 || options.GlobalMaxIPStates > 65536 {
		return nil, errors.New("global WAF IP budget must be 1..65536")
	}
	stateLock, err := maintenance.Acquire(options.StateDirectory, true)
	if err != nil {
		return nil, err
	}
	var epoch [16]byte
	if _, err := rand.Read(epoch[:]); err != nil {
		_ = stateLock.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{options: options, listeners: map[string]*liveListener{}, ctx: ctx, cancel: cancel, queue: make(chan traffic.Exchange, 64), stateLock: stateLock, connectionSlots: make(chan struct{}, 256)}
	e.tlsPins = tlsPinState{SchemaVersion: 1, Profiles: map[string]string{}}
	if err := readJSON(filepath.Join(options.StateDirectory, "tls-profiles.json"), &e.tlsPins); err != nil && !os.IsNotExist(err) {
		cancel()
		_ = stateLock.Close()
		return nil, errors.New("immutable certificate history unavailable or corrupt")
	}
	if e.tlsPins.SchemaVersion != 1 || len(e.tlsPins.Profiles) > maxTLSPins {
		cancel()
		_ = stateLock.Close()
		return nil, errors.New("immutable certificate history invalid")
	}
	for id, digest := range e.tlsPins.Profiles {
		if !identifier.MatchString(id) || len(digest) != len("sha256:")+64 || !strings.HasPrefix(digest, "sha256:") {
			cancel()
			_ = stateLock.Close()
			return nil, errors.New("immutable certificate history invalid")
		}
	}
	_, lkgErr := os.Stat(filepath.Join(options.StateDirectory, "policy.json"))
	e.waf = newWAF(options.StateDirectory, options.GlobalMaxIPStates, lkgErr == nil, options.Now())
	e.status = Status{Available: true, CollectorEpoch: hex.EncodeToString(epoch[:]), StartedAt: options.Now(), CountersReset: true, SupportedProfiles: []string{"http1"}}
	if options.TLSDirectory != "" {
		e.status.SupportedProfiles = append(e.status.SupportedProfiles, "https1", "https2")
	}
	e.active.Store(&activePolicy{routes: map[string]*compiledRoute{}})
	go e.recordWorker()
	return e, nil
}

func (e *Engine) recordWorker() {
	for {
		if e.ctx.Err() != nil {
			return
		}
		select {
		case <-e.ctx.Done():
			return
		case x := <-e.queue:
			pending := e.pendingCaptureDrops.Load()
			x.Dropped = x.Dropped || pending > 0
			x.RecorderUnavailable = e.recorderUnavailable.Load()
			if e.options.Sink == nil || !e.options.Sink.Submit(x) {
				e.captureDropped.Add(1)
				e.pendingCaptureDrops.Add(1)
				e.recorderUnavailable.Store(true)
			} else {
				e.recorderUnavailable.Store(false)
				if pending > 0 {
					e.pendingCaptureDrops.Add(^uint64(pending - 1))
				}
			}
		}
	}
}
func (e *Engine) emit(x traffic.Exchange) {
	// JSON escaping can enlarge an otherwise bounded prefix. Keep the metadata
	// rather than silently lose the complete exchange when serialization grows.
	raw, err := json.Marshal(x)
	if err != nil || len(raw) > traffic.MaxExchangeBytes {
		x.RequestBody.Data = ""
		x.RequestBody.CapturedBytes = 0
		x.RequestBody.SensitiveRaw = false
		x.RequestBody.NotCapturedReason = "exchange_encoding_budget"
		x.ResponseBody.Data = ""
		x.ResponseBody.CapturedBytes = 0
		x.ResponseBody.SensitiveRaw = false
		x.ResponseBody.NotCapturedReason = "exchange_encoding_budget"
		x.Truncated = true
		raw, err = json.Marshal(x)
		if err != nil || len(raw) > traffic.MaxExchangeBytes {
			x.RequestHeaders = nil
			x.ResponseHeaders = nil
			x.RequestTrailers = nil
			x.ResponseTrailers = nil
		}
	}
	select {
	case e.queue <- x:
	default:
		e.captureDropped.Add(1)
		e.pendingCaptureDrops.Add(1)
	}
}

func (e *Engine) Restore() error {
	var p Policy
	err := readJSON(filepath.Join(e.options.StateDirectory, "policy.json"), &p)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.New("last-known-good policy unavailable or corrupt")
	}
	return e.Apply(p)
}

func (e *Engine) Apply(input Policy) error {
	p, err := NormalizePolicy(input)
	if err != nil {
		e.setPolicyError(input.Revision, "policy validation failed")
		return err
	}
	// Deep-copy caller-owned slices before publishing immutable handlers.
	b, _ := json.Marshal(p)
	if json.Unmarshal(b, &p) != nil {
		return errors.New("policy copy failed")
	}
	digest := PolicyDigest(p)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.status.DesiredRevision = p.Revision
	current := e.active.Load()
	if p.Revision < current.policy.Revision || (p.Revision == current.policy.Revision && current.policy.Revision != 0 && digest != current.digest) {
		e.status.LastError = "policy revision conflict"
		return errors.New("policy revision must increase or exactly repeat")
	}
	profiles, err := e.prepareTLS(p)
	if err != nil {
		e.status.LastError = "local TLS certificate validation failed; previous revision retained"
		return err
	}
	if p.Revision == current.policy.Revision && digest == current.digest {
		e.status.LastError = ""
		return nil
	}
	if e.ctx.Err() != nil {
		return errors.New("proxy is closed")
	}
	next := &activePolicy{policy: p, digest: digest, routes: map[string]*compiledRoute{}}
	created := map[string]*liveListener{}
	cleanup := func() {
		for _, l := range created {
			_ = l.listener.Close()
		}
		for _, r := range next.routes {
			r.transport.CloseIdleConnections()
		}
	}
	for _, r := range p.Routes {
		compiled := e.compile(r)
		if isTLSProfile(r.Protocol) {
			compiled.tlsProfile = profiles[r.TLS.CertificateID]
			compiled.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: frontendALPN(r.Protocol), Certificates: []tls.Certificate{compiled.tlsProfile.certificate}}
		}
		next.routes[r.Listen] = compiled
		if _, ok := e.listeners[r.Listen]; ok {
			if err := e.validateListenerReuse(r); err != nil {
				cleanup()
				e.status.LastError = "listener header/idle limits require a new free listener"
				return err
			}
			continue
		}
		listener, err := e.options.Listen(listenNetwork(r.Listen), r.Listen)
		if err != nil {
			cleanup()
			e.status.LastError = "listener bind failed; previous revision retained"
			return errors.New("listener bind failed; previous revision retained")
		}
		address := r.Listen
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
			state := e.active.Load()
			if route := state.routes[address]; route != nil {
				e.serve(w, q, route, state.policy.Revision)
			} else {
				http.Error(w, "Route unavailable", http.StatusServiceUnavailable)
			}
		}), ReadHeaderTimeout: time.Duration(r.Limits.ReadHeaderTimeoutSeconds) * time.Second, IdleTimeout: time.Duration(r.Limits.IdleTimeoutSeconds) * time.Second, MaxHeaderBytes: r.Limits.MaxHeaderBytes, BaseContext: func(net.Listener) context.Context { return e.ctx }, TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}, ErrorLog: log.New(io.Discard, "", 0)}
		if err := configureHTTP2Server(server); err != nil {
			_ = listener.Close()
			cleanup()
			return errors.New("HTTP/2 listener configuration failed")
		}
		baseTLS := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) { return e.routeTLSConfig(address, hello) }}
		created[address] = &liveListener{server: server, listener: &profileListener{Listener: &boundedListener{Listener: listener, slots: e.connectionSlots, done: e.ctx.Done()}, engine: e, address: address, tlsConfig: baseTLS}}
	}
	if err := e.commitTLSPins(profiles); err != nil {
		cleanup()
		e.status.LastError = "immutable certificate history persistence failed; previous revision retained"
		return err
	}
	if current.policy.SchemaVersion == 1 {
		if err := atomicJSON(e.options.StateDirectory, "previous-policy.json", current.policy); err != nil {
			cleanup()
			e.status.LastError = "previous policy persistence failed"
			return errors.New("previous policy persistence failed")
		}
	}
	if err := atomicJSON(e.options.StateDirectory, "policy.json", p); err != nil {
		cleanup()
		e.status.LastError = "policy persistence failed; previous revision retained"
		return errors.New("policy persistence failed; previous revision retained")
	}
	e.active.Store(next)
	e.status.AppliedRevision = p.Revision
	e.status.PolicyDigest = digest
	e.status.Routes = len(p.Routes)
	e.status.LastError = ""
	for address, l := range created {
		e.listeners[address] = l
		go func() { _ = l.server.Serve(l.listener) }()
	}
	for address, l := range e.listeners {
		if next.routes[address] == nil {
			delete(e.listeners, address)
			// Applied status is observed under e.mu. Release the host binding
			// before exposing that status so a reviewed return can recreate the
			// application on this port immediately. Existing requests drain below.
			_ = l.listener.Close()
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = l.server.Shutdown(ctx)
				_ = l.server.Close()
			}()
		}
	}
	for _, r := range current.routes {
		r.transport.CloseIdleConnections()
	}
	return nil
}

// Caller holds e.mu; these net/http server fields are fixed at listener start.
func (e *Engine) validateListenerReuse(r Route) error {
	old := e.active.Load().routes[r.Listen].route.Limits
	if old.MaxHeaderBytes != r.Limits.MaxHeaderBytes || old.ReadHeaderTimeoutSeconds != r.Limits.ReadHeaderTimeoutSeconds || old.IdleTimeoutSeconds != r.Limits.IdleTimeoutSeconds {
		return errors.New("listener header/idle limits require a new free listener")
	}
	return nil
}

func (e *Engine) setPolicyError(rev uint64, message string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.status.DesiredRevision = rev
	e.status.LastError = message
}
func (e *Engine) Status() Status {
	e.mu.Lock()
	s := e.status
	e.mu.Unlock()
	e.waf.mu.Lock()
	s.WAFDegraded = e.waf.stateError
	e.waf.mu.Unlock()
	s.Counters = Counters{Accepted: e.accepted.Load(), Forwarded: e.forwarded.Load(), Rejected: e.rejected.Load(), WouldReject: e.wouldReject.Load(), UpstreamErrors: e.upstreamErrors.Load(), CaptureDropped: e.captureDropped.Load(), RequestBytes: e.requestBytes.Load(), ResponseBytes: e.responseBytes.Load()}
	return s
}
func (e *Engine) ListBans(service string) []Ban { return e.waf.list(service, e.options.Now()) }
func (e *Engine) AddBan(q BanRequest) (Ban, error) {
	ip, err := normalizedIP(q.IP)
	if err != nil || q.TTLSeconds < 1 || q.TTLSeconds > 3600 || q.Comment == "" || len(q.Comment) > 500 {
		return Ban{}, errors.New("valid IP, bounded TTL and comment required")
	}
	if !e.knownScope(q.ServiceID, q.RouteID) {
		return Ban{}, errors.New("unknown service or ban scope")
	}
	now := e.options.Now()
	b := Ban{ServiceID: q.ServiceID, RouteID: q.RouteID, IP: ip.String(), Reason: q.Comment, Source: "manual", CreatedAt: now, ExpiresAt: now.Add(time.Duration(q.TTLSeconds) * time.Second)}
	if err := e.audit("manual_ban_requested", q.ServiceID, b.IP, q.Comment); err != nil {
		return Ban{}, err
	}
	err = e.waf.add(b)
	if err != nil {
		return b, err
	}
	if err = e.audit("manual_ban_applied", q.ServiceID, b.IP, q.Comment); err != nil {
		return b, err
	}
	return b, nil
}
func (e *Engine) RemoveBan(q UnbanRequest) error {
	ip, err := normalizedIP(q.IP)
	if err != nil || q.Comment == "" || len(q.Comment) > 500 || !e.knownScope(q.ServiceID, q.RouteID) {
		return errors.New("known scope, IP and comment required")
	}
	q.IP = ip.String()
	if err := e.audit("unban_requested", q.ServiceID, q.IP, q.Comment); err != nil {
		return err
	}
	if err := e.waf.remove(q); err != nil {
		return err
	}
	return e.audit("unban_applied", q.ServiceID, q.IP, q.Comment)
}
func (e *Engine) knownScope(service, route string) bool {
	for _, r := range e.active.Load().policy.Routes {
		if r.ServiceID == service && scopeRoute(r) == route {
			return true
		}
	}
	return false
}
func (e *Engine) Close(ctx context.Context) error {
	e.cancel()
	e.mu.Lock()
	e.status.Available = false
	listeners := e.listeners
	e.listeners = map[string]*liveListener{}
	e.mu.Unlock()
	var result error
	for _, l := range listeners {
		result = errors.Join(result, l.server.Shutdown(ctx))
		_ = l.server.Close()
	}
	for _, route := range e.active.Load().routes {
		route.transport.CloseIdleConnections()
	}
	return errors.Join(result, e.stateLock.Close())
}

type exchangeContext struct {
	mu                                sync.Mutex
	aborted                           bool
	request, response                 *bodyCapture
	status                            int
	responseHeaders                   http.Header
	requestTrailers, responseTrailers http.Header
	source                            string
	upstreamError                     bool
	upgraded                          bool
	capturePolicy                     CapturePolicy
	redact                            *redactor
}
type exchangeKey struct{}

func (e *Engine) compile(r Route) *compiledRoute {
	u, _ := url.Parse(r.Upstream)
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: false, MaxConnsPerHost: r.Limits.MaxConcurrent, MaxResponseHeaderBytes: int64(r.Limits.MaxHeaderBytes), MaxIdleConnsPerHost: minInt(r.Limits.MaxConcurrent, 32), IdleConnTimeout: time.Duration(r.Limits.IdleTimeoutSeconds) * time.Second, ResponseHeaderTimeout: time.Duration(r.Limits.UpstreamResponseHeaderTimeoutSeconds) * time.Second, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext, DisableCompression: true}
	c := &compiledRoute{route: r, redact: newRedactor(r.Capture), slots: make(chan struct{}, r.Limits.MaxConcurrent), transport: transport}
	if r.Protocol == "https2" {
		c.transport = newH2Upstream(r, u)
	}
	c.proxy = &httputil.ReverseProxy{Transport: c.transport, FlushInterval: -1, ErrorLog: log.New(io.Discard, "", 0), Rewrite: func(p *httputil.ProxyRequest) {
		p.SetURL(u)
		p.Out.Host = p.In.Host
		p.Out.Trailer = p.In.Trailer
		p.Out.Header.Del("Forwarded")
		p.Out.Header.Del("X-Forwarded-For")
		p.Out.Header.Del("X-Forwarded-Host")
		p.Out.Header.Del("X-Forwarded-Proto")
		p.Out.Header.Del("X-Real-IP")
		p.Out.Header.Del("True-Client-IP")
		p.Out.Header.Del("CF-Connecting-IP")
		p.Out.Header.Set("X-Forwarded-For", p.In.Header.Get("X-CTFM-Effective-IP"))
		p.Out.Header.Set("X-Real-IP", p.In.Header.Get("X-CTFM-Effective-IP"))
		p.Out.Header.Del("X-CTFM-Effective-IP")
		p.Out.Header.Set("X-Forwarded-Host", p.In.Host)
		proto := "http"
		if p.In.TLS != nil {
			proto = "https"
		}
		p.Out.Header.Set("X-Forwarded-Proto", proto)
	}, ErrorHandler: func(w http.ResponseWriter, q *http.Request, _ error) {
		x := q.Context().Value(exchangeKey{}).(*exchangeContext)
		x.mu.Lock()
		x.status = 502
		x.source = "proxy"
		x.upstreamError = true
		x.mu.Unlock()
		e.upstreamErrors.Add(1)
		http.Error(w, "Upstream unavailable", 502)
	}, ModifyResponse: func(response *http.Response) error {
		x := response.Request.Context().Value(exchangeKey{}).(*exchangeContext)
		x.mu.Lock()
		x.status = response.StatusCode
		x.responseHeaders = response.Header.Clone()
		x.response = newBodyCapture(r.Capture, response.Header, c.redact)
		x.source = "upstream"
		if response.StatusCode == http.StatusSwitchingProtocols {
			body, ok := response.Body.(io.ReadWriteCloser)
			if !ok {
				x.mu.Unlock()
				return errors.New("unsupported upstream upgrade")
			}
			x.upgraded = true
			duplex := &duplexCounter{ReadWriteCloser: body, request: x.request, response: x.response}
			response.Body = duplex
			context.AfterFunc(response.Request.Context(), func() { _ = duplex.Close() })
		} else {
			response.Body = &captureReader{ReadCloser: response.Body, capture: x.response, onEOF: func() { x.mu.Lock(); x.responseTrailers = response.Trailer.Clone(); x.mu.Unlock() }}
		}
		x.mu.Unlock()
		return nil
	}}
	return c
}

func (e *Engine) serve(w http.ResponseWriter, q *http.Request, c *compiledRoute, revision uint64) {
	r := c.route
	e.accepted.Add(1)
	started := e.options.Now()
	host, _, err := net.SplitHostPort(q.RemoteAddr)
	if err != nil {
		e.captureDropped.Add(1)
		http.Error(w, "Invalid peer", 400)
		return
	}
	peerAddr, err := normalizedIP(host)
	if err != nil {
		e.captureDropped.Add(1)
		http.Error(w, "Invalid peer", 400)
		return
	}
	peer, client, source, ipErr := ClientIP(q, r.TrustedProxyCIDRs)
	if ipErr != nil {
		peer = peerAddr.String()
		client = peer
		source = "tcp_peer_invalid_forwarding_chain"
	}
	capturedURL, urlTruncated := c.redact.requestURL(q.URL)
	capturedHeaders, headersTruncated := c.redact.header(q.Header)
	x := traffic.Exchange{Metadata: traffic.Metadata{RequestID: e.status.CollectorEpoch + "-" + strconv.FormatUint(e.sequence.Add(1), 10), CollectorEpoch: e.status.CollectorEpoch, ServiceID: r.ServiceID, RouteID: r.ID, PolicyRevision: revision, At: started, UpdatedAt: started, State: "in_progress", Method: q.Method, URL: capturedURL, Upstream: r.Upstream, PeerIP: peer, ClientIP: client, ClientIPSource: source, WAFDecision: "not_evaluated", Truncated: urlTruncated || headersTruncated}, RequestHeaders: capturedHeaders}
	x.HTTPProtocol = "http/1.1"
	if q.ProtoMajor == 2 {
		x.HTTPProtocol = "h2"
	}
	requestTrailers := q.Trailer
	requestCapture := newBodyCapture(r.Capture, q.Header, c.redact)
	state := &exchangeContext{request: requestCapture, source: "proxy", capturePolicy: r.Capture, redact: c.redact}
	q = q.Clone(context.WithValue(q.Context(), exchangeKey{}, state))
	q.Trailer = requestTrailers
	ctx, cancel := context.WithTimeout(q.Context(), time.Duration(r.Limits.MaxConnectionSeconds)*time.Second)
	defer cancel()
	q = q.WithContext(ctx)
	// Context cancellation alone does not interrupt a stalled downstream body
	// read or write. Bound those socket operations too, then clear deadlines
	// before net/http reuses a completed keep-alive connection.
	controller := http.NewResponseController(w)
	deadline, _ := ctx.Deadline()
	_ = controller.SetReadDeadline(deadline)
	_ = controller.SetWriteDeadline(deadline)
	defer func() {
		// Leave expired/read-error deadlines intact while net/http closes or
		// drains the request body after this handler returns.
		if ctx.Err() != nil || state.request.readError() {
			return
		}
		_ = controller.SetReadDeadline(time.Time{})
		_ = controller.SetWriteDeadline(time.Time{})
	}()
	if q.Body != nil {
		q.Body = &captureReader{ReadCloser: q.Body, capture: requestCapture, onEOF: func() { state.mu.Lock(); state.requestTrailers = requestTrailers.Clone(); state.mu.Unlock() }}
	}
	e.emit(x)
	stopProgress := func() {}
	defer func() {
		stopProgress()
		final := e.snapshotExchange(x, state, c.redact, started, true, ctx.Err() != nil)
		e.requestBytes.Add(uint64(final.RequestBytes))
		e.responseBytes.Add(uint64(final.ResponseBytes))
		e.emit(final)
	}()
	reject := func(status int, reason string) {
		state.mu.Lock()
		state.status = status
		state.mu.Unlock()
		x.WAFReason = reason
		e.rejected.Add(1)
		http.Error(&proxyWriter{ResponseWriter: w, state: state}, http.StatusText(status), status)
	}
	if (r.Protocol == "https2" && q.ProtoMajor != 2) || (r.Protocol != "https2" && q.ProtoMajor != 1) || q.Method == http.MethodConnect || q.URL.IsAbs() || q.URL.Host != "" {
		reject(400, "unsupported_request_profile")
		return
	}
	if isTLSProfile(r.Protocol) != (q.TLS != nil) {
		w.Header().Set("Connection", "close")
		reject(400, "transport_profile_changed")
		return
	}
	if q.TLS != nil && !tlsNameMatches(r, q.TLS.ServerName) {
		w.Header().Set("Connection", "close")
		reject(421, "tls_server_name_mismatch")
		return
	}
	headerBytes := len(q.RequestURI) + len(q.Host)
	for key, values := range q.Header {
		for _, v := range values {
			headerBytes += len(key) + len(v)
		}
	}
	if headerBytes > r.Limits.MaxHeaderBytes {
		reject(431, "header_limit")
		return
	}
	if (r.Protocol != "https2" && strings.Contains(strings.ToLower(q.Header.Get("Content-Type")), "application/grpc")) || (q.Header.Get("Upgrade") != "" && (r.Protocol == "https2" || !strings.EqualFold(q.Header.Get("Upgrade"), "websocket"))) {
		reject(415, "unsupported_protocol")
		return
	}
	if r.Host != "" && !strings.EqualFold(q.Host, r.Host) {
		reject(421, "unknown_host")
		return
	}
	if ipErr != nil {
		reject(400, "invalid_forwarding_chain")
		return
	}
	decision := e.waf.check(r, client, e.options.Now())
	x.WAFDecision = decision.decision
	x.WAFReason = decision.reason
	if decision.blocked {
		state.mu.Lock()
		state.source = "waf"
		state.mu.Unlock()
		w.Header().Set("Retry-After", strconv.Itoa(decision.retryAfter))
		w.Header().Set("X-CTFM-WAF-Rule", decision.reason)
		reject(429, decision.reason)
		return
	}
	if decision.decision == "would_block" {
		e.wouldReject.Add(1)
	}
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		reject(503, "connection_capacity")
		return
	}
	if r.Limits.MaxBodyBytes > 0 {
		if q.ContentLength > r.Limits.MaxBodyBytes {
			reject(413, "request_body_limit")
			return
		}
		q.Body = http.MaxBytesReader(w, q.Body, r.Limits.MaxBodyBytes)
	}
	// Intermediate exchanges publish counters only. Incomplete payload chunks
	// never reach the queue, so a secret split across reads cannot leak.
	done, stopped := make(chan struct{}), make(chan struct{})
	base := x
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				e.emit(e.snapshotExchange(base, state, c.redact, started, false, false))
			}
		}
	}()
	stopProgress = func() { close(done); <-stopped }
	q.Header.Set("X-CTFM-Effective-IP", client)
	e.forwarded.Add(1)
	c.proxy.ServeHTTP(&proxyWriter{ResponseWriter: w, state: state}, q)
}

func (e *Engine) snapshotExchange(base traffic.Exchange, state *exchangeContext, redact *redactor, started time.Time, final, cancelled bool) traffic.Exchange {
	x := base
	now := e.options.Now()
	x.UpdatedAt = now
	x.DurationMS = mathDuration(now.Sub(started))
	state.mu.Lock()
	status, source, upgraded, aborted, response := state.status, state.source, state.upgraded, state.aborted, state.response
	headers := state.responseHeaders.Clone()
	requestTrailers, responseTrailers := state.requestTrailers.Clone(), state.responseTrailers.Clone()
	state.mu.Unlock()
	x.Status = status
	x.ResponseSource = source
	if final {
		x.EndAt = &now
		x.State = "completed"
		if x.Status == 0 {
			x.Status = 502
		}
		if cancelled || aborted || state.request.readError() || (response != nil && response.readError()) {
			x.State = "aborted"
		}
		x.RequestBody = state.request.snapshot()
		if response != nil {
			x.ResponseBody = response.snapshot()
		}
	} else {
		x.RequestBody = state.request.progress()
		if response != nil {
			x.ResponseBody = response.progress()
		}
	}
	if upgraded {
		x.RequestBody.Data = ""
		x.RequestBody.CapturedBytes = 0
		x.RequestBody.NotCapturedReason = "websocket_frames_not_captured"
		x.ResponseBody.Data = ""
		x.ResponseBody.CapturedBytes = 0
		x.ResponseBody.NotCapturedReason = "websocket_frames_not_captured"
	}
	if x.State == "aborted" {
		x.RequestBody.Data = ""
		x.RequestBody.CapturedBytes = 0
		x.RequestBody.NotCapturedReason = "aborted_exchange"
		x.ResponseBody.Data = ""
		x.ResponseBody.CapturedBytes = 0
		x.ResponseBody.NotCapturedReason = "aborted_exchange"
	}
	x.RequestBytes = x.RequestBody.ObservedBytes
	x.ResponseBytes = x.ResponseBody.ObservedBytes
	var headersTruncated bool
	x.ResponseHeaders, headersTruncated = redact.header(headers)
	if final {
		var dropped bool
		x.RequestTrailers, dropped = redact.header(requestTrailers)
		headersTruncated = headersTruncated || dropped
		x.ResponseTrailers, dropped = redact.header(responseTrailers)
		headersTruncated = headersTruncated || dropped
	}
	x.Truncated = x.Truncated || headersTruncated || x.RequestBody.Truncated || x.ResponseBody.Truncated
	return x
}

type proxyWriter struct {
	http.ResponseWriter
	state *exchangeContext
}

func (w *proxyWriter) WriteHeader(status int) {
	if status >= 200 {
		w.state.mu.Lock()
		w.state.status = status
		w.state.responseHeaders = w.Header().Clone()
		if w.state.source != "upstream" {
			w.state.response = newBodyCapture(w.state.capturePolicy, w.Header(), w.state.redact)
		}
		w.state.mu.Unlock()
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *proxyWriter) Write(p []byte) (int, error) {
	w.state.mu.Lock()
	status := w.state.status
	w.state.mu.Unlock()
	if status == 0 {
		w.WriteHeader(200)
	}
	n, err := w.ResponseWriter.Write(p)
	w.state.mu.Lock()
	response, source := w.state.response, w.state.source
	if err != nil {
		w.state.aborted = true
	}
	w.state.mu.Unlock()
	if source != "upstream" && response != nil {
		response.write(p[:n])
		response.mu.Lock()
		response.complete = err == nil && n == len(p)
		response.mu.Unlock()
	}
	return n, err
}

func (w *proxyWriter) Flush() { _ = http.NewResponseController(w.ResponseWriter).Flush() }
func (w *proxyWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}
func (w *proxyWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type duplexCounter struct {
	io.ReadWriteCloser
	request, response *bodyCapture
}

func (d *duplexCounter) Read(p []byte) (int, error) {
	n, e := d.ReadWriteCloser.Read(p)
	if n > 0 {
		d.response.mu.Lock()
		d.response.observed += int64(n)
		d.response.mu.Unlock()
	}
	return n, e
}
func (d *duplexCounter) Write(p []byte) (int, error) {
	n, e := d.ReadWriteCloser.Write(p)
	if n > 0 {
		d.request.mu.Lock()
		d.request.observed += int64(n)
		d.request.mu.Unlock()
	}
	return n, e
}
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func mathDuration(d time.Duration) float64 {
	if d < 0 {
		return 0
	}
	return float64(d) / float64(time.Millisecond)
}

type boundedListener struct {
	net.Listener
	slots chan struct{}
	done  <-chan struct{}
}

// Select the immutable active transport after accepting each TCP connection.
// This permits atomic HTTP/TLS policy changes on an existing proxy listener;
// connections using the previous transport are rejected by serve.
type profileListener struct {
	net.Listener
	engine    *Engine
	address   string
	tlsConfig *tls.Config
}

func (l *profileListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if route := l.engine.active.Load().routes[l.address]; route != nil && isTLSProfile(route.route.Protocol) {
		return tls.Server(conn, l.tlsConfig), nil
	}
	return conn, nil
}

func (l *boundedListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &boundedConn{Conn: c, release: func() { <-l.slots }}, nil
}

type boundedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *boundedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }

func (e *Engine) ReportPolicyFileError() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.status.LastError = "desired policy file unavailable or invalid; last-known-good retained"
}
