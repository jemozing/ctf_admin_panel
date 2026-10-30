package traffic

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Tokens struct{ Ingest, Read string }

func validSecret(s string) bool {
	return len(s) >= 32 && len(s) <= 256 && !strings.ContainsAny(s, " \r\n\t")
}

// Handler authenticates recorder access separately from dashboard sessions.
// Ingest credentials cannot read captured data, and read credentials cannot
// change records. RBAC/sensitive access are rechecked by the dashboard gateway.
func Handler(store *Store, tokens Tokens) (http.Handler, error) {
	if store == nil || !validSecret(tokens.Ingest) || !validSecret(tokens.Read) || tokens.Ingest == tokens.Read {
		return nil, errors.New("recorder needs distinct strong ingest/read tokens")
	}
	slots := make(chan struct{}, 32)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
			respond(w, 200, map[string]string{"status": "ok"})
			return
		}
		if r.URL.RawQuery != "" && r.URL.Path != "/v1/exchanges" {
			httpError(w, 400, "invalid_query")
			return
		}
		if len(r.Header.Values("Authorization")) != 1 {
			httpError(w, 401, "unauthorized")
			return
		}
		secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if secret == r.Header.Get("Authorization") {
			httpError(w, 401, "unauthorized")
			return
		}
		expected := tokens.Read
		if r.Method == http.MethodPost && r.URL.Path == "/v1/exchanges" {
			expected = tokens.Ingest
		}
		if subtle.ConstantTimeCompare([]byte(secret), []byte(expected)) != 1 {
			httpError(w, 401, "unauthorized")
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			httpError(w, 503, "recorder_busy")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		switch {
		case r.URL.Path == "/v1/status" && r.Method == http.MethodGet:
			value, err := store.Status(ctx)
			if err != nil {
				httpError(w, 503, "recorder_unavailable")
				return
			}
			respond(w, 200, value)
		case r.URL.Path == "/v1/exchanges" && r.Method == http.MethodPost:
			var value Exchange
			reader := http.MaxBytesReader(w, r.Body, MaxExchangeBytes)
			decoder := json.NewDecoder(reader)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&value); err != nil {
				httpError(w, 400, "invalid_exchange")
				return
			}
			if err := decoder.Decode(new(any)); err != io.EOF {
				httpError(w, 400, "invalid_exchange")
				return
			}
			sequence, err := store.Ingest(ctx, value)
			if errors.Is(err, ErrConflict) {
				httpError(w, 409, "exchange_conflict")
				return
			}
			if errors.Is(err, ErrQuota) {
				httpError(w, 507, "recorder_quota")
				return
			}
			if err != nil {
				httpError(w, 400, "exchange_not_stored")
				return
			}
			respond(w, 202, map[string]any{"stored": true, "sequence": sequence})
		case r.URL.Path == "/v1/exchanges" && r.Method == http.MethodGet:
			query, err := ParseRawQuery(r.URL.RawQuery)
			if err != nil {
				httpError(w, 400, "invalid_query")
				return
			}
			value, err := store.List(ctx, query)
			if err != nil {
				httpError(w, 400, "invalid_query_or_recorder_unavailable")
				return
			}
			respond(w, 200, value)
		case strings.HasPrefix(r.URL.Path, "/v1/exchanges/") && r.Method == http.MethodGet:
			id := strings.TrimPrefix(r.URL.Path, "/v1/exchanges/")
			if !validID(id) {
				httpError(w, 400, "invalid_request_id")
				return
			}
			value, err := store.Detail(ctx, id)
			if errors.Is(err, ErrNotFound) {
				httpError(w, 404, "not_found")
				return
			}
			if err != nil {
				httpError(w, 503, "recorder_unavailable")
				return
			}
			respond(w, 200, value)
		default:
			httpError(w, 404, "not_found")
		}
	}), nil
}

func respond(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func httpError(w http.ResponseWriter, status int, code string) {
	respond(w, status, map[string]string{"code": code, "message": strings.ReplaceAll(code, "_", " ")})
}

func ParseRawQuery(raw string) (Query, error) {
	v, err := url.ParseQuery(raw)
	if err != nil {
		return Query{}, err
	}
	return ParseQuery(v)
}

func ParseQuery(v url.Values) (Query, error) {
	var out Query
	var err error
	allowed := map[string]bool{"service_id": true, "route_id": true, "from": true, "until": true, "ip": true, "method": true, "status": true, "url": true, "waf": true, "cursor": true, "limit": true}
	for key, list := range v {
		if !allowed[key] || (key != "service_id" && len(list) != 1) {
			return out, errors.New("unknown or duplicated traffic query option")
		}
	}
	out.ServiceIDs = v["service_id"]
	out.RouteID = v.Get("route_id")
	out.From = v.Get("from")
	out.Until = v.Get("until")
	out.IP = v.Get("ip")
	out.Method = v.Get("method")
	out.Status = v.Get("status")
	out.URL = v.Get("url")
	out.WAF = v.Get("waf")
	out.Cursor = v.Get("cursor")
	if v.Has("limit") {
		out.Limit, err = strconv.Atoi(v.Get("limit"))
		if err != nil {
			return out, err
		}
	}
	if _, _, err := querySQL(out); err != nil {
		return out, err
	}
	if (v.Has("limit") && out.Limit < 1) || out.Limit > 200 {
		return out, errors.New("invalid traffic limit")
	}
	return out, nil
}

type Client struct {
	base  string
	token string
	http  *http.Client
}

func NewClient(base, token string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || !validSecret(token) {
		return nil, errors.New("invalid recorder endpoint or token")
	}
	transport := &http.Transport{Proxy: nil, MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 2 * time.Second, DisableCompression: true}
	return &Client{base: strings.TrimRight(base, "/"), token: token, http: &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("recorder redirect refused") }}}, nil
}

// NewUnixClient is a fixed, local HTTP transport. Request input cannot choose a
// network address, proxy server, alternate socket or redirect destination.
func NewUnixClient(socketPath, token string) (*Client, error) {
	if err := validateUnixPath(socketPath); err != nil {
		return nil, err
	}
	c, err := NewClient("http://recorder", token)
	if err != nil {
		return nil, err
	}
	t := c.http.Transport.(*http.Transport)
	t.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socketPath)
	}
	return c, nil
}

func (c *Client) Close() {
	if t, ok := c.http.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
}
func (c *Client) request(ctx context.Context, method, path string, body any, out any, want int) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		if len(encoded) > MaxExchangeBytes {
			return errors.New("exchange request exceeds limit")
		}
		reader = bytes.NewReader(encoded)
	}
	r, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", "Bearer "+c.token)
	r.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(r)
	if err != nil {
		return errors.New("traffic recorder transport unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != want {
		return fmt.Errorf("traffic recorder returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 4<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return errors.New("invalid traffic recorder response")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("trailing or oversized traffic recorder response")
	}
	return nil
}
func (c *Client) Ingest(ctx context.Context, value Exchange) error {
	var result struct {
		Stored   bool  `json:"stored"`
		Sequence int64 `json:"sequence"`
	}
	if err := c.request(ctx, http.MethodPost, "/v1/exchanges", value, &result, 202); err != nil {
		return err
	}
	if !result.Stored || result.Sequence < 1 {
		return errors.New("traffic recorder did not acknowledge storage")
	}
	return nil
}
func (c *Client) Status(ctx context.Context) (Status, error) {
	var out Status
	err := c.request(ctx, http.MethodGet, "/v1/status", nil, &out, 200)
	return out, err
}
func (c *Client) Detail(ctx context.Context, id string) (Exchange, error) {
	var out Exchange
	if !validID(id) {
		return out, errors.New("invalid traffic request ID")
	}
	err := c.request(ctx, http.MethodGet, "/v1/exchanges/"+url.PathEscape(id), nil, &out, 200)
	return out, err
}
func (c *Client) List(ctx context.Context, q Query) (Page, error) {
	var out Page
	values := QueryValues(q)
	if _, err := ParseQuery(values); err != nil {
		return out, err
	}
	path := "/v1/exchanges"
	if len(values) > 0 {
		path += "?" + values.Encode()
	}
	err := c.request(ctx, http.MethodGet, path, nil, &out, 200)
	return out, err
}

func QueryValues(q Query) url.Values {
	v := url.Values{}
	for _, id := range q.ServiceIDs {
		v.Add("service_id", id)
	}
	for key, value := range map[string]string{"route_id": q.RouteID, "from": q.From, "until": q.Until, "ip": q.IP, "method": q.Method, "status": q.Status, "url": q.URL, "waf": q.WAF, "cursor": q.Cursor} {
		if value != "" {
			v.Set(key, value)
		}
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	return v
}
