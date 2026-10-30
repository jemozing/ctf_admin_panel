package packets

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
	"path/filepath"
	"strings"
	"time"
)

type Tokens struct{ Ingest, Read string }

func validSecret(s string) bool {
	return len(s) >= 32 && len(s) <= 256 && !strings.ContainsAny(s, " \r\n\t")
}

// Handler authenticates every data endpoint independently of panel sessions.
// The daemon additionally restricts network ingress to capture writes and Unix
// control to reads/exports. The panel gateway enforces user RBAC and reauth.
func Handler(store *Store, tokens Tokens) (http.Handler, error) {
	if store == nil || !validSecret(tokens.Ingest) || !validSecret(tokens.Read) || tokens.Ingest == tokens.Read {
		return nil, errors.New("packet archive needs distinct strong ingest/read tokens")
	}
	slots := make(chan struct{}, 16)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
			respond(w, 200, map[string]string{"status": "ok"})
			return
		}
		if r.URL.RawQuery != "" && ((r.URL.Path != "/v1/packets" && r.URL.Path != "/v1/flows") || r.Method != http.MethodGet) || len(r.URL.RawQuery) > 12<<10 {
			httpError(w, 400, "invalid_query")
			return
		}
		if len(r.Header.Values("Authorization")) != 1 || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			httpError(w, 401, "unauthorized")
			return
		}
		secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		expected := tokens.Read
		if r.Method == http.MethodPost && r.URL.Path == "/v1/packets" {
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
			httpError(w, 503, "packet_archive_busy")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if strings.HasPrefix(r.URL.Path, "/v1/descriptors") {
			store.descriptorHTTP(w, r)
			return
		}
		if store.decodeHTTP(w, r) {
			return
		}
		if store.flowHTTP(w, r) {
			return
		}
		switch {
		case r.URL.Path == "/v1/status" && r.Method == http.MethodGet:
			v, err := store.Status(ctx)
			if err != nil {
				httpError(w, 503, "packet_archive_unavailable")
				return
			}
			respond(w, 200, v)
		case r.URL.Path == "/v1/packets" && r.Method == http.MethodPost:
			var v Record
			if decodeBody(w, r, &v, MaxRecordBytes) != nil {
				httpError(w, 400, "invalid_packet")
				return
			}
			seq, err := store.Ingest(ctx, v)
			if errors.Is(err, ErrConflict) {
				httpError(w, 409, "packet_conflict")
				return
			}
			if errors.Is(err, ErrQuota) {
				httpError(w, 507, "packet_archive_quota")
				return
			}
			if err != nil {
				httpError(w, 400, "packet_not_stored")
				return
			}
			respond(w, 202, map[string]any{"stored": true, "sequence": seq})
		case r.URL.Path == "/v1/packets" && r.Method == http.MethodGet:
			q, err := ParseRawQuery(r.URL.RawQuery)
			if err != nil {
				httpError(w, 400, "invalid_query")
				return
			}
			v, err := store.List(ctx, q)
			if err != nil {
				httpError(w, 400, "invalid_query_or_archive_unavailable")
				return
			}
			respond(w, 200, v)
		case r.URL.Path == "/v1/export" && r.Method == http.MethodPost:
			var q ExportRequest
			if decodeBody(w, r, &q, 16<<10) != nil {
				httpError(w, 400, "invalid_export")
				return
			}
			v, err := store.ExportPCAP(ctx, q)
			if err != nil {
				httpError(w, 400, "invalid_export_or_archive_unavailable")
				return
			}
			respond(w, 200, v)
		case strings.HasPrefix(r.URL.Path, "/v1/packets/") && r.Method == http.MethodGet:
			id := strings.TrimPrefix(r.URL.Path, "/v1/packets/")
			raw := strings.HasSuffix(id, "/raw")
			if raw {
				id = strings.TrimSuffix(id, "/raw")
			}
			if !validID(id) {
				httpError(w, 400, "invalid_packet_id")
				return
			}
			var v any
			var err error
			if raw {
				v, err = store.Raw(ctx, id)
			} else {
				v, err = store.Detail(ctx, id)
			}
			if errors.Is(err, ErrNotFound) {
				httpError(w, 404, "not_found")
				return
			}
			if err != nil {
				httpError(w, 503, "packet_archive_unavailable")
				return
			}
			respond(w, 200, v)
		default:
			httpError(w, 404, "not_found")
		}
	}), nil
}

// IngestOnly ensures a read credential cannot retrieve payload over the host
// network listener. ReadOnly ensures the local panel cannot inject packets.
func IngestOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" && r.Method == http.MethodGet || r.URL.Path == "/v1/packets" && r.Method == http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		httpError(w, 404, "not_found")
	})
}
func ReadOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/packets" {
			httpError(w, 404, "not_found")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func decodeBody(w http.ResponseWriter, r *http.Request, v any, limit int64) error {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func respond(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func httpError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	respond(w, status, map[string]string{"code": code, "message": strings.ReplaceAll(code, "_", " ")})
}

type Client struct {
	base, token string
	http        *http.Client
}

func NewClient(base, token string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || !validSecret(token) {
		return nil, errors.New("invalid packet archive endpoint or token")
	}
	transport := &http.Transport{Proxy: nil, MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 2 * time.Second, DisableCompression: true}
	return &Client{base: strings.TrimRight(base, "/"), token: token, http: &http.Client{Transport: transport, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("packet archive redirect refused") }}}, nil
}
func NewUnixClient(path, token string) (*Client, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 || path == "/" {
		return nil, errors.New("invalid packet archive Unix socket")
	}
	c, err := NewClient("http://packets", token)
	if err != nil {
		return nil, err
	}
	c.http.Transport.(*http.Transport).DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", path)
	}
	return c, nil
}
func (c *Client) Close() {
	if t, ok := c.http.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
}
func (c *Client) request(ctx context.Context, method, path string, body, out any, want int) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		if len(encoded) > MaxRecordBytes {
			return errors.New("packet archive request exceeds bound")
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
		return errors.New("packet archive transport unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != want {
		switch response.StatusCode {
		case 400:
			return ErrInvalid
		case 404:
			return ErrNotFound
		case 409:
			return ErrConflict
		case 507:
			return ErrQuota
		}
		return fmt.Errorf("packet archive returned HTTP %d", response.StatusCode)
	}
	d := json.NewDecoder(io.LimitReader(response.Body, 12<<20))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid or oversized packet archive response")
	}
	return nil
}
func (c *Client) Ingest(ctx context.Context, v Record) error {
	var result struct {
		Stored   bool  `json:"stored"`
		Sequence int64 `json:"sequence"`
	}
	if err := c.request(ctx, http.MethodPost, "/v1/packets", v, &result, 202); err != nil {
		return err
	}
	if !result.Stored || result.Sequence < 1 {
		return errors.New("packet archive did not acknowledge storage")
	}
	return nil
}
func (c *Client) Status(ctx context.Context) (Status, error) {
	var out Status
	err := c.request(ctx, http.MethodGet, "/v1/status", nil, &out, 200)
	return out, err
}
func (c *Client) List(ctx context.Context, q Query) (Page, error) {
	var out Page
	values := QueryValues(q)
	if _, err := ParseQuery(values); err != nil {
		return out, err
	}
	path := "/v1/packets"
	if len(values) > 0 {
		path += "?" + values.Encode()
	}
	err := c.request(ctx, http.MethodGet, path, nil, &out, 200)
	return out, err
}
func (c *Client) Detail(ctx context.Context, id string) (Metadata, error) {
	var out Metadata
	if !validID(id) {
		return out, errors.New("invalid packet ID")
	}
	err := c.request(ctx, http.MethodGet, "/v1/packets/"+url.PathEscape(id), nil, &out, 200)
	return out, err
}
func (c *Client) Raw(ctx context.Context, id string) (Record, error) {
	var out Record
	if !validID(id) {
		return out, errors.New("invalid packet ID")
	}
	err := c.request(ctx, http.MethodGet, "/v1/packets/"+url.PathEscape(id)+"/raw", nil, &out, 200)
	return out, err
}
func (c *Client) ExportPCAP(ctx context.Context, q ExportRequest) (Export, error) {
	var out Export
	err := c.request(ctx, http.MethodPost, "/v1/export", q, &out, 200)
	if err == nil && (len(out.Data) > MaxExportBytes || out.Packets < 0 || out.Packets > MaxExportPackets) {
		return Export{}, errors.New("invalid packet archive export response")
	}
	return out, err
}
