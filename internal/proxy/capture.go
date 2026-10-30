package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/ctf-service-manager/ctf-service-manager/internal/traffic"
)

var privateFields = []string{"authorization", "proxy-authorization", "cookie", "set-cookie", "password", "passwd", "token", "access_token", "refresh_token", "secret", "api_key", "x-api-key", "apikey", "key", "flag"}

type redactor struct {
	headers, query, fields map[string]bool
	patterns               []*regexp.Regexp
}

func newRedactor(c CapturePolicy) *redactor {
	r := &redactor{headers: map[string]bool{}, query: map[string]bool{}, fields: map[string]bool{}}
	for _, name := range privateFields {
		r.headers[name] = true
		r.query[name] = true
		r.fields[name] = true
	}
	for _, name := range c.RedactHeaders {
		r.headers[strings.ToLower(name)] = true
	}
	for _, name := range c.RedactQueryFields {
		r.query[strings.ToLower(name)] = true
	}
	for _, name := range c.RedactBodyFields {
		r.fields[strings.ToLower(name)] = true
	}
	for _, pattern := range c.BodyPatterns {
		if re, e := regexp.Compile(pattern); e == nil {
			r.patterns = append(r.patterns, re)
		}
	}
	return r
}

func (r *redactor) text(s string) string {
	const budget = 65536
	for _, p := range r.patterns {
		matches := p.FindAllStringIndex(s, 8193)
		if len(matches) > 8192 {
			return "[OMITTED:redaction_budget]"
		}
		var out strings.Builder
		out.Grow(minInt(len(s), budget))
		previous := 0
		for _, m := range matches {
			if out.Len()+m[0]-previous+len("[REDACTED]") > budget {
				return "[OMITTED:redaction_budget]"
			}
			out.WriteString(s[previous:m[0]])
			out.WriteString("[REDACTED]")
			previous = m[1]
		}
		if out.Len()+len(s)-previous > budget {
			return "[OMITTED:redaction_budget]"
		}
		out.WriteString(s[previous:])
		s = out.String()
	}
	return s
}

func (r *redactor) header(h http.Header) (http.Header, bool) {
	out := make(http.Header, len(h))
	truncated := false
	budget := 32768
	totalValues := 0
	for key, values := range h {
		if len(out) >= 64 {
			return out, true
		}
		if len(key) > 128 {
			truncated = true
			continue
		}
		for i, v := range values {
			if i >= 32 || totalValues >= 128 {
				return out, true
			}
			totalValues++
			if r.headers[strings.ToLower(key)] {
				v = "[REDACTED]"
			} else {
				v = r.text(v)
			}
			if len(v) > 4096 {
				v = v[:4096] + "[TRUNCATED]"
				truncated = true
			}
			if len(key)+len(v) > budget {
				return out, true
			}
			budget -= len(key) + len(v)
			out.Add(key, strings.ToValidUTF8(v, "�"))
		}
	}
	return out, truncated
}
func (r *redactor) requestURL(u *url.URL) (string, bool) {
	path := u.EscapedPath()
	truncated := false
	if path == "" {
		path = "/"
	}
	if len(path) > 8192 {
		path = "/[omitted:path_budget]"
		truncated = true
	}
	if u.RawQuery == "" {
		return r.text(path), truncated
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return r.text(path) + "?[REDACTED:malformed_query]", true
	}
	for key, values := range query {
		if r.query[strings.ToLower(key)] {
			query[key] = []string{"[REDACTED]"}
		} else {
			for i, v := range values {
				values[i] = r.text(v)
			}
		}
	}
	result := r.text(path) + "?" + query.Encode()
	if len(result) > 8192 {
		result = r.text(path) + "?capture=omitted_query_budget"
		truncated = true
	}
	return result, truncated
}

type bodyCapture struct {
	mu       sync.Mutex
	data     []byte
	observed int64
	limit    int
	policy   CapturePolicy
	header   http.Header
	redact   *redactor
	err      bool
	complete bool
}

func newBodyCapture(p CapturePolicy, h http.Header, r *redactor) *bodyCapture {
	meta := http.Header{}
	meta.Set("Content-Type", h.Get("Content-Type"))
	meta.Set("Content-Encoding", h.Get("Content-Encoding"))
	return &bodyCapture{limit: p.MaxBodyBytes, policy: p, header: meta, redact: r}
}
func (c *bodyCapture) write(p []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.observed += int64(len(p))
	if (c.policy.Mode == "bounded_body" || c.policy.Mode == "grpc_body") && len(c.data) < c.limit {
		n := c.limit - len(c.data)
		if n > len(p) {
			n = len(p)
		}
		c.data = append(c.data, p[:n]...)
	}
}
func (c *bodyCapture) snapshot() traffic.Body {
	c.mu.Lock()
	defer c.mu.Unlock()
	rawType, rawEncoding := c.header.Get("Content-Type"), c.header.Get("Content-Encoding")
	body := traffic.Body{ObservedBytes: c.observed, ContentType: c.header.Get("Content-Type"), ContentEncoding: c.header.Get("Content-Encoding"), Truncated: c.observed > int64(len(c.data)) && (c.policy.Mode == "bounded_body" || c.policy.Mode == "grpc_body")}
	if c.redact.headers["content-type"] {
		body.ContentType = "[REDACTED]"
	} else {
		body.ContentType = c.redact.text(body.ContentType)
	}
	if c.redact.headers["content-encoding"] {
		body.ContentEncoding = "[REDACTED]"
	} else {
		body.ContentEncoding = c.redact.text(body.ContentEncoding)
	}
	if len(body.ContentType) > 256 || len(body.ContentEncoding) > 128 {
		body.ContentType = ""
		body.ContentEncoding = ""
		body.NotCapturedReason = "content_metadata_budget"
		return body
	}
	if c.policy.Mode != "bounded_body" && c.policy.Mode != "grpc_body" {
		body.NotCapturedReason = "metadata_only"
		return body
	}
	if c.err {
		body.NotCapturedReason = "stream_read_error"
		return body
	}
	if rawEncoding != "" && rawEncoding != "identity" {
		body.NotCapturedReason = "encoded_body_not_decoded"
		return body
	}
	if c.observed == 0 {
		body.Encoding = "utf8"
		return body
	}
	if c.policy.Mode == "grpc_body" {
		if c.redact.headers["content-type"] || c.redact.headers["content-encoding"] {
			body.NotCapturedReason = "grpc_content_metadata_redacted"
			return body
		}
		media, _, err := mime.ParseMediaType(rawType)
		if err != nil || !(media == "application/grpc" || strings.HasPrefix(media, "application/grpc+")) {
			body.NotCapturedReason = "opaque_capture_requires_grpc"
			return body
		}
		if len(c.policy.RedactBodyFields) > 0 || len(c.policy.BodyPatterns) > 0 {
			body.NotCapturedReason = "opaque_grpc_redaction_unavailable"
			return body
		}
		body.SensitiveRaw = true
		body.Encoding = "base64"
		body.Data = base64.StdEncoding.EncodeToString(c.data)
		body.CapturedBytes = int64(len(c.data))
		if !c.complete {
			body.NotCapturedReason = "grpc_capture_incomplete"
			body.Truncated = true
		}
		return body
	}
	if c.observed > 0 && !c.complete {
		body.NotCapturedReason = "body_not_fully_observed"
		return body
	}

	if body.Truncated {
		body.NotCapturedReason = "truncated_body_redaction_not_complete"
		return body
	}
	if !utf8.Valid(c.data) {
		body.NotCapturedReason = "unsupported_binary_redaction"
		return body
	}
	contentType, _, err := mime.ParseMediaType(rawType)
	if err != nil {
		body.NotCapturedReason = "unsupported_content_type"
		return body
	}
	var data []byte
	switch {
	case contentType == "application/json" || strings.HasSuffix(contentType, "+json"):
		var value any
		decoder := json.NewDecoder(bytes.NewReader(c.data))
		decoder.UseNumber()
		if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF {
			body.NotCapturedReason = "invalid_json_redaction"
			return body
		}
		if !c.redact.walk(value, 0) {
			body.NotCapturedReason = "json_depth_budget"
			return body
		}
		data, _ = json.Marshal(value)
	case contentType == "application/x-www-form-urlencoded":
		values, e := url.ParseQuery(string(c.data))
		if e != nil {
			body.NotCapturedReason = "invalid_form_redaction"
			return body
		}
		for key, items := range values {
			if c.redact.fields[strings.ToLower(key)] {
				values[key] = []string{"[REDACTED]"}
			} else {
				for i, v := range items {
					items[i] = c.redact.text(v)
				}
			}
		}
		data = []byte(values.Encode())
	case strings.HasPrefix(contentType, "text/"):
		// Plain text has no structured field boundaries. Configured expressions
		// are applied to the complete bounded body, never to incomplete chunks.
		data = []byte(c.redact.text(string(c.data)))
	default:
		body.NotCapturedReason = "unsupported_content_type"
		return body
	}
	if string(data) == "[OMITTED:redaction_budget]" {
		body.NotCapturedReason = "redaction_budget"
		return body
	}
	if len(data) > c.limit {
		body.NotCapturedReason = "redacted_representation_exceeds_budget"
		body.Truncated = true
		return body
	}
	body.Encoding = "utf8"
	body.Data = string(data)
	body.CapturedBytes = int64(len(c.data))
	return body
}
func (r *redactor) walk(v any, depth int) bool {
	if depth > 32 {
		return false
	}
	switch value := v.(type) {
	case map[string]any:
		for key, child := range value {
			if r.fields[strings.ToLower(key)] {
				value[key] = "[REDACTED]"
			} else if s, ok := child.(string); ok {
				value[key] = r.text(s)
			} else if !r.walk(child, depth+1) {
				return false
			}
		}
	case []any:
		for i, child := range value {
			if s, ok := child.(string); ok {
				value[i] = r.text(s)
			} else if !r.walk(child, depth+1) {
				return false
			}
		}
	}
	return true
}

type captureReader struct {
	io.ReadCloser
	capture *bodyCapture
	onEOF   func()
}

func (r *captureReader) Read(p []byte) (int, error) {
	n, e := r.ReadCloser.Read(p)
	if n > 0 {
		r.capture.write(p[:n])
	}
	if e == io.EOF {
		r.capture.mu.Lock()
		r.capture.complete = true
		r.capture.mu.Unlock()
		if r.onEOF != nil {
			r.onEOF()
		}
	}
	if e != nil && e != io.EOF {
		r.capture.mu.Lock()
		r.capture.err = true
		r.capture.mu.Unlock()
	}
	return n, e
}

func (c *bodyCapture) readError() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.err }
func (c *bodyCapture) progress() traffic.Body {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := traffic.Body{ObservedBytes: c.observed, NotCapturedReason: "in_progress"}
	if s := c.header.Get("Content-Type"); len(s) <= 256 {
		if c.redact.headers["content-type"] {
			b.ContentType = "[REDACTED]"
		} else {
			b.ContentType = c.redact.text(s)
		}
	}
	if s := c.header.Get("Content-Encoding"); len(s) <= 128 {
		if c.redact.headers["content-encoding"] {
			b.ContentEncoding = "[REDACTED]"
		} else {
			b.ContentEncoding = c.redact.text(s)
		}
	}
	return b
}
