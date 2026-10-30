package traffic

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

var privateFields = map[string]bool{"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true, "x-api-key": true, "api_key": true, "apikey": true, "access_token": true, "refresh_token": true, "token": true, "password": true, "passwd": true, "secret": true, "flag": true}

func sanitizeExchange(e *Exchange, now time.Time) error {
	if !validID(e.RequestID) || !validID(e.CollectorEpoch) || !validID(e.ServiceID) || !validID(e.RouteID) {
		return errors.New("invalid traffic exchange identity")
	}
	if e.At.IsZero() || e.UpdatedAt.IsZero() || e.UpdatedAt.Before(e.At) || e.At.After(now.Add(time.Minute)) || e.At.Before(now.Add(-24*time.Hour)) {
		return errors.New("invalid traffic exchange time")
	}
	if e.State != "in_progress" && e.State != "completed" && e.State != "aborted" {
		return errors.New("invalid traffic exchange state")
	}
	if e.EndAt != nil && (e.EndAt.Before(e.At) || e.EndAt.After(now.Add(time.Minute))) {
		return errors.New("invalid traffic completion time")
	}
	if !validToken(e.Method, 32) || len(e.URL) > 8192 || len(e.Upstream) > 2048 || len(e.ClientIPSource) > 64 || len(e.WAFReason) > 512 || !validToken(e.WAFDecision, 64) || !validDuration(e.DurationMS) || e.RequestBytes < 0 || e.ResponseBytes < 0 || e.Status < 0 || e.Status > 599 || (e.Status > 0 && e.Status < 100) {
		return errors.New("invalid traffic exchange metadata")
	}
	if e.HTTPProtocol != "" && e.HTTPProtocol != "http/1.1" && e.HTTPProtocol != "h2" {
		return errors.New("invalid HTTP protocol provenance")
	}
	if e.ResponseSource != "" && e.ResponseSource != "upstream" && e.ResponseSource != "proxy" && e.ResponseSource != "waf" {
		return errors.New("invalid traffic response source")
	}
	for _, target := range []*string{&e.ClientIP, &e.PeerIP} {
		ip, err := netip.ParseAddr(*target)
		if err != nil || ip.Zone() != "" {
			return errors.New("invalid traffic client IP")
		}
		*target = ip.Unmap().String()
	}
	u, err := url.ParseRequestURI(e.URL)
	if err != nil {
		return errors.New("invalid traffic URL")
	}
	u.User = nil
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return errors.New("invalid traffic URL query")
	}
	for key := range query {
		if privateFields[strings.ToLower(key)] {
			query[key] = []string{"[REDACTED]"}
		}
	}
	u.RawQuery = query.Encode()
	e.URL = safeText(u.String())
	e.WAFReason = safeText(e.WAFReason)
	if e.Upstream != "" {
		up, err := url.Parse(e.Upstream)
		if err != nil || up.User != nil || up.RawQuery != "" || up.Fragment != "" {
			return errors.New("invalid recorded upstream")
		}
	}
	if e.RequestHeaders, err = cleanHeaders(e.RequestHeaders); err != nil {
		return err
	}
	if e.ResponseHeaders, err = cleanHeaders(e.ResponseHeaders); err != nil {
		return err
	}
	if e.RequestTrailers, err = cleanHeaders(e.RequestTrailers); err != nil {
		return err
	}
	if e.ResponseTrailers, err = cleanHeaders(e.ResponseTrailers); err != nil {
		return err
	}
	for _, body := range []*Body{&e.RequestBody, &e.ResponseBody} {
		if body.SensitiveRaw && e.HTTPProtocol != "h2" {
			return errors.New("opaque gRPC capture requires H2 provenance")
		}
		if err := cleanBody(body); err != nil {
			return err
		}
	}
	return nil
}

func safeText(s string) string {
	return strings.Map(func(r rune) rune {
		if (r < 32 && r != '\t' && r != '\n' && r != '\r') || r == 127 {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, "�"))
}

func cleanHeaders(in http.Header) (http.Header, error) {
	if len(in) > 64 {
		return nil, errors.New("too many recorded HTTP headers")
	}
	out := http.Header{}
	size := 0
	values := 0
	for key, list := range in {
		if !validToken(key, 128) || len(list) > 32 {
			return nil, errors.New("invalid recorded HTTP header")
		}
		name := http.CanonicalHeaderKey(key)
		if privateFields[strings.ToLower(key)] {
			out[name] = []string{"[REDACTED]"}
			continue
		}
		for _, v := range list {
			size += len(key) + len(v)
			values++
			if size > 32<<10 || values > 128 {
				return nil, errors.New("recorded HTTP headers exceed bound")
			}
			out[name] = append(out[name], safeText(v))
		}
	}
	return out, nil
}

func cleanBody(b *Body) error {
	if b.ObservedBytes < 0 || b.CapturedBytes < 0 || b.CapturedBytes > b.ObservedBytes || len(b.ContentType) > 256 || len(b.ContentEncoding) > 128 || len(b.NotCapturedReason) > 128 {
		return errors.New("invalid recorded body counters")
	}
	if b.Encoding != "" && b.Encoding != "utf8" && b.Encoding != "base64" {
		return errors.New("invalid body encoding")
	}
	var data []byte
	if b.Encoding == "base64" {
		var err error
		data, err = base64.StdEncoding.DecodeString(b.Data)
		if err != nil {
			return errors.New("invalid captured base64 body")
		}
	} else {
		if !utf8.ValidString(b.Data) {
			return errors.New("invalid captured UTF-8 body")
		}
		data = []byte(b.Data)
	}
	if len(data) > MaxBodyBytes {
		return errors.New("captured body exceeds limit")
	}
	if b.SensitiveRaw {
		media, _, err := mime.ParseMediaType(b.ContentType)
		if err != nil || !(media == "application/grpc" || strings.HasPrefix(media, "application/grpc+")) || b.Encoding != "base64" || b.CapturedBytes != int64(len(data)) {
			return errors.New("invalid opaque gRPC capture")
		}
	}
	if len(data) == 0 {
		return nil
	}
	omit := func(reason string) {
		b.Data = ""
		b.Encoding = ""
		b.CapturedBytes = 0
		b.SensitiveRaw = false
		b.NotCapturedReason = reason
	}
	if b.ContentEncoding != "" && !strings.EqualFold(b.ContentEncoding, "identity") {
		omit("encoded_body_not_safely_redactable")
		return nil
	}
	media, _, err := mime.ParseMediaType(b.ContentType)
	if err != nil {
		omit("unsupported_body_format")
		return nil
	}
	if b.SensitiveRaw {
		if b.Encoding != "base64" || !(media == "application/grpc" || strings.HasPrefix(media, "application/grpc+")) || b.CapturedBytes != int64(len(data)) {
			return errors.New("invalid opaque gRPC capture")
		}
		return nil
	}
	switch {
	case media == "application/json" || strings.HasSuffix(media, "+json"):
		var value any
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		if !json.Valid(data) || decoder.Decode(&value) != nil || !redactJSON(value, 0) {
			omit("incomplete_or_unsupported_json")
			return nil
		}
		data, _ = json.Marshal(value)
	case media == "application/x-www-form-urlencoded":
		values, err := url.ParseQuery(string(data))
		if err != nil {
			omit("invalid_form_body")
			return nil
		}
		for k := range values {
			if privateFields[strings.ToLower(k)] {
				values[k] = []string{"[REDACTED]"}
			}
		}
		data = []byte(values.Encode())
	case strings.HasPrefix(media, "text/"):
		// Configured text/flag patterns have already run in the proxy. The
		// recorder still rejects controls and never interprets this as markup.
		data = []byte(safeText(string(data)))
	default:
		omit("unsupported_body_format")
		return nil
	}
	if len(data) > MaxBodyBytes {
		omit("redaction_output_exceeded_limit")
		b.Truncated = true
		return nil
	}
	b.Data = string(data)
	b.Encoding = "utf8"
	return nil
}

func redactJSON(v any, depth int) bool {
	if depth > 32 {
		return false
	}
	switch x := v.(type) {
	case map[string]any:
		for k, value := range x {
			if privateFields[strings.ToLower(k)] {
				x[k] = "[REDACTED]"
			} else if !redactJSON(value, depth+1) {
				return false
			}
		}
	case []any:
		for _, value := range x {
			if !redactJSON(value, depth+1) {
				return false
			}
		}
	}
	return true
}
