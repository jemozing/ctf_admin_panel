package packetcapture

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

func (e *Engine) ControlHandler(token string) (http.Handler, error) {
	if len(token) < 32 || len(token) > 256 || strings.ContainsAny(token, "\r\n \t") {
		return nil, errors.New("invalid capture control token")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.URL.Path == "/healthz" && r.Method == http.MethodGet && r.URL.RawQuery == "" && r.Header.Get("Origin") == "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
			return
		}
		if r.Header.Get("Origin") != "" || len(r.Header.Values("Authorization")) != 1 || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "capture control authentication required", http.StatusUnauthorized)
			return
		}
		if r.URL.RawQuery != "" {
			http.Error(w, "unexpected capture query", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/status":
			_ = json.NewEncoder(w).Encode(e.Status())
		case r.Method == http.MethodGet && r.URL.Path == "/v1/interfaces":
			list, err := e.Interfaces()
			if err != nil {
				http.Error(w, "capture interfaces unavailable", http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(list)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/pause":
			body, err := io.ReadAll(io.LimitReader(r.Body, 1))
			if err != nil || len(body) != 0 {
				http.Error(w, "capture pause takes no body", http.StatusBadRequest)
				return
			}
			if err = e.Pause(); err != nil {
				http.Error(w, "capture unavailable", http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(e.Status())
		case r.Method == http.MethodPost && r.URL.Path == "/v1/preflight":
			var p Policy
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxPolicyBytes))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&p) != nil || decoder.Decode(new(any)) != io.EOF {
				http.Error(w, "invalid capture policy JSON", http.StatusBadRequest)
				return
			}
			if err := e.Preflight(p); err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		default:
			http.Error(w, "capture control endpoint not found", http.StatusNotFound)
		}
	}), nil
}
