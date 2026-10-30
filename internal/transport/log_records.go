package transport

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

// LogQuery is a bounded view over current registered containers. No daemon
// options, paths, or container IDs are accepted from the browser.
type LogQuery struct {
	Component string `json:"component"`
	Tail      int    `json:"tail"`
	Since     string `json:"since,omitempty"`
	Until     string `json:"until,omitempty"`
	Search    string `json:"search,omitempty"`
	Include   string `json:"include,omitempty"`
	Exclude   string `json:"exclude,omitempty"`
}
type LogRecord struct {
	ID          string `json:"id"`
	At          string `json:"at,omitempty"`
	Component   string `json:"component"`
	ContainerID string `json:"container_id"`
	Stream      string `json:"stream"`
	Text        string `json:"text"`
	Truncated   bool   `json:"truncated,omitempty"`
}
type LogSource struct {
	Component   string `json:"component"`
	ContainerID string `json:"container_id,omitempty"`
	Driver      string `json:"driver,omitempty"`
	Error       string `json:"error,omitempty"`
	TTY         bool   `json:"tty,omitempty"`
}
type LogPage struct {
	At        time.Time   `json:"at"`
	Records   []LogRecord `json:"records"`
	Sources   []LogSource `json:"sources"`
	Truncated bool        `json:"truncated"`
	Limit     int         `json:"limit"`
}

func (q LogQuery) Validate() error {
	if q.Component != "*" && !metricsComponentPattern.MatchString(q.Component) {
		return fmt.Errorf("select one registered component or *")
	}
	if q.Tail < 1 || q.Tail > 500 {
		return fmt.Errorf("tail must be between 1 and 500 per component")
	}
	var since, until time.Time
	for key, raw := range map[string]string{"since": q.Since, "until": q.Until} {
		if raw == "" {
			continue
		}
		value, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil || len(raw) > 64 {
			return fmt.Errorf("%s must be an RFC3339 timestamp", key)
		}
		if key == "since" {
			since = value
		} else {
			until = value
		}
	}
	if !since.IsZero() && !until.IsZero() && until.Before(since) {
		return fmt.Errorf("until precedes since")
	}
	if len(q.Search) > 256 {
		return fmt.Errorf("search exceeds 256 bytes")
	}
	for _, pattern := range []string{q.Include, q.Exclude} {
		if len(pattern) > 256 {
			return fmt.Errorf("regex exceeds 256 bytes")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("invalid RE2 regular expression")
		}
	}
	return nil
}
func ParseLogQuery(raw string) (LogQuery, error) {
	q := LogQuery{Component: "*", Tail: 200}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return q, fmt.Errorf("invalid log query")
	}
	for key, items := range values {
		if len(items) != 1 {
			return q, fmt.Errorf("duplicate log option")
		}
		switch key {
		case "component":
			q.Component = items[0]
		case "tail":
			q.Tail, err = strconv.Atoi(items[0])
			if err != nil {
				return q, fmt.Errorf("invalid tail")
			}
		case "since":
			q.Since = items[0]
		case "until":
			q.Until = items[0]
		case "search":
			q.Search = items[0]
		case "include":
			q.Include = items[0]
		case "exclude":
			q.Exclude = items[0]
		default:
			return q, fmt.Errorf("unknown log option")
		}
	}
	return q, q.Validate()
}
func (q LogQuery) Values() url.Values {
	v := url.Values{"component": {q.Component}, "tail": {strconv.Itoa(q.Tail)}}
	for key, value := range map[string]string{"since": q.Since, "until": q.Until, "search": q.Search, "include": q.Include, "exclude": q.Exclude} {
		if value != "" {
			v.Set(key, value)
		}
	}
	return v
}

type LogRecordsBackend interface {
	LogRecords(context.Context, domain.ID, LogQuery) (LogPage, error)
}

func (s *Server) logRecordsEndpoint(w http.ResponseWriter, r *http.Request, id domain.ID) {
	q, err := ParseLogQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, 400, "invalid_query", err.Error())
		return
	}
	b, ok := s.options.Backend.(LogRecordsBackend)
	if !ok {
		writeError(w, 501, "not_implemented", "structured logs unavailable")
		return
	}
	v, err := b.LogRecords(r.Context(), id, q)
	if err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, 200, v)
}
func (c *Client) LogRecords(ctx context.Context, id domain.ID, q LogQuery) (LogPage, error) {
	var v LogPage
	if err := id.Validate(); err != nil {
		return v, err
	}
	if err := q.Validate(); err != nil {
		return v, err
	}
	err := c.request(ctx, http.MethodGet, "/v1/services/"+string(id)+"/log-records?"+q.Values().Encode(), nil, &v)
	return v, err
}
