package transport

import (
	"context"
	"fmt"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"net/http"
	"net/url"
	"time"
)

type FilesQuery struct {
	Comparison string    `json:"comparison"`
	ReleaseID  domain.ID `json:"release_id,omitempty"`
	Path       string    `json:"path,omitempty"`
}
type FileDifference struct {
	Path   string                `json:"path"`
	Change string                `json:"change"`
	Before *domain.ManifestEntry `json:"before,omitempty"`
	After  *domain.ManifestEntry `json:"after,omitempty"`
}
type FileText struct {
	Path         string  `json:"path"`
	Before       *string `json:"before"`
	After        *string `json:"after"`
	BeforeReason string  `json:"before_reason,omitempty"`
	AfterReason  string  `json:"after_reason,omitempty"`
}
type FilesResult struct {
	Comparison   string           `json:"comparison"`
	BeforeDigest domain.Digest    `json:"before_digest"`
	AfterDigest  domain.Digest    `json:"after_digest"`
	SnapshotID   domain.ID        `json:"snapshot_id,omitempty"`
	Changes      []FileDifference `json:"changes"`
	Truncated    bool             `json:"truncated"`
	File         *FileText        `json:"file,omitempty"`
	At           time.Time        `json:"at"`
}

func (q FilesQuery) Validate() error {
	switch q.Comparison {
	case "candidate", "workspace", "drift":
		if q.ReleaseID != "" {
			return fmt.Errorf("release_id is only supported for release comparison")
		}
	case "release":
		if err := q.ReleaseID.Validate(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown file comparison")
	}
	if q.Path != "" {
		return domain.ValidateRelativePath(q.Path)
	}
	return nil
}
func ParseFilesQuery(raw string) (FilesQuery, error) {
	q := FilesQuery{Comparison: "candidate"}
	v, err := url.ParseQuery(raw)
	if err != nil {
		return q, fmt.Errorf("invalid file query")
	}
	for k, items := range v {
		if len(items) != 1 {
			return q, fmt.Errorf("duplicate file option")
		}
		switch k {
		case "comparison":
			q.Comparison = items[0]
		case "release_id":
			q.ReleaseID = domain.ID(items[0])
		case "path":
			q.Path = items[0]
		default:
			return q, fmt.Errorf("unknown file option")
		}
	}
	return q, q.Validate()
}
func (q FilesQuery) Values() url.Values {
	v := url.Values{"comparison": {q.Comparison}}
	if q.ReleaseID != "" {
		v.Set("release_id", string(q.ReleaseID))
	}
	if q.Path != "" {
		v.Set("path", q.Path)
	}
	return v
}

type FilesBackend interface {
	Files(context.Context, domain.ID, FilesQuery) (FilesResult, error)
}

func (s *Server) filesEndpoint(w http.ResponseWriter, r *http.Request, id domain.ID) {
	q, err := ParseFilesQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, 400, "invalid_query", err.Error())
		return
	}
	b, ok := s.options.Backend.(FilesBackend)
	if !ok {
		writeError(w, 501, "not_implemented", "files unavailable")
		return
	}
	v, err := b.Files(r.Context(), id, q)
	if err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, 200, v)
}
func (c *Client) Files(ctx context.Context, id domain.ID, q FilesQuery) (FilesResult, error) {
	var v FilesResult
	if err := id.Validate(); err != nil {
		return v, err
	}
	if err := q.Validate(); err != nil {
		return v, err
	}
	err := c.request(ctx, http.MethodGet, "/v1/services/"+string(id)+"/files?"+q.Values().Encode(), nil, &v)
	return v, err
}
