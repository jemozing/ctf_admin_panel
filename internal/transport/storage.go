package transport

import (
	"context"
	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/storage"
	"io"
	"net/http"
	"os"
	"time"
)

type RetentionPlan struct {
	At                 time.Time              `json:"at"`
	RetireReleases     []domain.ID            `json:"retire_releases"`
	DeleteSnapshots    []domain.ID            `json:"delete_snapshots"`
	ProtectedSnapshots map[domain.ID][]string `json:"protected_snapshots"`
	ProtectedReleases  map[domain.ID][]string `json:"protected_releases"`
}
type StorageStatus struct {
	Policy           config.StoragePolicy `json:"policy"`
	State            storage.Usage        `json:"state"`
	Snapshots        storage.Usage        `json:"snapshots"`
	Staging          storage.Usage        `json:"staging"`
	StateCapacity    storage.Space        `json:"state_capacity"`
	DockerUsageBytes uint64               `json:"docker_usage_bytes"`
	DockerCapacity   *storage.Space       `json:"docker_capacity,omitempty"`
	Plan             RetentionPlan        `json:"retention_plan"`
}
type StorageBackend interface {
	StorageStatus(context.Context) (StorageStatus, error)
	Rotate(context.Context) (RetentionPlan, error)
}

func (s *Server) storageEndpoint(w http.ResponseWriter, r *http.Request, p Principal) {
	backend, ok := s.options.Backend.(StorageBackend)
	if !ok {
		writeError(w, 501, "not_implemented", "storage maintenance unavailable")
		return
	}
	if r.URL.Path == "/v1/storage" && r.Method == http.MethodGet {
		result, err := backend.StorageStatus(r.Context())
		if err != nil {
			backendError(w, err)
			return
		}
		writeJSON(w, 200, result)
		return
	}
	if r.URL.Path != "/v1/storage/rotate" {
		writeError(w, 404, "not_found", "unknown maintenance endpoint")
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	if p.UID != uint32(os.Geteuid()) {
		writeError(w, 403, "local_admin_required", "rotation requires the local executor administrator")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8))
	if err != nil || len(body) != 0 {
		writeError(w, 400, "invalid_request", "rotation does not accept user-supplied object IDs or options")
		return
	}
	result, err := backend.Rotate(r.Context())
	if err != nil {
		backendError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (c *Client) StorageStatus(ctx context.Context) (StorageStatus, error) {
	var v StorageStatus
	err := c.request(ctx, http.MethodGet, "/v1/storage", nil, &v)
	return v, err
}
func (c *Client) Rotate(ctx context.Context) (RetentionPlan, error) {
	var v RetentionPlan
	err := c.request(ctx, http.MethodPost, "/v1/storage/rotate", nil, &v)
	return v, err
}
