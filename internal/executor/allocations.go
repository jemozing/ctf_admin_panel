package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/storage"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type operationContextKey struct{}
type allocation struct {
	ID          domain.ID `json:"id"`
	OperationID domain.ID `json:"operation_id,omitempty"`
	Directory   string    `json:"directory,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

func allocationOperation(ctx context.Context) domain.ID {
	v, _ := ctx.Value(operationContextKey{}).(domain.ID)
	return v
}
func (m *Manager) allocationIdle(ctx context.Context, a allocation) (bool, error) {
	if a.OperationID == "" {
		return true, nil
	}
	op, err := m.Store.GetOperation(ctx, a.OperationID)
	if errors.Is(err, store.ErrNotFound) {
		return false, fmt.Errorf("allocation owner operation unavailable: %w", err)
	}
	if err != nil {
		return false, err
	}
	return op.State.Terminal(), nil
}

// Cleanup touches only executor allocation receipts, under the same artifact
// gate as the worker. An unrecorded directory is never guessed to be garbage.
func (m *Manager) cleanupAllocations(ctx context.Context) error {
	records, err := m.Store.List(ctx, "snapshot_allocation", "")
	if err != nil {
		return err
	}
	for _, record := range records {
		needs, err := m.Store.MetadataRestoreNeedsReview(ctx, record.ServiceID)
		if err != nil {
			return err
		}
		if needs {
			continue
		}
		var a allocation
		if err := json.Unmarshal(record.Payload, &a); err != nil {
			return err
		}
		var snapshot domain.Snapshot
		err = m.Store.Get(ctx, "snapshot", a.ID, &snapshot)
		if err == nil {
			continue
		}
		if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		idle, err := m.allocationIdle(ctx, a)
		if err != nil {
			return err
		}
		if !idle {
			continue
		}
		if err := m.Snapshots.RemoveUnpublished(ctx, a.ID); err != nil {
			return err
		}
	}
	records, err = m.Store.List(ctx, "build_allocation", "")
	if err != nil {
		return err
	}
	if len(records) > 0 {
		if err := ensureStaging(m.Config.StateDirectory); err != nil {
			return err
		}
	}
	for _, record := range records {
		needs, err := m.Store.MetadataRestoreNeedsReview(ctx, record.ServiceID)
		if err != nil {
			return err
		}
		if needs {
			continue
		}
		var a allocation
		if err := json.Unmarshal(record.Payload, &a); err != nil {
			return err
		}
		idle, err := m.allocationIdle(ctx, a)
		if err != nil {
			return err
		}
		if !idle {
			continue
		}
		if !strings.HasPrefix(a.Directory, "build-") || filepath.Base(a.Directory) != a.Directory {
			return errors.New("invalid recorded staging allocation")
		}
		if err := storage.RemoveStagingTree(ctx, stagingPath(m.Config.StateDirectory), a.Directory); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) reserveBuildDirectory(ctx context.Context, service, op domain.ID) (string, error) {
	if err := ensureStaging(m.Config.StateDirectory); err != nil {
		return "", err
	}
	id := NewID("build-")
	// A crash at any subsequent point leaves a receipt the janitor can reconcile.
	if err := m.Store.PutImmutable(ctx, "build_allocation", id, service, allocation{ID: id, OperationID: op, Directory: string(id), CreatedAt: time.Now().UTC()}); err != nil {
		return "", err
	}
	root, err := os.OpenRoot(stagingPath(m.Config.StateDirectory))
	if err != nil {
		return "", err
	}
	defer root.Close()
	if err := root.Mkdir(string(id), 0700); err != nil {
		return "", err
	}
	dir, err := root.Open(".")
	if err != nil {
		return "", err
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	return filepath.Join(stagingPath(m.Config.StateDirectory), string(id)), nil
}
