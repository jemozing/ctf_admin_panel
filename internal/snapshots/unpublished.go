package snapshots

import (
	"context"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/storage"
)

// RemoveUnpublished cleans an allocation interrupted before snapshot publication.
// The caller must prove from a durable allocation receipt that no snapshot record
// exists and that its owning operation is terminal, while holding the executor's
// artifact gate. Incomplete metadata and private temporary files are expected.
func (s *Store) RemoveUnpublished(ctx context.Context, id domain.ID) error {
	if err := id.Validate(); err != nil {
		return err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return storage.RemovePrivateTree(ctx, s.directory, string(id))
}
