package filesystem

import (
	"context"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

// Observe hashes the active managed tree without creating or modifying files.
// Two observations reject concurrent edits; descriptor-relative access enforces
// the same path/type/mount rules as Capture.
func Observe(ctx context.Context, root string, managed []domain.ManagedPath, exclusions []string) (domain.Manifest, error) {
	p, err := makePolicy(managed, exclusions)
	if err != nil {
		return domain.Manifest{}, err
	}
	d, err := openDirectory(root)
	if err != nil {
		return domain.Manifest{}, err
	}
	defer d.close()
	before, seen, err := scan(ctx, d, p, nil)
	if err != nil {
		return domain.Manifest{}, err
	}
	after, again, err := scan(ctx, d, p, nil)
	if err != nil {
		return domain.Manifest{}, err
	}
	if before.Digest() != after.Digest() || !sameObservations(seen, again) {
		return domain.Manifest{}, ErrSourceChanged
	}
	return before, nil
}
