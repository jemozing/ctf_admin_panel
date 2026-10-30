package filesystem

import (
	"context"
	"fmt"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"io"
)

// ReadVerifiedFile reads only an already observed manifest entry. It uses the
// same descriptor/mount/type policy as Capture and rejects concurrent changes.
func ReadVerifiedFile(ctx context.Context, root string, entry domain.ManifestEntry, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if entry.Type != domain.EntryFile || entry.Size > limit || limit < 0 {
		return nil, fmt.Errorf("file is not a bounded regular text candidate")
	}
	d, err := openDirectory(root)
	if err != nil {
		return nil, err
	}
	defer d.close()
	f, before, err := d.open(entry.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	after, err := identify(info)
	if err != nil {
		return nil, err
	}
	if before != after || int64(len(data)) != entry.Size || domain.Hash(data) != entry.Digest {
		return nil, ErrSourceChanged
	}
	return data, ctx.Err()
}
