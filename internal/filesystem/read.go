package filesystem

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
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
	var data bytes.Buffer
	if err := CopyVerifiedFile(ctx, root, entry, &data); err != nil {
		return nil, err
	}
	return data.Bytes(), nil
}

// CopyVerifiedFile streams a bounded manifest entry and verifies its digest.
// The caller must discard the destination if verification fails.
func CopyVerifiedFile(ctx context.Context, root string, entry domain.ManifestEntry, destination io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if entry.Type != domain.EntryFile || entry.Size < 0 || entry.Size > maxFileBytes {
		return fmt.Errorf("file is not a bounded regular manifest entry")
	}
	d, err := openDirectory(root)
	if err != nil {
		return err
	}
	defer d.close()
	f, before, err := d.open(entry.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	if !before.mode.IsRegular() || before.size != entry.Size {
		return ErrSourceChanged
	}
	hasher := sha256.New()
	size, err := io.Copy(io.MultiWriter(destination, hasher), contextReader{ctx, io.LimitReader(f, entry.Size+1)})
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	after, err := identify(info)
	if err != nil {
		return err
	}
	if before != after || size != entry.Size || domain.Digest("sha256:"+hex.EncodeToString(hasher.Sum(nil))) != entry.Digest {
		return ErrSourceChanged
	}
	return ctx.Err()
}
