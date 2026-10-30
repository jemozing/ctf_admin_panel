package backup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
)

func auditID() domain.ID {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic("secure randomness unavailable")
	}
	return domain.ID("export-" + hex.EncodeToString(value[:]))
}
func recordExportAudit(ctx context.Context, db *store.Store, request domain.ID, mode Mode, destination, result string) error {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return db.AppendMaintenanceAudit(writeCtx, store.MaintenanceAudit{ID: auditID(), RequestID: request, At: time.Now().UTC(), LocalUID: uint32(os.Geteuid()), Action: "backup.export", TargetDigest: domain.Hash([]byte(destination)), Mode: string(mode), Result: result})
}
