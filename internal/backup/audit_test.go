package backup

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
)

func TestExportAuditsLocalActorAndFinalResultWithoutPrivateValues(t *testing.T) {
	f := makeFixture(t)
	for _, failure := range []bool{false, true} {
		filename := "success.tar"
		max := int64(0)
		if failure {
			filename = "failed.tar"
			max = 1
		}
		report, err := Create(t.Context(), Options{ExecutorState: f.executor, DashboardState: f.dashboard, Configuration: f.configuration, Destination: filepath.Join(f.root, "backups", filename), MaxBytes: max})
		if (err != nil) != failure {
			t.Fatalf("wrong backup result: %v", err)
		}
		if report.AuditRequestID == "" {
			t.Fatal("export missing audit identity")
		}
	}
	db, err := store.Open(filepath.Join(f.executor, "executor.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	records, err := db.List(t.Context(), "maintenance_audit", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 4 {
		t.Fatalf("missing export attempts/results: %d", len(records))
	}
	seenSuccess, seenFailure := false, false
	for _, record := range records {
		text := string(record.Payload)
		if strings.Contains(text, secretMarker) || strings.Contains(text, "success.tar") {
			t.Fatal("private text/path leaked in maintenance audit")
		}
		seenSuccess = seenSuccess || strings.Contains(text, `"result":"succeeded"`)
		seenFailure = seenFailure || strings.Contains(text, `"result":"failed"`)
	}
	if !seenSuccess || !seenFailure {
		t.Fatal("export completion audit missing")
	}
}
