package executor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

func TestLoadSnapshotRequiresExactRegisteredGitProvenance(t *testing.T) {
	for _, field := range []string{"url", "ref", "subdirectory", "commit", "revision", "removed", "injected"} {
		t.Run(field, func(t *testing.T) {
			f := newPlanningFixture(t)
			provenance := &domain.GitProvenance{URL: "https://github.com/example/service.git", Ref: "main", Subdirectory: "service", Commit: strings.Repeat("a", 40), SourceRevision: 1}
			var snapshot domain.Snapshot
			if field == "injected" {
				snapshot = f.baseline
			} else {
				var err error
				snapshot, err = f.m.capture(t.Context(), f.s, "local-admin", domain.SnapshotCandidate, f.s.SourceDirectory, provenance)
				if err != nil {
					t.Fatal(err)
				}
			}
			loaded, err := f.m.loadSnapshot(t.Context(), snapshot.ID)
			if err != nil || !reflect.DeepEqual(loaded.GitSource, snapshot.GitSource) {
				t.Fatalf("unchanged snapshot failed: %#v %v", loaded.GitSource, err)
			}
			tampered := snapshot
			if snapshot.GitSource != nil {
				copy := *snapshot.GitSource
				tampered.GitSource = &copy
			}
			switch field {
			case "url":
				tampered.GitSource.URL = "https://gitlab.com/example/other.git"
			case "ref":
				tampered.GitSource.Ref = "release"
			case "subdirectory":
				tampered.GitSource.Subdirectory = "other"
			case "commit":
				tampered.GitSource.Commit = strings.Repeat("b", 40)
			case "revision":
				tampered.GitSource.SourceRevision = 2
			case "removed":
				tampered.GitSource = nil
			case "injected":
				tampered.GitSource = provenance
			}
			metadata := filepath.Join(f.m.Config.StateDirectory, "snapshots", string(snapshot.ID), "snapshot.json")
			encoded, err := json.Marshal(tampered)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(metadata, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(metadata, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(metadata, 0400); err != nil {
				t.Fatal(err)
			}
			// Content and provenance remain individually valid; only comparison to
			// the immutable SQLite registration can reject this metadata corruption.
			if _, err := f.m.Snapshots.Load(t.Context(), snapshot.ID); err != nil {
				t.Fatalf("invalid tampering fixture: %v", err)
			}
			if _, err := f.m.loadSnapshot(t.Context(), snapshot.ID); err == nil || !strings.Contains(err.Error(), "registered immutable metadata") {
				t.Fatalf("accepted %s provenance mismatch: %v", field, err)
			}
		})
	}
}
