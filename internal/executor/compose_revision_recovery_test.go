package executor

import (
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

func TestAutomaticComposeRecoveryRecognizesOnlyApprovedFiles(t *testing.T) {
	entry := func(path, value string) domain.ManifestEntry {
		return domain.ManifestEntry{Path: path, Type: domain.EntryFile, Mode: 0600, Size: int64(len(value)), Digest: domain.Hash([]byte(value))}
	}
	tree := func(entries ...domain.ManifestEntry) domain.Manifest {
		m, err := domain.NewManifest(entries)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	oldCompose, newCompose := entry("compose.yaml", "old"), entry("compose.yaml", "new")
	oldCode, newCode := entry("app.py", "before"), entry("app.py", "after")
	deleted, added := entry("old.py", "removed"), entry("new.py", "added")
	before := tree(oldCompose, oldCode, deleted)
	after := tree(newCompose, newCode, added)
	for _, actual := range []domain.Manifest{before, after, tree(newCompose, oldCode, deleted, added)} {
		if !knownComposeRecoveryTree(before, after, actual) {
			t.Fatal("approved partial tree could not be recovered")
		}
	}
	for _, actual := range []domain.Manifest{
		tree(oldCode, deleted),
		tree(newCompose, entry("app.py", "external edit"), added),
		tree(newCompose, newCode, added, entry("external.py", "unapproved file")),
	} {
		if knownComposeRecoveryTree(before, after, actual) {
			t.Fatal("unknown tree allowed automatic recovery")
		}
	}
}
