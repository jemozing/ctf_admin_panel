package snapshots

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

func TestCloneKeepsOriginalManifestWithoutWorkspaceMaterialization(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	source := sourceTree(t)
	original, err := s.Create(t.Context(), snapshotRequest("baseline"), source, managed, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := snapshotRequest("new-candidate")
	request.Purpose = domain.SnapshotCandidate
	cloned, err := s.Clone(t.Context(), original.ID, request, managed)
	if err != nil {
		t.Fatal(err)
	}
	if cloned.ID == original.ID || cloned.Purpose != domain.SnapshotCandidate || !reflect.DeepEqual(cloned.Manifest.Entries(), original.Manifest.Entries()) || cloned.ManifestDigest != original.ManifestDigest {
		t.Fatal("clone changed original modes/ownership or identity")
	}
	content, _ := s.ContentPath(cloned.ID)
	info, err := os.Stat(filepath.Join(content, "code/run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0400 {
		t.Fatalf("clone materialized executable mode in protected store: %o", info.Mode().Perm())
	}
	if err := os.WriteFile(filepath.Join(source, "code/run.sh"), []byte("edited active file"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(t.Context(), cloned.ID); err != nil {
		t.Fatal("clone depends on live source", err)
	}
	if _, err := s.Clone(t.Context(), original.ID, request, managed); !os.IsExist(err) {
		t.Fatalf("existing clone overwritten: %v", err)
	}
}

func TestCloneRejectsNarrowerMapAndTamperedSource(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	original, err := s.Create(t.Context(), snapshotRequest("baseline"), sourceTree(t), managed, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := snapshotRequest("narrow-candidate")
	request.Purpose = domain.SnapshotCandidate
	if _, err := s.Clone(t.Context(), original.ID, request, []domain.ManagedPath{{Path: "code/run.sh", Kind: domain.ManagedCode}}); err == nil {
		t.Fatal("silently dropped historical snapshot paths")
	}
	content, _ := s.ContentPath(original.ID)
	file := filepath.Join(content, "code/run.sh")
	if err := os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0400); err != nil {
		t.Fatal(err)
	}
	request.ID = "tampered-candidate"
	if _, err := s.Clone(t.Context(), original.ID, request, managed); err == nil {
		t.Fatal("tampered snapshot cloned")
	}
}
