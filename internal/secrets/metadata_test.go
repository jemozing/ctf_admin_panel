package secrets

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionMetadataDeletionAndTombstone(t *testing.T) {
	v, err := Open(filepath.Join(t.TempDir(), "vault"))
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	ref, err := v.Import("environment", []byte("private-value-never-in-metadata"))
	if err != nil {
		t.Fatal(err)
	}
	versions, err := v.Versions()
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(versions)
	if len(versions) != 1 || versions[0].Bytes != 31 || strings.Contains(string(encoded), "private-value") {
		t.Fatalf("bad metadata: %s", encoded)
	}
	if err := v.Delete(ref); err == nil {
		t.Fatal("non-revoked version deleted")
	}
	if err := v.Revoke(ref); err != nil {
		t.Fatal(err)
	}
	if err := v.Delete(ref); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Read(ref); err == nil {
		t.Fatal("deleted version is readable")
	}
	meta, err := v.Metadata(ref)
	if err != nil || !meta.Deleted || !meta.Revoked || meta.Bytes != 0 {
		t.Fatalf("missing deletion tombstone: %#v %v", meta, err)
	}
	if err := v.Delete(ref); err != nil {
		t.Fatal("delete retry failed", err)
	}
	if err := os.WriteFile(filepath.Join(v.root.Name(), filename(ref)), []byte("resurrected"), 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Read(ref); err == nil {
		t.Fatal("tombstoned version resurrected by file presence")
	}
}

func TestVersionMetadataRejectsSymlink(t *testing.T) {
	v, err := Open(filepath.Join(t.TempDir(), "vault"))
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	ref, err := v.Import("environment", []byte("private"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(v.root.Name(), filename(ref))); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(v.root.Name(), filename(ref))); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Versions(); err == nil {
		t.Fatal("vault metadata followed symlink")
	}
}
