package secrets

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

func TestVersionRetentionAndRevocation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	v, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	first, err := v.Import(domain.ID("service-env"), []byte("old"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := v.Import(domain.ID("service-env"), []byte("new"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Version == second.Version {
		t.Fatal("overwrote secret version")
	}
	got, err := v.Read(first)
	if err != nil || !bytes.Equal(got, []byte("old")) {
		t.Fatalf("old version lost: %q %v", got, err)
	}
	if err := v.Revoke(first); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Read(first); err == nil {
		t.Fatal("revoked secret is readable")
	}
	if _, err := v.Read(second); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(dir, filename(second))); err != nil || info.Mode().Perm() != 0400 {
		t.Fatalf("permissions: %v %v", info, err)
	}
}
