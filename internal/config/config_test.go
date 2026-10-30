package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApprovedPathRejectsEscapeAndSymlink(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "projects")
	outside := filepath.Join(base, "outside")
	for _, p := range []string{root, outside} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	c := Config{DiscoveryRoots: []string{root}}
	if err := c.CheckPath(outside, false); err == nil {
		t.Fatal("accepted outside directory")
	}
	if err := c.CheckPath(filepath.Join(root, "alias"), false); err == nil {
		t.Fatal("accepted escaping link")
	}
	// macOS aliases /var to /private/var; use its canonical path for this check.
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	c.DiscoveryRoots = []string{canonical}
	if err := c.CheckPath(canonical, false); err != nil {
		t.Fatal(err)
	}
}
