package filesystem

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

var codePolicy = []domain.ManagedPath{{Path: "code", Kind: domain.ManagedCode, Exclusions: []string{"uploads", ".env"}}}

func write(t *testing.T, root, name, contents string, mode os.FileMode) {
	t.Helper()
	name = filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, mode); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, root, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func fixtureSource(t *testing.T) string {
	t.Helper()
	source := t.TempDir()
	write(t, source, "code/run.sh", "#!/bin/sh\necho v1\n", 0755)
	write(t, source, "code/deleted.txt", "old", 0644)
	write(t, source, "code/uploads/flag", "CTFM_TEST_FLAG", 0600)
	write(t, source, "code/.env", "SECRET_TEST", 0600)
	write(t, source, "code/.git/config", "PRIVATE_TEST", 0600)
	write(t, source, "data/state.db", "UNCHANGED_TEST_STATE", 0600)
	write(t, source, "unmanaged.txt", "LEAVE_ME", 0644)
	return source
}

func captureFixture(t *testing.T, source string) (string, domain.Manifest) {
	t.Helper()
	target := filepath.Join(t.TempDir(), "content")
	manifest, err := Capture(context.Background(), source, target, codePolicy, nil)
	if err != nil {
		t.Fatal(err)
	}
	return target, manifest
}

func TestCaptureProtectsContentsAndBuildRestoresExecutableMode(t *testing.T) {
	source := fixtureSource(t)
	content, manifest := captureFixture(t, source)
	if err := Verify(context.Background(), content, manifest); err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, entry := range manifest.Entries() {
		paths = append(paths, entry.Path)
	}
	if !reflect.DeepEqual(paths, []string{"code", "code/deleted.txt", "code/run.sh"}) {
		t.Fatalf("copied excluded or unmanaged paths: %v", paths)
	}
	info, err := os.Stat(filepath.Join(content, "code/run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0400 {
		t.Fatalf("artifact mode=%o", info.Mode().Perm())
	}
	build := filepath.Join(t.TempDir(), "build")
	if err = MaterializeBuild(context.Background(), content, build, manifest); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(filepath.Join(build, "code/run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatalf("build lost executable mode: %o", info.Mode().Perm())
	}
	if read(t, build, "code/run.sh") != read(t, source, "code/run.sh") {
		t.Fatal("build content changed")
	}
	if err = os.WriteFile(filepath.Join(source, "code/run.sh"), []byte("after capture"), 0755); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(read(t, content, "code/run.sh"), "after capture") {
		t.Fatal("snapshot shares storage with source")
	}
}

func TestApplyPreservesDataAndUnmanagedFilesAndDeletesManagedFile(t *testing.T) {
	active := fixtureSource(t)
	_, previous := captureFixture(t, active)
	candidate := fixtureSource(t)
	write(t, candidate, "code/run.sh", "#!/bin/sh\necho v2\n", 0755)
	if err := os.Remove(filepath.Join(candidate, "code/deleted.txt")); err != nil {
		t.Fatal(err)
	}
	write(t, candidate, "code/new.txt", "new", 0640)
	content, next := captureFixture(t, candidate)
	err := Apply(context.Background(), content, active, previous, next, codePolicy, ApplyOptions{ApplicationsStopped: true, PreserveOwnership: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, active, "code/run.sh"), "v2") {
		t.Fatal("new version missing")
	}
	if _, err = os.Stat(filepath.Join(active, "code/deleted.txt")); !os.IsNotExist(err) {
		t.Fatal("removed managed file survived")
	}
	for name, value := range map[string]string{"code/uploads/flag": "CTFM_TEST_FLAG", "data/state.db": "UNCHANGED_TEST_STATE", "unmanaged.txt": "LEAVE_ME", "code/.env": "SECRET_TEST", "code/.git/config": "PRIVATE_TEST"} {
		if got := read(t, active, name); got != value {
			t.Fatalf("preserved path %s changed to %q", name, got)
		}
	}
	info, err := os.Stat(filepath.Join(active, "code/run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatal("active executable bit lost")
	}
}

func TestApplyRequiresStopAndRejectsDriftBeforeWriting(t *testing.T) {
	active := fixtureSource(t)
	_, previous := captureFixture(t, active)
	candidate := fixtureSource(t)
	write(t, candidate, "code/run.sh", "candidate", 0755)
	content, next := captureFixture(t, candidate)
	if err := Apply(context.Background(), content, active, previous, next, codePolicy, ApplyOptions{}); err == nil {
		t.Fatal("applied to running application")
	}
	write(t, active, "code/run.sh", "external SSH edit", 0755)
	err := Apply(context.Background(), content, active, previous, next, codePolicy, ApplyOptions{ApplicationsStopped: true})
	if !errors.Is(err, ErrDrift) {
		t.Fatalf("expected drift, got %v", err)
	}
	if read(t, active, "code/run.sh") != "external SSH edit" {
		t.Fatal("drift overwritten")
	}
}

func TestUnsupportedTypeTransitionFailsBeforeAnyWrites(t *testing.T) {
	active := fixtureSource(t)
	_, previous := captureFixture(t, active)
	candidate := fixtureSource(t)
	if err := os.Remove(filepath.Join(candidate, "code/deleted.txt")); err != nil {
		t.Fatal(err)
	}
	write(t, candidate, "code/deleted.txt/child", "new-directory", 0644)
	write(t, candidate, "code/run.sh", "must-not-apply", 0755)
	content, next := captureFixture(t, candidate)
	if err := Apply(context.Background(), content, active, previous, next, codePolicy, ApplyOptions{ApplicationsStopped: true}); err == nil {
		t.Fatal("unsupported type transition accepted")
	}
	if read(t, active, "code/deleted.txt") != "old" || strings.Contains(read(t, active, "code/run.sh"), "must-not-apply") {
		t.Fatal("unsupported transition partially applied")
	}
}

func TestCaptureRejectsSymlinksHardlinksAndSpecialFiles(t *testing.T) {
	for _, kind := range []string{"escaping-symlink", "internal-symlink", "hardlink", "fifo", "ancestor-symlink"} {
		t.Run(kind, func(t *testing.T) {
			source := t.TempDir()
			outside := t.TempDir()
			write(t, source, "code/normal", "SAFE", 0644)
			write(t, outside, "secret", "OUTSIDE_TEST_SECRET", 0600)
			var err error
			policy := codePolicy
			switch kind {
			case "escaping-symlink":
				err = os.Symlink(filepath.Join(outside, "secret"), filepath.Join(source, "code/evil"))
			case "internal-symlink":
				err = os.Symlink("normal", filepath.Join(source, "code/evil"))
			case "hardlink":
				err = os.Link(filepath.Join(outside, "secret"), filepath.Join(source, "code/evil"))
			case "fifo":
				err = syscall.Mkfifo(filepath.Join(source, "code/evil"), 0600)
			case "ancestor-symlink":
				err = os.Symlink("code", filepath.Join(source, "alias"))
				policy = []domain.ManagedPath{{Path: "alias/normal", Kind: domain.ManagedCode}}
			}
			if err != nil {
				t.Fatal(err)
			}
			_, err = Capture(context.Background(), source, filepath.Join(t.TempDir(), "snapshot"), policy, nil)
			if !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("unsafe %s accepted: %v", kind, err)
			}
			if read(t, outside, "secret") != "OUTSIDE_TEST_SECRET" {
				t.Fatal("outside target changed")
			}
		})
	}
}

func TestSourceChangesAfterReadAreRejected(t *testing.T) {
	for _, mutation := range []string{"overwrite", "add", "delete", "replace-same-content"} {
		t.Run(mutation, func(t *testing.T) {
			source := fixtureSource(t)
			_, err := capture(context.Background(), source, filepath.Join(t.TempDir(), "snapshot"), codePolicy, nil, func() {
				switch mutation {
				case "overwrite":
					write(t, source, "code/run.sh", "changed", 0755)
				case "add":
					write(t, source, "code/new", "new", 0644)
				case "delete":
					if err := os.Remove(filepath.Join(source, "code/run.sh")); err != nil {
						t.Fatal(err)
					}
				case "replace-same-content":
					contents := read(t, source, "code/run.sh")
					if err := os.Remove(filepath.Join(source, "code/run.sh")); err != nil {
						t.Fatal(err)
					}
					write(t, source, "code/run.sh", contents, 0755)
				}
			})
			if !errors.Is(err, ErrSourceChanged) {
				t.Fatalf("changed source accepted: %v", err)
			}
		})
	}
}

func TestArtifactTamperingAndUnauthorizedManifestFailBeforeApply(t *testing.T) {
	active := fixtureSource(t)
	_, previous := captureFixture(t, active)
	content, next := captureFixture(t, fixtureSource(t))
	name := filepath.Join(content, "code/run.sh")
	if err := os.Chmod(name, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("CORRUPTED"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, 0400); err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), content, active, previous, next, codePolicy, ApplyOptions{ApplicationsStopped: true}); err == nil {
		t.Fatal("corrupted artifact applied")
	}
	if !strings.Contains(read(t, active, "code/run.sh"), "v1") {
		t.Fatal("active files changed before integrity validation")
	}
	unauthorized, err := domain.NewManifest([]domain.ManifestEntry{{Path: "data/state.db", Type: domain.EntryFile, Size: 3, Digest: domain.Hash([]byte("bad")), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	if err = Apply(context.Background(), content, active, previous, unauthorized, codePolicy, ApplyOptions{ApplicationsStopped: true}); err == nil {
		t.Fatal("data path accepted as managed")
	}
	if read(t, active, "data/state.db") != "UNCHANGED_TEST_STATE" {
		t.Fatal("persistent data overwritten")
	}
}

func TestConcurrentAncestorReplacementDoesNotCopyOutside(t *testing.T) {
	source := t.TempDir()
	outside := t.TempDir()
	write(t, source, "code/normal", "SAFE_SOURCE", 0644)
	write(t, outside, "normal", "OUTSIDE_SECRET_MUST_NOT_BE_READ", 0644)
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		active := filepath.Join(source, "code")
		held := filepath.Join(source, "held")
		for {
			select {
			case <-stop:
				done <- nil
				return
			default:
			}
			if err := os.Rename(active, held); err != nil {
				done <- err
				return
			}
			if err := os.Symlink(outside, active); err != nil {
				_ = os.Rename(held, active)
				done <- err
				return
			}
			if err := os.Remove(active); err != nil {
				done <- err
				return
			}
			if err := os.Rename(held, active); err != nil {
				done <- err
				return
			}
		}
	}()
	defer func() {
		close(stop)
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	for i := 0; i < 30; i++ {
		destination := filepath.Join(t.TempDir(), "content")
		_, _ = Capture(context.Background(), source, destination, codePolicy, nil)
		// Check partial artifacts too: failing after copying a secret would still
		// be a disclosure into the executor's content store.
		err := filepath.WalkDir(destination, func(name string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !entry.Type().IsRegular() {
				return nil
			}
			data, err := os.ReadFile(name)
			if err != nil {
				return err
			}
			if strings.Contains(string(data), "OUTSIDE_SECRET") {
				t.Errorf("outside secret copied during ancestor race")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
