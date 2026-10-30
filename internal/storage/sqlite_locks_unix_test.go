//go:build linux || darwin

package storage

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
)

// A real second process is essential: SQLite's process-local lock bookkeeping
// hides POSIX record locks lost by closing another descriptor for the same inode.
func TestMeasurePreservesSQLiteWALAcrossProcesses(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	filename := filepath.Join(directory, "executor.db")
	db, err := store.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	put := func(id domain.ID) {
		t.Helper()
		if err := db.PutImmutable(ctx, "probe", id, "service", map[string]string{"id": string(id)}); err != nil {
			t.Fatal(err)
		}
	}
	put("initial")
	wal, err := os.Stat(filename + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	shm, err := os.Stat(filename + "-shm")
	if err != nil {
		t.Fatal(err)
	}
	peer := func(write string, expected ...string) {
		t.Helper()
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(expected)
		deadline, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		command := exec.CommandContext(deadline, binary, "-test.run=^TestMeasureSQLiteProcessHelper$")
		command.Env = append(os.Environ(), "CTFM_MEASURE_SQLITE_DB="+filename, "CTFM_MEASURE_SQLITE_WRITE="+write, "CTFM_MEASURE_SQLITE_EXPECT="+string(payload))
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("independent SQLite process failed: %v\n%s", err, output)
		}
		for suffix, original := range map[string]os.FileInfo{"-wal": wal, "-shm": shm} {
			actual, err := os.Stat(filename + suffix)
			if err != nil || !os.SameFile(original, actual) {
				t.Fatalf("quota measurement stripped SQLite locks: live %s sidecar removed or replaced: %v", suffix, err)
			}
		}
	}
	// Quota preflight scans the whole executor state, including its open DB and
	// sidecars. A peer's close must neither checkpoint nor unlink that live WAL.
	if _, err := Measure(ctx, directory); err != nil {
		t.Fatal(err)
	}
	peer("peer-one", "initial")
	put("writer-two")
	if _, err := Measure(ctx, directory); err != nil {
		t.Fatal(err)
	}
	peer("peer-three", "initial", "peer-one", "writer-two")
	var fromPeer map[string]string
	if err := db.Get(ctx, "probe", "peer-three", &fromPeer); err != nil || fromPeer["id"] != "peer-three" {
		t.Fatal("writer cannot observe the independent process commit", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = store.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []domain.ID{"initial", "peer-one", "writer-two", "peer-three"} {
		var value map[string]string
		if err := db.Get(ctx, "probe", id, &value); err != nil || value["id"] != string(id) {
			t.Fatalf("commit missing after writer close and reopen: %s: %v", id, err)
		}
	}
}

func TestMeasureSQLiteProcessHelper(t *testing.T) {
	filename := os.Getenv("CTFM_MEASURE_SQLITE_DB")
	if filename == "" {
		t.Skip("subprocess helper")
	}
	ctx := context.Background()
	db, err := store.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	var expected []domain.ID
	if err := json.Unmarshal([]byte(os.Getenv("CTFM_MEASURE_SQLITE_EXPECT")), &expected); err != nil {
		t.Fatal(err)
	}
	for _, id := range expected {
		var value map[string]string
		if err := db.Get(ctx, "probe", id, &value); err != nil || value["id"] != string(id) {
			t.Fatalf("peer cannot see committed %s: %v", id, err)
		}
	}
	if id := domain.ID(os.Getenv("CTFM_MEASURE_SQLITE_WRITE")); id != "" {
		if err := db.PutImmutable(ctx, "probe", id, "service", map[string]string{"id": string(id)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}
