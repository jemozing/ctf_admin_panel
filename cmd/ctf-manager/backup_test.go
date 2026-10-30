package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/backup"
	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/dashboard"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
)

func TestBackupRestoreCLIBypassesDefaultExecutorConfig(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	executorState := filepath.Join(root, "executor")
	dashboardState := filepath.Join(root, "dashboard")
	if err := os.Mkdir(executorState, 0700); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(executorState, "executor.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	server, err := dashboard.Open(dashboard.Config{StateDirectory: dashboardState, ExecutorSocket: filepath.Join(root, "executor.sock")})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.CreateAdmin(context.Background(), "admin", "administrator-password"); err != nil {
		t.Fatal(err)
	}
	server.Close()
	bootstrap := config.Config{StateDirectory: executorState, Socket: filepath.Join(root, "executor.sock"), DockerHost: "unix:///var/run/docker.sock", DockerBinary: "/usr/bin/true", DiscoveryRoots: []string{filepath.Join(root, "projects")}, WorkspaceRoots: []string{filepath.Join(root, "workspaces")}, Development: true, WebUID: os.Geteuid()}
	configuration := filepath.Join(root, "config.json")
	raw, _ := json.Marshal(bootstrap)
	os.WriteFile(configuration, raw, 0600)
	output := filepath.Join(root, "backup.tar")
	var stdout, stderr bytes.Buffer
	if err := run([]string{"--config", filepath.Join(root, "does-not-exist"), "backup", "--executor-state", executorState, "--dashboard-state", dashboardState, "--configuration", configuration, "--output", output}, &stdout, &stderr); err != nil {
		t.Fatalf("backup CLI: %v %s", err, stderr.String())
	}
	var report backup.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Mode != backup.Metadata {
		t.Fatal("default CLI exported protected state")
	}
	stdout.Reset()
	stderr.Reset()
	destination := filepath.Join(root, "restored")
	if err := run([]string{"--config", filepath.Join(root, "does-not-exist"), "restore", "--input", output, "--destination", destination}, &stdout, &stderr); err != nil {
		t.Fatalf("restore CLI: %v %s", err, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(destination, "restore-report.json")); err != nil {
		t.Fatal(err)
	}
}

func TestBackupPassphraseInputsAreExplicitAndPrivate(t *testing.T) {
	root := t.TempDir()
	insecure := filepath.Join(root, "insecure")
	os.WriteFile(insecure, []byte("long-backup-passphrase"), 0644)
	link := filepath.Join(root, "link")
	os.Symlink(insecure, link)
	for _, args := range [][]string{{"backup", "--passphrase-file", insecure}, {"backup", "--passphrase-file", link}, {"backup", "--passphrase-file", insecure, "--passphrase-stdin"}, {"backup", "--passphrase-stdin"}} {
		var output bytes.Buffer
		if err := runBackup(args, bytes.NewBufferString("short"), &output, &output); err == nil {
			t.Fatalf("unsafe passphrase input accepted: %v", args)
		}
	}
}
