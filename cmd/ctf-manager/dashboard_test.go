package main

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDashboardCommandsDoNotReadExecutorBootstrap(t *testing.T) {
	for _, command := range []string{"dashboard", "init-admin"} {
		t.Run(command, func(t *testing.T) {
			var output, diagnostic bytes.Buffer
			err := run([]string{"--config", "/missing-executor-bootstrap", command, "--help"}, &output, &diagnostic)
			if !errors.Is(err, flag.ErrHelp) {
				t.Fatalf("dashboard command consulted executor bootstrap: %v", err)
			}
		})
	}
}

func TestAdminBootstrapRejectsUnboundedPasswordBeforeStateCreation(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	var output, diagnostic bytes.Buffer
	err := runDashboard([]string{"init-admin", "--state", state}, strings.NewReader(strings.Repeat("x", 4097)), &output, &diagnostic)
	if err == nil || !strings.Contains(err.Error(), "exceeds 4096") {
		t.Fatalf("unexpected oversized password result: %v", err)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatalf("oversized input created state: %v", err)
	}
}

func TestAdminBootstrapRequiresPrivatePasswordFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(file, []byte("test-admin-password\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var output, diagnostic bytes.Buffer
	err := runDashboard([]string{"init-admin", "--password-file", file}, strings.NewReader(""), &output, &diagnostic)
	if err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("insecure password file accepted: %v", err)
	}
}

func TestAdminBootstrapUsesStdinAndCannotResetExistingAccounts(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	var output, diagnostic bytes.Buffer
	args := []string{"init-admin", "--state", state, "--username", "admin"}
	password := "test-admin-password"
	if err := runDashboard(args, strings.NewReader(password+"\n"), &output, &diagnostic); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "admin_created") || strings.Contains(output.String()+diagnostic.String(), password) {
		t.Fatalf("bootstrap output must confirm creation without exposing password")
	}
	output.Reset()
	if err := runDashboard(args, strings.NewReader("another-admin-password\n"), &output, &diagnostic); err == nil {
		t.Fatal("second bootstrap changed existing users")
	}
}
