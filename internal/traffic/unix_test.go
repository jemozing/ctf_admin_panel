package traffic

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestUnixRecorderClientUsesDedicatedSocketAndRejectsRoleBypass(t *testing.T) {
	s, clock := recorder(t, nil)
	root, err := os.MkdirTemp("", "ctfm-traffic-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "control.sock")
	listener, cleanup, err := ListenPrivateUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	ingest, read := strings.Repeat("i", 40), strings.Repeat("r", 40)
	handler, err := Handler(s, Tokens{Ingest: ingest, Read: read})
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	defer server.Close()
	go server.Serve(listener)
	writer, err := NewUnixClient(path, ingest)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	reader, err := NewUnixClient(path, read)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := writer.Ingest(context.Background(), observation(clock, "unix-record", "one")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Detail(context.Background(), "unix-record"); err == nil {
		t.Fatal("ingest token read payload")
	}
	if err := reader.Ingest(context.Background(), observation(clock, "forbidden", "one")); err == nil {
		t.Fatal("read token wrote capture")
	}
	page, err := reader.List(context.Background(), Query{ServiceIDs: []string{"one"}})
	if err != nil || len(page.Records) != 1 || page.Records[0].RequestID != "unix-record" {
		t.Fatal("Unix typed query failed")
	}
	if _, _, err := ListenPrivateUnix(path); err == nil {
		t.Fatal("active socket replaced")
	}
	if _, err := NewUnixClient("/tmp/../var/socket", read); err == nil {
		t.Fatal("noncanonical socket path accepted")
	}
}

func TestUnixSocketCleanupPreservesReplacementAndRefusesForeignFiles(t *testing.T) {
	root, err := os.MkdirTemp("", "ctfm-socket-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	os.Chmod(root, 0700)
	path := filepath.Join(root, "control.sock")
	listener, cleanup, err := ListenPrivateUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("keep me"), 0600); err != nil {
		t.Fatal(err)
	}
	cleanup()
	if value, err := os.ReadFile(path); err != nil || string(value) != "keep me" {
		t.Fatal("cleanup removed replacement")
	}
	if _, _, err := ListenPrivateUnix(path); err == nil {
		t.Fatal("regular file adopted as socket")
	}
	os.Remove(path)
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	stale.Close()
	current, remove, err := ListenPrivateUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	current.Close()
	remove()
}

func TestPrivateTokenFileRejectsSymlinkAndPublicOrHardlinkedMaterial(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "token")
	secret := strings.Repeat("a", 64)
	if err := os.WriteFile(path, []byte(secret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	value, err := ReadTokenFile(path)
	if err != nil || value != secret {
		t.Fatal("private token unreadable")
	}
	link := filepath.Join(root, "symlink")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTokenFile(link); err == nil {
		t.Fatal("token symlink followed")
	}
	os.Chmod(path, 0644)
	if _, err := ReadTokenFile(path); err == nil {
		t.Fatal("public token accepted")
	}
	os.Chmod(path, 0600)
	hard := filepath.Join(root, "hardlink")
	if err := os.Link(path, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTokenFile(path); err == nil {
		t.Fatal("aliased token accepted")
	}
	fifo := filepath.Join(root, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTokenFile(fifo); err == nil {
		t.Fatal("FIFO token accepted")
	}
}
