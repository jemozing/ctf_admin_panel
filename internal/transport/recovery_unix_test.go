//go:build linux || darwin

package transport

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
)

func leaveStaleSocket(t *testing.T, path string) os.FileInfo {
	t.Helper()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.Dial("unix", path)
	if err == nil {
		connection.Close()
		t.Fatal("fixture socket is active")
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("fixture is not provably stale: %v", err)
	}
	return info
}
func TestRecoveryReclaimsStaleSocketAndRestartsSamePath(t *testing.T) {
	path := socketPath(t)
	leaveStaleSocket(t, path)
	options := Options{SocketPath: path, RecoverStaleSocket: true}
	server, client := runServer(t, options)
	current, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if current.Mode()&os.ModeSocket == 0 {
		t.Fatal("reclaimed path is not a socket")
	}
	if _, err := client.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, client2 := runServer(t, options)
	if _, err := client2.Health(context.Background()); err != nil {
		t.Fatalf("restart at same socket path failed: %v", err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestRecoveryPreservesActiveSocketAndReleasesFailedAttemptLock(t *testing.T) {
	path := socketPath(t)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	defer listener.Close()
	old, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if lock, err := lockAndRecover(path); err == nil {
		releaseSocketLock(lock)
		t.Fatal("active socket reclaimed")
	} else if !strings.Contains(err.Error(), "active") {
		t.Fatalf("expected active socket rejection: %v", err)
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(old, current) {
		t.Fatal("active socket path replaced")
	}
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("active listener damaged: %v", err)
	}
	connection.Close()
	listener.Close()
	lock, err := lockAndRecover(path)
	if err != nil {
		t.Fatalf("failed active recovery leaked lock: %v", err)
	}
	releaseSocketLock(lock)
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("stale socket not removed after listener stopped")
	}
}
func TestRecoveryRefusesHeldLockWithoutTouchingSocket(t *testing.T) {
	path := socketPath(t)
	lock, err := lockAndRecover(path)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseSocketLock(lock)
	original := leaveStaleSocket(t, path)
	if second, err := lockAndRecover(path); err == nil {
		releaseSocketLock(second)
		t.Fatal("second executor acquired owned lock")
	} else if !strings.Contains(err.Error(), "lock") {
		t.Fatalf("unexpected lock rejection: %v", err)
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(original, current) {
		t.Fatal("locked socket path modified")
	}
}
func TestRecoveryRejectsForeignOwnedSocket(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing socket ownership requires root; exercised by isolated Linux transport test binary")
	}
	path := socketPath(t)
	leaveStaleSocket(t, path)
	if err := os.Chown(path, 10001, -1); err != nil {
		t.Fatal(err)
	}
	original, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if lock, err := lockAndRecover(path); err == nil {
		releaseSocketLock(lock)
		t.Fatal("foreign socket reclaimed")
	} else if !strings.Contains(err.Error(), "owned Unix socket") {
		t.Fatalf("wrong rejection: %v", err)
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(original, current) {
		t.Fatal("foreign socket path modified")
	}
}
func TestRecoveryRejectsUnsafeLockAndNonSocketPaths(t *testing.T) {
	for _, kind := range []string{"regular", "symlink", "writable-lock", "hardlinked-lock"} {
		t.Run(kind, func(t *testing.T) {
			path := socketPath(t)
			switch kind {
			case "regular":
				if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("missing-target", path); err != nil {
					t.Fatal(err)
				}
			case "writable-lock":
				if err := os.WriteFile(path+".lock", nil, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path+".lock", 0666); err != nil {
					t.Fatal(err)
				}
			case "hardlinked-lock":
				if err := os.WriteFile(path+".other", nil, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(path+".other", path+".lock"); err != nil {
					t.Fatal(err)
				}
			}
			if lock, err := lockAndRecover(path); err == nil {
				releaseSocketLock(lock)
				t.Fatal("unsafe recovery accepted")
			}
			if kind == "regular" {
				raw, err := os.ReadFile(path)
				if err != nil || string(raw) != "keep" {
					t.Fatal("non-socket contents changed")
				}
			}
			if kind == "symlink" {
				target, err := os.Readlink(path)
				if err != nil || target != "missing-target" {
					t.Fatal("non-socket symlink changed")
				}
			}
		})
	}
}
