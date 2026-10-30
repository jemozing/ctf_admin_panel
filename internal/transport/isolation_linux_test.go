//go:build linux

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
)

const isolationGroup = 10001

type helperProof struct {
	UID                    int    `json:"uid"`
	GID                    int    `json:"gid"`
	PID                    int    `json:"pid"`
	Capabilities           string `json:"effective_capabilities"`
	SocketDialled          bool   `json:"socket_dialled"`
	HealthAllowed          bool   `json:"health_allowed"`
	ServicesAllowed        bool   `json:"services_allowed"`
	PeerIdentityVerified   bool   `json:"peer_identity_verified"`
	PeerDenied             bool   `json:"peer_denied"`
	PrivateDirectoryDenied bool   `json:"private_directory_denied"`
	DatabaseReadDenied     bool   `json:"database_read_denied"`
	DatabaseWriteDenied    bool   `json:"database_write_denied"`
	SecretReadDenied       bool   `json:"secret_read_denied"`
}

// TestLinuxUIDIsolation is deliberately opt-in: only an isolated container should
// grant the helper SETUID/SETGID. Normal unit tests never require host root setup.
func TestLinuxUIDIsolation(t *testing.T) {
	if os.Getenv("CTFM_LINUX_UID_PROOF") != "1" {
		t.Skip("isolated Linux container UID proof is opt-in")
	}
	if os.Geteuid() != 0 || os.Getegid() != isolationGroup {
		t.Fatal("proof requires container user 0:10001")
	}
	if capabilities(t) != "00000000000000c0" {
		t.Fatal("proof requires only effective SETUID and SETGID capabilities")
	}
	if file, err := os.OpenFile("/.ctfm-uid-read-only-proof", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600); !errors.Is(err, syscall.EROFS) {
		if file != nil {
			file.Close()
			os.Remove("/.ctfm-uid-read-only-proof")
		}
		t.Fatalf("proof container root must be read-only: %v", err)
	}
	base, err := os.MkdirTemp("/tmp", "ctfm-uid-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	if err := os.Chmod(base, 0750); err != nil {
		t.Fatal(err)
	}
	runtimeDirectory := filepath.Join(base, "run")
	privateDirectory := filepath.Join(base, "private")
	for directory, mode := range map[string]os.FileMode{runtimeDirectory: 0750, privateDirectory: 0700} {
		if err := os.Mkdir(directory, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, mode); err != nil {
			t.Fatal(err)
		}
	}
	database := filepath.Join(privateDirectory, "executor.db")
	secret := filepath.Join(privateDirectory, "secret-version")
	state, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if err := state.PutImmutable(context.Background(), "configuration", "config-1", "flags", map[string]string{"kind": "synthetic-private-fixture"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("CTFM_SYNTHETIC_SECRET_NOT_FOR_HELPER"), 0600); err != nil {
		t.Fatal(err)
	}
	peerObserved := make(chan Principal, 1)
	socket := filepath.Join(runtimeDirectory, "executor.sock")
	server, err := NewServer(Options{SocketPath: socket, AllowedUIDs: []uint32{10001}, Backend: state, Submit: func(ctx context.Context, p Principal, r SubmitRequest) (domain.Operation, error) {
		peerObserved <- p
		return domain.NewOperation(domain.OperationSpec{ID: "peer-proof", Kind: r.Action, Initiator: domain.ID("uid-" + strconv.FormatUint(uint64(p.UID), 10)), IdempotencyKey: r.IdempotencyKey, ServiceID: r.ServiceID, ExpectedPolicyRevision: 1, ExpectedTreeDigest: domain.Hash(nil), Resources: []string{"service:" + string(r.ServiceID)}, TimeoutSeconds: 10}, time.Now())
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	defer func() {
		cancel()
		server.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(6 * time.Second):
			t.Error("server failed to shut down")
		}
	}()
	assertOwnership(t, runtimeDirectory, 0750)
	assertOwnership(t, privateDirectory, 0700)
	assertOwnership(t, socket, 0660)
	assertOwnership(t, database, 0600)
	assertOwnership(t, secret, 0600)
	allowed := runUIDHelper(t, 10001, "allowed", socket, privateDirectory, database, secret)
	denied := runUIDHelper(t, 10002, "denied", socket, privateDirectory, database, secret)
	var principal Principal
	select {
	case principal = <-peerObserved:
	case <-time.After(time.Second):
		t.Fatal("allowed helper principal was not observed")
	}
	if principal.UID != 10001 || principal.GID != isolationGroup || principal.PID != int32(allowed.PID) {
		t.Fatalf("SO_PEERCRED mismatch: %#v", principal)
	}
	for _, path := range []string{"/var/run/docker.sock", "/run/docker.sock"} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("Docker socket must not be present in proof container")
		}
	}
	interfaces, err := os.ReadDir("/sys/class/net")
	if err != nil {
		t.Fatal(err)
	}
	if len(interfaces) != 1 || interfaces[0].Name() != "lo" {
		t.Fatal("proof container must use --network none")
	}
	report := map[string]any{
		"schema_version": 1, "test": "linux_executor_peer_uid_and_private_state", "passed": true, "at": time.Now().UTC(),
		"runtime": runtime.GOOS + "/" + runtime.GOARCH, "image_id": os.Getenv("CTFM_UID_IMAGE_ID"), "executor_uid": os.Geteuid(), "shared_ipc_gid": os.Getegid(), "effective_capabilities": capabilities(t),
		"runtime_directory_mode": "0750", "socket_mode": "0660", "private_directory_mode": "0700", "private_file_mode": "0600",
		"allowed_helper": allowed, "denied_helper": denied, "observed_so_peercred": principal,
		"isolation": map[string]bool{"network_none": true, "docker_socket_absent": true, "read_only_container_root": true, "only_setuid_setgid_capabilities": true},
		"scope":     "Production Linux transport with real distinct peer UIDs; isolated test executor runs as container UID 0 to change helper UIDs. Does not prove installed systemd users or Docker authorization.",
	}
	if filename := os.Getenv("CTFM_UID_REPORT"); filename != "" {
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, append(encoded, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func assertOwnership(t *testing.T, filename string, mode os.FileMode) {
	t.Helper()
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != isolationGroup || info.Mode().Perm() != mode {
		t.Fatalf("unexpected ownership/mode for %s: %#v %o", filename, info.Sys(), info.Mode().Perm())
	}
}

func capabilities(t *testing.T) string {
	t.Helper()
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		}
	}
	t.Fatal("effective capabilities unavailable")
	return ""
}

func runUIDHelper(t *testing.T, uid uint32, mode, socket, privateDirectory, database, secret string) helperProof {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestLinuxUIDHelper$", "-test.count=1")
	command.Env = append(os.Environ(), "CTFM_LINUX_UID_HELPER="+mode, "CTFM_UID_SOCKET="+socket, "CTFM_UID_PRIVATE="+privateDirectory, "CTFM_UID_DATABASE="+database, "CTFM_UID_SECRET="+secret)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: isolationGroup, Groups: []uint32{isolationGroup}}}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("UID %d helper failed: %v\n%s", uid, err, output)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "CTFM_UID_HELPER_JSON:") {
			var proof helperProof
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "CTFM_UID_HELPER_JSON:")), &proof); err != nil {
				t.Fatal(err)
			}
			if proof.PID != command.ProcessState.Pid() {
				t.Fatal("helper PID mismatch")
			}
			return proof
		}
	}
	t.Fatalf("UID %d helper omitted proof: %s", uid, output)
	return helperProof{}
}

func TestLinuxUIDHelper(t *testing.T) {
	mode := os.Getenv("CTFM_LINUX_UID_HELPER")
	if mode == "" {
		t.Skip("credential-switched subprocess helper")
	}
	proof := helperProof{UID: os.Geteuid(), GID: os.Getegid(), PID: os.Getpid(), Capabilities: capabilities(t)}
	if proof.Capabilities != "0000000000000000" {
		t.Fatal("unprivileged helper retained capabilities")
	}
	socket := os.Getenv("CTFM_UID_SOCKET")
	connection, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		t.Fatalf("shared IPC group cannot reach socket: %v", err)
	}
	connection.Close()
	proof.SocketDialled = true
	client, err := NewClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if mode == "allowed" {
		health, err := client.Health(ctx)
		if err != nil || health.Status != "ok" {
			t.Fatalf("allowed peer health: %#v %v", health, err)
		}
		proof.HealthAllowed = true
		services, err := client.ListServices(ctx)
		if err != nil || services == nil {
			t.Fatalf("allowed peer services: %#v %v", services, err)
		}
		proof.ServicesAllowed = true
		op, err := client.Submit(ctx, SubmitRequest{ServiceID: "flags", Action: domain.OperationStart, IdempotencyKey: "linux-uid-proof"})
		if err != nil || string(op.Spec.Initiator) != "uid-"+strconv.Itoa(proof.UID) {
			t.Fatalf("peer identity not supplied by kernel credentials: %v", err)
		}
		proof.PeerIdentityVerified = true
	} else if mode == "denied" {
		_, err := client.Health(ctx)
		var protocol *ProtocolError
		if !errors.As(err, &protocol) || protocol.Status != 403 {
			t.Fatalf("non-allowlisted UID was not denied: %v", err)
		}
		_, err = client.ListServices(ctx)
		if !errors.As(err, &protocol) || protocol.Status != 403 {
			t.Fatalf("non-allowlisted UID read services: %v", err)
		}
		proof.PeerDenied = true
	} else {
		t.Fatal("unknown helper mode")
	}
	privateDirectory := os.Getenv("CTFM_UID_PRIVATE")
	database := os.Getenv("CTFM_UID_DATABASE")
	secret := os.Getenv("CTFM_UID_SECRET")
	if _, err := os.ReadDir(privateDirectory); !os.IsPermission(err) {
		t.Fatalf("helper could inspect private state directory: %v", err)
	}
	proof.PrivateDirectoryDenied = true
	if _, err := os.ReadFile(database); !os.IsPermission(err) {
		t.Fatalf("helper could read executor DB: %v", err)
	}
	proof.DatabaseReadDenied = true
	if file, err := os.OpenFile(database, os.O_WRONLY, 0); !os.IsPermission(err) {
		if file != nil {
			file.Close()
		}
		t.Fatalf("helper could open executor DB for write: %v", err)
	}
	proof.DatabaseWriteDenied = true
	if _, err := os.ReadFile(secret); !os.IsPermission(err) {
		t.Fatalf("helper could read executor secret: %v", err)
	}
	proof.SecretReadDenied = true
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("CTFM_UID_HELPER_JSON:" + string(encoded))
}
