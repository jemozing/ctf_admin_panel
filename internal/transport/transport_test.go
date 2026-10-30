package transport

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
)

type testBackend struct{}

func (testBackend) ListServices(context.Context) ([]domain.Service, error) {
	return []domain.Service{}, nil
}
func (testBackend) ListOperations(context.Context) ([]domain.Operation, error) {
	return []domain.Operation{}, nil
}
func (testBackend) GetOperation(context.Context, domain.ID) (domain.Operation, error) {
	return domain.Operation{}, store.ErrNotFound
}

func socketPath(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "ctf-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	return filepath.Join(directory, "executor.sock")
}

func runServer(t *testing.T, options Options) (*Server, *Client) {
	t.Helper()
	if options.SocketPath == "" {
		options.SocketPath = socketPath(t)
	}
	if options.Backend == nil {
		options.Backend = testBackend{}
	}
	if options.AllowedUIDs == nil {
		options.AllowedUIDs = []uint32{uint32(os.Geteuid())}
	}
	options.Development = true
	server, err := NewServer(options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	client, err := NewClient(options.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		client.Close()
		cancel()
		server.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("server did not terminate")
		}
	})
	return server, client
}

func TestPeerCredentialsAndTypedReadEndpoints(t *testing.T) {
	server, client := runServer(t, Options{})
	info, err := os.Lstat(server.options.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0660 {
		t.Fatalf("socket mode=%o", info.Mode().Perm())
	}
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	health, err := client.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if health.Status != "ok" || health.SchemaVersion != 1 {
		t.Fatalf("bad health: %#v", health)
	}
	if result, err := client.ListServices(context.Background()); err != nil || len(result) != 0 {
		t.Fatalf("services: %#v %v", result, err)
	}
	_, err = client.GetOperation(context.Background(), "missing")
	var protocol *ProtocolError
	if !errors.As(err, &protocol) || protocol.Status != 404 {
		t.Fatalf("missing operation error: %v", err)
	}
	if _, err := NewServer(server.options); err == nil {
		t.Fatal("active socket was replaced")
	}
	if _, err := client.Health(context.Background()); err != nil {
		t.Fatalf("existing server damaged: %v", err)
	}
}

func TestUnauthorizedUIDCannotReadOrSubmit(t *testing.T) {
	var called atomic.Int32
	_, client := runServer(t, Options{AllowedUIDs: []uint32{uint32(os.Geteuid()) + 1}, Submit: func(context.Context, Principal, SubmitRequest) (domain.Operation, error) {
		called.Add(1)
		return domain.Operation{}, nil
	}})
	_, err := client.Health(context.Background())
	var protocol *ProtocolError
	if !errors.As(err, &protocol) || protocol.Status != http.StatusForbidden {
		t.Fatalf("unauthorized peer accepted: %v", err)
	}
	_, err = client.Submit(context.Background(), SubmitRequest{ServiceID: "flags", Action: domain.OperationStart, IdempotencyKey: "key"})
	if !errors.As(err, &protocol) || protocol.Status != http.StatusForbidden {
		t.Fatalf("unauthorized submit: %v", err)
	}
	if called.Load() != 0 {
		t.Fatal("unauthorized action reached backend")
	}
}

func TestSubmitRejectsCommandsPathsDuplicatesAndOversizedInput(t *testing.T) {
	var called atomic.Int32
	_, client := runServer(t, Options{Submit: func(context.Context, Principal, SubmitRequest) (domain.Operation, error) {
		called.Add(1)
		return domain.Operation{}, nil
	}})
	cases := []struct {
		body   string
		status int
	}{
		{`{"service_id":"flags","action":"start","idempotency_key":"a","path":"/etc"}`, 400},
		{`{"service_id":"flags","action":"start","idempotency_key":"a","command":"rm -rf /"}`, 400},
		{`{"service_id":"flags","action":"start","action":"stop","idempotency_key":"a"}`, 400},
		{`{"service_id":"flags","Service_ID":"other","action":"start","idempotency_key":"a"}`, 400},
		{`{"service_id":"flags","action":"shell","idempotency_key":"a"}`, 400},
		{`{"service_id":"../etc","action":"start","idempotency_key":"a"}`, 400},
		{`{"service_id":"flags","action":"deploy","idempotency_key":"a"}`, 400},
		{`{"service_id":"flags","action":"start","idempotency_key":null}`, 400},
		{`{"service_id":"flags","action":"start","idempotency_key":"a"} {}`, 400},
		{`{"service_id":"flags","action":"start","idempotency_key":"` + strings.Repeat("x", MaxBodyBytes) + `"}`, 413},
	}
	for i, tc := range cases {
		request, err := http.NewRequest(http.MethodPost, "http://executor/v1/operations", strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.http.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != tc.status {
			t.Fatalf("case %d: status=%d want=%d", i, response.StatusCode, tc.status)
		}
	}
	if called.Load() != 0 {
		t.Fatal("invalid input reached submit callback")
	}
}

func TestValidSubmitUsesAuthenticatedPeerAndNilCallbackIsExplicit(t *testing.T) {
	_, client := runServer(t, Options{Submit: func(ctx context.Context, p Principal, r SubmitRequest) (domain.Operation, error) {
		if p.UID != uint32(os.Geteuid()) {
			t.Error("principal was not obtained from peer credentials")
		}
		return domain.NewOperation(domain.OperationSpec{ID: "op-1", Kind: r.Action, Initiator: "local-user", IdempotencyKey: r.IdempotencyKey, ServiceID: r.ServiceID, ExpectedPolicyRevision: 1, ExpectedTreeDigest: domain.Hash(nil), Resources: []string{"service:" + string(r.ServiceID)}, TimeoutSeconds: 30}, time.Now())
	}})
	op, err := client.Submit(context.Background(), SubmitRequest{ServiceID: "flags", Action: domain.OperationStart, IdempotencyKey: "start-1"})
	if err != nil {
		t.Fatal(err)
	}
	if op.Spec.ID != "op-1" || op.State != domain.OperationQueued {
		t.Fatalf("bad operation response: %#v", op)
	}
	_, disabled := runServer(t, Options{})
	_, err = disabled.Submit(context.Background(), SubmitRequest{ServiceID: "flags", Action: domain.OperationStart, IdempotencyKey: "key"})
	var protocol *ProtocolError
	if !errors.As(err, &protocol) || protocol.Status != 501 {
		t.Fatalf("missing callback pretends support: %v", err)
	}
}

func TestHostOriginAndPathAreNotBackendParameters(t *testing.T) {
	_, client := runServer(t, Options{})
	cases := []struct {
		target, host, origin string
		status               int
	}{
		{"http://executor/v1/services", "malicious.local", "", 403},
		{"http://executor/v1/services", "executor", "https://untrusted.example", 403},
		{"http://executor/v1/services?path=/etc", "executor", "", 400},
		{"http://executor/v1/operations/op%2Froot", "executor", "", 400},
	}
	for _, tc := range cases {
		request, err := http.NewRequest(http.MethodGet, tc.target, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = tc.host
		request.Header.Set("Origin", tc.origin)
		response, err := client.http.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != tc.status {
			t.Fatalf("target %s status=%d want=%d", tc.target, response.StatusCode, tc.status)
		}
	}
}

func TestClosePreservesReplacementAndRejectsUnsafeDirectory(t *testing.T) {
	server, _ := runServer(t, Options{})
	filename := server.options.SocketPath
	if err := os.Remove(filename); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(filename)
	if err != nil || string(actual) != "replacement" {
		t.Fatal("server removed a replacement socket path")
	}
	unsafe := filepath.Dir(socketPath(t))
	if err := os.Chmod(unsafe, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := NewServer(Options{SocketPath: filepath.Join(unsafe, "sock"), AllowedUIDs: []uint32{uint32(os.Geteuid())}, Backend: testBackend{}, Development: true}); err == nil {
		t.Fatal("writable socket directory accepted")
	}
	if runtime.GOOS != "linux" {
		if _, err := NewServer(Options{SocketPath: socketPath(t), AllowedUIDs: []uint32{uint32(os.Geteuid())}, Backend: testBackend{}}); err == nil {
			t.Fatal("production transport accepted non-Linux host")
		}
	}
}

func TestContextShutdownRemovesOwnSocket(t *testing.T) {
	filename := socketPath(t)
	server, err := NewServer(Options{SocketPath: filename, AllowedUIDs: []uint32{uint32(os.Geteuid())}, Backend: testBackend{}, Development: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("context shutdown hung")
	}
	if _, err := os.Lstat(filename); !os.IsNotExist(err) {
		t.Fatal("own socket remains after shutdown")
	}
}
