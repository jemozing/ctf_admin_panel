package transport

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

type managedPathsTestBackend struct {
	registrationTestBackend
	requests atomic.Int32
}

func (b *managedPathsTestBackend) ResolveRegistrationManagedPaths(_ context.Context, input RegistrationManagedPathsRequest) (RegistrationManagedPathsResult, error) {
	b.requests.Add(1)
	if input.ServiceID != "draft-game" || len(input.CodeBindings) != 2 || input.CodeBindings[0] != "mount-web" || input.CodeBindings[1] != "mount-cleaner" {
		return RegistrationManagedPathsResult{}, &RegistrationInputError{Message: "Choose discovered code bindings"}
	}
	return RegistrationManagedPathsResult{ManagedPaths: []domain.ManagedPath{{Path: "main.py", Kind: domain.ManagedCode}, {Path: "compose.yaml", Kind: domain.ManagedConfig}}}, nil
}

func TestTypedManagedPathsPreservesDraftAndBindingNames(t *testing.T) {
	backend := &managedPathsTestBackend{}
	_, client := runServer(t, Options{Backend: backend})
	result, err := client.ResolveRegistrationManagedPaths(t.Context(), RegistrationManagedPathsRequest{ServiceID: "draft-game", CodeBindings: []string{"mount-web", "mount-cleaner"}})
	if err != nil || len(result.ManagedPaths) != 2 || result.ManagedPaths[0].Path != "main.py" || result.ManagedPaths[1].Kind != domain.ManagedConfig {
		t.Fatalf("managed paths: %#v %v", result, err)
	}
	_, err = client.ResolveRegistrationManagedPaths(t.Context(), RegistrationManagedPathsRequest{ServiceID: "draft-other"})
	var protocol *ProtocolError
	if !errors.As(err, &protocol) || protocol.Status != 400 || !strings.Contains(protocol.Message, "discovered") || backend.requests.Load() != 2 {
		t.Fatalf("safe backend validation lost: %v", err)
	}
}

func TestManagedPathsRequestRejectsUnboundedAmbiguousAndPathInputs(t *testing.T) {
	backend := &managedPathsTestBackend{}
	_, client := runServer(t, Options{Backend: backend})
	for _, tc := range []struct {
		method, suffix, body string
		status               int
	}{
		{"GET", "", "", 405},
		{"POST", "?directory=/etc", `{}`, 400},
		{"POST", "", `{"service_id":"draft-game","code_bindings":["mount-web"],"directory":"/etc"}`, 400},
		{"POST", "", `{"service_id":"draft-game","Service_id":"draft-game"}`, 400},
		{"POST", "", `{"service_id":"draft-game","service_id":"draft-other"}`, 400},
		{"POST", "", `{"service_id":"draft-game","code_bindings":["mount-web"],"code_bindings":[]}`, 400},
		{"POST", "", `{"service_id":"draft-game","code_bindings":["mount-web","mount-web"]}`, 400},
		{"POST", "", `{"service_id":"draft-game","code_bindings":["../escape"]}`, 400},
		{"POST", "", `{"service_id":"draft-game","code_bindings":true}`, 400},
		{"POST", "", `{"service_id":"../escape","code_bindings":[]}`, 400},
		{"POST", "", `{"code_bindings":[]}`, 400},
		{"POST", "", `{} {}`, 400},
	} {
		request, err := http.NewRequest(tc.method, "http://executor/v1/registration/managed-paths"+tc.suffix, strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.http.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != tc.status {
			t.Errorf("%s %s: got %d want %d", tc.method, tc.body, response.StatusCode, tc.status)
		}
	}
	if backend.requests.Load() != 0 {
		t.Fatal("invalid request reached backend")
	}
	bindings := make([]string, 129)
	for i := range bindings {
		bindings[i] = fmt.Sprintf("mount-%d", i)
	}
	if ValidateRegistrationManagedPathsRequest(RegistrationManagedPathsRequest{ServiceID: "draft-game", CodeBindings: bindings}) == nil {
		t.Fatal("unbounded binding selection accepted")
	}
}

func TestManagedPathsOptionalAdapterDoesNotBreakOldRegistration(t *testing.T) {
	_, client := runServer(t, Options{Backend: &registrationTestBackend{}})
	if _, err := client.RegistrationOptions(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, err := client.ResolveRegistrationManagedPaths(t.Context(), RegistrationManagedPathsRequest{ServiceID: "draft-game"})
	var protocol *ProtocolError
	if !errors.As(err, &protocol) || protocol.Status != 501 {
		t.Fatalf("old adapter must fail closed: %v", err)
	}
}
