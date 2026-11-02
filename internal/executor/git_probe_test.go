package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/sourcegit"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func TestGitProbeDraftDoesNotRequireRegisteredServiceOrVault(t *testing.T) {
	m := &Manager{}
	request := transport.GitProbeRequest{Source: transport.GitSourceRequest{
		URL: "https://github.com/example/service.git", Token: "fixture-draft-token", Username: "oauth2",
	}}
	configuration, token, err := m.prepareGitProbe(t.Context(), request)
	defer clear(token)
	if err != nil || configuration.Ref != "HEAD" || configuration.URL != request.Source.URL || string(token) != request.Source.Token {
		t.Fatal("registration draft could not prepare its in-memory Git probe")
	}
}

func TestGitProbeSavedCredentialsAreReadOnlyAndScopedToExactURLAndUsername(t *testing.T) {
	f := gitPlanningFixture(t)
	const savedToken = "fixture-saved-probe-token"
	request := transport.GitSourceRequest{URL: "https://github.com/example/service.git", Ref: "main", Username: "oauth2", Token: savedToken}
	if _, err := f.m.ConfigureGitSource(t.Context(), f.s.ID, request); err != nil {
		t.Fatal(err)
	}
	request.Token = ""
	type captured struct {
		Store map[string]any
		Vault any
		Files []string
	}
	capture := func() captured {
		state := captured{Store: map[string]any{}}
		for _, kind := range []string{"git_source", "snapshot", "runtime_state", "release"} {
			records, err := f.m.Store.List(t.Context(), kind, f.s.ID)
			if err != nil {
				t.Fatal(err)
			}
			state.Store[kind] = records
		}
		operations, err := f.m.Store.ListOperations(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		state.Store["operations"] = operations
		state.Vault, err = f.m.Vault.Versions()
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{f.activeFile, f.workspaceFile} {
			data, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			state.Files = append(state.Files, string(data))
		}
		return state
	}
	before := capture()
	for _, tc := range []struct {
		name, url, username, token string
		clear                      bool
		want                       string
	}{
		{"same source", request.URL, request.Username, "", false, savedToken},
		{"other repository", "https://github.com/example/other.git", request.Username, "", false, ""},
		{"other host", "https://gitlab.com/example/service.git", request.Username, "", false, ""},
		{"other user", request.URL, "another-user", "", false, ""},
		{"clear saved credential", request.URL, request.Username, "", true, ""},
		{"override credential", request.URL, request.Username, "fixture-replacement-token", false, "fixture-replacement-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			draft := transport.GitProbeRequest{ServiceID: f.s.ID, Source: transport.GitSourceRequest{
				URL: tc.url, Ref: "refs/heads/release", Username: tc.username, Token: tc.token, ClearCredentials: tc.clear,
			}}
			configuration, token, err := f.m.prepareGitProbe(t.Context(), draft)
			defer clear(token)
			if err != nil || string(token) != tc.want || configuration.Ref != draft.Source.Ref {
				t.Fatal("credential selection crossed scope or discarded the selected ref")
			}
		})
	}
	if after := capture(); !reflect.DeepEqual(before, after) {
		t.Fatal("preparing a probe modified service state, secret versions, operations or files")
	}
	view, err := f.m.GitSource(t.Context(), f.s.ID)
	if err != nil || view.Revision != 1 || view.Ref != "main" || !view.HasCredentials {
		t.Fatal("probing changed the saved source")
	}
	public, err := json.Marshal(view)
	if err != nil || strings.Contains(string(public), savedToken) || strings.Contains(string(public), "fixture-replacement-token") {
		t.Fatal("probe token appeared in public configuration")
	}
}

func TestGitProbeSavedServiceWithoutSourceOrWithMissingService(t *testing.T) {
	f := gitPlanningFixture(t)
	request := transport.GitProbeRequest{ServiceID: f.s.ID, Source: transport.GitSourceRequest{URL: "https://github.com/example/service.git"}}
	configuration, token, err := f.m.prepareGitProbe(t.Context(), request)
	if err != nil || len(token) != 0 || configuration.Ref != "HEAD" {
		t.Fatal("unconfigured service did not support an anonymous draft probe")
	}
	request.ServiceID = "missing-service"
	request.Source.Token = "fixture-unsaved-token"
	if _, _, err := f.m.prepareGitProbe(t.Context(), request); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("unknown service accepted even with an explicit draft token")
	}
}

func TestGitProbeUnavailableSavedCredentialDoesNotExposeVaultDetails(t *testing.T) {
	f := gitPlanningFixture(t)
	request := transport.GitSourceRequest{URL: "https://github.com/example/service.git", Username: "oauth2", Token: "fixture-saved-probe-token"}
	if _, err := f.m.ConfigureGitSource(t.Context(), f.s.ID, request); err != nil {
		t.Fatal(err)
	}
	configuration, err := f.m.gitConfiguration(t.Context(), f.s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.m.Vault.Revoke(*configuration.Credential); err != nil {
		t.Fatal(err)
	}
	request.Token = ""
	_, token, err := f.m.prepareGitProbe(t.Context(), transport.GitProbeRequest{ServiceID: f.s.ID, Source: request})
	var unavailable *sourcegit.ProbeError
	if !errors.As(err, &unavailable) || unavailable.Code != "git_credentials_unavailable" || len(token) != 0 || unavailable.Message != "Git credentials unavailable; configure a new token" {
		t.Fatal("unavailable vault credential was accepted or revealed private diagnostics")
	}
	request.Token = "fixture-new-token"
	_, token, err = f.m.prepareGitProbe(t.Context(), transport.GitProbeRequest{ServiceID: f.s.ID, Source: request})
	defer clear(token)
	if err != nil || string(token) != request.Token {
		t.Fatal("explicit draft replacement unnecessarily read the revoked credential")
	}
}

func TestGitProbeValidatesAndCancelsBeforeCredentialReadOrNetwork(t *testing.T) {
	m := &Manager{}
	for _, source := range []transport.GitSourceRequest{
		{URL: "file:///private/service.git"},
		{URL: "https://github.com/example/service.git", Token: "bad\ntoken"},
		{URL: "https://github.com/example/service.git", Token: "fixture-token", ClearCredentials: true},
	} {
		if _, err := m.ProbeGitSource(t.Context(), transport.GitProbeRequest{ServiceID: domain.ID("known-service"), Source: source}); err == nil {
			t.Fatal("invalid draft reached credential handling or network")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	valid := transport.GitProbeRequest{Source: transport.GitSourceRequest{URL: "https://github.com/example/service.git"}}
	if _, err := m.ProbeGitSource(ctx, valid); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled probe reached network")
	}
	if len(gitProbeSlots) != 0 {
		t.Fatal("invalid or cancelled probe retained a subprocess slot")
	}
}

func TestGitProbeConcurrencyGateRejectsBeforeCredentialRead(t *testing.T) {
	// A bare Manager has no store. If this draft reaches service lookup instead
	// of the process-wide gate, it returns NotFound rather than Busy.
	gitProbeSlots <- struct{}{}
	gitProbeSlots <- struct{}{}
	defer func() { <-gitProbeSlots; <-gitProbeSlots }()
	m := &Manager{}
	input := transport.GitProbeRequest{ServiceID: "missing-service", Source: transport.GitSourceRequest{URL: "https://github.com/example/service.git"}}
	if _, err := m.ProbeGitSource(t.Context(), input); !errors.Is(err, store.ErrBusy) {
		t.Fatal("saturated probe gate did not reject before reading credentials")
	}
}
