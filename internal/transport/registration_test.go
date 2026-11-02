package transport

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
)

type registrationTestBackend struct {
	testBackend
	proposals, approvals atomic.Int32
}

func (*registrationTestBackend) RegistrationOptions(context.Context) (RegistrationOptions, error) {
	return RegistrationOptions{DiscoveryRoots: []string{"/srv/services"}, WorkspaceRoots: []string{"/srv/workspaces"}}, nil
}
func (*registrationTestBackend) BrowseRegistrationDirectories(_ context.Context, r RegistrationBrowseRequest) (RegistrationDirectoryListing, error) {
	if r.Directory != "" && r.Directory != "/srv/services" {
		return RegistrationDirectoryListing{}, &RegistrationInputError{Message: "Directory outside approved roots"}
	}
	return RegistrationDirectoryListing{Directory: r.Directory, Directories: []RegistrationDirectoryEntry{{Name: "game", Path: "/srv/services/game"}}, ComposeFiles: []string{}}, nil
}
func (*registrationTestBackend) InspectRegistration(_ context.Context, r RegistrationInspectRequest) (RegistrationInspection, error) {
	if r.ProjectDirectory != "/srv/services/game" {
		return RegistrationInspection{}, &RegistrationInputError{Message: "Project outside approved roots"}
	}
	return RegistrationInspection{Service: domain.Service{ID: "draft-game"}, Warnings: []string{"Review data"}}, nil
}
func (b *registrationTestBackend) ProposeRegistration(_ context.Context, r RegistrationProposalRequest) (store.Proposal, error) {
	b.proposals.Add(1)
	return store.Proposal{ID: "proposal-test", Digest: domain.Hash([]byte("proposal")), Actor: r.Initiator, Service: r.Service}, nil
}
func (b *registrationTestBackend) ApproveRegistration(_ context.Context, r RegistrationApproveRequest) (RegistrationApproval, error) {
	b.approvals.Add(1)
	return RegistrationApproval{Service: domain.Service{ID: "draft-game"}, Initialized: false, Operation: &domain.Operation{Spec: domain.OperationSpec{ID: "op-baseline"}}}, nil
}

func TestTypedRegistrationRoutesAndSafeValidation(t *testing.T) {
	b := &registrationTestBackend{}
	_, c := runServer(t, Options{Backend: b})
	options, err := c.RegistrationOptions(t.Context())
	if err != nil || len(options.DiscoveryRoots) != 1 {
		t.Fatalf("options: %#v %v", options, err)
	}
	listing, err := c.BrowseRegistrationDirectories(t.Context(), RegistrationBrowseRequest{Directory: "/srv/services"})
	if err != nil || listing.Directory != "/srv/services" || len(listing.Directories) != 1 || listing.Directories[0].Path != "/srv/services/game" {
		t.Fatalf("directory listing: %#v %v", listing, err)
	}
	_, err = c.BrowseRegistrationDirectories(t.Context(), RegistrationBrowseRequest{Directory: "/etc"})
	var browseError *ProtocolError
	if !errors.As(err, &browseError) || browseError.Status != 400 || !strings.Contains(browseError.Message, "approved") {
		t.Fatalf("directory validation lost: %v", err)
	}
	inspection, err := c.InspectRegistration(t.Context(), RegistrationInspectRequest{ProjectDirectory: "/srv/services/game"})
	if err != nil || inspection.Service.ID != "draft-game" {
		t.Fatalf("inspect: %#v %v", inspection, err)
	}
	_, err = c.InspectRegistration(t.Context(), RegistrationInspectRequest{ProjectDirectory: "/etc"})
	var p *ProtocolError
	if !errors.As(err, &p) || p.Status != 400 || !strings.Contains(p.Message, "approved") {
		t.Fatalf("input validation lost: %v", err)
	}
	proposal, err := c.ProposeRegistration(t.Context(), RegistrationProposalRequest{Service: inspection.Service, Initiator: "user-admin"})
	if err != nil || proposal.Actor != "user-admin" || b.proposals.Load() != 1 {
		t.Fatalf("proposal: %#v %v", proposal, err)
	}
	approval, err := c.ApproveRegistration(t.Context(), RegistrationApproveRequest{ProposalID: proposal.ID, Digest: proposal.Digest, Initiator: "user-admin"})
	if err != nil || approval.Operation.Spec.ID != "op-baseline" || b.approvals.Load() != 1 {
		t.Fatalf("approval: %#v %v", approval, err)
	}
	for _, body := range []string{`{"proposal_id":"proposal-test","digest":"bad","initiator":"user-admin"}`, `{"proposal_id":"proposal-test","digest":"` + string(proposal.Digest) + `","initiator":"user-admin","root":"/etc"}`, `{} {}`} {
		r, err := http.NewRequest("POST", "http://executor/v1/registration/approve", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		response, err := c.http.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 400 {
			t.Fatalf("accepted invalid approval %s => %d", body, response.StatusCode)
		}
	}
	if b.approvals.Load() != 1 {
		t.Fatal("invalid approval reached backend")
	}
}

func TestRegistrationDirectoryRequestRejectsQueryMethodAndAmbiguousJSON(t *testing.T) {
	_, c := runServer(t, Options{Backend: &registrationTestBackend{}})
	for _, tc := range []struct {
		method, suffix, body string
		status               int
	}{
		{"GET", "", "", 405},
		{"POST", "?root=/etc", `{}`, 400},
		{"POST", "", `{"directory":"/srv/services","directory":"/etc"}`, 400},
		{"POST", "", `{"Directory":"/srv/services"}`, 400},
		{"POST", "", `{"directory":"/srv/services","root":"/etc"}`, 400},
		{"POST", "", `{"directory":true}`, 400},
	} {
		r, err := http.NewRequest(tc.method, "http://executor/v1/registration/directories"+tc.suffix, strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		response, err := c.http.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != tc.status {
			t.Errorf("%s %s %s: got %d want %d", tc.method, tc.suffix, tc.body, response.StatusCode, tc.status)
		}
	}
}

func TestRegistrationJSONRejectsDuplicateAndCaseAliasedFieldsRecursively(t *testing.T) {
	for _, body := range []string{`null`, `[]`, `{"service":{"id":"a","id":"b"}}`, `{"service":{"ID":"a"}}`, `{"Service":{"id":"a"}}`, `{"service":{"containers":[{"component":"app","role":"database","role":"application"}]}}`, `{"service":{"managed_paths":[{"path":"app","Kind":"code"}]}}`, `{"service":{},"service":{}}`, `{} {}`} {
		var input RegistrationProposalRequest
		if err := DecodeRegistrationJSON([]byte(body), &input); err == nil {
			t.Errorf("accepted ambiguous JSON %s", body)
		}
	}
	var input RegistrationProposalRequest
	if err := DecodeRegistrationJSON([]byte(`{"service":{"id":"a","containers":[{"component":"app","role":"application"}],"managed_paths":[{"path":"app","kind":"code","exclusions":[".git"]}]},"initiator":"user-admin"}`), &input); err != nil {
		t.Fatalf("valid nested JSON: %v", err)
	}
}
