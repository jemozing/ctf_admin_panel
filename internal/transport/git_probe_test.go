package transport

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/sourcegit"
)

type gitProbeTestBackend struct {
	testBackend
	checks  atomic.Int32
	browses atomic.Int32
}

func (b *gitProbeTestBackend) ProbeGitSource(_ context.Context, input GitProbeRequest) (GitProbeResult, error) {
	b.checks.Add(1)
	if input.Source.Ref == "missing" {
		return GitProbeResult{}, &sourcegit.ProbeError{Code: "git_access_failed", Message: "Git repository is unavailable"}
	}
	return GitProbeResult{Branches: []sourcegit.RemoteRef{{Name: "main", Ref: "refs/heads/main", Commit: strings.Repeat("a", 40)}}, SelectedRef: input.Source.Ref, RefStatus: "available", CheckedAt: time.Now().UTC()}, nil
}

func (b *gitProbeTestBackend) BrowseGitDirectories(_ context.Context, input GitDirectoriesRequest) (GitDirectoryListing, error) {
	b.browses.Add(1)
	if input.Directory == "missing" {
		return GitDirectoryListing{}, &sourcegit.ProbeError{Code: "git_directory_missing", Message: "Git directory is unavailable"}
	}
	root := ""
	return GitDirectoryListing{Directory: input.Directory, Parent: &root, Directories: []sourcegit.DirectoryEntry{}}, nil
}

func TestGitDirectoryBrowseTypedClientAndInvalidPath(t *testing.T) {
	b := &gitProbeTestBackend{}
	_, c := runServer(t, Options{Backend: b})
	input := GitDirectoriesRequest{
		Source:    GitSourceRequest{URL: "https://github.com/example/service.git", Ref: "refs/heads/main"},
		Directory: "vuln-service",
	}
	result, err := c.BrowseGitDirectories(t.Context(), input)
	if err != nil || result.Directory != "vuln-service" || result.Parent == nil || *result.Parent != "" || result.Directories == nil {
		t.Fatalf("browse result: %#v %v", result, err)
	}
	input.Directory = "missing"
	_, err = c.BrowseGitDirectories(t.Context(), input)
	var protocol *ProtocolError
	if !errors.As(err, &protocol) || protocol.Status != 404 || protocol.Code != "git_directory_missing" {
		t.Fatalf("missing directory error: %v", err)
	}
	for _, directory := range []string{"../outside", "service/.git", "/etc"} {
		request, err := http.NewRequest("POST", "http://executor/v1/git/directories", strings.NewReader(
			`{"source":{"url":"https://github.com/example/service.git"},"directory":"`+directory+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := c.http.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 400 {
			t.Errorf("invalid directory %q reached browse route: %d", directory, response.StatusCode)
		}
	}
	if b.browses.Load() != 2 {
		t.Fatal("invalid browse reached backend")
	}
}

func TestGitProbeTypedClientAndSafeFailure(t *testing.T) {
	b := &gitProbeTestBackend{}
	_, c := runServer(t, Options{Backend: b})
	input := GitProbeRequest{Source: GitSourceRequest{URL: "https://github.com/example/service.git", Ref: "HEAD", Token: "test-secret"}}
	result, err := c.ProbeGitSource(t.Context(), input)
	if err != nil || result.RefStatus != "available" || len(result.Branches) != 1 || result.Branches[0].Ref != "refs/heads/main" {
		t.Fatalf("probe result: %#v %v", result, err)
	}
	input.Source.Ref = "missing"
	_, err = c.ProbeGitSource(t.Context(), input)
	var protocol *ProtocolError
	if !errors.As(err, &protocol) || protocol.Status != 502 || protocol.Code != "git_access_failed" || strings.Contains(protocol.Message, input.Source.Token) {
		t.Fatalf("unsafe or lost probe error: %v", err)
	}
	if c.http.Timeout != 20*time.Second || c.transport.ResponseHeaderTimeout != 10*time.Second {
		t.Fatal("probe changed ordinary RPC timeouts")
	}
}

func TestGitProbeRejectsInvalidRequestsBeforeBackend(t *testing.T) {
	b := &gitProbeTestBackend{}
	_, c := runServer(t, Options{Backend: b})
	for _, tc := range []struct {
		method, query, body, media string
		status                     int
	}{
		{"GET", "", "", "application/json", 405},
		{"POST", "?url=https://elsewhere.invalid", `{}`, "application/json", 400},
		{"POST", "", `{"source":{"url":"file:///tmp/repo"}}`, "application/json", 400},
		{"POST", "", `{"source":{"url":"https://github.com/e/r.git","token":"a","token":"b"}}`, "application/json", 400},
		{"POST", "", `{"source":{"URL":"https://github.com/e/r.git"}}`, "application/json", 400},
		{"POST", "", `{"source":{"url":"https://github.com/e/r.git"},"initiator":"forged"}`, "application/json", 400},
		{"POST", "", `{"source":{"url":"https://github.com/e/r.git"},"service_id":"../game"}`, "application/json", 400},
		{"POST", "", `{}`, "text/plain", 415},
		{"POST", "", strings.Repeat(" ", 16*1024+1), "application/json", 413},
	} {
		r, err := http.NewRequest(tc.method, "http://executor/v1/git/probe"+tc.query, strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", tc.media)
		response, err := c.http.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != tc.status {
			t.Errorf("%s %s: got %d want %d", tc.method, tc.query, response.StatusCode, tc.status)
		}
	}
	if b.checks.Load() != 0 {
		t.Fatal("invalid probe reached backend")
	}
}
