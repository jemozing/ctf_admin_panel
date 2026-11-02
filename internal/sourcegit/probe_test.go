package sourcegit

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProbeRefAdvertisementResolvesExactSelection(t *testing.T) {
	first, second, tag := strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40)
	data := "ref: refs/heads/main\tHEAD\n" + first + "\tHEAD\n" + first + "\trefs/heads/main\n" + second + "\trefs/heads/feature/ctf\n" + tag + "\trefs/tags/release\n" + second + "\trefs/tags/release^{}\n" + first + "\trefs/pull/1/head\n"
	for _, tc := range []struct {
		ref, status, object string
	}{
		{"HEAD", "available", first}, {"main", "available", first}, {"refs/heads/main", "available", first},
		{"feature/ctf", "available", second}, {"release", "available", second}, {"refs/tags/release", "available", second},
		{"missing", "missing", ""}, {"refs/heads/missing", "missing", ""},
		{second, "available", second}, {strings.Repeat("d", 40), "unverified", ""},
	} {
		t.Run(tc.ref, func(t *testing.T) {
			result, err := parseRemoteRefs([]byte(data), tc.ref)
			if err != nil || result.RefStatus != tc.status || result.ResolvedCommit != tc.object || result.SelectedRef != tc.ref || result.DefaultBranch != "main" || len(result.Branches) != 2 {
				t.Fatalf("wrong advertised ref result: %#v %v", result, err)
			}
			if result.Branches[0].Ref != "refs/heads/feature/ctf" || result.Branches[0].Name != "feature/ctf" {
				t.Fatal("branch names are not sorted/full refs")
			}
		})
	}
	ambiguous, err := parseRemoteRefs([]byte(data+second+"\trefs/tags/main\n"), "main")
	if err != nil || ambiguous.RefStatus != "ambiguous" || ambiguous.ResolvedCommit != "" {
		t.Fatal("unqualified ambiguous branch/tag falsely selected", err)
	}
	qualified, err := parseRemoteRefs([]byte(data+second+"\trefs/tags/main\n"), "refs/heads/main")
	if err != nil || qualified.RefStatus != "available" || qualified.ResolvedCommit != first {
		t.Fatal("qualified branch did not disambiguate", err)
	}
	empty, err := parseRemoteRefs(nil, "HEAD")
	if err != nil || empty.RefStatus != "missing" || empty.Branches == nil {
		t.Fatal("empty repository result", err)
	}
}

func TestProbeRejectsIncompleteMalformedConflictingAndOversizedAds(t *testing.T) {
	object := strings.Repeat("a", 40)
	for _, data := range []string{
		"sensitive-remote-diagnostic", "\n", object + " refs/heads/main\n", object + "\trefs/heads/main",
		object + "\trefs/heads/main\textra\n", "bad\trefs/heads/main\n", object + "\t../escape\n",
		object + "\trefs/heads/a..b\n", object + "\trefs/tags/only-peeled^{}\n",
		strings.Repeat("0", 40) + "\tHEAD\n", strings.Repeat("0", 64) + "\trefs/heads/main\n", object + "\trefs/heads/a.lock/child\n",
		object + "\trefs/heads/main\n" + object + "\trefs/heads/main\n",
		"ref: refs/heads/main\tHEAD\nref: refs/heads/other\tHEAD\n",
		"ref: refs/tags/main\tHEAD\n", "ref: refs/heads/main\trefs/heads/alias\n",
		"ref: refs/heads/main\tHEAD\n" + object + "\tHEAD\n" + strings.Repeat("b", 40) + "\trefs/heads/main\n",
		strings.Repeat("a", MaxProbeBytes+1),
	} {
		_, err := parseRemoteRefs([]byte(data), "HEAD")
		if err == nil || strings.Contains(err.Error(), "sensitive-remote") {
			t.Fatalf("malformed advertisement accepted or echoed: %v", err)
		}
	}
	var count bytes.Buffer
	for i := 0; i <= MaxProbeRefs; i++ {
		fmt.Fprintf(&count, "%s\trefs/heads/b%d\n", object, i)
	}
	_, err := parseRemoteRefs(count.Bytes(), "HEAD")
	var safe *ProbeError
	if !errors.As(err, &safe) || safe.Code != "git_limits" {
		t.Fatal("reference count not bounded", err)
	}
}

func TestProbeBranchDisplayLimitKeepsCompleteRefValidation(t *testing.T) {
	object := strings.Repeat("e", 40)
	var data bytes.Buffer
	for i := MaxProbeBranches + 10; i >= 0; i-- {
		fmt.Fprintf(&data, "%s\trefs/heads/b%04d\n", object, i)
	}
	result, err := parseRemoteRefs(data.Bytes(), "refs/heads/b0266")
	if err != nil || !result.Truncated || len(result.Branches) != MaxProbeBranches || result.Branches[0].Name != "b0000" || result.Branches[255].Name != "b0255" || result.RefStatus != "available" || result.ResolvedCommit != object {
		t.Fatalf("display limit lost ordering or complete validation: %#v %v", result, err)
	}
}

func TestProbeAcceptsExtendedAdvertisementNamesWithoutExpandingSourceProfile(t *testing.T) {
	object := strings.Repeat("a", 40)
	base := "ref: refs/heads/main\tHEAD\n" + object + "\tHEAD\n" + object + "\trefs/heads/main\n"
	tags := object + "\trefs/tags/v1.0+build\n" + object + "\trefs/tags/релиз\n"
	for _, selected := range []string{"HEAD", "main"} {
		result, err := parseRemoteRefs([]byte(base+tags), selected)
		if err != nil || result.RefStatus != "available" || result.ResolvedCommit != object || len(result.Branches) != 1 || result.Truncated {
			t.Fatalf("unrelated extended tags broke supported ref %s: %#v %v", selected, result, err)
		}
		result, err = parseRemoteRefs([]byte(base+tags+object+"\trefs/heads/ветка\n"+object+"\trefs/heads/feature+build\n"), selected)
		if err != nil || result.RefStatus != "available" || result.ResolvedCommit != object || len(result.Branches) != 1 || result.Branches[0].Ref != "refs/heads/main" || !result.Truncated {
			t.Fatalf("unsupported branches broke supported ref %s: %#v %v", selected, result, err)
		}
		for _, branch := range result.Branches {
			if err := (Config{URL: "https://example.invalid/repository.git", Ref: branch.Ref}).Validate(); err != nil {
				t.Fatal("unselectable branch leaked into dropdown", err)
			}
		}
	}
	unicodeDefault := "ref: refs/heads/ветка\tHEAD\n" + object + "\tHEAD\n" + object + "\trefs/heads/ветка\n"
	result, err := parseRemoteRefs([]byte(unicodeDefault), "HEAD")
	if err != nil || result.RefStatus != "available" || result.ResolvedCommit != object || result.DefaultBranch != "ветка" || len(result.Branches) != 0 || !result.Truncated {
		t.Fatalf("Unicode default branch metadata or HEAD lost: %#v %v", result, err)
	}
	for _, ref := range []string{"refs/heads/ветка", "refs/tags/v1.0+build"} {
		if (Config{URL: "https://example.invalid/repository.git", Ref: ref}).Validate() == nil {
			t.Fatal("existing source ref profile unexpectedly expanded")
		}
	}
}

func TestProbeAdvertisementNamesStillRejectInvalidGitRefComponents(t *testing.T) {
	object := strings.Repeat("a", 40)
	for _, name := range []string{"refs/heads/a b", "refs/heads/a\tb", "refs/heads/a\x00b", "refs/heads/a\x7fb", "refs/heads/a..b", "refs/heads/a@{b", "refs/heads/.hidden", "refs/heads/a.lock/child", "refs/heads/a//b", "refs/heads/a/", "refs/heads/a.", "refs/heads/a~b", "refs/heads/a^b", "refs/heads/a:b", "refs/heads/a?b", "refs/heads/a*b", "refs/heads/a[b", "refs/heads/a\\b", "refs/heads/a\u2028b", "refs/heads/" + string([]byte{0xff})} {
		if _, err := parseRemoteRefs([]byte(object+"\t"+name+"\n"), "HEAD"); err == nil {
			t.Errorf("invalid remote Git ref accepted: %q", name)
		}
	}
}

func TestProbeHTTPSCredentialsAndReadOnlyAdvertisement(t *testing.T) {
	f := newHTTPSGitFixture(t)
	r := f.runner(t, "test-only-private-token", true)
	result, err := probeRemote(t.Context(), r, f.branch, f.url)
	if err != nil || result.RefStatus != "available" || result.ResolvedCommit != f.commit || result.CheckedAt.IsZero() || result.DefaultBranch != f.branch || len(result.Branches) != 1 {
		t.Fatalf("actual HTTPS probe failed: %#v %v", result, err)
	}
	if _, err := os.Stat(filepath.Join(r.repo, "FETCH_HEAD")); !os.IsNotExist(err) {
		t.Fatal("probe fetched objects")
	}
	if err := filepath.WalkDir(filepath.Join(r.repo, "objects"), func(_ string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			t.Error("probe created a Git object")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		token string
		trust bool
	}{{"wrong-token", true}, {"", true}, {"test-only-private-token", false}} {
		_, err := probeRemote(t.Context(), f.runner(t, tc.token, tc.trust), f.branch, f.url)
		var safe *ProbeError
		if !errors.As(err, &safe) || safe.Code != "git_access_failed" {
			t.Fatal("invalid auth/TLS passed", err)
		}
	}
	other := strings.TrimSuffix(f.url, "/private.git") + "/other.git"
	_, err = probeRemote(t.Context(), r, f.branch, other)
	if err == nil || f.alternateRequests.Load() == 0 || f.alternateCredential.Load() {
		t.Fatal("credential escaped URL scope", err)
	}
	secret := []byte("test-only-private-token")
	encoded := []byte(base64.StdEncoding.EncodeToString(append([]byte("oauth2:"), secret...)))
	argv := []byte(strings.Join(r.command(t.Context(), "ls-remote", "--symref", "--", f.url).Args, " "))
	if bytes.Contains(argv, secret) || bytes.Contains(argv, encoded) {
		t.Fatal("credential in command arguments")
	}
	if err := filepath.WalkDir(r.repo, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		if bytes.Contains(data, secret) || bytes.Contains(data, encoded) {
			t.Error("credential persisted by probe")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestProbeHTTPSErrorAndCancellation(t *testing.T) {
	f := newHTTPSGitFixture(t)
	f.mode.Store(3)
	_, err := probeRemote(t.Context(), f.runner(t, "test-only-private-token", true), f.branch, f.url)
	var safe *ProbeError
	if !errors.As(err, &safe) || safe.Code != "git_access_failed" {
		t.Fatal("HTTP503 not safely diagnosed", err)
	}
	f.mode.Store(4)
	r := f.runner(t, "test-only-private-token", true)
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = probeRemote(ctx, r, f.branch, f.url)
	if !errors.As(err, &safe) || safe.Code != "git_timeout" || time.Since(start) > 4*time.Second {
		t.Fatal("transport timeout was not bounded/redacted", err)
	}
	select {
	case <-f.canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("TLS request survived process cancellation")
	}
}

func TestProbeHTTPSRedirectDoesNotFollowOrForwardCredentials(t *testing.T) {
	f := newHTTPSGitFixture(t)
	var targetHits atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		w.WriteHeader(200)
	}))
	defer target.Close()
	f.redirect = target.URL
	f.mode.Store(1)
	_, err := probeRemote(t.Context(), f.runner(t, "test-only-private-token", true), f.branch, f.url)
	var safe *ProbeError
	if !errors.As(err, &safe) || safe.Code != "git_access_failed" || targetHits.Load() != 0 {
		t.Fatal("probe followed redirect or disclosed URL-scoped credential", err)
	}
}

func TestProbeOutputOverflowTerminatesChildAndRedactsDiagnostics(t *testing.T) {
	directory, err := os.MkdirTemp("", "ctfm-probe-runner-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(directory, "repo")
	if err := os.Mkdir(repo, 0700); err != nil {
		t.Fatal(err)
	}
	if err := prepareRepository(repo); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(directory, "fake-git")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\necho 'sensitive-remote-diagnostic' >&2\nwhile :; do printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\trefs/heads/main\\n'; done\n"), 0755); err != nil {
		t.Fatal(err)
	}
	r := runner{binary: binary, repo: repo, env: []string{"PATH=/usr/bin:/bin"}}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	start := time.Now()
	_, err = probeRemote(ctx, r, "HEAD", "https://example.invalid/repository.git")
	var safe *ProbeError
	if !errors.As(err, &safe) || safe.Code != "git_limits" || strings.Contains(err.Error(), "sensitive-remote") || time.Since(start) > 3*time.Second {
		t.Fatal("output overflow not bounded/redacted", err)
	}
}

func TestGitOutputLimitsCannotBeBypassedByIOCopyReaderFrom(t *testing.T) {
	// os/exec connects stdout using io.Copy. Embedding bytes.Buffer would
	// promote ReadFrom and bypass a custom Write limit on that actual path.
	limited := &limitedBuffer{limit: 8}
	if _, unsafe := any(limited).(io.ReaderFrom); unsafe {
		t.Fatal("limited output exposes a bypassing ReaderFrom")
	}
	if _, err := io.Copy(limited, strings.NewReader(strings.Repeat("x", 20))); err == nil || len(limited.Bytes()) > 8 {
		t.Fatal("existing fetch output limit bypassed")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	probe := &probeOutput{limit: 8, cancel: cancel}
	if _, unsafe := any(probe).(io.ReaderFrom); unsafe {
		t.Fatal("probe output exposes a bypassing ReaderFrom")
	}
	if _, err := io.Copy(probe, strings.NewReader(strings.Repeat("x", 20))); err == nil || !probe.overflow || len(probe.Bytes()) > 8 || ctx.Err() == nil {
		t.Fatal("probe output limit bypassed or did not cancel transport")
	}
}

func TestPublicProbeValidatesBeforeNetworkAndPreservesUnavailableDiagnosis(t *testing.T) {
	for _, config := range []Config{
		{URL: "file:///tmp/repository.git", Ref: "HEAD"}, {URL: "https://127.0.0.1/repository.git", Ref: "HEAD"},
		{URL: "https://github.com/owner/repository.git", Ref: "main..other"},
	} {
		_, err := Probe(t.Context(), config, nil)
		var safe *ProbeError
		if !errors.As(err, &safe) || safe.Code != "git_invalid" {
			t.Fatal("invalid public input reached network", err)
		}
	}
	config := Config{URL: "https://github.com/owner/repository.git", Ref: "HEAD"}
	_, err := Probe(t.Context(), config, []byte("bad\ntoken"))
	var safe *ProbeError
	if !errors.As(err, &safe) || safe.Code != "git_invalid" {
		t.Fatal("invalid credential accepted", err)
	}
	t.Setenv("PATH", t.TempDir())
	_, err = Probe(t.Context(), config, nil)
	if !errors.As(err, &safe) || safe.Code != "git_unavailable" {
		t.Fatal("unavailable Git misclassified as cancellation", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = Probe(ctx, config, nil)
	if !errors.As(err, &safe) || safe.Code != "git_canceled" {
		t.Fatal("cancel not diagnosed", err)
	}
}

func TestPublicProbeRejectsDNSResolvingToRestrictedHost(t *testing.T) {
	if _, err := os.Stat("/usr/bin/git"); err != nil {
		t.Skip("Git unavailable")
	}
	_, err := Probe(t.Context(), Config{URL: "https://localhost/repository.git", Ref: "HEAD"}, nil)
	var safe *ProbeError
	if !errors.As(err, &safe) || safe.Code != "git_restricted_host" {
		t.Fatal("restricted DNS hostname reached HTTPS transport", err)
	}
}
