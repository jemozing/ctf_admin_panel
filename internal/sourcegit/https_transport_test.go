package sourcegit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// These tests use a package-private runner and a disposable local TLS server.
// Production Fetch still rejects private addresses and has no CA/test bypass.
type httpsGitFixture struct {
	url, ca, work, bare, root, commit, branch string
	mode                                      atomic.Int32
	authFailures                              atomic.Int32
	alternateRequests                         atomic.Int32
	alternateCredential                       atomic.Bool
	hung                                      chan struct{}
	canceled                                  chan struct{}
	redirect                                  string
}

func fixtureGit(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "core.hooksPath=/dev/null", "-c", "user.email=fixture@example.invalid", "-c", "user.name=Fixture", "-C", repo}, args...)...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + repo, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fixture git command failed: %v %s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func newHTTPSGitFixture(t *testing.T) *httpsGitFixture {
	t.Helper()
	work, commit := fixtureRepository(t, map[string]string{"app/version": "version=1\n"})
	root, err := os.MkdirTemp("", "ctfm-https-git-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	if err = os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	f := &httpsGitFixture{root: root, work: work, commit: commit, branch: fixtureGit(t, work, "symbolic-ref", "--short", "HEAD"), hung: make(chan struct{}, 1), canceled: make(chan struct{}, 1)}
	f.bare = filepath.Join(root, "private.git")
	fixtureGit(t, work, "clone", "--bare", work, f.bare)
	backend := filepath.Join(fixtureGit(t, work, "--exec-path"), "git-http-backend")
	if _, err = os.Stat(backend); err != nil {
		t.Skip("git-http-backend unavailable")
	}
	handler := &cgi.Handler{Path: backend, Dir: root, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null"}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/other.git") {
			f.alternateRequests.Add(1)
			f.alternateCredential.Store(r.Header.Get("Authorization") != "")
			w.WriteHeader(401)
			return
		}
		user, password, ok := r.BasicAuth()
		if !ok || user != "oauth2" || password != "test-only-private-token" {
			f.authFailures.Add(1)
			w.Header().Set("WWW-Authenticate", `Basic realm="test fixture"`)
			w.WriteHeader(401)
			return
		}
		switch f.mode.Load() {
		case 1:
			http.Redirect(w, r, f.redirect+r.URL.RequestURI(), http.StatusTemporaryRedirect)
			return
		case 2:
			w.Header().Set("Content-Type", "text/plain")
			switch r.URL.Path {
			case "/private.git/info/refs":
				w.Write([]byte(f.commit + "\trefs/heads/" + f.branch + "\n"))
			case "/private.git/HEAD":
				w.Write([]byte("ref: refs/heads/" + f.branch + "\n"))
			case "/private.git/objects/info/http-alternates":
				w.Write([]byte(f.redirect + "/objects\n"))
			default:
				w.WriteHeader(404)
			}
			return
		case 3:
			w.WriteHeader(503)
			return
		case 4:
			select {
			case f.hung <- struct{}{}:
			default:
			}
			<-r.Context().Done()
			select {
			case f.canceled <- struct{}{}:
			default:
			}
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	f.url = server.URL + "/private.git"
	f.ca = filepath.Join(root, "fixture-ca.pem")
	if err = os.WriteFile(f.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0644); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *httpsGitFixture) runner(t *testing.T, token string, trust bool) runner {
	t.Helper()
	repo, err := os.MkdirTemp(f.root, "client-")
	if err != nil {
		t.Fatal(err)
	}
	if err = prepareRepository(repo); err != nil {
		t.Fatal(err)
	}
	binary, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	r := runner{binary: binary, root: f.root, repo: repo, env: gitEnvironment(repo, Config{URL: f.url, Ref: f.branch}, []byte(token))}
	if trust {
		r.env = append(r.env, "GIT_SSL_CAINFO="+f.ca)
	}
	if err = r.command(t.Context(), "init", "--bare", ".").Run(); err != nil {
		t.Fatal(err)
	}
	return r
}
func fixtureFetch(ctx context.Context, r runner, url, ref string) error {
	return r.command(ctx, "fetch", "--depth=1", "--no-tags", "--no-recurse-submodules", "--", url, ref).Run()
}

func TestHTTPSGitAuthenticationTLSRedirectsAndOfflineFailures(t *testing.T) {
	f := newHTTPSGitFixture(t)
	good := f.runner(t, "test-only-private-token", true)
	if err := fixtureFetch(t.Context(), good, f.url, f.branch); err != nil {
		t.Fatalf("authenticated smart HTTPS fetch failed: %v", err)
	}
	commit, err := good.command(t.Context(), "rev-parse", "--verify", "FETCH_HEAD^{commit}").Output()
	if err != nil || strings.TrimSpace(string(commit)) != f.commit {
		t.Fatal("wrong fetched commit", err)
	}
	for _, test := range []struct {
		name, token string
		trust       bool
	}{{"wrong token", "incorrect-token", true}, {"no credentials", "", true}, {"untrusted TLS", "test-only-private-token", false}} {
		t.Run(test.name, func(t *testing.T) {
			r := f.runner(t, test.token, test.trust)
			if err := fixtureFetch(t.Context(), r, f.url, f.branch); err == nil {
				t.Fatal("unsafe/unavailable transport succeeded")
			}
		})
	}
	if f.authFailures.Load() == 0 {
		t.Fatal("private authentication failure was not exercised")
	}
	var redirectHits atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirectHits.Add(1); w.WriteHeader(200) }))
	defer target.Close()
	f.redirect = target.URL
	f.mode.Store(1)
	r := f.runner(t, "test-only-private-token", true)
	if err := fixtureFetch(t.Context(), r, f.url, f.branch); err == nil || redirectHits.Load() != 0 {
		t.Fatal("redirect followed or accepted")
	}
	f.mode.Store(2)
	r = f.runner(t, "test-only-private-token", true)
	if err := fixtureFetch(t.Context(), r, f.url, f.branch); err == nil || redirectHits.Load() != 0 {
		t.Fatal("dumb HTTP/alternate object transport accepted")
	}
	f.mode.Store(3)
	r = f.runner(t, "test-only-private-token", true)
	if err := fixtureFetch(t.Context(), r, f.url, f.branch); err == nil {
		t.Fatal("offline/503 fetch succeeded")
	}
	f.mode.Store(0)
	r = f.runner(t, "test-only-private-token", true)
	other := strings.TrimSuffix(f.url, "/private.git") + "/other.git"
	if err := fixtureFetch(t.Context(), r, other, f.branch); err == nil || f.alternateRequests.Load() == 0 || f.alternateCredential.Load() {
		t.Fatal("URL-scoped credential escaped to a different repository")
	}
	if err := fixtureFetch(t.Context(), r, f.url, "missing-branch"); err == nil {
		t.Fatal("missing ref unexpectedly succeeded")
	}
	secret := []byte("test-only-private-token")
	encoded := []byte(base64.StdEncoding.EncodeToString(append([]byte("oauth2:"), secret...)))
	argv := []byte(strings.Join(r.command(t.Context(), "fetch", "--", f.url, f.branch).Args, " "))
	if bytes.Contains(argv, secret) || bytes.Contains(argv, encoded) {
		t.Fatal("credential leaked into argv")
	}
	if err := filepath.WalkDir(f.root, func(name string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !e.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		if bytes.Contains(data, secret) || bytes.Contains(data, encoded) {
			t.Errorf("credential persisted in fixture client/server repository: %s", filepath.Base(name))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPSGitCancellationKillsTransportAndMovingRefDoesNotChangeExport(t *testing.T) {
	f := newHTTPSGitFixture(t)
	r := f.runner(t, "test-only-private-token", true)
	if err := fixtureFetch(t.Context(), r, f.url, f.branch); err != nil {
		t.Fatal(err)
	}
	listing, err := r.command(t.Context(), "ls-tree", "-rz", "--full-tree", f.commit).Output()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := parseTree(listing, "")
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(f.root, "export")
	if err = os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	if err = exportBlobs(t.Context(), r, destination, entries); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(f.work, "app/version"), []byte("version=2\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fixtureGit(t, f.work, "add", ".")
	fixtureGit(t, f.work, "commit", "-m", "second version")
	next := fixtureGit(t, f.work, "rev-parse", "HEAD")
	fixtureGit(t, f.work, "push", f.bare, "HEAD:refs/heads/"+f.branch)
	if err = fixtureFetch(t.Context(), r, f.url, f.branch); err != nil {
		t.Fatal(err)
	}
	actual, err := r.command(t.Context(), "rev-parse", "FETCH_HEAD").Output()
	if err != nil || strings.TrimSpace(string(actual)) != next || next == f.commit {
		t.Fatal("moving branch did not resolve a new exact commit", err)
	}
	old, err := os.ReadFile(filepath.Join(destination, "app/version"))
	if err != nil || string(old) != "version=1\n" {
		t.Fatal("moving remote branch changed exported immutable source", err)
	}
	if _, err = parseTree(listing, "absent-subdirectory"); err == nil {
		t.Fatal("missing subdirectory accepted")
	}
	f.mode.Store(4)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- fixtureFetch(ctx, r, f.url, f.branch) }()
	select {
	case <-f.hung:
	case <-time.After(5 * time.Second):
		t.Fatal("test request did not enter slow server")
	}
	cancel()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("cancelled HTTPS fetch succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancel did not terminate Git process group")
	}
	select {
	case <-f.canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled transport left HTTPS request running")
	}
}
