package sourcegit

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureRepository(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("Git unavailable")
	}
	root, err := os.MkdirTemp("", "ctfm-git-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "core.hooksPath=/dev/null", "-c", "user.email=fixture@example.invalid", "-c", "user.name=Fixture", "-C", root}, args...)...)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + root, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("fixture Git failed: %s %v", out, err)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "--template=", ".")
	for name, value := range files {
		filename := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(value), 0644); err != nil {
			t.Fatal(err)
		}
	}
	git("add", ".")
	git("commit", "-m", "fixture")
	return root, git("rev-parse", "HEAD")
}

func TestFetchExportsExactCommitWithoutAmbientConfigOrCredentialsOnDisk(t *testing.T) {
	repo, commit := fixtureRepository(t, map[string]string{"service/app/main.txt": "version=2\n", "service/.gitattributes": "*.txt filter=untrusted\n", "unrelated.txt": "outside source\n"})
	marker := filepath.Join(t.TempDir(), "filter-ran")
	global := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(global, []byte("[filter \"untrusted\"]\n smudge = touch "+marker+"\n required = true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", global)
	t.Setenv("GIT_PROXY_COMMAND", "must-not-run")
	t.Setenv("HTTPS_PROXY", "https://invalid.example:1")
	token := []byte("SECRET_TOKEN_84628648")
	tree, err := fetch(t.Context(), Config{URL: "file://" + repo, Ref: "HEAD", Subdirectory: "service", Username: "oauth2"}, token, true)
	if err != nil {
		t.Fatal(err)
	}
	defer tree.Close()
	if tree.Commit != commit {
		t.Fatalf("commit %s != %s", tree.Commit, commit)
	}
	data, err := os.ReadFile(filepath.Join(tree.Directory, "app", "main.txt"))
	if err != nil || string(data) != "version=2\n" {
		t.Fatalf("wrong export: %s %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(tree.Directory, "unrelated.txt")); !os.IsNotExist(err) {
		t.Fatal("subdirectory escape")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("repository filter ran")
	}
	encoded := base64.StdEncoding.EncodeToString(append([]byte("oauth2:"), token...))
	if err := filepath.WalkDir(tree.root, func(name string, e os.DirEntry, err error) error {
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
		if bytes.Contains(data, token) || bytes.Contains(data, []byte(encoded)) {
			t.Fatalf("credential persisted in %s", name)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	root := tree.root
	if err := tree.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("isolated checkout not removed")
	}
}

func TestFetchRejectsLFSPointersAndOversizedBlob(t *testing.T) {
	for _, test := range []struct{ name, data string }{
		{"lfs", "version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 200\n"},
		{"large", strings.Repeat("x", int(MaxFileBytes)+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo, _ := fixtureRepository(t, map[string]string{"app/file": test.data})
			if tree, err := fetch(t.Context(), Config{URL: "file://" + repo, Ref: "HEAD"}, nil, true); err == nil {
				tree.Close()
				t.Fatal("unsupported blob accepted")
			}
		})
	}
}

func TestFetchAcceptsBundledSourceOrExecutableAboveEightMiB(t *testing.T) {
	// Real CTF repositories include SQLite amalgamations and supplied executables.
	// Keep the per-file limit bounded while accepting these ordinary artifacts.
	data := strings.Repeat("x", 13<<20)
	repo, commit := fixtureRepository(t, map[string]string{"app/bundled": data})
	tree, err := fetch(t.Context(), Config{URL: "file://" + repo, Ref: "HEAD"}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	defer tree.Close()
	actual, err := os.ReadFile(filepath.Join(tree.Directory, "app/bundled"))
	if err != nil || tree.Commit != commit || string(actual) != data {
		t.Fatalf("bundled artifact was not exported exactly: %v", err)
	}
}

func TestFetchRejectsCombinedTreeOverBudget(t *testing.T) {
	repo, _ := fixtureRepository(t, map[string]string{
		"app/a": strings.Repeat("a", 12<<20),
		"app/b": strings.Repeat("b", 12<<20),
		"app/c": strings.Repeat("c", 9<<20),
	})
	if tree, err := fetch(t.Context(), Config{URL: "file://" + repo, Ref: "HEAD"}, nil, true); err == nil {
		tree.Close()
		t.Fatal("combined source tree above budget accepted")
	}
}

func TestProductionRejectsUnsafeURLsRefsAndPrivateHosts(t *testing.T) {
	base := Config{URL: "https://github.com/SibirCTF/service.git", Ref: "HEAD"}
	for _, raw := range []string{"file:///tmp/repo", "ssh://git@example.com/repo", "git@example.com:repo", "http://github.com/x", "https://user:secret@github.com/x", "https://github.com/x?token=secret", "https://github.com/x#ref", "https://127.0.0.1/x", "https://10.0.0.2/x", "https://[::1]/x", "https://100.64.1.2/x", "https://github.com/%0asecret"} {
		t.Run(raw, func(t *testing.T) {
			v := base
			v.URL = raw
			if err := v.Validate(); err == nil {
				t.Fatal("unsafe URL accepted")
			}
		})
	}
	for _, ref := range []string{"-upload-pack=touch", "HEAD:refs/heads/x", "refs/heads/../main", "main^{tree}", "main~1", "main@{0}", "main.lock", "a//b", "main\n"} {
		v := base
		v.Ref = ref
		if err := v.Validate(); err == nil {
			t.Fatalf("unsafe ref %q accepted", ref)
		}
	}
	for _, ip := range []string{"127.0.0.1", "169.254.169.254", "::ffff:127.0.0.1", "fc00::1", "fe80::1", "192.0.2.1", "198.19.1.1"} {
		if publicAddress(netip.MustParseAddr(ip)) {
			t.Fatalf("restricted IP accepted: %s", ip)
		}
	}
	if !publicAddress(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("public IP rejected")
	}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := Fetch(t.Context(), Config{URL: "file:///tmp/repo", Ref: "HEAD"}, nil); err == nil {
		t.Fatal("private test transport exposed through production entry")
	}
}

func TestTreeRejectsSymlinksSubmodulesAndTraversal(t *testing.T) {
	object := strings.Repeat("a", 40)
	for _, raw := range []string{
		"120000 blob " + object + "\tapp/link\x00",
		"160000 commit " + object + "\tapp/module\x00",
		"100644 blob " + object + "\t../outside\x00",
		"100644 blob " + object + "\tapp/.git/config\x00",
		"100644 blob " + object + "\t.gitmodules\x00",
	} {
		if _, err := parseTree([]byte(raw), ""); err == nil {
			t.Fatalf("unsafe tree accepted: %q", raw)
		}
	}
}

func TestRunnerDoesNotPutCredentialsInArgumentsOrInheritAmbientEnvironment(t *testing.T) {
	r := runner{binary: "/usr/bin/git", repo: "/tmp", env: []string{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0=secret"}}
	cmd := r.command(context.Background(), "fetch", "--", "https://github.com/x/y.git", "HEAD")
	if strings.Contains(strings.Join(cmd.Args, " "), "secret") {
		t.Fatal("credential in arguments")
	}
	if len(cmd.Env) != 3 {
		t.Fatal("ambient environment inherited")
	}
	if os.Geteuid() == 0 && (cmd.SysProcAttr == nil || cmd.SysProcAttr.Credential == nil || cmd.SysProcAttr.Credential.Uid == 0) {
		t.Fatal("Git child retains root")
	}
}
