// Package sourcegit reads a bounded Git tree without running repository code.
// Git only fetches objects into an isolated bare repository. Files are exported
// from exact blobs by this package, so checkout hooks, filters and submodules
// cannot run, and Git never receives a service or executor state directory.
package sourcegit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

const (
	MaxRepositoryBytes int64 = 64 << 20
	MaxTreeBytes       int64 = 32 << 20
	MaxFileBytes       int64 = 16 << 20
	MaxFiles                 = 20000
	Timeout                  = 120 * time.Second
)

var refPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$`)
var objectPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
var versionPattern = regexp.MustCompile(`^git version ([0-9]+)\.([0-9]+)`)

type Config struct {
	URL          string `json:"url"`
	Ref          string `json:"ref"`
	Subdirectory string `json:"subdirectory,omitempty"`
	Username     string `json:"username,omitempty"`
}

func (c Config) Validate() error {
	u, err := url.Parse(c.URL)
	if err != nil || len(c.URL) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.Path == "" || strings.ContainsAny(c.URL, "\\\x00\r\n\t ") || strings.HasPrefix(u.Path, "//") {
		return errors.New("Git URL must be an HTTPS repository URL without embedded credentials, query or fragment")
	}
	for _, ch := range u.Path {
		if ch < 0x20 || ch == 0x7f {
			return errors.New("Git URL contains a control character")
		}
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !publicAddress(ip) {
		return errors.New("Git URL must address a public HTTPS host")
	}
	if !refPattern.MatchString(c.Ref) || strings.Contains(c.Ref, "..") || strings.Contains(c.Ref, "//") || strings.HasSuffix(c.Ref, "/") || strings.HasSuffix(c.Ref, ".") || strings.Contains(c.Ref, "/.") || strings.HasSuffix(c.Ref, ".lock") {
		return errors.New("Git ref must be HEAD, a branch, tag or exact commit without revision expressions")
	}
	if c.Subdirectory != "" {
		if err := domain.ValidateRelativePath(c.Subdirectory); err != nil {
			return err
		}
		for _, p := range strings.Split(c.Subdirectory, "/") {
			if strings.EqualFold(p, ".git") {
				return errors.New("Git metadata cannot be a source directory")
			}
		}
	}
	if len(c.Username) > 128 || strings.ContainsAny(c.Username, ":\x00\r\n\t ") {
		return errors.New("invalid Git username")
	}
	for _, ch := range c.Username {
		if ch < 0x21 || ch > 0x7e {
			return errors.New("Git username must use printable ASCII")
		}
	}
	return nil
}

type Tree struct {
	Directory string
	Commit    string
	root      string
}

func (t *Tree) Close() error { return os.RemoveAll(t.root) }

// Fetch accepts only production HTTPS transport. The test-only local transport
// seam is private to this package and cannot be enabled by configuration or IPC.
func Fetch(ctx context.Context, c Config, token []byte) (*Tree, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return fetch(ctx, c, token, false)
}

type runner struct {
	binary, root, repo, resolution string
	env                            []string
	local                          bool
}

func (r runner) command(ctx context.Context, args ...string) *exec.Cmd {
	configuration := []string{
		"protocol.allow=never", "protocol.https.allow=always", "http.proxy=",
		"http.followRedirects=false", "http.sslVerify=true", "credential.helper=",
		"core.hooksPath=/dev/null", "init.templateDir=", "fetch.fsckObjects=true",
		"transfer.fsckObjects=true", "fetch.uriprotocols=", "transfer.bundleURI=false",
		"pack.threads=1", "index-pack.threads=1", "pack.windowMemory=16m",
		"pack.deltaCacheSize=8m", "core.packedGitWindowSize=1m", "core.packedGitLimit=32m",
		"core.deltaBaseCacheLimit=8m",
	}
	var fixed []string
	for _, value := range configuration {
		fixed = append(fixed, "-c", value)
	}
	if r.local {
		fixed = append(fixed, "-c", "protocol.file.allow=always")
	}
	if r.resolution != "" {
		fixed = append(fixed, "-c", "http.curloptResolve="+r.resolution)
	}
	cmd := exec.CommandContext(ctx, r.binary, append(fixed, args...)...)
	cmd.Dir = r.repo
	cmd.Env = r.env
	cmd.Stderr = io.Discard // Never persist remote diagnostics or credentials.
	configureProcess(cmd)
	return cmd
}

func fetch(parent context.Context, c Config, token []byte, local bool) (_ *Tree, resultErr error) {
	if err := validateGitToken(token); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, Timeout)
	defer cancel()
	binary, err := exec.LookPath("git")
	if err != nil {
		return nil, errors.New("Git executable is unavailable")
	}
	root, err := os.MkdirTemp("", "ctfm-git-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			_ = os.RemoveAll(root)
		}
	}()
	if err := os.Chmod(root, 0711); err != nil {
		return nil, err
	}
	repo := filepath.Join(root, "objects")
	if err := os.Mkdir(repo, 0700); err != nil {
		return nil, err
	}
	if err := prepareRepository(repo); err != nil {
		return nil, err
	}
	env := gitEnvironment(repo, c, token)
	r := runner{binary: binary, root: root, repo: repo, env: env, local: local}
	if err := verifyGitVersion(ctx, r); err != nil {
		return nil, err
	}
	if !local {
		r.resolution, err = pinnedGitResolution(ctx, c.URL)
		if err != nil {
			return nil, err
		}
	}
	// The Docker /tmp tmpfs provides a hard outer bound; this early check also
	// bounds native development fetches and stops oversized packs promptly.
	quotaDone := make(chan struct{})
	quotaStopped := make(chan struct{})
	defer func() { close(quotaDone); <-quotaStopped }()
	go func() {
		defer close(quotaStopped)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-quotaDone:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				err := checkRepository(repo)
				if err != nil {
					cancel()
					return
				}
			}
		}
	}()
	if err := r.command(ctx, "init", "--bare", ".").Run(); err != nil {
		return nil, errors.New("cannot initialize isolated Git repository")
	}
	// Depth is also a transport boundary: Git refuses the dumb HTTP walker,
	// which otherwise supports server-supplied alternate repository URLs.
	if err := r.command(ctx, "fetch", "--depth=1", "--no-tags", "--no-recurse-submodules", "--", c.URL, c.Ref).Run(); err != nil {
		return nil, errors.New("Git fetch failed; verify HTTPS URL, ref, credentials and repository limits")
	}
	if err := checkRepository(repo); err != nil {
		return nil, err
	}
	commitOut, err := r.command(ctx, "rev-parse", "--verify", "FETCH_HEAD^{commit}").Output()
	commit := strings.TrimSpace(string(commitOut))
	if err != nil || !objectPattern.MatchString(commit) {
		return nil, errors.New("Git ref does not resolve to one exact commit")
	}
	listing := &limitedBuffer{limit: 4 << 20}
	listCmd := r.command(ctx, "ls-tree", "-rz", "--full-tree", commit)
	listCmd.Stdout = listing
	if err := listCmd.Run(); err != nil {
		return nil, errors.New("Git tree exceeds listing limits")
	}
	entries, err := parseTree(listing.Bytes(), c.Subdirectory)
	if err != nil {
		return nil, err
	}
	destination := filepath.Join(root, "tree")
	if err := os.Mkdir(destination, 0700); err != nil {
		return nil, err
	}
	if err := exportBlobs(ctx, r, destination, entries); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.New("Git source operation expired or exceeded repository limits")
	}
	return &Tree{Directory: destination, Commit: commit, root: root}, nil
}

// gitEnvironment is shared with transport tests so they exercise the exact
// URL-scoped credential configuration used by production. Fetch still performs
// all URL/public-address checks; no test transport is configurable through it.
func gitEnvironment(repo string, c Config, token []byte) []string {
	env := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + repo, "XDG_CONFIG_HOME=" + repo, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/bin/false", "GIT_SSH_COMMAND=/bin/false", "GIT_LFS_SKIP_SMUDGE=1", "GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1", "LC_ALL=C"}
	if len(token) > 0 {
		username := c.Username
		if username == "" {
			username = "oauth2"
		}
		// Redirects are disabled by runner.command. The header is never an
		// argv, repository setting or persisted configuration file.
		header := base64.StdEncoding.EncodeToString(append([]byte(username+":"), token...))
		env = append(env, "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http."+c.URL+".extraHeader", "GIT_CONFIG_VALUE_0=Authorization: Basic "+header)
	}
	return env
}

type entry struct {
	name, object string
	mode         os.FileMode
}

func parseTree(data []byte, subdirectory string) ([]entry, error) {
	entries := []entry{}
	all := bytes.Split(data, []byte{0})
	if len(all) > MaxFiles+1 {
		return nil, errors.New("Git tree file limit exceeded")
	}
	prefix := ""
	if subdirectory != "" {
		prefix = subdirectory + "/"
	}
	for _, raw := range all {
		if len(raw) == 0 {
			continue
		}
		header, name, ok := strings.Cut(string(raw), "\t")
		parts := strings.Split(header, " ")
		if !ok || len(parts) != 3 || parts[1] != "blob" || !objectPattern.MatchString(parts[2]) || (parts[0] != "100644" && parts[0] != "100755") {
			return nil, errors.New("Git symlinks, submodules and special files are unsupported")
		}
		if err := domain.ValidateRelativePath(name); err != nil {
			return nil, errors.New("Git tree contains an unsafe path")
		}
		for _, part := range strings.Split(name, "/") {
			if strings.EqualFold(part, ".git") || strings.EqualFold(part, ".gitmodules") {
				return nil, errors.New("Git metadata and submodules are unsupported")
			}
		}
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		name = strings.TrimPrefix(name, prefix)
		mode := os.FileMode(0644)
		if parts[0] == "100755" {
			mode = 0755
		}
		entries = append(entries, entry{name, parts[2], mode})
	}
	if len(entries) == 0 {
		return nil, errors.New("Git source directory contains no files")
	}
	return entries, nil
}

func exportBlobs(ctx context.Context, r runner, destination string, entries []entry) (resultErr error) {
	cmd := r.command(ctx, "cat-file", "--batch")
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return errors.New("cannot read Git objects")
	}
	ok := false
	defer func() {
		_ = in.Close()
		if !ok {
			// Close the read end before signalling. A Git process blocked on a
			// large blob then sees EPIPE even if a misconfigured host denies
			// cross-UID signals. Production Compose grants CAP_KILL explicitly.
			_ = out.Close()
			killErr := cmd.Cancel()
			if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
				resultErr = errors.Join(resultErr, errors.New("Git child signal denied; executor requires CAP_KILL"))
			}
			waited := make(chan error, 1)
			go func() { waited <- cmd.Wait() }()
			select {
			case <-waited:
			case <-time.After(3 * time.Second):
				resultErr = errors.Join(resultErr, errors.New("Git child cleanup did not finish within limit"))
			}
		}
	}()
	reader := bufio.NewReaderSize(out, 32*1024)
	var total int64
	for _, e := range entries {
		if _, err := io.WriteString(in, e.object+"\n"); err != nil {
			return errors.New("cannot request Git object")
		}
		header, err := reader.ReadString('\n')
		if err != nil || len(header) > 200 {
			return errors.New("invalid Git object header")
		}
		fields := strings.Fields(header)
		if len(fields) != 3 || fields[0] != e.object || fields[1] != "blob" {
			return errors.New("Git object is not the selected blob")
		}
		size, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil || size < 0 || size > MaxFileBytes || size > MaxTreeBytes-total {
			return errors.New("Git source byte limit exceeded")
		}
		total += size
		filename := filepath.Join(destination, filepath.FromSlash(e.name))
		if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
			return err
		}
		f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, e.mode)
		if err != nil {
			return errors.New("Git tree has conflicting paths")
		}
		if err := f.Chmod(e.mode); err != nil {
			f.Close()
			return err
		}
		prefix, readErr := reader.Peek(int(min(size, 128)))
		if readErr == nil && bytes.HasPrefix(prefix, []byte("version https://git-lfs.github.com/spec/v1\n")) {
			f.Close()
			return errors.New("Git LFS pointers are unsupported")
		}
		_, copyErr := io.CopyN(f, reader, size)
		closeErr := f.Close()
		if copyErr != nil || closeErr != nil {
			return errors.New("cannot export Git object")
		}
		if separator, err := reader.ReadByte(); err != nil || separator != '\n' {
			return errors.New("invalid Git object separator")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	_ = in.Close()
	if err := cmd.Wait(); err != nil {
		return errors.New("Git object reader failed")
	}
	ok = true
	return nil
}

type limitedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (b *limitedBuffer) Bytes() []byte { return b.buffer.Bytes() }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buffer.Len() {
		return 0, errors.New("Git output limit exceeded")
	}
	return b.buffer.Write(p)
}

// CleanSubdirectory applies the UI default without accepting path aliases.
func CleanSubdirectory(value string) string {
	if value == "." {
		return ""
	}
	return value
}

func publicAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, raw := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::/96", "64:ff9b::/96", "64:ff9b:1::/48", "2001::/23", "2001:db8::/32", "2002::/16"} {
		if netip.MustParsePrefix(raw).Contains(ip) {
			return false
		}
	}
	return true
}

func checkRepository(repo string) error {
	var size int64
	count := 0
	err := filepath.WalkDir(repo, func(_ string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		count++
		if count > MaxFiles*2 {
			return errors.New("Git repository entry limit exceeded")
		}
		if e.Type().IsRegular() {
			entrySize, err := repositoryEntrySize(e)
			if err != nil {
				return err
			}
			size += entrySize
			if size > MaxRepositoryBytes {
				return errors.New("Git repository byte limit exceeded")
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	// A temporary lock may disappear during the scan, but losing the whole
	// repository must still fail the quota check.
	info, err := os.Lstat(repo)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("Git repository directory is unavailable")
	}
	return nil
}

func repositoryEntrySize(entry fs.DirEntry) (int64, error) {
	info, err := entry.Info()
	// Git atomically removes or renames temporary pack/ref/maintenance files.
	// Only a vanished child entry is benign; permission and other errors remain
	// fatal, and walker/root errors are handled separately by checkRepository.
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}
