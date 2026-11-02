package sourcegit

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	ProbeTimeout     = 20 * time.Second
	MaxProbeBytes    = 512 * 1024
	MaxProbeRefs     = 8192
	MaxProbeBranches = 256
)

type RemoteRef struct {
	Name   string `json:"name"`
	Ref    string `json:"ref"`
	Commit string `json:"commit"`
}

// ProbeError contains only fixed diagnostics; remote stderr, credentials and
// filesystem errors must never cross the executor boundary.
type ProbeError struct {
	Code    string
	Message string
}

func (e *ProbeError) Error() string { return e.Message }

func probeFailure(code, message string) error {
	return &ProbeError{Code: code, Message: message}
}

// ProbeResult describes only the server's advertisement at check time. Object
// type, repository contents and a subdirectory are still verified by Fetch.
type ProbeResult struct {
	Branches       []RemoteRef `json:"branches"`
	DefaultBranch  string      `json:"default_branch,omitempty"`
	SelectedRef    string      `json:"selected_ref"`
	ResolvedCommit string      `json:"resolved_commit,omitempty"`
	RefStatus      string      `json:"ref_status"`
	Truncated      bool        `json:"truncated"`
	CheckedAt      time.Time   `json:"checked_at"`
}

// Probe verifies public HTTPS access and reads refs without fetching objects or
// creating a source candidate. It shares Fetch's DNS, TLS and credential policy.
func Probe(parent context.Context, c Config, token []byte) (result ProbeResult, resultErr error) {
	checkContext := parent
	var cancelCheck context.CancelFunc
	defer func() {
		if cancelCheck != nil {
			defer cancelCheck()
		}
		if resultErr == nil {
			return
		}
		var safe *ProbeError
		if errors.As(resultErr, &safe) {
			return
		}
		if checkContext.Err() != nil {
			resultErr = probeContextError(checkContext)
		} else {
			resultErr = probeFailure("git_unavailable", "Git connection check is unavailable; verify executor Git installation")
		}
	}()
	var empty ProbeResult
	if err := c.Validate(); err != nil {
		return empty, probeFailure("git_invalid", "Git connection settings are invalid; verify HTTPS URL, ref and credentials")
	}
	if err := validateGitToken(token); err != nil {
		return empty, probeFailure("git_invalid", "Git credentials have an invalid format")
	}
	ctx, cancel := context.WithTimeout(parent, ProbeTimeout)
	checkContext = ctx
	cancelCheck = cancel
	if ctx.Err() != nil {
		return empty, probeContextError(ctx)
	}
	binary, err := exec.LookPath("git")
	if err != nil {
		return empty, errors.New("Git executable is unavailable")
	}
	root, err := os.MkdirTemp("", "ctfm-git-probe-")
	if err != nil {
		return empty, errors.New("Cannot prepare isolated Git connection check")
	}
	defer os.RemoveAll(root)
	if err := os.Chmod(root, 0711); err != nil {
		return empty, errors.New("Cannot prepare isolated Git connection check")
	}
	repo := filepath.Join(root, "objects")
	if err := os.Mkdir(repo, 0700); err != nil {
		return empty, errors.New("Cannot prepare isolated Git connection check")
	}
	if err := prepareRepository(repo); err != nil {
		return empty, errors.New("Cannot prepare isolated Git connection check")
	}
	r := runner{binary: binary, root: root, repo: repo, env: gitEnvironment(repo, c, token)}
	if err := verifyGitVersion(ctx, r); err != nil {
		return empty, err
	}
	r.resolution, err = pinnedGitResolution(ctx, c.URL)
	if err != nil {
		return empty, err
	}
	if err := r.command(ctx, "init", "--bare", ".").Run(); err != nil {
		if ctx.Err() != nil {
			return empty, probeContextError(ctx)
		}
		return empty, errors.New("Cannot initialize isolated Git connection check")
	}
	return probeRemote(ctx, r, c.Ref, c.URL)
}

func probeContextError(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return probeFailure("git_canceled", "Git connection check was cancelled")
	}
	return probeFailure("git_timeout", "Git connection check timed out; verify network access and try again")
}

// probeRemote's unexported runner seam lets tests use a disposable TLS server.
// Production callers can only enter through Probe's public HTTPS/DNS checks.
func probeRemote(parent context.Context, r runner, selected, remote string) (ProbeResult, error) {
	ctx, cancel := context.WithTimeout(parent, ProbeTimeout)
	defer cancel()
	output := probeOutput{limit: MaxProbeBytes, cancel: cancel}
	cmd := r.command(ctx, "ls-remote", "--symref", "--", remote)
	cmd.Stdout = &output
	if err := cmd.Run(); err != nil {
		if output.overflow {
			return ProbeResult{}, probeFailure("git_limits", "Git reference advertisement exceeds connection-check limits")
		}
		if ctx.Err() != nil {
			return ProbeResult{}, probeContextError(ctx)
		}
		return ProbeResult{}, probeFailure("git_access_failed", "Git connection check failed; verify HTTPS URL, credentials, TLS and repository access")
	}
	if ctx.Err() != nil {
		return ProbeResult{}, probeContextError(ctx)
	}
	result, err := parseRemoteRefs(output.Bytes(), selected)
	if err != nil {
		return ProbeResult{}, err
	}
	result.CheckedAt = time.Now().UTC()
	return result, nil
}

type probeOutput struct {
	buffer   bytes.Buffer
	limit    int
	cancel   context.CancelFunc
	overflow bool
}

func (b *probeOutput) Bytes() []byte { return b.buffer.Bytes() }

func (b *probeOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buffer.Len() {
		b.overflow = true
		b.cancel()
		return 0, errors.New("Git reference advertisement exceeds limit")
	}
	return b.buffer.Write(p)
}

func parseRemoteRefs(data []byte, selected string) (ProbeResult, error) {
	result := ProbeResult{Branches: []RemoteRef{}, SelectedRef: selected, RefStatus: "missing"}
	invalid := probeFailure("git_invalid", "Git server returned an invalid reference advertisement")
	if len(data) > MaxProbeBytes {
		return ProbeResult{}, probeFailure("git_limits", "Git reference advertisement exceeds connection-check limits")
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		return ProbeResult{}, invalid
	}
	lines := bytes.Split(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'})
	if len(lines) > MaxProbeRefs {
		return ProbeResult{}, probeFailure("git_limits", "Git reference count exceeds connection-check limits")
	}
	objects := make(map[string]string)
	defaultRef := ""
	for _, line := range lines {
		if len(line) == 0 {
			if len(data) == 0 {
				continue
			}
			return ProbeResult{}, invalid
		}
		left, right, ok := strings.Cut(string(line), "\t")
		if !ok || strings.Contains(right, "\t") || len(line) > 1024 {
			return ProbeResult{}, invalid
		}
		if strings.HasPrefix(left, "ref: ") {
			name := strings.TrimPrefix(left, "ref: ")
			if right != "HEAD" || defaultRef != "" || !advertisedRefName(name, false) || !strings.HasPrefix(name, "refs/heads/") {
				return ProbeResult{}, invalid
			}
			defaultRef = name
			continue
		}
		if !objectPattern.MatchString(left) || strings.Trim(left, "0") == "" || !advertisedRefName(right, true) {
			return ProbeResult{}, invalid
		}
		if _, duplicate := objects[right]; duplicate {
			return ProbeResult{}, invalid
		}
		objects[right] = left
	}
	for name := range objects {
		if strings.HasSuffix(name, "^{}") {
			if _, ok := objects[strings.TrimSuffix(name, "^{}")]; !ok {
				return ProbeResult{}, invalid
			}
		}
	}
	if defaultRef != "" {
		result.DefaultBranch = strings.TrimPrefix(defaultRef, "refs/heads/")
		if head, branch := objects["HEAD"], objects[defaultRef]; head != "" && branch != "" && head != branch {
			return ProbeResult{}, invalid
		}
	}
	for name, object := range objects {
		if strings.HasPrefix(name, "refs/heads/") {
			// A remote may advertise legal Git names outside the narrower
			// source configuration profile. Such refs must not break checks
			// of HEAD/main, but cannot be offered as selectable source refs.
			if err := (Config{URL: "https://example.invalid/repository.git", Ref: name}).Validate(); err != nil {
				result.Truncated = true
				continue
			}
			result.Branches = append(result.Branches, RemoteRef{Name: strings.TrimPrefix(name, "refs/heads/"), Ref: name, Commit: object})
		}
	}
	sort.Slice(result.Branches, func(i, j int) bool { return result.Branches[i].Name < result.Branches[j].Name })
	if len(result.Branches) > MaxProbeBranches {
		result.Branches = result.Branches[:MaxProbeBranches]
		result.Truncated = true
	}
	var matches []string
	switch {
	case selected == "HEAD":
		if object := objects["HEAD"]; object != "" {
			matches = append(matches, object)
		}
	case objectPattern.MatchString(selected):
		result.RefStatus = "unverified"
		for _, object := range objects {
			if object == selected {
				matches = []string{object}
				break
			}
		}
	case strings.HasPrefix(selected, "refs/"):
		if object := objects[selected]; object != "" {
			if peeled := objects[selected+"^{}"]; peeled != "" {
				object = peeled
			}
			matches = append(matches, object)
		}
	default:
		for _, prefix := range []string{"refs/heads/", "refs/tags/"} {
			name := prefix + selected
			if object := objects[name]; object != "" {
				if peeled := objects[name+"^{}"]; peeled != "" {
					object = peeled
				}
				matches = append(matches, object)
			}
		}
	}
	if len(matches) == 1 {
		result.ResolvedCommit = matches[0]
		result.RefStatus = "available"
	} else if len(matches) > 1 {
		result.RefStatus = "ambiguous"
	}
	return result, nil
}

func advertisedRefName(name string, allowSpecial bool) bool {
	if name == "HEAD" {
		return allowSpecial
	}
	if strings.HasSuffix(name, "^{}") {
		if !allowSpecial || !strings.HasPrefix(name, "refs/tags/") {
			return false
		}
		name = strings.TrimSuffix(name, "^{}")
	}
	if !utf8.ValidString(name) || !strings.HasPrefix(name, "refs/") || strings.HasSuffix(name, "/") || strings.Contains(name, "..") || strings.Contains(name, "//") || strings.HasSuffix(name, ".") || strings.Contains(name, "@{") || strings.ContainsAny(name, `~^:?*[\`) {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	for _, character := range name {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func validateGitToken(token []byte) error {
	if len(token) > 4096 || bytes.ContainsAny(token, "\x00\r\n") {
		return errors.New("invalid Git token")
	}
	for _, ch := range token {
		if ch < 0x21 || ch > 0x7e {
			return errors.New("Git token must use printable ASCII")
		}
	}
	return nil
}

func verifyGitVersion(ctx context.Context, r runner) error {
	version, err := r.command(ctx, "version").Output()
	match := versionPattern.FindSubmatch(version)
	if err != nil || len(match) != 3 {
		return errors.New("cannot verify Git version")
	}
	major, _ := strconv.Atoi(string(match[1]))
	minor, _ := strconv.Atoi(string(match[2]))
	if major < 2 || major == 2 && minor < 40 {
		return errors.New("Git 2.40 or newer is required for pinned HTTPS resolution")
	}
	return nil
}

func pinnedGitResolution(ctx context.Context, remote string) (string, error) {
	u, _ := url.Parse(remote) // Config.Validate is called before this helper.
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", u.Hostname())
	if err != nil || len(addresses) == 0 || len(addresses) > 16 {
		if ctx.Err() != nil {
			return "", probeContextError(ctx)
		}
		return "", probeFailure("git_dns_failed", "Git host cannot be resolved")
	}
	for _, ip := range addresses {
		if !publicAddress(ip) {
			return "", probeFailure("git_restricted_host", "Git host resolves to a restricted network")
		}
	}
	if _, err := netip.ParseAddr(u.Hostname()); err == nil {
		return "", nil
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	var pinned []string
	for _, address := range addresses {
		ip := address.Unmap().String()
		if address.Is6() {
			ip = "[" + ip + "]"
		}
		pinned = append(pinned, ip)
	}
	return u.Hostname() + ":" + port + ":" + strings.Join(pinned, ","), nil
}
