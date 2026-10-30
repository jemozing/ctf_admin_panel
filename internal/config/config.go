// Package config loads the executor's local, administrator-controlled bootstrap.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

type Config struct {
	StateDirectory         string          `json:"state_directory"`
	Socket                 string          `json:"socket"`
	DockerHost             string          `json:"docker_host"`
	DockerBinary           string          `json:"docker_binary"`
	ComposeBinary          string          `json:"compose_binary,omitempty"`
	DiscoveryRoots         []string        `json:"discovery_roots"`
	WorkspaceRoots         []string        `json:"workspace_roots"`
	WebUID                 int             `json:"web_uid"`
	Storage                StoragePolicy   `json:"storage,omitempty"`
	Scheduler              SchedulerPolicy `json:"scheduler,omitempty"`
	DockerStorageDirectory string          `json:"docker_storage_directory,omitempty"`
	HostMetrics            bool            `json:"host_metrics,omitempty"`
	Proxy                  ProxyPolicy     `json:"proxy,omitempty"`
	Capture                CapturePolicy   `json:"capture,omitempty"`
	Development            bool            `json:"development"`
}

func Load(name string) (Config, error) {
	var c Config
	f, err := os.Open(name)
	if err != nil {
		return c, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return c, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return c, errors.New("bootstrap must be a regular file without group/world write permission")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return c, errors.New("cannot verify bootstrap ownership")
	}
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, fmt.Errorf("bootstrap: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, errors.New("bootstrap must contain one JSON object")
	}
	if !c.Development && owner.Uid != 0 {
		return c, errors.New("production bootstrap must be owned by root")
	}
	if c.Development && int(owner.Uid) != os.Geteuid() {
		return c, errors.New("development bootstrap must belong to the invoking user")
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if err := c.Capture.Validate(c); err != nil {
		return err
	}
	if err := c.Proxy.Validate(c); err != nil {
		return err
	}
	if err := c.Scheduler.Validate(); err != nil {
		return err
	}
	if err := c.Storage.Validate(); err != nil {
		return err
	}
	if c.DockerStorageDirectory != "" && (!filepath.IsAbs(c.DockerStorageDirectory) || filepath.Clean(c.DockerStorageDirectory) != c.DockerStorageDirectory || c.DockerStorageDirectory == "/") {
		return errors.New("docker_storage_directory must be an absolute approved read-only Docker data root")
	}
	for name, value := range map[string]string{"state_directory": c.StateDirectory, "socket": c.Socket, "docker_binary": c.DockerBinary} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value || strings.ContainsRune(value, 0) {
			return fmt.Errorf("%s must be a canonical absolute path", name)
		}
	}
	if c.ComposeBinary != "" && (!filepath.IsAbs(c.ComposeBinary) || filepath.Clean(c.ComposeBinary) != c.ComposeBinary || strings.ContainsRune(c.ComposeBinary, 0)) {
		return errors.New("compose_binary must be an explicit canonical absolute path")
	}
	if !strings.HasPrefix(c.DockerHost, "unix:///") {
		return errors.New("MVP Docker endpoint must be an explicit local unix socket")
	}
	if c.WebUID < 0 {
		return errors.New("web_uid must be nonnegative")
	}
	if len(c.DiscoveryRoots) == 0 || len(c.WorkspaceRoots) == 0 {
		return errors.New("discovery_roots and workspace_roots are required")
	}
	for _, root := range append(append([]string{}, c.DiscoveryRoots...), c.WorkspaceRoots...) {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
			return errors.New("allowed roots must be canonical absolute paths other than /")
		}
		if overlap(root, c.StateDirectory) {
			return errors.New("allowed roots and executor state must not overlap")
		}
	}
	if !c.Development && runtime.GOOS != "linux" {
		return errors.New("production executor requires Linux; development mode does not provide production isolation")
	}
	if !c.Development && (c.WebUID == 0 || c.WebUID == os.Geteuid()) {
		return errors.New("production web UID must be unprivileged and distinct from executor UID")
	}
	return nil
}

func (c Config) CheckPath(name string, workspace bool) error {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return errors.New("path must be canonical and absolute")
	}
	roots := c.DiscoveryRoots
	if workspace {
		roots = c.WorkspaceRoots
	}
	for _, root := range roots {
		rel, err := filepath.Rel(root, name)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		r, err := os.OpenRoot(root)
		if err != nil {
			return err
		}
		defer r.Close()
		info, err := r.Stat(rel)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return errors.New("registered root must be a directory")
		}
		// Canonical bootstrap roots and registered roots must not be aliases through symlinks.
		resolved, err := filepath.EvalSymlinks(name)
		if err != nil {
			return err
		}
		if resolved != name {
			return errors.New("registered directory must not contain symbolic-link components")
		}
		return nil
	}
	return errors.New("path is outside administrator-approved roots")
}

func overlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}
