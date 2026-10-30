// Package executor owns privileged application operations. Registration is also
// exposed through authenticated dashboard Admin routes within bootstrap roots.
package executor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/maintenance"
	"github.com/ctf-service-manager/ctf-service-manager/internal/policy"
	"github.com/ctf-service-manager/ctf-service-manager/internal/secrets"
	"github.com/ctf-service-manager/ctf-service-manager/internal/snapshots"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"sync"
)

type Manager struct {
	Config         config.Config
	Store          *store.Store
	Engine         *docker.Engine
	Vault          *secrets.Vault
	Snapshots      *snapshots.Store
	submitMu       sync.Mutex
	registrationMu sync.Mutex
	artifactMu     sync.Mutex
	metricsOnce    sync.Once
	metrics        *metricsCollector
	maintenance    *maintenance.Lock
	captureMu      sync.Mutex
	captureError   string
	proxyMu        sync.Mutex
	proxyCancel    context.CancelFunc
	proxyWG        sync.WaitGroup
	proxyError     string
	cutoverCtx     context.Context
	cutoverCancel  context.CancelFunc
	cutoverWG      sync.WaitGroup
	cutoverRuntime cutoverRuntimeDriver
	cutoverClosing bool
	cutoverReady   bool
}

func Open(c config.Config) (*Manager, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(c.StateDirectory, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(c.StateDirectory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("executor state directory must be private (0700) and not a symbolic link")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Geteuid() {
		return nil, errors.New("executor state must be owned by the executor UID")
	}
	stateLock, err := maintenance.Acquire(c.StateDirectory, false)
	if err != nil {
		return nil, err
	}
	opened := false
	defer func() {
		if !opened {
			_ = stateLock.Close()
		}
	}()
	db, err := store.Open(filepath.Join(c.StateDirectory, "executor.db"))
	if err != nil {
		return nil, err
	}
	vault, err := secrets.Open(filepath.Join(c.StateDirectory, "secrets"))
	if err != nil {
		db.Close()
		return nil, err
	}
	engine, err := docker.New(c)
	if err != nil {
		vault.Close()
		db.Close()
		return nil, err
	}
	artifacts, err := snapshots.NewStore(filepath.Join(c.StateDirectory, "snapshots"))
	if err != nil {
		engine.Close()
		vault.Close()
		db.Close()
		return nil, err
	}
	opened = true
	m := &Manager{Config: c, Store: db, Engine: engine, Vault: vault, Snapshots: artifacts, maintenance: stateLock}
	m.cutoverCtx, m.cutoverCancel = context.WithCancel(context.Background())
	m.startProxyPublication()
	return m, nil
}
func (m *Manager) Close() error {
	// Cancel first: an active worker may hold proxyMu while waiting on Docker.
	// The same immutable CancelFunc is safe to call concurrently.
	if m.cutoverCancel != nil {
		m.cutoverCancel()
	}
	m.proxyMu.Lock()
	m.cutoverClosing = true
	m.cutoverReady = false
	m.proxyMu.Unlock()
	m.cutoverWG.Wait()
	if m.proxyCancel != nil {
		m.proxyCancel()
		m.proxyWG.Wait()
	}
	return errors.Join(m.Engine.Close(), m.Vault.Close(), m.Snapshots.Close(), m.Store.Close(), m.maintenance.Close())
}

func NewID(prefix string) domain.ID {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("secure randomness unavailable")
	}
	return domain.ID(prefix + hex.EncodeToString(b))
}

type Configuration struct {
	Model       map[string]any                     `json:"model"`
	Environment map[string]domain.SecretVersionRef `json:"environment_versions"`
	FileInputs  map[string]domain.SecretVersionRef `json:"file_input_versions"`
}

func (m *Manager) Propose(ctx context.Context, service domain.Service, actor domain.ID) (store.Proposal, error) {
	if err := m.requireAdmin(); err != nil {
		return store.Proposal{}, err
	}
	if err := service.Validate(); err != nil {
		return store.Proposal{}, err
	}
	report, err := docker.Normalize(ctx, m.Config, docker.ComposeInput{ProjectDirectory: service.ProjectDirectory, ProjectName: service.ComposeProject, Files: service.ComposeFiles, Profiles: service.Profiles})
	if err != nil {
		return store.Proposal{}, err
	}
	containers, err := m.Engine.Inventory(ctx, service.ComposeProject)
	if err != nil {
		return store.Proposal{}, err
	}
	if err := policy.ValidateRegistration(m.Config, service, report, containers); err != nil {
		return store.Proposal{}, err
	}
	configuration, refs, err := m.freezeConfiguration(service.ID, report)
	if err != nil {
		return store.Proposal{}, err
	}
	service.SecretVersions = refs
	encoded, err := json.Marshal(configuration)
	if err != nil {
		return store.Proposal{}, err
	}
	digest := domain.Hash(encoded)
	if err := m.Store.PutImmutable(ctx, "configuration", domain.ID(string(digest)[7:]), service.ID, configuration); err != nil {
		return store.Proposal{}, err
	}
	return m.Store.CreateProposal(ctx, NewID("proposal-"), service, digest, actor, time.Now().UTC())
}

func (m *Manager) Approve(ctx context.Context, id domain.ID, digest domain.Digest, actor domain.ID) (domain.Service, error) {
	unlockAdmission, err := m.lockCutoverAdmission()
	if err != nil {
		return domain.Service{}, err
	}
	defer unlockAdmission()
	if err := m.requireNoPendingCutover(ctx); err != nil {
		return domain.Service{}, err
	}
	if err := m.requireAdmin(); err != nil {
		return domain.Service{}, err
	}
	proposal, err := m.Store.GetProposal(ctx, id)
	if err != nil {
		return domain.Service{}, err
	}
	if overlay, err := m.runtimePortOverlay(ctx, proposal.Service.ID); err != nil {
		return domain.Service{}, err
	} else if overlay.Active {
		return domain.Service{}, proxyInput("Return transferred ports before changing service registration")
	}
	if proposal.Digest != digest {
		return domain.Service{}, errors.New("proposal digest does not match the reviewed registration")
	}
	configuration, err := m.LoadConfiguration(ctx, proposal.ConfigurationDigest)
	if err != nil {
		return domain.Service{}, err
	}
	model, err := m.renderConfiguration(configuration)
	if err != nil {
		return domain.Service{}, err
	}
	service := proposal.Service
	report := docker.Analyze(docker.ComposeInput{ProjectDirectory: service.ProjectDirectory, ProjectName: service.ComposeProject, Files: service.ComposeFiles, Profiles: service.Profiles}, model)
	containers, err := m.Engine.Inventory(ctx, service.ComposeProject)
	if err != nil {
		return domain.Service{}, err
	}
	if err := policy.ValidateRegistration(m.Config, service, report, containers); err != nil {
		return domain.Service{}, err
	}
	return m.Store.ApproveProposal(ctx, id, digest, actor, time.Now().UTC())
}

func (m *Manager) LoadConfiguration(ctx context.Context, digest domain.Digest) (Configuration, error) {
	var result Configuration
	if err := digest.Validate(); err != nil {
		return result, err
	}
	if err := m.Store.Get(ctx, "configuration", domain.ID(string(digest)[7:]), &result); err != nil {
		return result, err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return result, err
	}
	if domain.Hash(encoded) != digest {
		return result, errors.New("configuration integrity check failed")
	}
	return result, nil
}

func (m *Manager) freezeConfiguration(service domain.ID, report docker.ComposeReport) (Configuration, []domain.SecretVersionRef, error) {
	c := Configuration{Environment: map[string]domain.SecretVersionRef{}, FileInputs: map[string]domain.SecretVersionRef{}}
	if err := json.Unmarshal(report.Normalized, &c.Model); err != nil {
		return c, nil, err
	}
	refs := []domain.SecretVersionRef{}
	services, _ := c.Model["services"].(map[string]any)
	for name, raw := range services {
		component, _ := raw.(map[string]any)
		if env, ok := component["environment"]; ok {
			data, err := json.Marshal(env)
			if err != nil {
				return c, nil, err
			}
			ref, err := m.Vault.Import(secretID(service, "env-"+name), data)
			if err != nil {
				return c, nil, err
			}
			c.Environment[name] = ref
			refs = append(refs, ref)
			delete(component, "environment")
		}
	}
	for _, section := range []string{"secrets", "configs"} {
		items, _ := c.Model[section].(map[string]any)
		for name, raw := range items {
			object, _ := raw.(map[string]any)
			if file, ok := object["file"].(string); ok {
				data, exists := report.PrivateInputs[file]
				if !exists {
					return c, nil, errors.New("file-backed configuration was not captured securely")
				}
				ref, err := m.Vault.Import(secretID(service, section+"-"+name), data)
				if err != nil {
					return c, nil, err
				}
				key := section + "/" + name
				c.FileInputs[key] = ref
				refs = append(refs, ref)
				object["file"] = "ctfm-secret://" + string(ref.SecretID) + "/" + string(ref.Version)
			}
		}
	}
	return c, refs, nil
}

func (m *Manager) renderConfiguration(c Configuration) (map[string]any, error) {
	encoded, err := json.Marshal(c.Model)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(encoded, &doc); err != nil {
		return nil, err
	}
	services, _ := doc["services"].(map[string]any)
	for name, ref := range c.Environment {
		raw, err := m.Vault.Read(ref)
		if err != nil {
			return nil, fmt.Errorf("environment secret unavailable for %s", name)
		}
		var env any
		if err := json.Unmarshal(raw, &env); err != nil {
			return nil, errors.New("invalid environment secret")
		}
		s, ok := services[name].(map[string]any)
		if !ok {
			return nil, errors.New("environment component not in configuration")
		}
		s["environment"] = env
	}
	// Keep immutable references for approval. Runtime materialization of secret
	// files is handled when a release is prepared, not by reading original files.
	for _, ref := range c.FileInputs {
		if _, err := m.Vault.Read(ref); err != nil {
			return nil, errors.New("configuration secret version is unavailable")
		}
	}
	return doc, nil
}

func secretID(service domain.ID, key string) domain.ID {
	digest := domain.Hash([]byte(string(service) + "/" + key))
	return domain.ID("secret-" + string(digest)[7:39])
}
func (m *Manager) requireAdmin() error {
	if !m.Config.Development && os.Geteuid() != 0 {
		return errors.New("registration and policy approval require the local OS administrator")
	}
	return nil
}
