package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/maintenance"
	"github.com/ctf-service-manager/ctf-service-manager/internal/secrets"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
)

// SecretsAdmin is an offline local tool, not a second service deployment engine.
// Its exclusive lifetime lock conflicts with executor and backup. No Docker API,
// command execution or application file access is available here.
type SecretsAdmin struct {
	config config.Config
	db     *store.Store
	vault  *secrets.Vault
	lock   *maintenance.Lock
}
type SecretDependency struct {
	Kind      string    `json:"kind"`
	ID        domain.ID `json:"id"`
	ServiceID domain.ID `json:"service_id"`
}
type SecretVersionView struct {
	Metadata   secrets.VersionMetadata `json:"metadata"`
	Dependents []SecretDependency      `json:"dependents"`
}
type SecretChangePlan struct {
	Action             string            `json:"action"`
	Version            SecretVersionView `json:"version"`
	ConfirmationDigest domain.Digest     `json:"confirmation_digest"`
}

func OpenSecretsAdmin(c config.Config) (*SecretsAdmin, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if !c.Development && os.Geteuid() != 0 {
		return nil, errors.New("secret maintenance requires the local OS administrator")
	}
	info, err := os.Lstat(c.StateDirectory)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || st.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("executor state must be a private directory owned by this administrator")
	}
	lock, err := maintenance.Acquire(c.StateDirectory, true)
	if err != nil {
		return nil, err
	}
	db, err := store.Open(filepath.Join(c.StateDirectory, "executor.db"))
	if err != nil {
		lock.Close()
		return nil, err
	}
	vault, err := secrets.Open(filepath.Join(c.StateDirectory, "secrets"))
	if err != nil {
		db.Close()
		lock.Close()
		return nil, err
	}
	return &SecretsAdmin{config: c, db: db, vault: vault, lock: lock}, nil
}
func (a *SecretsAdmin) Close() error {
	return errors.Join(a.vault.Close(), a.db.Close(), a.lock.Close())
}
func (a *SecretsAdmin) idle(ctx context.Context) error {
	ops, err := a.db.ListOperations(ctx)
	if err != nil {
		return err
	}
	for _, op := range ops {
		if !op.State.Terminal() {
			return errors.New("secret mutation refused while queued, interrupted or unresolved operations exist; finish recovery first")
		}
	}
	return nil
}
func refEqual(a, b domain.SecretVersionRef) bool {
	return a.SecretID == b.SecretID && a.Version == b.Version
}
func (a *SecretsAdmin) dependencies(ctx context.Context, ref domain.SecretVersionRef) ([]SecretDependency, error) {
	result := []SecretDependency{}
	seen := map[SecretDependency]bool{}
	add := func(kind string, id, service domain.ID) {
		d := SecretDependency{kind, id, service}
		if !seen[d] {
			seen[d] = true
			result = append(result, d)
		}
	}
	services, err := a.db.ListServices(ctx)
	if err != nil {
		return nil, err
	}
	for _, service := range services {
		for _, value := range service.SecretVersions {
			if refEqual(ref, value) {
				add("service_policy", service.ID, service.ID)
			}
		}
	}
	for _, kind := range []string{"release", "configuration", "git_source", "health_policy"} {
		records, err := a.db.List(ctx, kind, "")
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			match := false
			switch kind {
			case "release":
				var value domain.Release
				if err := json.Unmarshal(record.Payload, &value); err != nil {
					return nil, err
				}
				for _, v := range value.Spec().Secrets {
					match = match || refEqual(ref, v)
				}
			case "configuration":
				var value Configuration
				if err := json.Unmarshal(record.Payload, &value); err != nil {
					return nil, err
				}
				for _, v := range value.Environment {
					match = match || refEqual(ref, v)
				}
				for key, v := range value.FileInputs {
					if refEqual(ref, v) {
						match = true
						id := domain.ID(string(domain.Hash([]byte(key + "/" + string(ref.SecretID) + "/" + string(ref.Version))))[7:])
						add("runtime_input", id, record.ServiceID)
					}
				}
			case "git_source":
				var value gitSourceConfiguration
				if err := json.Unmarshal(record.Payload, &value); err != nil {
					return nil, err
				}
				match = value.Credential != nil && refEqual(ref, *value.Credential)
			case "health_policy":
				var value healthPolicyRecord
				if err := json.Unmarshal(record.Payload, &value); err != nil {
					return nil, err
				}
				match = refEqual(ref, value.Input)
			}
			if match {
				add(kind, record.ID, record.ServiceID)
			}
		}
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		return a.Kind+"/"+string(a.ServiceID)+"/"+string(a.ID) < b.Kind+"/"+string(b.ServiceID)+"/"+string(b.ID)
	})
	return result, nil
}
func (a *SecretsAdmin) Versions(ctx context.Context) ([]SecretVersionView, error) {
	versions, err := a.vault.Versions()
	if err != nil {
		return nil, err
	}
	result := []SecretVersionView{}
	for _, v := range versions {
		d, err := a.dependencies(ctx, v.Reference)
		if err != nil {
			return nil, err
		}
		result = append(result, SecretVersionView{v, d})
	}
	return result, nil
}
func (a *SecretsAdmin) Plan(ctx context.Context, action string, ref domain.SecretVersionRef) (SecretChangePlan, error) {
	p := SecretChangePlan{Action: action}
	if action != "revoke" && action != "delete" && action != "inspect" {
		return p, errors.New("unknown secret action")
	}
	meta, err := a.vault.Metadata(ref)
	if err != nil {
		return p, err
	}
	d, err := a.dependencies(ctx, ref)
	if err != nil {
		return p, err
	}
	p.Version = SecretVersionView{meta, d}
	encoded, _ := json.Marshal(p)
	p.ConfirmationDigest = domain.Hash(encoded)
	return p, nil
}
func (a *SecretsAdmin) audit(ctx context.Context, request domain.ID, action string, target domain.Digest, result string) error {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return a.db.AppendMaintenanceAudit(writeCtx, store.MaintenanceAudit{ID: NewID("audit-"), RequestID: request, At: time.Now().UTC(), LocalUID: uint32(os.Geteuid()), Action: "secret." + action, TargetDigest: target, Mode: "secret_version", Result: result})
}
func (a *SecretsAdmin) Import(ctx context.Context, id domain.ID, data []byte) (ref domain.SecretVersionRef, resultErr error) {
	if err := id.Validate(); err != nil {
		return ref, err
	}
	if len(data) > 1<<20 {
		return ref, errors.New("secret exceeds 1 MiB")
	}
	if err := a.idle(ctx); err != nil {
		return ref, err
	}
	request := NewID("secret-change-")
	target := domain.Hash([]byte(id))
	if err := a.audit(ctx, request, "import", target, "started"); err != nil {
		return ref, err
	}
	defer func() {
		result := "succeeded"
		if resultErr != nil {
			result = "failed"
		}
		resultErr = errors.Join(resultErr, a.audit(ctx, request, "import", target, result))
	}()
	return a.vault.Import(id, data)
}
func (a *SecretsAdmin) Change(ctx context.Context, action string, ref domain.SecretVersionRef, confirmation domain.Digest) (resultErr error) {
	if action != "revoke" && action != "delete" {
		return errors.New("unknown secret change")
	}
	if err := a.idle(ctx); err != nil {
		return err
	}
	plan, err := a.Plan(ctx, action, ref)
	if err != nil {
		return err
	}
	if plan.ConfirmationDigest != confirmation {
		return errors.New("secret dependency plan changed or was not explicitly confirmed")
	}
	request := NewID("secret-change-")
	encoded, _ := json.Marshal(ref)
	target := domain.Hash(encoded)
	if err := a.audit(ctx, request, action, target, "started"); err != nil {
		return err
	}
	defer func() {
		result := "succeeded"
		if resultErr != nil {
			result = "failed"
		}
		resultErr = errors.Join(resultErr, a.audit(ctx, request, action, target, result))
	}()
	if action == "revoke" {
		if plan.Version.Metadata.Revoked {
			return nil
		}
		return a.vault.Revoke(ref)
	}
	if err := a.vault.Delete(ref); err != nil {
		return err
	}
	for _, dependency := range plan.Version.Dependents {
		if dependency.Kind != "runtime_input" {
			continue
		}
		if err := a.deleteRuntimeInput(dependency.ID); err != nil {
			return err
		}
	}
	return nil
}
func (a *SecretsAdmin) deleteRuntimeInput(id domain.ID) error {
	if err := id.Validate(); err != nil {
		return err
	}
	directory := filepath.Join(a.config.StateDirectory, "runtime-inputs")
	before, err := os.Lstat(directory)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.IsDir() || before.Mode().Perm() != 0700 || owner.Uid != uint32(os.Geteuid()) {
		return errors.New("materialized secret input root must be an executor-owned private directory")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	pinned, err := root.Open(".")
	if err != nil {
		return err
	}
	opened, statErr := pinned.Stat()
	pinned.Close()
	if statErr != nil || !os.SameFile(before, opened) {
		return errors.New("materialized secret input root changed during open")
	}
	info, err := root.Lstat(string(id))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0444 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		return errors.New("materialized secret input metadata changed; automatic deletion refused")
	}
	if err := root.Remove(string(id)); err != nil {
		return err
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
