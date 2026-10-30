package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/executor"
)

func runSecrets(c config.Config, args []string, input io.Reader, out, errOut io.Writer) error {
	if len(args) < 2 {
		return errors.New("usage: secrets list|inspect|import|revoke|delete [options]")
	}
	action := args[1]
	flags := flag.NewFlagSet("secrets "+action, flag.ContinueOnError)
	flags.SetOutput(errOut)
	id := flags.String("secret-id", "", "immutable secret identity")
	version := flags.String("version", "", "exact secret version")
	file := flags.String("file", "", "private input file (import only; value never passed as argument)")
	stdin := flags.Bool("stdin", false, "read exact secret bytes from stdin (import only)")
	confirm := flags.String("confirm", "", "confirmation_digest from the inspected dependency plan")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional secret arguments")
	}
	if action != "import" && (*file != "" || *stdin) {
		return errors.New("secret input is accepted only by import")
	}
	if action != "revoke" && action != "delete" && *confirm != "" {
		return errors.New("confirmation is accepted only by revoke/delete")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := executor.OpenSecretsAdmin(c)
	if err != nil {
		return err
	}
	defer admin.Close()
	switch action {
	case "list":
		if *id != "" || *version != "" {
			return errors.New("list does not accept a secret selection")
		}
		values, err := admin.Versions(ctx)
		if err != nil {
			return err
		}
		return emit(out, values)
	case "inspect":
		if *version != "" {
			plan, err := admin.Plan(ctx, "inspect", domain.SecretVersionRef{SecretID: domain.ID(*id), Version: domain.ID(*version)})
			if err != nil {
				return err
			}
			return emit(out, plan)
		}
		if err := domain.ID(*id).Validate(); err != nil {
			return err
		}
		values, err := admin.Versions(ctx)
		if err != nil {
			return err
		}
		selected := []executor.SecretVersionView{}
		for _, value := range values {
			if value.Metadata.Reference.SecretID == domain.ID(*id) {
				selected = append(selected, value)
			}
		}
		return emit(out, selected)
	case "import":
		if *version != "" {
			return errors.New("new version IDs are generated, not supplied")
		}
		if (*file != "") == *stdin {
			return errors.New("choose exactly one private --file or --stdin input")
		}
		if err := domain.ID(*id).Validate(); err != nil {
			return err
		}
		if *file != "" {
			opened, err := openSecretInput(*file)
			if err != nil {
				return err
			}
			defer opened.Close()
			input = opened
		}
		data, err := io.ReadAll(io.LimitReader(input, (1<<20)+1))
		if err != nil {
			return errors.New("cannot read private secret input")
		}
		defer clear(data)
		before, err := admin.Versions(ctx)
		if err != nil {
			return err
		}
		previous := []executor.SecretVersionView{}
		for _, value := range before {
			if value.Metadata.Reference.SecretID == domain.ID(*id) {
				previous = append(previous, value)
			}
		}
		ref, err := admin.Import(ctx, domain.ID(*id), data)
		if err != nil {
			return err
		}
		return emit(out, struct {
			Reference            domain.SecretVersionRef      `json:"reference"`
			PreviousVersions     []executor.SecretVersionView `json:"previous_versions"`
			RuntimePolicyChanged bool                         `json:"runtime_policy_changed"`
		}{ref, previous, false})
	case "revoke", "delete":
		ref := domain.SecretVersionRef{SecretID: domain.ID(*id), Version: domain.ID(*version)}
		plan, err := admin.Plan(ctx, action, ref)
		if err != nil {
			return err
		}
		if err := emit(out, plan); err != nil {
			return err
		}
		if *confirm == "" {
			return fmt.Errorf("confirmation required after reviewing dependents; repeat with --confirm %s", plan.ConfirmationDigest)
		}
		if err := admin.Change(ctx, action, ref, domain.Digest(*confirm)); err != nil {
			return err
		}
		return emit(out, map[string]any{"action": action, "reference": ref, "result": "succeeded"})
	default:
		return errors.New("unknown secret action")
	}
}

func openSecretInput(name string) (*os.File, error) {
	before, err := os.Lstat(name)
	if err != nil {
		return nil, errors.New("cannot inspect private secret input")
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("secret input must be a private regular file owned by the local administrator")
	}
	file, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("cannot open private secret input")
	}
	info, err := file.Stat()
	if err != nil || !os.SameFile(before, info) {
		file.Close()
		return nil, errors.New("private secret input changed during open")
	}
	return file, nil
}
