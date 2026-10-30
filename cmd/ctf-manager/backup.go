package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/ctf-service-manager/ctf-service-manager/internal/backup"
)

func runBackup(args []string, input io.Reader, out, errOut io.Writer) error {
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(errOut)
	passphraseFile := flags.String("passphrase-file", "", "private passphrase file; enables protected full backup (never pass a password on the command line)")
	passphraseStdin := flags.Bool("passphrase-stdin", false, "read protected backup passphrase from stdin")
	maxBytes := flags.Int64("max-bytes", backup.DefaultMaxBytes, "maximum uncompressed artifact bytes")
	var executorState, dashboardState, configuration, output, source, destination *string
	if args[0] == "backup" {
		executorState = flags.String("executor-state", "", "private executor state directory")
		dashboardState = flags.String("dashboard-state", "", "private dashboard state directory")
		configuration = flags.String("configuration", "", "administrator-owned executor bootstrap JSON")
		output = flags.String("output", "", "new private output file outside panel state")
	} else {
		source = flags.String("input", "", "backup file")
		destination = flags.String("destination", "", "new destination directory; existing paths are refused")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("backup and restore do not accept positional arguments")
	}
	if *passphraseFile != "" && *passphraseStdin {
		return errors.New("choose one passphrase input")
	}
	var passphrase []byte
	if *passphraseFile != "" || *passphraseStdin {
		if *passphraseFile != "" {
			info, err := os.Lstat(*passphraseFile)
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
				return errors.New("passphrase file must be private and cannot be a symlink")
			}
			file, err := os.Open(*passphraseFile)
			if err != nil {
				return err
			}
			defer file.Close()
			opened, err := file.Stat()
			if err != nil || !os.SameFile(info, opened) {
				return errors.New("passphrase file changed during open")
			}
			input = file
		}
		data, err := io.ReadAll(io.LimitReader(input, 4098))
		if err != nil {
			return fmt.Errorf("read backup passphrase: %w", err)
		}
		passphrase = data
		if len(passphrase) > 0 && passphrase[len(passphrase)-1] == '\n' {
			passphrase = passphrase[:len(passphrase)-1]
		}
		if len(passphrase) < 16 || len(passphrase) > 4096 {
			return errors.New("backup passphrase must contain 16..4096 bytes")
		}
		defer func() {
			for i := range passphrase {
				passphrase[i] = 0
			}
			for i := range data {
				data[i] = 0
			}
		}()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var report backup.Report
	var err error
	if args[0] == "backup" {
		report, err = backup.Create(ctx, backup.Options{ExecutorState: *executorState, DashboardState: *dashboardState, Configuration: *configuration, Destination: *output, Passphrase: passphrase, MaxBytes: *maxBytes})
	} else {
		report, err = backup.Restore(ctx, backup.RestoreOptions{Source: *source, Destination: *destination, Passphrase: passphrase, MaxBytes: *maxBytes})
	}
	if err != nil {
		return err
	}
	return emit(out, report)
}
