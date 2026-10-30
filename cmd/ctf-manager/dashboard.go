package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/dashboard"
)

func runDashboard(args []string, input io.Reader, out, errOut io.Writer) error {
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(errOut)
	state := flags.String("state", "/var/lib/ctf-manager", "private dashboard state directory (not executor state)")
	if args[0] == "init-admin" {
		username := flags.String("username", "admin", "first administrator username")
		passwordFile := flags.String("password-file", "", "password file, otherwise read stdin; one final LF is removed")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("init-admin does not accept positional arguments")
		}
		if *passwordFile != "" {
			file, err := os.Open(*passwordFile)
			if err != nil {
				return err
			}
			defer file.Close()
			info, err := file.Stat()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
				return errors.New("password file must be regular and private (0600 or stricter)")
			}
			input = file
		}
		password, err := io.ReadAll(io.LimitReader(input, 4097))
		if err != nil {
			return fmt.Errorf("read administrator password: %w", err)
		}
		if len(password) > 4096 {
			return errors.New("administrator password input exceeds 4096 bytes")
		}
		server, err := dashboard.Open(dashboard.Config{StateDirectory: *state, ExecutorSocket: "/run/ctf-manager/executor.sock"})
		if err != nil {
			return err
		}
		defer server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := server.CreateAdmin(ctx, *username, strings.TrimSuffix(string(password), "\n")); err != nil {
			return err
		}
		return emit(out, map[string]any{"status": "admin_created", "username": *username})
	}
	listen := flags.String("listen", "127.0.0.1:8765", "dashboard HTTP listen address")
	socket := flags.String("socket", "/run/ctf-manager/executor.sock", "executor Unix socket")
	hosts := flags.String("allowed-hosts", "", "comma-separated exact Host values, including port; default loopback hosts at listen port")
	secureCookies := flags.Bool("secure-cookies", false, "require HTTPS-only cookies")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("dashboard does not accept positional arguments")
	}
	var allowedHosts []string
	if *hosts != "" {
		allowedHosts = strings.Split(*hosts, ",")
	}
	server, err := dashboard.Open(dashboard.Config{Listen: *listen, StateDirectory: *state, ExecutorSocket: *socket, AllowedHosts: allowedHosts, SecureCookies: *secureCookies})
	if err != nil {
		return err
	}
	defer server.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := emit(out, map[string]any{"status": "starting", "listen": *listen, "secure_cookies": *secureCookies}); err != nil {
		return err
	}
	return server.Serve(ctx)
}
