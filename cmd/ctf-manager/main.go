package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/executor"
	"github.com/ctf-service-manager/ctf-service-manager/internal/policy"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"github.com/moby/moby/client"
)

const version = "0.1.0-dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "ctf-manager:", err)
		os.Exit(1)
	}
}

func run(args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("ctf-manager", flag.ContinueOnError)
	flags.SetOutput(errOut)
	configPath := flags.String("config", "/etc/ctf-manager/executor.json", "administrator-owned executor bootstrap")
	flags.Usage = func() {
		fmt.Fprintln(errOut, "Usage: ctf-manager [--config FILE] version|dashboard|init-admin|doctor|inventory|inspect-project|propose|approve|services|operations|executor|status|service|operation|events|diagnostics|cancel|preview|submit|proxy-cutovers|proxy-return-preview|proxy-return-confirm|storage|rotate|backup|restore|secrets")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	remaining := flags.Args()
	if len(remaining) == 0 {
		flags.Usage()
		return errors.New("command is required")
	}
	if remaining[0] == "version" {
		_, err := fmt.Fprintln(out, version)
		return err
	}
	// Dashboard has no access to the administrator's executor bootstrap or state.
	if remaining[0] == "backup" || remaining[0] == "restore" {
		return runBackup(remaining, os.Stdin, out, errOut)
	}
	if remaining[0] == "dashboard" || remaining[0] == "init-admin" {
		return runDashboard(remaining, os.Stdin, out, errOut)
	}
	c, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if remaining[0] == "secrets" {
		return runSecrets(c, remaining, os.Stdin, out, errOut)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	switch remaining[0] {
	case "executor":
		m, err := executor.Open(c)
		if err != nil {
			return err
		}
		defer m.Close()
		server, err := transport.NewServer(transport.Options{SocketPath: c.Socket, AllowedUIDs: []uint32{uint32(os.Geteuid()), uint32(c.WebUID)}, Backend: m, Submit: m.Submit, Development: c.Development, RecoverStaleSocket: true})
		if err != nil {
			return err
		}
		defer server.Close()
		lifetime, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := emit(out, map[string]any{"status": "listening", "socket": c.Socket, "development": c.Development, "operations_enabled": true}); err != nil {
			return err
		}
		results := make(chan error, 2)
		go func() { results <- m.Run(lifetime) }()
		go func() { results <- server.Serve(lifetime) }()
		metricsDone := make(chan struct{})
		go func() { defer close(metricsDone); m.RunMetrics(lifetime) }()
		runtimeEventsDone := make(chan struct{})
		go func() { defer close(runtimeEventsDone); m.RunRuntimeEvents(lifetime) }()
		first := <-results
		stop()
		second := <-results
		<-metricsDone
		<-runtimeEventsDone
		return errors.Join(first, second)
	case "storage", "rotate":
		api, err := transport.NewClient(c.Socket)
		if err != nil {
			return err
		}
		defer api.Close()
		if remaining[0] == "storage" {
			result, err := api.StorageStatus(ctx)
			if err != nil {
				return err
			}
			return emit(out, result)
		}
		result, err := api.Rotate(ctx)
		if err != nil {
			return err
		}
		return emit(out, result)
	case "service", "operation", "events", "diagnostics", "cancel", "preview", "submit":
		return remoteOperation(ctx, c.Socket, remaining, out, errOut)
	case "proxy-cutovers", "proxy-return-preview", "proxy-return-confirm":
		return remoteProxyReturn(ctx, c.Socket, remaining, out, errOut)
	case "status":
		api, err := transport.NewClient(c.Socket)
		if err != nil {
			return err
		}
		defer api.Close()
		health, err := api.Health(ctx)
		if err != nil {
			return err
		}
		return emit(out, health)
	case "doctor":
		return doctor(ctx, c, out)
	case "inventory":
		f := flag.NewFlagSet("inventory", flag.ContinueOnError)
		f.SetOutput(errOut)
		project := f.String("project", "", "filter existing Compose project")
		if err := f.Parse(remaining[1:]); err != nil {
			return err
		}
		e, err := docker.New(c)
		if err != nil {
			return err
		}
		defer e.Close()
		items, err := e.Inventory(ctx, *project)
		if err != nil {
			return err
		}
		return emit(out, items)
	case "inspect-project":
		f := flag.NewFlagSet("inspect-project", flag.ContinueOnError)
		f.SetOutput(errOut)
		dir := f.String("directory", "", "existing project directory")
		name := f.String("project", "", "existing Compose project name")
		files := f.String("files", "compose.yaml", "comma-separated project-relative Compose files")
		profiles := f.String("profiles", "", "comma-separated profiles")
		if err := f.Parse(remaining[1:]); err != nil {
			return err
		}
		input := docker.ComposeInput{ProjectDirectory: *dir, ProjectName: *name, Files: strings.Split(*files, ",")}
		if *profiles != "" {
			input.Profiles = strings.Split(*profiles, ",")
		}
		report, err := docker.Normalize(ctx, c, input)
		if err != nil {
			return err
		}
		return emit(out, report)
	case "propose":
		f := flag.NewFlagSet("propose", flag.ContinueOnError)
		f.SetOutput(errOut)
		file := f.String("service", "", "reviewed service policy JSON")
		actor := f.String("actor", "os-admin", "local audit identity")
		if err := f.Parse(remaining[1:]); err != nil {
			return err
		}
		if *file == "" {
			return errors.New("--service FILE is required")
		}
		var service domain.Service
		if err := loadJSON(*file, &service); err != nil {
			return err
		}
		m, err := executor.Open(c)
		if err != nil {
			return err
		}
		defer m.Close()
		proposal, err := m.Propose(ctx, service, domain.ID(*actor))
		if err != nil {
			var diagnostic *policy.RegistrationError
			if errors.As(err, &diagnostic) {
				if writeErr := emit(out, diagnostic); writeErr != nil {
					return writeErr
				}
			}
			return err
		}
		return emit(out, proposal)
	case "approve":
		f := flag.NewFlagSet("approve", flag.ContinueOnError)
		f.SetOutput(errOut)
		id := f.String("proposal", "", "immutable proposal ID")
		digest := f.String("digest", "", "reviewed proposal SHA-256 digest")
		actor := f.String("actor", "os-admin", "local audit identity")
		if err := f.Parse(remaining[1:]); err != nil {
			return err
		}
		m, err := executor.Open(c)
		if err != nil {
			return err
		}
		defer m.Close()
		service, err := m.Approve(ctx, domain.ID(*id), domain.Digest(*digest), domain.ID(*actor))
		if err != nil {
			return err
		}
		return emit(out, service)
	case "services", "operations":
		m, err := executor.Open(c)
		if err != nil {
			return err
		}
		defer m.Close()
		if remaining[0] == "services" {
			items, err := m.Store.ListServices(ctx)
			if err != nil {
				return err
			}
			return emit(out, items)
		}
		items, err := m.Store.ListOperations(ctx)
		if err != nil {
			return err
		}
		return emit(out, items)
	default:
		return fmt.Errorf("unknown command %q", remaining[0])
	}
}

func loadJSON(file string, out any) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, (1<<20)+1))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("one JSON object is required")
	}
	return nil
}

func emit(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

type check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

func doctor(ctx context.Context, c config.Config, out io.Writer) error {
	checks := []check{{"platform", runtime.GOOS == "linux" || c.Development, runtime.GOOS + "/" + runtime.GOARCH}, {"isolation", !c.Development, "development mode bypasses production platform/isolation requirements"}}
	if !c.Development {
		checks[1].Detail = "production configuration"
	}
	composeVersion, err := docker.ComposeVersion(ctx, c)
	checks = append(checks, check{"compose", err == nil, composeVersion})
	e, err := docker.New(c)
	if err != nil {
		checks = append(checks, check{"docker", false, err.Error()})
	} else {
		defer e.Close()
		ping, err := e.Client.Ping(ctx, client.PingOptions{})
		detail := ""
		if err != nil {
			detail = err.Error()
		} else {
			detail = "API " + ping.APIVersion
		}
		checks = append(checks, check{"docker", err == nil, detail})
	}
	for _, root := range c.DiscoveryRoots {
		err := c.CheckPath(root, false)
		detail := root
		if err != nil {
			detail = err.Error()
		}
		checks = append(checks, check{"discovery_root", err == nil, detail})
	}
	for _, root := range c.WorkspaceRoots {
		err := c.CheckPath(root, true)
		detail := root
		if err != nil {
			detail = err.Error()
		}
		checks = append(checks, check{"workspace_root", err == nil, detail})
	}
	if err := emit(out, checks); err != nil {
		return err
	}
	for _, item := range checks {
		if !item.OK && item.Name != "isolation" {
			return errors.New("preflight failed")
		}
	}
	return nil
}
