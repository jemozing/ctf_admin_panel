package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/packetcapture"
	"github.com/ctf-service-manager/ctf-service-manager/internal/packets"
	"github.com/ctf-service-manager/ctf-service-manager/internal/traffic"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func localURL(raw string, health bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !ip.IsLoopback() {
		return false
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	if health {
		return u.Path == "/healthz"
	}
	return u.Path == "" || u.Path == "/"
}

func run(args []string) error {
	if len(args) > 0 && args[0] == "health" {
		flags := flag.NewFlagSet("health", flag.ContinueOnError)
		endpoint := flags.String("url", "http://127.0.0.1:9803/healthz", "capture loopback health URL")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || !localURL(*endpoint, true) {
			return errors.New("capture health requires an explicit loopback URL")
		}
		client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		response, err := client.Get(*endpoint)
		if err != nil {
			return errors.New("capture health unavailable")
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			return errors.New("capture health unavailable")
		}
		return nil
	}
	flags := flag.NewFlagSet("ctfm-capture", flag.ContinueOnError)
	policyFile := flags.String("policy-file", "/etc/ctfm-capture/policy.json", "executor-approved desired capture policy")
	listen := flags.String("control-listen", "127.0.0.1:9803", "separate loopback control listener; empty requires --control-unix")
	controlUnix := flags.String("control-unix", "", "private authenticated capture control socket")
	controlTokenFile := flags.String("control-token-file", "/run/secrets/control", "private control token")
	ingestURL := flags.String("ingest-url", "http://127.0.0.1:9804", "private ingest-only packet archive endpoint")
	ingestTokenFile := flags.String("ingest-token-file", "/run/secrets/ingest", "private ingest-only token")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected capture arguments")
	}
	if !filepath.IsAbs(*policyFile) || filepath.Clean(*policyFile) != *policyFile {
		return errors.New("absolute capture policy path required")
	}
	if !localURL(*ingestURL, false) {
		return errors.New("packet ingest must use an explicit loopback origin")
	}
	controlToken, err := traffic.ReadTokenFile(*controlTokenFile)
	if err != nil {
		return err
	}
	ingestToken, err := traffic.ReadTokenFile(*ingestTokenFile)
	if err != nil {
		return err
	}
	if controlToken == ingestToken {
		return errors.New("capture control and ingest tokens must differ")
	}
	client, err := packets.NewClient(*ingestURL, ingestToken)
	if err != nil {
		return errors.New("invalid packet ingest endpoint")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// A pause is intentionally not persisted by this read-only process. On a
	// restart, require the executor to publish a fresh runtime-verified file
	// before enabling capture, so an old pre-mutation lease cannot reactivate.
	activationStarted := time.Now()
	engine, err := packetcapture.New(packetcapture.Options{Sink: recorderSink{client: client, ctx: ctx}})
	if err != nil {
		return err
	}
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = engine.Close(shutdown)
	}()
	handler, err := engine.ControlHandler(controlToken)
	if err != nil {
		return err
	}
	var servers []*http.Server
	var cleanups []func()
	defer func() {
		for _, server := range servers {
			shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = server.Shutdown(shutdown)
			cancel()
		}
		for _, cleanup := range cleanups {
			cleanup()
		}
	}()
	errorsFromServer := make(chan error, 2)
	serve := func(listener net.Listener) {
		server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 20 * time.Second, MaxHeaderBytes: 8192}
		servers = append(servers, server)
		go func() {
			if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				select {
				case errorsFromServer <- err:
				default:
				}
			}
		}()
	}
	if *listen != "" {
		host, port, err := net.SplitHostPort(*listen)
		ip, ipErr := netip.ParseAddr(host)
		number, portErr := strconv.Atoi(port)
		if err != nil || ipErr != nil || !ip.IsLoopback() || portErr != nil || number < 1 || number > 65535 {
			return errors.New("capture control listener requires literal loopback IP and port")
		}
		listener, err := net.Listen("tcp", *listen)
		if err != nil {
			return errors.New("capture control listener unavailable")
		}
		serve(listener)
	}
	if *controlUnix != "" {
		listener, cleanup, err := traffic.ListenPrivateUnix(*controlUnix)
		if err != nil {
			return err
		}
		cleanups = append(cleanups, cleanup)
		serve(listener)
	}
	if len(servers) == 0 {
		return errors.New("a private capture control listener is required")
	}
	var lastFingerprint string
	reload := func() {
		info, err := os.Stat(*policyFile)
		if err != nil {
			_ = engine.Pause()
			engine.ReportPolicyFileError()
			return
		}
		identity, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			_ = engine.Pause()
			engine.ReportPolicyFileError()
			return
		}
		fingerprint := fmt.Sprintf("%d:%d:%d:%d", info.Size(), info.ModTime().UnixNano(), identity.Dev, identity.Ino)
		if fingerprint == lastFingerprint {
			return
		}
		lastFingerprint = fingerprint
		if err := activateDesired(engine, *policyFile, info.ModTime(), activationStarted); err != nil {
			fmt.Fprintln(os.Stderr, "capture: desired policy activation failed; fresh executor lease required and previous scope retained only until lease expiry")
		}
	}
	reload()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-errorsFromServer:
			return errors.New("capture control server stopped")
		case <-ticker.C:
			reload()
		}
	}
}

func activateDesired(engine *packetcapture.Engine, path string, modified, started time.Time) error {
	p, err := packetcapture.LoadPolicyFile(path)
	if err != nil {
		engine.ReportPolicyFileError()
		return err
	}
	if p.Enabled && !modified.After(started) {
		engine.ReportPolicyFileError()
		return errors.New("fresh runtime verification required after collector restart")
	}
	return engine.Apply(p)
}

type recorderSink struct {
	client *packets.Client
	ctx    context.Context
}

func (s recorderSink) Submit(record packets.Record) bool {
	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
	defer cancel()
	return s.client.Ingest(ctx, record) == nil
}
