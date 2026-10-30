// ctfm-packets stores bounded passively observed packets in a separate archive.
// It has no raw sockets, Docker, or privileged executor interface.
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
	"strings"
	"syscall"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/packets"
	"github.com/ctf-service-manager/ctf-service-manager/internal/traffic"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) > 0 && args[0] == "health" {
		return health(args[1:])
	}
	f := flag.NewFlagSet("ctfm-packets", flag.ContinueOnError)
	listen := f.String("listen", "127.0.0.1:9804", "private recorder HTTP listen address")
	controlUnix := f.String("control-unix", "", "optional separate private Unix HTTP control/read socket")
	state := f.String("state", "/var/lib/ctfm-packets", "dedicated private recorder directory")
	ingest := f.String("ingest-token-file", "", "private ingest credential file")
	read := f.String("read-token-file", "", "private metadata/raw/export credential file")
	quota := f.Int64("quota-bytes", 256<<20, "hard SQLite database/journal budget")
	service := f.Int64("per-service-bytes", 64<<20, "per-service logical archive budget")
	reserve := f.Int64("minimum-free-bytes", 1<<30, "free space reserve beyond worst-case recorder journal")
	retention := f.Int("retention-seconds", 3600, "traffic retention window")
	records := f.Int("max-records", 100000, "maximum stored packets")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected recorder arguments")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return errors.New("invalid recorder listen address")
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return errors.New("recorder listen must use a literal IP")
	}
	if *retention < 1 || *retention > 86400 {
		return errors.New("recorder retention must be 1..86400 seconds")
	}
	ingestToken, err := traffic.ReadTokenFile(*ingest)
	if err != nil {
		return fmt.Errorf("ingest credential: %w", err)
	}
	readToken, err := traffic.ReadTokenFile(*read)
	if err != nil {
		return fmt.Errorf("read credential: %w", err)
	}
	store, err := packets.Open(packets.Config{StateDirectory: *state, QuotaBytes: *quota, PerServiceBytes: *service, MinimumFreeBytes: *reserve, Retention: time.Duration(*retention) * time.Second, MaxRecords: *records})
	if err != nil {
		return err
	}
	defer store.Close()
	handler, err := packets.Handler(store, packets.Tokens{Ingest: ingestToken, Read: readToken})
	if err != nil {
		return err
	}
	listeners := []net.Listener{}
	handlers := []http.Handler{packets.IngestOnly(handler)}
	tcp, err := net.Listen("tcp", *listen)
	if err != nil {
		return errors.New("recorder private HTTP bind failed")
	}
	listeners = append(listeners, tcp)
	defer tcp.Close()
	if *controlUnix != "" {
		unix, cleanup, err := traffic.ListenPrivateUnix(*controlUnix)
		if err != nil {
			return err
		}
		defer cleanup()
		listeners = append(listeners, unix)
		handlers = append(handlers, packets.ReadOnly(handler))
	}
	servers := []*http.Server{}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errorsCh := make(chan error, len(listeners))
	for index, listener := range listeners {
		server := &http.Server{Handler: handlers[index], ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10}
		servers = append(servers, server)
		go func() { errorsCh <- server.Serve(listener) }()
	}
	var serveError error
	select {
	case <-ctx.Done():
	case serveError = <-errorsCh:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, server := range servers {
		_ = server.Shutdown(shutdown)
	}
	if serveError != nil && !errors.Is(serveError, http.ErrServerClosed) {
		return errors.New("recorder HTTP server failed")
	}
	return nil
}

func health(args []string) error {
	f := flag.NewFlagSet("health", flag.ContinueOnError)
	address := f.String("url", "http://127.0.0.1:9804/healthz", "loopback health URL")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected health arguments")
	}
	u, err := url.Parse(*address)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/healthz" {
		return errors.New("invalid loopback health URL")
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !ip.Unmap().IsLoopback() {
		return errors.New("health URL must use loopback")
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("health redirect refused") }}
	r, err := client.Get(strings.TrimRight(*address, "/"))
	if err != nil {
		return errors.New("recorder health unavailable")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return errors.New("recorder unhealthy")
	}
	return nil
}
