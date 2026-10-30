package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/proxy"
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
		f := flag.NewFlagSet("health", flag.ContinueOnError)
		endpoint := f.String("url", "http://127.0.0.1:9801/healthz", "local health URL")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if !localURL(*endpoint, true) {
			return errors.New("health requires explicit loopback URL")
		}
		client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		r, err := client.Get(*endpoint)
		if err != nil {
			return errors.New("proxy health unavailable")
		}
		defer r.Body.Close()
		if r.StatusCode != 200 {
			return errors.New("proxy health unavailable")
		}
		return nil
	}
	if len(args) > 0 && args[0] == "emergency" {
		return emergency(args[1:])
	}
	if len(args) > 0 && args[0] == "control" {
		return control(args[1:])
	}
	f := flag.NewFlagSet("ctfm-proxy", flag.ContinueOnError)
	policyFile := f.String("policy-file", "/etc/ctfm-proxy/policy.json", "root-approved desired policy")
	state := f.String("state", "/var/lib/ctfm-proxy", "private LKG/WAF state")
	tlsDirectory := f.String("tls-directory", "", "private read-only directory of immutable TLS certificate profiles")
	listen := f.String("control-listen", "127.0.0.1:9801", "separate loopback control listener; empty requires --control-unix")
	unix := f.String("control-unix", "", "separate private proxy control socket")
	controlTokenFile := f.String("control-token-file", "/run/secrets/control", "private control token")
	recorderURL := f.String("recorder-url", "http://127.0.0.1:9802", "private recorder endpoint")
	recorderTokenFile := f.String("recorder-token-file", "/run/secrets/ingest", "private ingest-only token")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected proxy arguments")
	}
	if !filepath.IsAbs(*policyFile) || filepath.Clean(*policyFile) != *policyFile {
		return errors.New("absolute desired policy path required")
	}
	token, err := readToken(*controlTokenFile)
	if err != nil {
		return err
	}
	ingestToken, err := readToken(*recorderTokenFile)
	if err != nil {
		return err
	}
	client, err := traffic.NewClient(*recorderURL, ingestToken)
	if err != nil {
		return errors.New("invalid recorder endpoint")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	e, err := proxy.NewEngine(proxy.Options{StateDirectory: *state, TLSDirectory: *tlsDirectory, Sink: recorderSink{client: client, ctx: ctx}})
	if err != nil {
		return err
	}
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = e.Close(shutdown)
	}()
	handler, err := e.ControlHandler(token)
	if err != nil {
		return err
	}
	servers := []*http.Server{}
	cleanups := []func(){}
	defer func() {
		for _, s := range servers {
			shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = s.Shutdown(shutdown)
			cancel()
		}
		for _, cleanup := range cleanups {
			cleanup()
		}
	}()
	serve := func(listener net.Listener) {
		server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
		servers = append(servers, server)
		go func() { _ = server.Serve(listener) }()
	}
	if *listen != "" {
		host, _, err := net.SplitHostPort(*listen)
		ip, e := netip.ParseAddr(host)
		if err != nil || e != nil || !ip.IsLoopback() {
			return errors.New("control TCP listener must use literal loopback IP")
		}
		listener, err := net.Listen("tcp", *listen)
		if err != nil {
			return errors.New("control listener unavailable")
		}
		serve(listener)
	}
	if *unix != "" {
		listener, cleanup, err := traffic.ListenPrivateUnix(*unix)
		if err != nil {
			return err
		}
		cleanups = append(cleanups, cleanup)
		serve(listener)
	}
	if len(servers) == 0 {
		return errors.New("a separate private control listener is required")
	}
	if err := e.Restore(); err != nil {
		fmt.Fprintln(os.Stderr, "proxy: last-known-good policy cannot be restored; listeners remain closed")
	}
	var lastFingerprint string
	reload := func() {
		info, err := os.Stat(*policyFile)
		if err != nil {
			e.ReportPolicyFileError()
			return
		}
		fingerprint := fmt.Sprintf("%d:%d:%v", info.Size(), info.ModTime().UnixNano(), info.Sys())
		if fingerprint == lastFingerprint {
			return
		}
		p, err := proxy.LoadPolicyFile(*policyFile)
		lastFingerprint = fingerprint
		if err != nil {
			e.ReportPolicyFileError()
			fmt.Fprintln(os.Stderr, "proxy: desired policy rejected; last-known-good retained")
			return
		}
		if err := e.Apply(p); err != nil {
			fmt.Fprintln(os.Stderr, "proxy: policy activation failed; last-known-good retained")
		}
	}
	reload()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			reload()
		}
	}
}

type recorderSink struct {
	client *traffic.Client
	ctx    context.Context
}

func (s recorderSink) Submit(x traffic.Exchange) bool {
	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
	defer cancel()
	return s.client.Ingest(ctx, x) == nil
}

func readToken(path string) (string, error) {
	return traffic.ReadTokenFile(path)
}

func control(args []string) error {
	f := flag.NewFlagSet("control", flag.ContinueOnError)
	endpoint := f.String("url", "http://127.0.0.1:9801", "private loopback control origin")
	unix := f.String("unix", "", "private proxy control socket")
	tokenFile := f.String("token-file", "/run/secrets/control", "private token file")
	service := f.String("service", "", "service ID")
	ip := f.String("ip", "", "normalized IP")
	route := f.String("route", "", "optional route-specific scope")
	comment := f.String("comment", "", "audit comment")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 1 {
		return errors.New("control requires status, bans or unban")
	}
	token, err := readToken(*tokenFile)
	if err != nil {
		return err
	}
	transport := &http.Transport{Proxy: nil}
	origin := *endpoint
	if *unix != "" {
		if !filepath.IsAbs(*unix) || filepath.Clean(*unix) != *unix {
			return errors.New("absolute control socket required")
		}
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", *unix)
		}
		origin = "http://proxy-control"
	} else if !localURL(origin, false) {
		return errors.New("control requires explicit loopback origin")
	}
	method, path := http.MethodGet, "/v1/status"
	var body io.Reader
	switch f.Arg(0) {
	case "status":
	case "bans":
		path = "/v1/bans"
	case "unban":
		method = http.MethodPost
		path = "/v1/unban"
		data, _ := json.Marshal(proxy.UnbanRequest{ServiceID: *service, RouteID: *route, IP: *ip, Comment: *comment})
		body = bytes.NewReader(data)
	default:
		return errors.New("unknown control action")
	}
	request, err := http.NewRequest(method, strings.TrimRight(origin, "/")+path, body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("private control request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("private control action rejected")
	}
	_, err = io.Copy(os.Stdout, io.LimitReader(response.Body, 4<<20))
	return err
}

func emergency(args []string) error {
	f := flag.NewFlagSet("emergency", flag.ContinueOnError)
	file := f.String("policy-file", "", "host desired policy path")
	state := f.String("state", "", "host private proxy state path")
	action := f.String("action", "", "disable-waf or restore-previous")
	service := f.String("service", "", "registered service ID")
	comment := f.String("comment", "", "required audit comment")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *comment == "" || len(*comment) > 500 || !filepath.IsAbs(*file) || !filepath.IsAbs(*state) {
		return errors.New("explicit desired/state paths, action and bounded audit comment required")
	}
	release, err := proxy.LockPolicyDirectory(filepath.Dir(*file))
	if err != nil {
		return err
	}
	defer release()
	current, err := proxy.LoadPolicyFile(*file)
	if err != nil {
		return err
	}
	digest := proxy.PolicyDigest(current)
	next := current
	lkg, err := proxy.LoadPolicyFile(filepath.Join(*state, "policy.json"))
	if err != nil {
		return errors.New("current proxy state unavailable")
	}
	revision := current.Revision
	if lkg.Revision > revision {
		revision = lkg.Revision
	}
	switch *action {
	case "disable-waf":
		found := false
		for i := range next.Routes {
			if next.Routes[i].ServiceID == *service {
				next.Routes[i].WAF.Mode = "off"
				found = true
			}
		}
		if !found {
			return errors.New("unknown service")
		}
	case "restore-previous":
		next, err = proxy.LoadPolicyFile(filepath.Join(*state, "previous-policy.json"))
		if err != nil {
			return errors.New("previous proxy policy unavailable")
		}
	default:
		return errors.New("unsupported emergency action")
	}
	next.Revision = revision + 1
	if err := proxy.RecordEmergencyAudit(*state, "emergency_requested", *service, *comment, next.Revision); err != nil {
		return err
	}
	if err := proxy.WriteDesiredPolicy(*file, next, digest); err != nil {
		return err
	}
	if err := proxy.RecordEmergencyAudit(*state, "emergency_desired_written", *service, *comment, next.Revision); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"action": *action, "service_id": *service, "new_revision": next.Revision, "status": "desired_policy_written", "observed_activation": "check_control_status", "comment": *comment})
}

func localURL(raw string, health bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	a, err := netip.ParseAddr(u.Hostname())
	if err != nil || !a.IsLoopback() {
		return false
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil || p < 1 || p > 65535 {
		return false
	}
	if health {
		return u.Path == "/healthz"
	}
	return u.Path == ""
}
