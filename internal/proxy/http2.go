package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

type idleTransport interface {
	http.RoundTripper
	CloseIdleConnections()
}

func isTLSProfile(protocol string) bool { return protocol == "https1" || protocol == "https2" }
func frontendALPN(protocol string) []string {
	if protocol == "https2" {
		return []string{"h2"}
	}
	return []string{"http/1.1"}
}

// Enable the bounded H2 implementation once per listener; route-specific ALPN
// still decides whether a connection can use it after an atomic policy change.
func configureHTTP2Server(server *http.Server) error {
	return http2.ConfigureServer(server, &http2.Server{MaxConcurrentStreams: 128, MaxDecoderHeaderTableSize: 4096, MaxEncoderHeaderTableSize: 4096, MaxReadFrameSize: 16384, MaxUploadBufferPerConnection: 1 << 20, MaxUploadBufferPerStream: 64 << 10, IdleTimeout: server.IdleTimeout, ReadIdleTimeout: 15 * time.Second, PingTimeout: 5 * time.Second, WriteByteTimeout: 10 * time.Second})
}

// HTTPS/2 termination deliberately uses prior-knowledge plaintext H2 only on
// the frozen literal loopback origin. This is not a generic h2c/open proxy.
func newH2Upstream(r Route, u *url.URL) idleTransport {
	expected := upstreamAddress(u.String())
	tr := &http2.Transport{AllowHTTP: true, DisableCompression: true, MaxHeaderListSize: uint32(r.Limits.MaxHeaderBytes), MaxReadFrameSize: 16384, MaxDecoderHeaderTableSize: 4096, MaxEncoderHeaderTableSize: 4096, StrictMaxConcurrentStreams: true, IdleConnTimeout: time.Duration(r.Limits.IdleTimeoutSeconds) * time.Second, ReadIdleTimeout: 15 * time.Second, PingTimeout: 5 * time.Second, WriteByteTimeout: 10 * time.Second,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			ip, parseErr := netip.ParseAddr(host)
			if err != nil || parseErr != nil || !ip.Unmap().IsLoopback() || addr != expected {
				return nil, errors.New("HTTP/2 upstream differs from frozen loopback target")
			}
			return (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, network, expected)
		}}
	return &headerDeadlineTransport{Transport: tr, timeout: time.Duration(r.Limits.UpstreamResponseHeaderTimeoutSeconds) * time.Second}
}

type headerDeadlineTransport struct {
	*http2.Transport
	timeout time.Duration
}

func (t *headerDeadlineTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancel(r.Context())
	timer := time.AfterFunc(t.timeout, cancel)
	response, err := t.Transport.RoundTrip(r.WithContext(ctx))
	timer.Stop()
	if err != nil {
		cancel()
		return nil, err
	}
	response.Body = &cancelResponseBody{ReadCloser: response.Body, cancel: cancel}
	return response, nil
}

type cancelResponseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelResponseBody) Close() error { b.cancel(); return b.ReadCloser.Close() }

// ProbeHTTP2Origins verifies only the HTTP/2 connection preface/SETTINGS, never
// sends a request or invokes a game RPC. The executor supplies these origins
// from frozen, registered current bindings before a pending cutover.
type HTTP2ProbeRequest struct {
	Upstreams          []string `json:"upstreams"`
	AllowHostAddresses bool     `json:"allow_host_addresses,omitempty"`
}

func ProbeHTTP2Origins(ctx context.Context, origins []string) error {
	return probeHTTP2Origins(ctx, origins, false)
}
func probeHTTP2Origins(ctx context.Context, origins []string, allowHost bool) error {
	if len(origins) < 1 || len(origins) > MaxCutoverUpstreams {
		return errors.New("HTTP/2 origin probe budget exceeded")
	}
	var local []netip.Addr
	if allowHost {
		interfaces, err := net.Interfaces()
		if err != nil || len(interfaces) > 256 {
			return errors.New("host interface inventory unavailable")
		}
		for _, iface := range interfaces {
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			addresses, err := iface.Addrs()
			if err != nil || len(addresses) > 256 {
				return errors.New("host interface addresses unavailable")
			}
			for _, address := range addresses {
				prefix, err := netip.ParsePrefix(address.String())
				if err == nil {
					local = append(local, prefix.Addr().Unmap())
				}
			}
		}
	}
	addresses := []string{}
	seen := map[string]bool{}
	for _, origin := range origins {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") || len(origin) > 2048 {
			return errors.New("HTTP/2 probe requires a frozen loopback origin")
		}
		ip, err := netip.ParseAddr(u.Hostname())
		port, portErr := strconv.Atoi(u.Port())
		if err != nil || ip.Zone() != "" || !approvedH2ProbeIP(ip, allowHost, local) || portErr != nil || port < 1 || port > 65535 {
			return errors.New("HTTP/2 probe requires an explicit literal loopback port")
		}
		address := net.JoinHostPort(ip.Unmap().String(), strconv.Itoa(port))
		if !seen[address] {
			addresses = append(addresses, address)
			seen[address] = true
		}
	}
	run, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	jobs := make(chan string)
	var wg sync.WaitGroup
	var first error
	var mu sync.Mutex
	for range minInt(4, len(addresses)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for address := range jobs {
				if err := probeHTTP2Address(run, address); err != nil {
					mu.Lock()
					if first == nil {
						first = errors.New("frozen upstream did not return an HTTP/2 server preface")
					}
					mu.Unlock()
					cancel()
				}
			}
		}()
	}
	for _, address := range addresses {
		select {
		case jobs <- address:
		case <-run.Done():
		}
	}
	close(jobs)
	wg.Wait()
	if first != nil {
		return first
	}
	return run.Err()
}
func probeHTTP2Address(ctx context.Context, address string) error {
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		return err
	}
	fr := http2.NewFramer(conn, conn)
	fr.SetMaxReadFrameSize(16384)
	if err := fr.WriteSettings(); err != nil {
		return err
	}
	frame, err := fr.ReadFrame()
	if err != nil {
		return err
	}
	settings, ok := frame.(*http2.SettingsFrame)
	if !ok || settings.IsAck() {
		return errors.New("missing initial HTTP/2 SETTINGS")
	}
	return nil
}

func approvedH2ProbeIP(ip netip.Addr, allowHost bool, local []netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() {
		return true
	}
	if !allowHost {
		return false
	}
	for _, address := range local {
		if ip == address.Unmap() {
			return true
		}
	}
	return false
}
