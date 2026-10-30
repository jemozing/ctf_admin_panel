package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testCertificate(t *testing.T, root, id string, names []string, before, after time.Time) (*x509.CertPool, []byte) {
	t.Helper()
	if err := os.Chmod(root, 0750); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "local proxy test"}, NotBefore: before, NotAfter: after, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"certificate.pem": certPEM, "private-key.pem": keyPEM} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0640); err != nil {
			t.Fatal(err)
		}
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("test certificate unavailable")
	}
	return roots, der
}

func testTLSEngine(t *testing.T, upstream, directory string) (*Engine, Route) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	used := false
	e, err := NewEngine(Options{StateDirectory: filepath.Join(t.TempDir(), "state"), TLSDirectory: directory, Listen: func(network, addr string) (net.Listener, error) {
		if addr == address && !used {
			used = true
			return listener, nil
		}
		return net.Listen(network, addr)
	}})
	if err != nil {
		t.Fatal(err)
	}
	r := DefaultRoute()
	r.ID, r.ServiceID, r.Component = "tls-route", "tls-service", "app"
	r.Listen, r.Upstream, r.WAF.Mode = address, upstream, "off"
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 1, Routes: []Route{r}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = e.Close(ctx)
		_ = listener.Close()
	})
	return e, r
}

func dialTestTLS(t *testing.T, r Route, roots *x509.CertPool, name string, protocols []string) (*tls.Conn, error) {
	t.Helper()
	return tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", r.Listen, &tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS12, NextProtos: protocols})
}

func exchangeOnConn(t *testing.T, conn net.Conn, host string) (int, string) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, string(data)
}

func TestTLSHandshakeSNIHTTP1ALPNAndForwardedScheme(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	roots, _ := testCertificate(t, dir, "game-v1", []string{"game.test"}, now.Add(-time.Hour), now.Add(time.Hour))
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, r.Header.Get("X-Forwarded-Proto")) }))
	defer up.Close()
	e, r := testTLSEngine(t, up.URL, dir)
	r.Protocol, r.Host, r.TLS = "https1", "game.test", &TLSRoutePolicy{CertificateID: "game-v1"}
	p := Policy{SchemaVersion: 1, Revision: 2, Routes: []Route{r}}
	if err := e.Preflight(p); err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(p); err != nil {
		t.Fatal(err)
	}
	conn, err := dialTestTLS(t, r, roots, "game.test", []string{"h2", "http/1.1"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if state := conn.ConnectionState(); state.NegotiatedProtocol != "http/1.1" || state.Version < tls.VersionTLS12 {
		t.Fatal("unsupported TLS/ALPN negotiated")
	}
	if status, body := exchangeOnConn(t, conn, "game.test"); status != 200 || body != "https" {
		t.Fatal("TLS request did not forward with HTTPS scheme")
	}
	if status, _ := exchangeOnConn(t, conn, "other.test"); status != 421 {
		t.Fatal("TLS SNI and HTTP Host mismatch accepted")
	}
	for _, test := range []struct {
		name string
		alpn []string
	}{{"other.test", []string{"http/1.1"}}, {"game.test", []string{"h2"}}} {
		bad, err := dialTestTLS(t, r, roots, test.name, test.alpn)
		if bad != nil {
			bad.Close()
		}
		if err == nil {
			t.Fatal("wrong SNI or h2-only TLS client accepted")
		}
	}
	old, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", r.Listen, &tls.Config{RootCAs: roots, ServerName: "game.test", MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11})
	if old != nil {
		old.Close()
	}
	if err == nil {
		t.Fatal("legacy TLS protocol accepted")
	}
	plain, err := net.DialTimeout("tcp", r.Listen, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if status, _ := exchangeOnConn(t, plain, "game.test"); status != 400 {
		t.Fatal("plaintext accepted on HTTPS route")
	}
}

func TestTLSInvalidProfilePreservesLKGAndNewIDRotates(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	roots, der := testCertificate(t, dir, "game-v1", []string{"game.test"}, now.Add(-time.Hour), now.Add(time.Hour))
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer up.Close()
	e, r := testTLSEngine(t, up.URL, dir)
	r.Protocol, r.Host, r.TLS = "https1", "game.test", &TLSRoutePolicy{CertificateID: "game-v1"}
	p := Policy{SchemaVersion: 1, Revision: 2, Routes: []Route{r}}
	if err := e.Apply(p); err != nil {
		t.Fatal(err)
	}
	lkg, _ := os.ReadFile(filepath.Join(e.options.StateDirectory, "policy.json"))
	testCertificate(t, dir, "expired", []string{"game.test"}, now.Add(-2*time.Hour), now.Add(-time.Hour))
	testCertificate(t, dir, "wrong-name", []string{"other.test"}, now.Add(-time.Hour), now.Add(time.Hour))
	for _, id := range []string{"expired", "wrong-name", "missing", "../game-v1"} {
		r.TLS = &TLSRoutePolicy{CertificateID: id}
		next := Policy{SchemaVersion: 1, Revision: 3, Routes: []Route{r}}
		if e.Preflight(next) == nil || e.Apply(next) == nil {
			t.Fatal("invalid TLS profile passed preflight or activation")
		}
		current, _ := os.ReadFile(filepath.Join(e.options.StateDirectory, "policy.json"))
		if !bytes.Equal(lkg, current) || e.Status().AppliedRevision != 2 {
			t.Fatal("invalid TLS profile changed LKG")
		}
	}
	conn, err := dialTestTLS(t, p.Routes[0], roots, "game.test", []string{"http/1.1"})
	if err != nil {
		t.Fatal("old certificate stopped serving after rejected activation")
	}
	if !bytes.Equal(conn.ConnectionState().PeerCertificates[0].Raw, der) {
		t.Fatal("LKG certificate changed")
	}
	conn.Close()
	newRoots, newDER := testCertificate(t, dir, "game-v2", []string{"game.test"}, now.Add(-time.Hour), now.Add(time.Hour))
	r.TLS = &TLSRoutePolicy{CertificateID: "game-v2"}
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 3, Routes: []Route{r}}); err != nil {
		t.Fatal(err)
	}
	rotated, err := dialTestTLS(t, r, newRoots, "game.test", []string{"http/1.1"})
	if err != nil {
		t.Fatal(err)
	}
	defer rotated.Close()
	if !bytes.Equal(rotated.ConnectionState().PeerCertificates[0].Raw, newDER) {
		t.Fatal("new immutable profile not selected on new handshake")
	}
}

func TestTLSIPSubjectAlternativeNameAllowsClientWithoutSNI(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	roots, _ := testCertificate(t, dir, "ip-profile", []string{"127.0.0.1"}, now.Add(-time.Hour), now.Add(time.Hour))
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer up.Close()
	e, r := testTLSEngine(t, up.URL, dir)
	r.Protocol, r.Host, r.TLS = "https1", "127.0.0.1", &TLSRoutePolicy{CertificateID: "ip-profile"}
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 2, Routes: []Route{r}}); err != nil {
		t.Fatal(err)
	}
	// Go omits SNI for literal IP ServerName while still verifying the IP SAN.
	conn, err := dialTestTLS(t, r, roots, "127.0.0.1", []string{"http/1.1"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if status, body := exchangeOnConn(t, conn, "127.0.0.1"); status != 200 || body != "ok" {
		t.Fatal("valid literal IP TLS route failed")
	}
}

func TestTLSImmutableIDSurvivesRestartAndInventoryContainsNoPEM(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	roots, _ := testCertificate(t, dir, "game-v1", []string{"game.test"}, now.Add(-time.Hour), now.Add(time.Hour))
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer up.Close()
	e, r := testTLSEngine(t, up.URL, dir)
	r.Protocol, r.Host, r.TLS = "https1", "game.test", &TLSRoutePolicy{CertificateID: "game-v1"}
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 2, Routes: []Route{r}}); err != nil {
		t.Fatal(err)
	}
	page, err := e.TLSCertificates()
	if err != nil || len(page.Certificates) != 1 || !page.Certificates[0].Valid || page.Certificates[0].FingerprintSHA256 == "" {
		t.Fatal("certificate metadata unavailable")
	}
	token := strings.Repeat("c", 64)
	handler, _ := e.ControlHandler(token)
	for _, authorized := range []bool{false, true} {
		request := httptest.NewRequest("GET", "/v1/tls/certificates", nil)
		if authorized {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, request)
		expected := 401
		if authorized {
			expected = 200
		}
		if w.Code != expected || strings.Contains(w.Body.String(), "BEGIN") || strings.Contains(w.Body.String(), "PRIVATE KEY") || strings.Contains(w.Body.String(), dir) {
			t.Fatal("certificate control API leaked private material or ignored authorization")
		}
	}
	testCertificate(t, dir, "game-v1", []string{"game.test"}, now.Add(-time.Hour), now.Add(time.Hour))
	if e.Apply(Policy{SchemaVersion: 1, Revision: 3, Routes: []Route{r}}) == nil {
		t.Fatal("existing certificate ID was mutable")
	}
	page, err = e.TLSCertificates()
	if err != nil || page.Certificates[0].Valid || page.Certificates[0].ErrorCode != "immutable_profile_changed" {
		t.Fatal("modified immutable certificate not visible as invalid")
	}
	conn, err := dialTestTLS(t, r, roots, "game.test", []string{"http/1.1"})
	if err != nil {
		t.Fatal("modified disk profile affected in-memory LKG")
	}
	conn.Close()
	state := e.options.StateDirectory
	if err := e.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewEngine(Options{StateDirectory: state, TLSDirectory: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close(context.Background())
	if restarted.Restore() == nil || restarted.Status().Routes != 0 {
		t.Fatal("restart forgot immutable certificate identity")
	}
}

func TestTLSFilesRejectPublicModeLinksFIFOAndMismatchedPair(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	testCertificate(t, dir, "good", []string{"game.test"}, now.Add(-time.Hour), now.Add(time.Hour))
	testCertificate(t, dir, "other", []string{"game.test"}, now.Add(-time.Hour), now.Add(time.Hour))
	e, err := NewEngine(Options{StateDirectory: filepath.Join(t.TempDir(), "state"), TLSDirectory: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(context.Background())
	key := filepath.Join(dir, "good", "private-key.pem")
	goodKey, _ := os.ReadFile(key)
	if err := os.Chmod(key, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := e.readCertificateProfile("good"); err == nil {
		t.Fatal("public private-key mode accepted")
	}
	_ = os.Chmod(key, 0640)
	hard := filepath.Join(dir, "hard-key")
	if err := os.Link(key, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := e.readCertificateProfile("good"); err == nil {
		t.Fatal("hardlinked private key accepted")
	}
	_ = os.Remove(hard)
	_ = os.Remove(key)
	if err := os.Symlink(filepath.Join(dir, "other", "private-key.pem"), key); err != nil {
		t.Fatal(err)
	}
	if _, err := e.readCertificateProfile("good"); err == nil {
		t.Fatal("private-key symlink followed")
	}
	_ = os.Remove(key)
	if err := unix.Mkfifo(key, 0600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := e.readCertificateProfile("good"); err == nil || time.Since(start) > time.Second {
		t.Fatal("private-key FIFO accepted or blocked")
	}
	_ = os.Remove(key)
	other, _ := os.ReadFile(filepath.Join(dir, "other", "private-key.pem"))
	_ = os.WriteFile(key, other, 0640)
	if _, err := e.readCertificateProfile("good"); err == nil {
		t.Fatal("mismatched key pair accepted")
	}
	_ = os.WriteFile(key, goodKey, 0640)
	if _, err := e.readCertificateProfile("good"); err != nil {
		t.Fatal("restored private profile rejected")
	}
}

func TestHTTPAndTLSProfileChangesUseSameListenerAndCloseOldTransport(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	roots, _ := testCertificate(t, dir, "game", []string{"game.test"}, now.Add(-time.Hour), now.Add(time.Hour))
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer up.Close()
	e, r := testTLSEngine(t, up.URL, dir)
	plain, err := net.DialTimeout("tcp", r.Listen, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if status, _ := exchangeOnConn(t, plain, "game.test"); status != 200 {
		t.Fatal("initial HTTP route unavailable")
	}
	r.Protocol, r.Host, r.TLS = "https1", "game.test", &TLSRoutePolicy{CertificateID: "game"}
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 2, Routes: []Route{r}}); err != nil {
		t.Fatal(err)
	}
	if status, _ := exchangeOnConn(t, plain, "game.test"); status != 400 {
		t.Fatal("old plaintext connection continued after HTTPS activation")
	}
	secured, err := dialTestTLS(t, r, roots, "game.test", []string{"http/1.1"})
	if err != nil {
		t.Fatal(err)
	}
	defer secured.Close()
	if status, _ := exchangeOnConn(t, secured, "game.test"); status != 200 {
		t.Fatal("new TLS transport unavailable")
	}
	r.Protocol, r.TLS = "http1", nil
	if err := e.Apply(Policy{SchemaVersion: 1, Revision: 3, Routes: []Route{r}}); err != nil {
		t.Fatal(err)
	}
	if status, _ := exchangeOnConn(t, secured, "game.test"); status != 400 {
		t.Fatal("old TLS connection continued after HTTP activation")
	}
	if status, _, _ := request(t, r, "GET", "/", "", http.Header{"Host": {"game.test"}}); status != 421 {
		// request() addresses the listener directly and preserves its Host;
		// use a raw request with the exact configured domain below.
		t.Fatal("exact HTTP Host matching changed")
	}
	current, err := net.DialTimeout("tcp", r.Listen, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	if status, _ := exchangeOnConn(t, current, "game.test"); status != 200 {
		t.Fatal("HTTP transport did not return on same listener")
	}
}

func TestCutoverPreflightChecksPendingHostPortAndConstrainedExceptions(t *testing.T) {
	old, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	future, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	futureAddress := future.Addr().String()
	future.Close()
	e, err := NewEngine(Options{StateDirectory: filepath.Join(t.TempDir(), "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(context.Background())
	r := DefaultRoute()
	r.ID, r.ServiceID, r.Component = "route", "service", "app"
	r.Listen, r.Upstream = old.Addr().String(), "http://"+futureAddress
	p := Policy{SchemaVersion: 1, Revision: 1, Routes: []Route{r}}
	q := CutoverPreflightRequest{Policy: p, ReleasedListeners: []string{r.Listen}, PendingUpstreams: []string{r.Upstream}}
	if e.Preflight(p) == nil {
		t.Fatal("ordinary preflight accepted application-owned listener")
	}
	if err := e.PreflightCutover(q); err != nil {
		t.Fatal(err)
	}
	busy, err := net.Listen("tcp", futureAddress)
	if err != nil {
		t.Fatal("cutover preflight left pending port reserved")
	}
	if e.PreflightCutover(q) == nil {
		t.Fatal("occupied future host port passed cutover preflight")
	}
	busy.Close()
	q.PendingUpstreams = []string{"http://127.0.0.1:9"}
	if e.PreflightCutover(q) == nil {
		t.Fatal("unrelated pending origin accepted")
	}
	q.PendingUpstreams, q.ReleasedListeners = []string{r.Upstream}, []string{r.Listen, r.Listen}
	if e.PreflightCutover(q) == nil {
		t.Fatal("duplicate released listener accepted")
	}
	q.ReleasedListeners = []string{r.Listen}
	q.Policy.Routes[0].Protocol, q.Policy.Routes[0].Host, q.Policy.Routes[0].TLS = "https1", "game.test", &TLSRoutePolicy{CertificateID: "missing"}
	if e.PreflightCutover(q) == nil {
		t.Fatal("cutover bypassed TLS profile validation")
	}
	if e.Status().AppliedRevision != 0 || e.Status().Routes != 0 {
		t.Fatal("cutover preflight activated policy")
	}
	if _, err := os.Stat(filepath.Join(e.options.StateDirectory, "policy.json")); !os.IsNotExist(err) {
		t.Fatal("cutover preflight wrote LKG")
	}
	encoded, _ := json.Marshal(q)
	if bytes.Contains(encoded, []byte("BEGIN")) {
		t.Fatal("PEM entered typed cutover policy")
	}
}

func TestExplicitIPv4AndIPv6WildcardsSharePortForCutoverAndActivation(t *testing.T) {
	check, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback unavailable in this environment")
	}
	check.Close()
	v4, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(v4.Addr().String())
	v6, err := net.Listen("tcp6", "[::]:"+port)
	if err != nil {
		v4.Close()
		t.Fatal("explicit IPv6 wildcard conflicted with IPv4 wildcard", err)
	}
	defer v4.Close()
	defer v6.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "both-families") }))
	defer up.Close()
	e, err := NewEngine(Options{StateDirectory: filepath.Join(t.TempDir(), "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(context.Background())
	r4 := DefaultRoute()
	r4.ID, r4.ServiceID, r4.Component = "ipv4", "game", "app"
	r4.Listen, r4.Upstream, r4.WAF.Mode = "0.0.0.0:"+port, up.URL, "off"
	r6 := r4
	r6.ID, r6.Listen = "ipv6", "[::]:"+port
	p := Policy{SchemaVersion: 1, Revision: 1, Routes: []Route{r4, r6}}
	if err := e.PreflightCutover(CutoverPreflightRequest{Policy: p, ReleasedListeners: []string{r4.Listen, r6.Listen}}); err != nil {
		t.Fatal(err)
	}
	v4.Close()
	v6.Close()
	if err := e.Preflight(p); err != nil {
		t.Fatal("ordinary post-cutover preflight could not bind both families", err)
	}
	if err := e.Apply(p); err != nil {
		t.Fatal("activation could not bind both families", err)
	}
	for _, address := range []string{"127.0.0.1:" + port, "[::1]:" + port} {
		conn, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if status, body := exchangeOnConn(t, conn, "game.test"); status != 200 || body != "both-families" {
			t.Fatal("one IP family did not forward")
		}
		conn.Close()
	}
}

func TestAppliedRemovalReleasesHostPortBeforeStatusWhileRequestDrains(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		fmt.Fprint(w, "existing-request")
	}))
	defer up.Close()
	defer finish()
	e, r := testEngine(t, up.URL, nil)
	conn, err := net.DialTimeout("tcp", r.Listen, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: game.test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("existing request did not reach upstream")
	}
	started := time.Now()
	err = e.Apply(Policy{SchemaVersion: 1, Revision: 2, Routes: []Route{}})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > 500*time.Millisecond {
		t.Fatal("removing listener blocked on existing request drain")
	}
	if status := e.Status(); status.AppliedRevision != 2 || status.Routes != 0 {
		t.Fatal("removed policy not observed active")
	}
	replacement, err := net.Listen(listenNetwork(r.Listen), r.Listen)
	if err != nil {
		t.Fatal("applied revision was exposed while original host port remained bound", err)
	}
	replacement.Close()
	finish()
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != 200 || string(data) != "existing-request" {
		t.Fatal("listener removal aborted an existing request instead of draining")
	}
}
