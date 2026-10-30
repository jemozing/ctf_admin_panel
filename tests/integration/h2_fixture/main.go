// Isolated synthetic HTTP/2 fixture for process-level TLS visibility checks.
// This is not installed in a runtime image and never contacts a non-loopback host.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

var first = message([]byte{0, 0xff, 'f', 'l', 'a', 'g', '!', '1'})
var second = message([]byte("second grpc message"))

func message(data []byte) []byte {
	out := make([]byte, 5+len(data))
	binary.BigEndian.PutUint32(out[1:5], uint32(len(data)))
	copy(out[5:], data)
	return out
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "synthetic h2 fixture failed:", err)
		os.Exit(1)
	}
}
func run() error {
	fs := flag.NewFlagSet("h2-fixture", flag.ContinueOnError)
	mode := fs.String("mode", "", "upstream or client")
	listen := fs.String("listen", "127.0.0.1:0", "loopback fixture")
	target := fs.String("target", "", "TLS loopback target")
	ca := fs.String("ca", "", "synthetic certificate")
	action := fs.String("action", "unary", "client scenario")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if *mode == "upstream" {
		return upstream(*listen)
	}
	if *mode != "client" {
		return errors.New("invalid mode")
	}
	return client(*target, *ca, *action)
}
func upstream(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		return errors.New("fixture must bind loopback")
	}
	var calls atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]int64{"calls": calls.Load()})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.ProtoMajor != 2 {
			http.Error(w, "HTTP2 required", 400)
			return
		}
		w.Header().Set("Content-Type", "application/grpc+proto")
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message, X-Api-Key")
		w.Header().Set("X-Observed-Proto", r.Header.Get("X-Forwarded-Proto"))
		w.Header().Set("X-Auth-Preserved", fmt.Sprint(r.Header.Get("Authorization") == "Bearer h2-private-fixture"))
		w.Header().Set("X-Observed-Client-IP", r.Header.Get("X-Forwarded-For"))
		if strings.HasSuffix(r.URL.Path, "/Bidi") {
			for {
				header := make([]byte, 5)
				_, err := io.ReadFull(r.Body, header)
				if err == io.EOF {
					break
				}
				if err != nil {
					return
				}
				n := binary.BigEndian.Uint32(header[1:5])
				if n > 1<<20 {
					return
				}
				body := make([]byte, n)
				if _, err := io.ReadFull(r.Body, body); err != nil {
					return
				}
				w.Write(append(header, body...))
				w.(http.Flusher).Flush()
			}
		} else {
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				return
			}
			w.Write(body)
		}
		w.Header().Set("Grpc-Status", "0")
		w.Header().Set("Grpc-Message", "done")
		w.Header().Set("X-Api-Key", "private-trailer")
	})
	server := &http.Server{Addr: address, Handler: h2c.NewHandler(mux, &http2.Server{MaxConcurrentStreams: 128}), ReadHeaderTimeout: 3 * time.Second, IdleTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()
	err = server.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
func client(address, caFile, action string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		return errors.New("client target must be loopback")
	}
	pool := x509.NewCertPool()
	if action != "untrusted" {
		data, err := os.ReadFile(caFile)
		if err != nil || !pool.AppendCertsFromPEM(data) {
			return errors.New("fixture trust unavailable")
		}
	}
	tr := &http2.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}, DialTLSContext: func(ctx context.Context, network, _ string, cfg *tls.Config) (net.Conn, error) {
		return (&tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Second}, Config: cfg}).DialContext(ctx, network, address)
	}}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	base := "https://localhost:" + port
	makeRequest := func(path string, body io.Reader) (*http.Request, error) {
		req, err := http.NewRequest("POST", base+path, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/grpc+proto")
		req.Header.Set("Te", "trailers")
		req.Header.Set("Authorization", "Bearer h2-private-fixture")
		req.Header.Set("X-Forwarded-For", "203.0.113.99")
		return req, nil
	}
	unary := func() (map[string]any, error) {
		req, _ := makeRequest("/test.Echo/Unary", bytes.NewReader(first))
		if action == "bad-host" {
			req.Host = "unrelated.test"
		}
		response, err := c.Do(req)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}
		return map[string]any{"status": response.StatusCode, "h2": response.ProtoMajor == 2, "alpn": response.TLS.NegotiatedProtocol, "body_equal": bytes.Equal(data, first), "grpc_status": response.Trailer.Get("Grpc-Status"), "forwarded_proto": response.Header.Get("X-Observed-Proto"), "auth_preserved": response.Header.Get("X-Auth-Preserved") == "true", "client_ip": response.Header.Get("X-Observed-Client-IP")}, nil
	}
	var result map[string]any
	switch action {
	case "unary", "bad-host":
		result, err = unary()
	case "untrusted":
		_, err = unary()
		result = map[string]any{"tls_rejected": err != nil}
		err = nil
	case "multiplex":
		var wg sync.WaitGroup
		var passed atomic.Int32
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				v, e := unary()
				if e == nil && v["h2"] == true && v["body_equal"] == true && v["grpc_status"] == "0" {
					passed.Add(1)
				}
			}()
		}
		wg.Wait()
		result = map[string]any{"passed": passed.Load(), "total": 8}
	case "bidi":
		reader, writer := io.Pipe()
		defer reader.Close()
		defer writer.Close()
		req, _ := makeRequest("/test.Echo/Bidi", reader)
		written := make(chan error, 1)
		go func() { _, e := writer.Write(first); written <- e }()
		response, e := c.Do(req)
		if e != nil {
			return e
		}
		defer response.Body.Close()
		part := make([]byte, len(first))
		_, e = io.ReadFull(response.Body, part)
		if e != nil {
			return e
		}
		if e = <-written; e != nil {
			return e
		}
		firstEqual := bytes.Equal(part, first)
		go func() {
			_, e := writer.Write(second)
			if e == nil {
				e = writer.Close()
			}
			written <- e
		}()
		rest, e := io.ReadAll(response.Body)
		if e != nil {
			return e
		}
		if e = <-written; e != nil {
			return e
		}
		result = map[string]any{"before_request_eof": firstEqual, "second_equal": bytes.Equal(rest, second), "grpc_status": response.Trailer.Get("Grpc-Status"), "h2": response.ProtoMajor == 2}
	default:
		return errors.New("invalid client action")
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
