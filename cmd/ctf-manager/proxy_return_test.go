package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func TestProxyReturnCLIRequiresExactReviewAndUsesLiveExecutor(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "ctfm-return-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socket := filepath.Join(directory, "executor.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	digest := domain.Hash([]byte("return-current-ports"))
	var paths []string
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/proxy/cutovers":
			_, _ = w.Write([]byte(`[]`))
		case "/v1/proxy/cutover/return-preview":
			var in transport.ProxyCutoverReturnRequest
			if json.NewDecoder(r.Body).Decode(&in) != nil || in.CutoverID != "cutover-current" || string(in.Initiator) != fmt.Sprintf("uid-%d", os.Geteuid()) {
				t.Error("preview actor or identity changed")
			}
			_ = json.NewEncoder(w).Encode(transport.ProxyCutoverPreview{ProposalID: "return-plan", Digest: digest, Mode: "return"})
		case "/v1/proxy/cutover/confirm":
			var in transport.ProxyConfirmRequest
			if json.NewDecoder(r.Body).Decode(&in) != nil || in.ProposalID != "return-plan" || in.Digest != digest || string(in.Initiator) != fmt.Sprintf("uid-%d", os.Geteuid()) {
				t.Error("confirmation lost reviewed identity")
			}
			_ = json.NewEncoder(w).Encode(transport.ProxyCutoverView{ID: "cutover-current", State: "queued"})
		default:
			t.Error("unexpected privileged request")
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	for _, args := range [][]string{{"proxy-cutovers"}, {"proxy-return-preview", "--cutover", "cutover-current"}, {"proxy-return-confirm", "--proposal", "return-plan", "--digest", string(digest)}} {
		var out bytes.Buffer
		if err := remoteProxyReturn(t.Context(), socket, args, &out, io.Discard); err != nil {
			t.Fatal(err)
		}
		if !json.Valid(out.Bytes()) {
			t.Fatal("invalid CLI result")
		}
	}
	if strings.Join(paths, ",") != "/v1/proxy/cutovers,/v1/proxy/cutover/return-preview,/v1/proxy/cutover/confirm" {
		t.Fatal(paths)
	}
}

func TestProxyReturnCLIRejectsMissingDigestBeforeOpeningAnyExecutor(t *testing.T) {
	for _, args := range [][]string{{"proxy-return-confirm"}, {"proxy-return-confirm", "--proposal", "return-plan"}, {"proxy-return-preview", "--cutover", "../escape"}, {"proxy-cutovers", "--digest", string(domain.Hash([]byte("unreviewed")))}, {"proxy-return-confirm", "--proposal", "return-plan", "--digest", "not-a-digest"}} {
		err := remoteProxyReturn(context.Background(), "/no-such-executor", args, io.Discard, io.Discard)
		if err == nil || strings.Contains(err.Error(), "dial") {
			t.Fatalf("unreviewed command reached transport: %v", err)
		}
	}
}
