package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	proxyengine "github.com/ctf-service-manager/ctf-service-manager/internal/proxy"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func TestProxyConfirmationBindsExactDesiredFileSnapshot(t *testing.T) {
	ctx := context.Background()
	m, _ := proxyControlFixture(t)
	stale := proxyEmptyPreview(t, m, 1)
	path := filepath.Join(m.Config.Proxy.PolicyDirectory, "policy.json")
	// Preserve the semantic policy and revision but change its bytes. The
	// administrator must review a new snapshot even for a formatting-only edit.
	changed, err := json.MarshalIndent(proxyPublishedPolicy(t, m), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	changed = append(changed, '\n')
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, changed) {
		t.Fatal("fixture did not change the desired file snapshot")
	}
	if err = os.WriteFile(path, changed, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err = m.ProxyConfirm(ctx, transport.ProxyConfirmRequest{ProposalID: stale.ProposalID, Digest: stale.Digest, Initiator: "admin-test"}); err == nil {
		t.Fatal("stale confirmation replaced an unreviewed same-revision file edit")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, changed) || proxyRevisionCount(t, m) != 0 {
		t.Fatalf("rejected confirmation modified desired file or immutable history: %v", err)
	}
	fresh := proxyEmptyPreview(t, m, 1)
	if fresh.Policy.Revision != 2 || fresh.PreviousPolicy.Revision != 1 {
		t.Fatalf("fresh snapshot did not preserve the semantic base revision: %+v", fresh)
	}
	if _, err = m.ProxyConfirm(ctx, transport.ProxyConfirmRequest{ProposalID: fresh.ProposalID, Digest: fresh.Digest, Initiator: "admin-test"}); err != nil {
		t.Fatalf("freshly reviewed desired file could not be confirmed: %v", err)
	}
	if proxyPublishedPolicy(t, m).Revision != 2 || proxyRevisionCount(t, m) != 1 {
		t.Fatal("fresh confirmation failed to publish exactly one next revision")
	}
}

func TestProxyUnsafeDesiredFilesAreNeverRecoveredAsMissing(t *testing.T) {
	for _, name := range []string{"malformed", "oversized", "symlink"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			m, engine := proxyControlFixture(t)
			first := proxyEmptyPreview(t, m, 1)
			confirmed := transport.ProxyConfirmRequest{ProposalID: first.ProposalID, Digest: first.Digest, Initiator: "admin-test"}
			if _, err := m.ProxyConfirm(ctx, confirmed); err != nil {
				t.Fatal(err)
			}
			pending := proxyEmptyPreview(t, m, 2)
			path := filepath.Join(m.Config.Proxy.PolicyDirectory, "policy.json")
			var outside string
			switch name {
			case "malformed":
				if err := os.WriteFile(path, []byte(`{"schema_version":1,"revision":2,"routes":`), 0640); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.WriteFile(path, bytes.Repeat([]byte(" "), proxyengine.MaxPolicyBytes+1), 0640); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				outside = filepath.Join(t.TempDir(), "external-policy.json")
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(outside, raw, 0640); err != nil {
					t.Fatal(err)
				}
				if err = os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, err = m.proxyFileSnapshot(); err == nil {
				t.Fatal("unsafe desired file accepted as an available or missing snapshot")
			}
			if _, err = m.ProxyPreview(ctx, transport.ProxyPreviewRequest{ExpectedRevision: 2, Routes: []transport.ProxyRouteInput{}, Initiator: "admin-test"}); err == nil {
				t.Fatal("new preview hid an unsafe desired file behind database state")
			}
			if _, err = m.ProxyConfirm(ctx, transport.ProxyConfirmRequest{ProposalID: pending.ProposalID, Digest: pending.Digest, Initiator: "admin-test"}); err == nil {
				t.Fatal("confirmation overwrote an unsafe desired file")
			}
			if _, err = m.ProxyConfirm(ctx, confirmed); err == nil {
				t.Fatal("idempotent confirmation retry overwrote an unsafe desired file")
			}
			if err = m.reconcileProxyPublication(ctx); err == nil {
				t.Fatal("publisher treated an unsafe desired file as missing and recovered over it")
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("unsafe desired file or link was replaced: %v", err)
			}
			afterContents, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(contents, afterContents) {
				t.Fatalf("unsafe desired file bytes were modified: %v", err)
			}
			if outside != "" {
				target, err := os.Readlink(path)
				if err != nil || target != outside {
					t.Fatalf("desired symlink target changed: %q %v", target, err)
				}
				outsideContents, err := os.ReadFile(outside)
				if err != nil || !bytes.Equal(contents, outsideContents) {
					t.Fatalf("symlink target was modified: %v", err)
				}
			}
			if proxyRevisionCount(t, m) != 1 || engine.Status().AppliedRevision != 1 {
				t.Fatal("unsafe desired file changed confirmed history or last-known-good runtime")
			}
		})
	}
}
