package backup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
)

func TestFullRestoreRequiresExplicitProxyReconnection(t *testing.T) {
	f := makeFixture(t)
	raw, err := os.ReadFile(f.configuration)
	if err != nil {
		t.Fatal(err)
	}
	var bootstrap config.Config
	if err = json.Unmarshal(raw, &bootstrap); err != nil {
		t.Fatal(err)
	}
	bootstrap.Proxy = config.ProxyPolicy{Enabled: true, PolicyDirectory: filepath.Join(f.root, "proxy-policy"), ControlURL: "http://127.0.0.1:9801", TrafficURL: "http://127.0.0.1:9802", ControlTokenFile: filepath.Join(f.root, "proxy-control.token"), TrafficTokenFile: filepath.Join(f.root, "proxy-read.token"), AllowedListenIPs: []string{"127.0.0.1"}, ListenPortMin: 10080, ListenPortMax: 10179, ProxyGID: 10002}
	raw, _ = json.Marshal(bootstrap)
	if err = os.WriteFile(f.configuration, raw, 0600); err != nil {
		t.Fatal(err)
	}
	options := f.options("proxy-protected.ctfmbak")
	options.Passphrase = passphrase
	if _, err = Create(t.Context(), options); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(f.root, "restored-proxy")
	report, err := Restore(t.Context(), RestoreOptions{Source: options.Destination, Destination: destination, Passphrase: passphrase})
	if err != nil {
		t.Fatal(err)
	}
	if !report.ProxyReconfigurationRequired {
		t.Fatal("proxy reconnection review was not reported")
	}
	actual, err := config.Load(filepath.Join(destination, "config", "executor.json"))
	if err != nil {
		t.Fatal(err)
	}
	if actual.Proxy.Enabled {
		t.Fatal("restored panel could automatically replace an independent live proxy policy")
	}
	if actual.Proxy.PolicyDirectory != bootstrap.Proxy.PolicyDirectory {
		t.Fatal("installation information needed for explicit review was lost")
	}
}
