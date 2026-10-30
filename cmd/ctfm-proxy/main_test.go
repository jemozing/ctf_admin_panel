package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/proxy"
)

func TestLocalControlURLsCannotExfiltrateToken(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1:9801@evil.example", "http://evil.example:9801", "https://127.0.0.1:9801", "http://127.0.0.1:9801/path", "http://127.0.0.1:9801?token=x", "http://127.0.0.1:9801#x"} {
		if localURL(raw, false) {
			t.Fatalf("unsafe origin accepted %s", raw)
		}
	}
	if !localURL("http://127.0.0.1:9801", false) || !localURL("http://[::1]:9801/healthz", true) {
		t.Fatal("literal loopback endpoints rejected")
	}
}

func TestTokenFilePrivateRegularAndNoValueInErrors(t *testing.T) {
	file := filepath.Join(t.TempDir(), "token")
	secret := strings.Repeat("private-secret", 4)
	if err := os.WriteFile(file, []byte(secret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := readToken(file); err != nil || got != secret {
		t.Fatal("private token unavailable")
	}
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readToken(file); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("public token or secret-bearing error accepted")
	}
	if err := os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	_ = os.Symlink(file, link)
	if _, err := readToken(link); err == nil {
		t.Fatal("token symlink followed")
	}
	hard := filepath.Join(t.TempDir(), "hardlink")
	if err := os.Link(file, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := readToken(file); err == nil {
		t.Fatal("hardlinked token accepted")
	}
}

func TestEmergencyDisableWritesHigherRevisionPreservesOwnerModeAndRoutes(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "policy.json")
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	r := proxy.DefaultRoute()
	r.ID = "route"
	r.ServiceID = "service"
	r.Component = "app"
	r.Listen = "127.0.0.1:19000"
	r.Upstream = "http://127.0.0.1:18000"
	r.WAF.Mode = "enforce"
	p := proxy.Policy{SchemaVersion: 1, Revision: 4, Routes: []proxy.Route{r}}
	data, _ := json.Marshal(p)
	if err := os.WriteFile(file, data, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "policy.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := emergency([]string{"--policy-file", file, "--state", state, "--action", "disable-waf", "--service", "service", "--comment", "checker requires temporary bypass"}); err != nil {
		t.Fatal(err)
	}
	next, err := proxy.LoadPolicyFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if next.Revision != 5 || next.Routes[0].WAF.Mode != "off" || next.Routes[0].Upstream != r.Upstream || next.Routes[0].Listen != r.Listen {
		t.Fatal("emergency changed routing or did not disable WAF")
	}
	info, _ := os.Stat(file)
	if info.Mode().Perm() != 0640 {
		t.Fatal("policy mode changed")
	}
}
