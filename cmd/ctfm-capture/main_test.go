package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/packetcapture"
	"github.com/ctf-service-manager/ctf-service-manager/internal/packets"
)

type noPackets struct{}

func (noPackets) Read(ctx context.Context) (packetcapture.Frame, error) {
	<-ctx.Done()
	return packetcapture.Frame{}, ctx.Err()
}
func (noPackets) Close() error { return nil }

type discardPackets struct{}

func (discardPackets) Submit(packets.Record) bool { return true }

func TestRestartDuringRuntimeMutationRequiresFreshFileAndLease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "desired.json")
	var opens atomic.Int32
	newEngine := func() *packetcapture.Engine {
		e, err := packetcapture.New(packetcapture.Options{Sink: discardPackets{}, Interfaces: func() ([]packetcapture.Interface, error) {
			return []packetcapture.Interface{{Name: "fixture0", Index: 7, Supported: true, Up: true}}, nil
		}, OpenSource: func(packetcapture.Interface) (packetcapture.Source, error) { opens.Add(1); return noPackets{}, nil }})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = e.Close(context.Background()) })
		return e
	}
	p := packetcapture.Policy{SchemaVersion: 1, Revision: 1, Enabled: true, Snaplen: 0, MaxPacketsPerSecond: 1000, LeaseUntil: time.Now().Add(30 * time.Second), Interfaces: []packetcapture.InterfacePolicy{{Name: "fixture0", Index: 7, Endpoints: []packetcapture.Endpoint{{ServiceID: "game", Component: "app", Protocol: "tcp", Address: "172.20.0.5", Port: 7000}}}}}
	write := func() {
		body, _ := json.Marshal(p)
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	first := newEngine()
	started := time.Now()
	if err := activateDesired(first, path, started.Add(-time.Second), started); err == nil || first.Status().Running || opens.Load() != 0 {
		t.Fatal("existing enabled file opened a source after collector restart")
	}
	if err := activateDesired(first, path, started.Add(time.Millisecond), started); err != nil || !first.Status().Running {
		t.Fatalf("fresh verified publisher file failed to start: %v", err)
	}
	if err := first.Pause(); err != nil {
		t.Fatal(err)
	}
	if err := activateDesired(first, path, started.Add(time.Millisecond), started); err == nil || first.Status().Running {
		t.Fatal("pre-pause lease resumed observation")
	}
	_ = first.Close(context.Background())
	second := newEngine()
	restarted := started.Add(2 * time.Millisecond)
	if err := activateDesired(second, path, started.Add(time.Millisecond), restarted); err == nil || second.Status().Running || opens.Load() != 1 {
		t.Fatal("restart during mutation replayed pre-pause desired file")
	}
	p.LeaseUntil = p.LeaseUntil.Add(time.Second)
	write()
	if err := activateDesired(second, path, restarted.Add(time.Millisecond), restarted); err != nil || !second.Status().Running || opens.Load() != 2 {
		t.Fatalf("fresh runtime verification failed after restart: %v", err)
	}
}
