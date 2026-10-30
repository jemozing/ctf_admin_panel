package proxy

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
)

func TestCutoverRejectsWildcardOverlapBeforeAnyHostProbe(t *testing.T) {
	for _, pair := range [][2]string{{"0.0.0.0:18080", "127.0.0.1:18080"}, {"[::]:18080", "[::1]:18080"}, {"0.0.0.0:18080", "[::ffff:127.0.0.1]:18080"}} {
		t.Run(pair[1], func(t *testing.T) {
			probes := 0
			e, err := NewEngine(Options{StateDirectory: filepath.Join(t.TempDir(), "state"), Listen: func(string, string) (net.Listener, error) { probes++; return nil, errors.New("probe should not run") }})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close(context.Background())
			first, second := DefaultRoute(), DefaultRoute()
			first.ID, second.ID = "one", "two"
			for _, r := range []*Route{&first, &second} {
				r.ServiceID = "game"
				r.Component = "app"
				r.Upstream = "http://127.0.0.1:29080"
			}
			first.Listen, second.Listen = pair[0], pair[1]
			if err = e.PreflightCutover(CutoverPreflightRequest{Policy: Policy{SchemaVersion: 1, Revision: 1, Routes: []Route{first, second}}, ReleasedListeners: pair[:], PendingUpstreams: []string{first.Upstream}}); err == nil {
				t.Fatal("impossible publication group accepted")
			}
			if probes != 0 {
				t.Fatal("overlap was discovered only after probing host ports")
			}
		})
	}
	first, second := DefaultRoute(), DefaultRoute()
	first.ID, second.ID = "v4", "v6"
	for _, r := range []*Route{&first, &second} {
		r.ServiceID = "game"
		r.Component = "app"
		r.Upstream = "http://127.0.0.1:29080"
	}
	first.Listen, second.Listen = "0.0.0.0:18080", "[::]:18080"
	if _, err := NormalizePolicy(Policy{SchemaVersion: 1, Revision: 1, Routes: []Route{first, second}}); err != nil {
		t.Fatalf("separate tcp4/tcp6 wildcard families became invalid: %v", err)
	}
}
