package docker

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestComposePublishedPortChanges(t *testing.T) {
	current := decodeComposeResourceTest(t, `{"services":{"app":{"ports":[{"target":8070,"published":"18021","host_ip":"127.0.0.1","protocol":"tcp","mode":"ingress"},{"target":9000,"protocol":"udp"}]},"db":{"image":"db"}}}`)
	proposed := decodeComposeResourceTest(t, `{"services":{"app":{"ports":[{"target":9000,"protocol":"udp"},{"target":8070,"published":"8070","protocol":"tcp","mode":"ingress"}]},"db":{"image":"db"}}}`)
	want := []ComposeResourceChange{{Component: "app", Setting: "ports", Before: "127.0.0.1:18021 → 8070/tcp", After: "*:8070 → 8070/tcp"}}
	got, err := ComposeResourceChanges(current, proposed, []string{"app"})
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("changes = %+v, %v", got, err)
	}
	wantPorts := []PublishedPortBinding{{Component: "app", Published: 8070, Target: 8070, Protocol: "tcp"}}
	gotPorts, err := ComposeChangedPublishedPorts(current, proposed, []string{"app"})
	if err != nil || !reflect.DeepEqual(gotPorts, wantPorts) {
		t.Fatalf("desired publications = %+v, %v", gotPorts, err)
	}
	back, err := ComposeResourceChanges(proposed, current, []string{"app"})
	if err != nil || len(back) != 1 || back[0].Before != want[0].After || back[0].After != want[0].Before {
		t.Fatalf("reverse changes = %+v, %v", back, err)
	}
}

func TestComposePortPreflightIncludesOnlyNewFixedBindings(t *testing.T) {
	current := decodeComposeResourceTest(t, `{"services":{"app":{"image":"app:old","ports":[{"target":8070,"published":"18021"},{"target":8081,"published":"9000","protocol":"udp"}]}}}`)
	proposed := decodeComposeResourceTest(t, `{"services":{"app":{"image":"app:new","ports":[{"target":8070,"published":"8070"},{"target":8081,"published":"9000","protocol":"udp"}]}}}`)
	want := []PublishedPortBinding{{Component: "app", Published: 8070, Target: 8070, Protocol: "tcp"}}
	got, err := ComposeChangedPublishedPorts(current, proposed, []string{"app"})
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("desired publications = %+v, %v", got, err)
	}
}

func TestComposePublishedPortChangeRejectsUnsafeBindings(t *testing.T) {
	base := `{"services":{"app":{"ports":[{"target":8070,"published":"18021","host_ip":"127.0.0.1"}]},"db":{"ports":[{"target":5432,"published":"8070","host_ip":"127.0.0.1"}]}}}`
	for _, tt := range []struct {
		name    string
		change  func(map[string]any, map[string]any, map[string]any)
		message string
	}{
		{"implicit wildcard conflicts with dependency", func(_, _, port map[string]any) {
			port["published"] = "8070"
			delete(port, "host_ip")
		}, "conflicting publication"},
		{"bad bind address", func(_, _, port map[string]any) { port["host_ip"] = "host.example" }, "invalid publication address"},
		{"changes internal port", func(_, _, port map[string]any) { port["target"] = 8071 }, "must keep existing container ports"},
		{"changes transport", func(_, _, port map[string]any) { port["protocol"] = "udp" }, "must keep existing container ports"},
		{"uses dynamic range", func(_, _, port map[string]any) { port["published"] = "8070-8080" }, "must keep existing container ports"},
		{"removes the fixed mapping", func(_, app, _ map[string]any) { delete(app, "ports") }, "must keep existing container ports"},
		{"changes dependency publication", func(services, _, _ map[string]any) {
			services["db"].(map[string]any)["ports"] = []any{}
		}, "non-target Compose component"},
		{"adds unsupported mode", func(_, _, port map[string]any) { port["mode"] = "host" }, "unsupported publication settings"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			current := decodeComposeResourceTest(t, base)
			proposed := decodeComposeResourceTest(t, base)
			services := proposed["services"].(map[string]any)
			app := services["app"].(map[string]any)
			port := app["ports"].([]any)[0].(map[string]any)
			tt.change(services, app, port)
			if _, err := ComposeResourceChanges(current, proposed, []string{"app"}); err == nil || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("error = %v, want %q", err, tt.message)
			}
		})
	}
}

func TestPublishedPortOverlap(t *testing.T) {
	for _, tt := range []struct {
		left, right string
		otherProto  string
		overlap     bool
	}{
		{"", "::1", "tcp", true},
		{"", "127.0.0.1", "tcp", true},
		{"0.0.0.0", "127.0.0.1", "tcp", true},
		{"::", "::1", "tcp", true},
		{"::", "127.0.0.1", "tcp", false},
		{"127.0.0.1", "127.0.0.2", "tcp", false},
		{"127.0.0.1", "127.0.0.1", "udp", false},
	} {
		left, _ := netip.ParseAddr(tt.left)
		right, _ := netip.ParseAddr(tt.right)
		a := PublishedPortBinding{HostIP: left, Published: 8070, Target: 1, Protocol: "tcp"}
		b := PublishedPortBinding{HostIP: right, Published: 8070, Target: 2, Protocol: tt.otherProto}
		if a.Overlaps(b) != tt.overlap || b.Overlaps(a) != tt.overlap {
			t.Errorf("%s/tcp vs %s/%s overlap, want %v", tt.left, tt.right, tt.otherProto, tt.overlap)
		}
	}
}
