package docker

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/moby/moby/client"
)

func TestLoopbackTCPPortReservedUsesOnlyActiveDockerPortEvidence(t *testing.T) {
	for _, tt := range []struct {
		name, status, configured, observed string
		reserved, failed                   bool
	}{
		{"missing image does not prevent a free port", "running", `{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"29081"}]}`, `{}`, false, false},
		{"implicit Docker wildcard is reserved", "running", `{"80/tcp":[{"HostIp":"","HostPort":"29080"}]}`, `{}`, true, false},
		{"IPv6 wildcard is reserved while paused", "paused", `{"80/tcp":[{"HostIp":"::","HostPort":"29080"}]}`, `{}`, true, false},
		{"configured TCP range is reserved while restarting", "restarting", `{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"29075-29085"}]}`, `{}`, true, false},
		{"Docker NAT reservation after a dynamic allocation", "running", `{"80/tcp":[{"HostIp":"","HostPort":"0"}]}`, `{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"29080"}]}`, true, false},
		{"other protocols and explicit non-loopback addresses do not conflict", "running", `{"80/udp":[{"HostIp":"0.0.0.0","HostPort":"29080"}],"80/tcp":[{"HostIp":"192.0.2.2","HostPort":"29080"}]}`, `{}`, false, false},
		{"container stopped after list", "exited", `{"80/tcp":[{"HostIp":"","HostPort":"29080"}]}`, `{}`, false, false},
		{"malformed relevant binding fails closed", "running", `{"80/tcp":[{"HostIp":"","HostPort":"invalid"}]}`, `{}`, false, true},
		{"container disappeared after list fails closed", "", "", "", false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			api, err := client.New(client.WithHost("http://docker.invalid"), client.WithAPIVersion("1.56"), client.WithHTTPClient(&http.Client{Transport: metricsRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				var body string
				status := http.StatusOK
				switch {
				case strings.HasSuffix(r.URL.Path, "/containers/json"):
					var filters client.Filters
					if err := json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters); err != nil || len(filters["status"]) != 3 || !filters["status"]["running"] || !filters["status"]["paused"] || !filters["status"]["restarting"] {
						t.Fatalf("unexpected container status filters: %v %v", filters, err)
					}
					body = `[{"Id":"unrelated","State":"running"}]`
				case strings.HasSuffix(r.URL.Path, "/containers/unrelated/json"):
					if tt.status == "" {
						body, status = `{"message":"no such container"}`, http.StatusNotFound
						break
					}
					body = `{"Id":"unrelated","Image":"sha256:unavailable","State":{"Status":"` + tt.status + `"},"HostConfig":{"PortBindings":` + tt.configured + `},"NetworkSettings":{"Ports":` + tt.observed + `}}`
				default:
					t.Fatalf("port check requested unrelated Docker evidence: %s", r.URL.Path)
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}))
			if err != nil {
				t.Fatal(err)
			}
			defer api.Close()
			reserved, err := (&Engine{Client: api}).LoopbackTCPPortReserved(t.Context(), []int{29080})
			if (err != nil) != tt.failed || reserved != tt.reserved || calls != 2 {
				t.Fatalf("reserved=%v err=%v Docker requests=%d", reserved, err, calls)
			}
		})
	}
}
