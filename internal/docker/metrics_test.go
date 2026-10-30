package docker

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/moby/moby/client"
)

type metricsRoundTrip func(*http.Request) (*http.Response, error)

func (f metricsRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMetricsInventoryOnlyInspectsApprovedIDsAndNoRuntimeApproval(t *testing.T) {
	calls := 0
	wrongProject := false
	api, err := client.New(client.WithHost("http://docker.invalid"), client.WithAPIVersion("1.56"), client.WithHTTPClient(&http.Client{Transport: metricsRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/containers/approved/json") {
			t.Fatalf("unexpected metric daemon action %s %s", r.Method, r.URL.Path)
		}
		project := "game"
		if wrongProject {
			project = "foreign"
		}
		body := `{"Id":"approved","RestartCount":2,"State":{"Status":"running","OOMKilled":false},"Config":{"Labels":{"com.docker.compose.project":"` + project + `","com.docker.compose.service":"app"}},"HostConfig":{"NanoCpus":500000000,"PidsLimit":32}}`
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	e := &Engine{Client: api}
	items, err := e.MetricsInventory(context.Background(), "game", []string{"approved"})
	if err != nil || len(items) != 1 || items[0].RestartCount == nil || *items[0].RestartCount != 2 || items[0].CPULimitPercent == nil || *items[0].CPULimitPercent != 50 || items[0].OOMKilled == nil || *items[0].OOMKilled || items[0].PidsLimit == nil || *items[0].PidsLimit != 32 {
		t.Fatalf("metric mapping %+v %v", items, err)
	}
	wrongProject = true
	if _, err = e.MetricsInventory(context.Background(), "game", []string{"approved"}); err == nil {
		t.Fatal("crossproject statistics accepted")
	}
	if calls != 2 {
		t.Fatal("metrics triggered extraimage/network/volume API")
	}
}
