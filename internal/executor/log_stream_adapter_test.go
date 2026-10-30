package executor

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"github.com/moby/moby/client"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type logRoundTrip func(*http.Request) (*http.Response, error)

func (f logRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestStructuredLogsMergeApprovedContainersRespectDriverAndFollowRecreation(t *testing.T) {
	f := newPlanningFixture(t)
	s := f.s
	s.PolicyRevision = 2
	s.Containers = append(s.Containers, domain.ContainerRef{Component: "db", ID: strings.Repeat("b", 64), ImageID: domain.Hash([]byte("db-image")), Role: domain.RoleDatabase})
	proposal, err := f.m.Store.CreateProposal(t.Context(), "logs-policy", s, domain.Hash([]byte("configuration")), "admin", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.m.Store.ApproveProposal(t.Context(), proposal.ID, proposal.Digest, "admin", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	appID := s.Containers[0].ID
	dbID := s.Containers[1].ID
	dbDriver := "json-file"
	reads := 0
	api, err := client.New(client.WithHost("http://docker.invalid"), client.WithAPIVersion("1.56"), client.WithHTTPClient(&http.Client{Transport: logRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" {
			t.Fatalf("log view performed mutation: %s", r.Method)
		}
		var body []byte
		switch {
		case strings.HasSuffix(r.URL.Path, "/containers/json"):
			if !strings.Contains(r.URL.Query().Get("filters"), "flags") {
				t.Fatal("project filter lost")
			}
			body, _ = json.Marshal([]map[string]any{{"Id": appID, "Labels": map[string]string{"com.docker.compose.project": "flags", "com.docker.compose.service": "app"}}, {"Id": dbID, "Labels": map[string]string{"com.docker.compose.project": "flags", "com.docker.compose.service": "db"}}})
		case strings.Contains(r.URL.Path, "/containers/") && strings.HasSuffix(r.URL.Path, "/json"):
			id, component, image, driver := appID, "app", s.Containers[0].ImageID, "json-file"
			if strings.Contains(r.URL.Path, dbID) {
				id, component, image, driver = dbID, "db", s.Containers[1].ImageID, dbDriver
			}
			body, _ = json.Marshal(map[string]any{"Id": id, "Image": image, "State": map[string]any{"Status": "running"}, "Config": map[string]any{"Labels": map[string]string{"com.docker.compose.project": "flags", "com.docker.compose.service": component}}, "HostConfig": map[string]any{"LogConfig": map[string]string{"Type": driver}}})
		case strings.Contains(r.URL.Path, "/images/"):
			body = []byte(`{"Id":"` + string(s.Containers[0].ImageID) + `","Config":{}}`)
		case strings.HasSuffix(r.URL.Path, "/logs"):
			reads++
			if r.URL.Query().Get("timestamps") != "1" || r.URL.Query().Get("tail") != "200" {
				t.Fatalf("unbounded/untimestamped log request: %s", r.URL.RawQuery)
			}
			var data bytes.Buffer
			frame := func(stream byte, text string) {
				header := make([]byte, 8)
				header[0] = stream
				binary.BigEndian.PutUint32(header[4:], uint32(len(text)))
				data.Write(header)
				data.WriteString(text)
			}
			frame(1, "2026-10-19T00:00:00Z first\n")
			frame(2, "2026-10-19T00:00:01Z error\n")
			body = data.Bytes()
		default:
			t.Fatalf("unexpected daemon read %s", r.URL.Path)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(body))}, nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	f.m.Engine = &docker.Engine{Client: api}
	first, err := f.m.LogRecords(t.Context(), s.ID, transport.LogQuery{Component: "*", Tail: 200})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Records) != 4 || len(first.Sources) != 2 || reads != 2 {
		t.Fatalf("merged logs lost component or stream: %+v", first)
	}
	dbDriver = "none"
	appID = strings.Repeat("c", 64)
	second, err := f.m.LogRecords(t.Context(), s.ID, transport.LogQuery{Component: "*", Tail: 200})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Records) != 2 || second.Records[0].ContainerID != appID || reads != 3 {
		t.Fatalf("replacement/driver handling failed: %+v", second)
	}
	for _, record := range first.Records {
		if record.ID == second.Records[0].ID {
			t.Fatal("recreated container shares record identity")
		}
	}
	for _, source := range second.Sources {
		if source.Component == "db" && (source.Driver != "none" || source.Error == "") {
			t.Fatal("logging driver limitation hidden")
		}
	}
	if _, err = f.m.LogRecords(t.Context(), s.ID, transport.LogQuery{Component: "foreign", Tail: 200}); err == nil {
		t.Fatal("unregistered component logs exposed")
	}
}
