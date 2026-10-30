package executor

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/secrets"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"github.com/moby/moby/client"
)

func dockerTimeQuery(raw string) string {
	if raw == "" {
		return ""
	}
	stamp, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return raw
	}
	return fmt.Sprintf("%d.%09d", stamp.Unix(), stamp.Nanosecond())
}

func dockerLogFrame(stream byte, text string) []byte {
	header := make([]byte, 8)
	header[0] = stream
	binary.BigEndian.PutUint32(header[4:], uint32(len(text)))
	return append(header, []byte(text)...)
}

func TestLogRecordsLongLinesFiltersAndMalformedFramesRemainBounded(t *testing.T) {
	f := newPlanningFixture(t)
	vault, err := secrets.Open(filepath.Join(f.m.Config.StateDirectory, "log-test-vault"))
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()
	f.m.Vault = vault
	const private = "CTF_TEST_SECRET_ALPHABET_0123456789"
	ref, err := vault.Import("log-private", []byte(`{"PASSWORD":"`+private+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	s := f.s
	s.PolicyRevision++
	s.SecretVersions = []domain.SecretVersionRef{ref}
	proposal, err := f.m.Store.CreateProposal(t.Context(), "log-limits-policy", s, domain.Hash([]byte("configuration")), "admin", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.m.Store.ApproveProposal(t.Context(), proposal.ID, proposal.Digest, "admin", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var body []byte
	var selected transport.LogQuery
	api, err := client.New(client.WithHost("http://docker.invalid"), client.WithAPIVersion("1.56"), client.WithHTTPClient(&http.Client{Transport: logRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" {
			t.Fatal("log observation performed a mutation")
		}
		var response []byte
		switch {
		case strings.HasSuffix(r.URL.Path, "/containers/json"):
			response, _ = json.Marshal([]map[string]any{{"Id": s.Containers[0].ID, "Labels": map[string]string{"com.docker.compose.project": s.ComposeProject, "com.docker.compose.service": "app"}}})
		case strings.Contains(r.URL.Path, "/containers/") && strings.HasSuffix(r.URL.Path, "/json"):
			response, _ = json.Marshal(map[string]any{"Id": s.Containers[0].ID, "Image": s.Containers[0].ImageID, "Config": map[string]any{}, "HostConfig": map[string]any{"LogConfig": map[string]string{"Type": "json-file"}}})
		case strings.Contains(r.URL.Path, "/images/"):
			response = []byte(`{"Id":"` + string(s.Containers[0].ImageID) + `","Config":{}}`)
		case strings.HasSuffix(r.URL.Path, "/logs"):
			q := r.URL.Query()
			if q.Get("since") != dockerTimeQuery(selected.Since) || q.Get("until") != dockerTimeQuery(selected.Until) || q.Get("timestamps") != "1" || q.Get("include") != "" || q.Get("search") != "" {
				t.Errorf("typed time/filter boundary changed: %s", r.URL.RawQuery)
			}
			response = body
		default:
			t.Fatalf("unexpected Docker request %s", r.URL.Path)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(response))}, nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	f.m.Engine = &docker.Engine{Client: api}
	timestamp := "2026-10-20T00:00:00.000000001Z "
	for _, test := range []struct {
		name       string
		payload    []byte
		query      transport.LogQuery
		records    int
		incomplete bool
	}{
		{"control expansion", dockerLogFrame(1, timestamp+strings.Repeat("\x1b", 20000)+"\n"), transport.LogQuery{Component: "*", Tail: 500}, 1, false},
		{"multibyte cap", dockerLogFrame(1, timestamp+strings.Repeat("界", 20000)+"\n"), transport.LogQuery{Component: "*", Tail: 500}, 1, false},
		{"private value crossing display boundary", dockerLogFrame(1, timestamp+strings.Repeat("x", 16380)+private+strings.Repeat("y", 20000)+"\n"), transport.LogQuery{Component: "*", Tail: 500}, 1, false},
		{"many newline records", dockerLogFrame(1, strings.Repeat("x\n", 100000)), transport.LogQuery{Component: "*", Tail: 500}, 500, true},
		{"bounded RE2 with literal text", append(dockerLogFrame(1, timestamp+"error KEEP\n"+timestamp+"error debug keep\n"+timestamp+"error other\n"), dockerLogFrame(2, timestamp+"ERROR keep <script>alert(1)</script>\n")...), transport.LogQuery{Component: "*", Tail: 500, Search: "keep", Include: "(?i)error", Exclude: "debug", Since: "2026-10-19T00:00:00Z", Until: "2026-10-21T00:00:00Z"}, 2, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			body, selected = test.payload, test.query
			page, err := f.m.LogRecords(t.Context(), s.ID, selected)
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Records) != test.records || test.incomplete && !page.Truncated {
				t.Fatalf("records/truncation mismatch: %d %v", len(page.Records), page.Truncated)
			}
			for _, record := range page.Records {
				if len(record.Text) > 16384 || !utf8.ValidString(record.Text) || strings.Contains(record.Text, "\x1b") || strings.Contains(record.Text, "CTF_TEST_SECRET") {
					t.Fatalf("unbounded/unsafe normalized line (%d bytes)", len(record.Text))
				}
			}
			encoded, err := json.Marshal(page)
			if err != nil || len(encoded) > 1<<20 {
				t.Fatal("bounded structured response exceeded 1 MiB", len(encoded), err)
			}
		})
	}
	// A truncated raw record can contain only a prefix of a private value, so it
	// must be dropped rather than sent through an exact-value redactor.
	header := make([]byte, 8)
	header[0] = 1
	binary.BigEndian.PutUint32(header[4:], 1<<20)
	body = append(header, []byte(timestamp+"complete\n"+timestamp+private[:14])...)
	selected = transport.LogQuery{Component: "*", Tail: 200}
	page, err := f.m.LogRecords(t.Context(), s.ID, selected)
	if err != nil || !page.Truncated || len(page.Records) != 1 || page.Records[0].Text != "complete" {
		t.Fatalf("partial secret line escaped incomplete-frame handling: %+v %v", page, err)
	}
	binary.BigEndian.PutUint32(header[4:], 0xffffffff)
	body = append(header, []byte("unused payload")...)
	page, err = f.m.LogRecords(t.Context(), s.ID, selected)
	if err != nil || !page.Truncated || len(page.Records) != 0 || len(page.Sources) != 1 || page.Sources[0].Error == "" {
		t.Fatalf("forged huge mux frame accepted: %+v %v", page, err)
	}
	// No observation or malformed frame modifies registered source files.
	data, err := os.ReadFile(f.activeFile)
	if err != nil || string(data) != "version = 1\n" {
		t.Fatal("log observation changed active files", err)
	}
}
