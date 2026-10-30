package executor

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/moby/moby/client"
)

type retentionRoundTrip func(*http.Request) (*http.Response, error)

func (f retentionRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestImageRetirementDeletesOnlyExactOwnedTagWithoutForceOrPrune(t *testing.T) {
	for _, retargeted := range []bool{false, true} {
		t.Run(map[bool]string{false: "owned", true: "externally_retargeted"}[retargeted], func(t *testing.T) {
			f := newPlanningFixture(t)
			s := retentionSnapshot(t, f, "retired-image-tree", domain.SnapshotCandidate, time.Now().Add(-48*time.Hour))
			r := retentionRelease(t, f, s, "retired-image-release", time.Now().Add(-48*time.Hour))
			spec := r.Spec()
			if err := f.m.Store.PutImmutable(t.Context(), "retired_release", spec.ID, f.s.ID, retirement{spec.ID, time.Now(), "test"}); err != nil {
				t.Fatal(err)
			}
			removed := 0
			tag := spec.Images[0].RetentionTag
			imageID := string(spec.Images[0].ImageID)
			if retargeted {
				imageID = string(domain.Hash([]byte("another-image")))
			}
			api, err := client.New(client.WithHost("http://daemon.test"), client.WithAPIVersion("1.56"), client.WithHTTPClient(&http.Client{Transport: retentionRoundTrip(func(req *http.Request) (*http.Response, error) {
				body := ""
				status := 200
				switch req.Method {
				case http.MethodGet:
					if !strings.HasSuffix(req.URL.Path, "/images/"+tag+"/json") {
						t.Fatalf("unexpected inspect: %s", req.URL.Path)
					}
					body = `{"Id":"` + imageID + `"}`
				case http.MethodDelete:
					removed++
					if !strings.HasSuffix(req.URL.Path, "/images/"+tag) || req.URL.Query().Get("force") != "" || req.URL.Query().Get("noprune") != "1" {
						t.Fatalf("unsafe image deletion: %s", req.URL)
					}
					body = `[{"Untagged":"` + tag + `"}]`
				default:
					t.Fatalf("unexpected daemon operation %s %s", req.Method, req.URL)
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}))
			if err != nil {
				t.Fatal(err)
			}
			defer api.Close()
			f.m.Engine = &docker.Engine{Client: api}
			err = f.m.cleanupRetiredImageTags(t.Context())
			if retargeted {
				if err == nil || removed != 0 {
					t.Fatalf("externally retargeted image removed: %v/%d", err, removed)
				}
			} else {
				if err != nil || removed != 1 {
					t.Fatalf("expected exact untag: %v/%d", err, removed)
				}
				if err := f.m.cleanupRetiredImageTags(t.Context()); err != nil || removed != 1 {
					t.Fatal("image GC was not idempotent", err, removed)
				}
			}
		})
	}
}
