package transport

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

type gitTestBackend struct {
	testBackend
	writes atomic.Int32
}

func (*gitTestBackend) GitSource(context.Context, domain.ID) (GitSourceView, error) {
	return GitSourceView{Configured: true, URL: "https://github.com/SibirCTF/ncdex.git", Ref: "HEAD", Revision: 1, HasCredentials: true}, nil
}
func (b *gitTestBackend) ConfigureGitSource(_ context.Context, _ domain.ID, r GitSourceRequest) (GitSourceView, error) {
	b.writes.Add(1)
	return GitSourceView{Configured: true, URL: r.URL, Ref: r.Ref, Revision: 2, HasCredentials: r.Token != ""}, nil
}
func TestTypedGitSourceEndpointRejectsUnsafeTransportAndArbitraryInputs(t *testing.T) {
	b := &gitTestBackend{}
	_, c := runServer(t, Options{Backend: b})
	v, err := c.GitSource(t.Context(), "game")
	if err != nil || !v.HasCredentials {
		t.Fatalf("source metadata %#v %v", v, err)
	}
	v, err = c.ConfigureGitSource(t.Context(), "game", GitSourceRequest{URL: v.URL, Ref: "HEAD", Token: "private"})
	if err != nil || v.Revision != 2 {
		t.Fatalf("save source %#v %v", v, err)
	}
	for _, body := range []string{
		`{"url":"file:///tmp/repo","ref":"HEAD"}`,
		`{"url":"https://github.com/x/y.git","ref":"HEAD","command":"id"}`,
		`{"url":"https://user:secret@github.com/x/y.git","ref":"HEAD"}`,
		`{"url":"https://github.com/x/y.git","ref":"HEAD"} {}`,
	} {
		r, _ := http.NewRequest("POST", "http://executor/v1/services/game/source", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		response, err := c.http.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 400 {
			t.Fatalf("unsafe source accepted: %d", response.StatusCode)
		}
	}
	if b.writes.Load() != 1 {
		t.Fatal("invalid input reached executor backend")
	}
}
