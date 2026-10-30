package transport

import (
	"context"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"strings"
	"testing"
)

func TestLogQueryUsesBoundedRE2AndTypedTimeSelectors(t *testing.T) {
	for _, raw := range []string{"", "component=*&tail=500&include=error%7Cwarn&since=2026-10-19T00%3A00%3A00Z", "component=app&tail=1&exclude=debug"} {
		if _, err := ParseLogQuery(raw); err != nil {
			t.Fatalf("valid %s: %v", raw, err)
		}
	}
	for _, raw := range []string{"component=../../etc", "component=app&tail=0", "component=app&tail=501", "component=app&tail=1&command=id", "component=app&tail=1&tail=2", "include=%28%3Fa%29", "include=" + strings.Repeat("x", 257), "since=yesterday", "since=2026-10-19T00%3A00%3A00Z&until=2026-10-18T00%3A00%3A00Z", "component=%zz"} {
		if _, err := ParseLogQuery(raw); err == nil {
			t.Errorf("unsafe query accepted: %s", raw)
		}
	}
}

type extendedDetailsBackend struct {
	detailTestBackend
	records int
	files   int
	query   LogQuery
}

func (b *extendedDetailsBackend) LogRecords(_ context.Context, _ domain.ID, q LogQuery) (LogPage, error) {
	b.records++
	b.query = q
	return LogPage{Records: []LogRecord{}, Sources: []LogSource{}}, nil
}
func (b *extendedDetailsBackend) Files(_ context.Context, _ domain.ID, _ FilesQuery) (FilesResult, error) {
	b.files++
	return FilesResult{}, nil
}
func TestFilesQueryRejectsTraversalCrossTargetAndUnknownFields(t *testing.T) {
	for _, raw := range []string{"comparison=candidate", "comparison=release&release_id=rel-good&path=app%2Fmain.py", "comparison=drift"} {
		if _, err := ParseFilesQuery(raw); err != nil {
			t.Fatal(raw, err)
		}
	}
	for _, raw := range []string{"comparison=release", "comparison=candidate&release_id=rel-good", "comparison=workspace&path=..%2F.env", "comparison=drift&path=%2Fetc%2Fpasswd", "comparison=release&release_id=rel-good&root=/", "comparison=candidate&path=a&path=b"} {
		if _, err := ParseFilesQuery(raw); err == nil {
			t.Errorf("invalid file selector accepted: %s", raw)
		}
	}
}
