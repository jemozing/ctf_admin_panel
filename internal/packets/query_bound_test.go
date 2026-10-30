package packets

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestLargeCandidatePageBound(t *testing.T) {
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, func(c *Config) { c.QuotaBytes = 32 << 20; c.PerServiceBytes = 8 << 20 })
	candidates := make([]Candidate, 256)
	for i := range candidates {
		candidates[i] = Candidate{fmt.Sprintf("svc-%03d-", i) + strings.Repeat("s", 110), strings.Repeat("c", 120)}
	}
	for i := 0; i < 35; i++ {
		r := fixture(now, fmt.Sprintf("wide-%d", i))
		r.Data = nil
		r.CapturedLength = 0
		r.Truncated = true
		r.NotCapturedReason = "metadata_only"
		r.Attribution = "ambiguous"
		r.ServiceID = ""
		r.Component = ""
		r.Candidates = candidates
		mustIngest(t, s, r)
	}
	p, err := s.List(context.Background(), Query{Limit: 200})
	if err != nil || !p.HasMore || len(p.Records) == 0 || len(p.Records) >= 35 || p.NextCursor == "" {
		t.Fatalf("unbounded large metadata page: count=%d more=%v err=%v", len(p.Records), p.HasMore, err)
	}
	next, err := s.List(context.Background(), Query{Limit: 200, Cursor: p.NextCursor})
	if err != nil || len(p.Records)+len(next.Records) != 35 {
		t.Fatalf("bounded page skipped packets: %v", err)
	}
}
