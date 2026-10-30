package packets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/flows"
)

// FlowPage contains metadata only. Query freezes the capture end/cursor for a
// subsequent sensitive detail request, rather than silently changing a window.
type FlowPage struct {
	Flows          []flows.Metadata `json:"flows"`
	Epoch          string           `json:"epoch"`
	ScannedPackets int              `json:"scanned_packets"`
	ScannedBytes   int              `json:"scanned_bytes"`
	Truncated      bool             `json:"truncated"`
	Gap            bool             `json:"gap"`
	Reasons        []string         `json:"reasons"`
	Query          Query            `json:"query"`
	SnapshotCursor string           `json:"snapshot_cursor"`
}
type FlowDetailRequest struct {
	Query  Query  `json:"query"`
	FlowID string `json:"flow_id"`
}

var flowAnalysisSlots = make(chan struct{}, 2)
var ErrFlowBusy = errors.New("flow analysis capacity exhausted")

type flowScan struct {
	packets        []flows.Packet
	original       map[string]Metadata
	query          Query
	epoch          string
	gap, truncated bool
	bytes          int
	reasons        []string
}

func (s *Store) readFlowWindow(ctx context.Context, q Query) (flowScan, error) {
	if err := ctx.Err(); err != nil {
		return flowScan{}, err
	}
	wait := time.NewTicker(5 * time.Millisecond)
	defer wait.Stop()
	for !s.mu.TryLock() {
		select {
		case <-ctx.Done():
			return flowScan{}, ctx.Err()
		case <-wait.C:
		}
	}
	defer s.mu.Unlock()
	result := flowScan{packets: []flows.Packet{}, original: map[string]Metadata{}, query: q, epoch: s.epoch, reasons: []string{}}
	if s.closed {
		return result, errors.New("packet archive closed")
	}
	if q.Limit < 0 || q.Limit > 200 {
		return result, errors.New("flow list limit must be 1..200")
	}
	now := s.config.Now().UTC()
	if q.From == "" {
		q.From = now.Add(-s.config.Retention).Format(time.RFC3339Nano)
	}
	if q.Until == "" {
		q.Until = now.Format(time.RFC3339Nano)
	}
	// Direction/individual port filters select conversations by an observed
	// matching packet. They must not drop the opposite direction before assembly.
	broad := q
	broad.Direction = ""
	broad.SourcePort = 0
	broad.DestinationPort = 0
	where, args, err := querySQL(broad)
	if err != nil {
		return result, err
	}
	if _, _, err = querySQL(q); err != nil {
		return result, err
	}
	where = append(where, "p.at>=?")
	args = append(args, now.Add(-s.config.Retention).UnixNano())
	var maxSeq, retired int64
	if err = s.db.QueryRowContext(ctx, "SELECT value FROM packet_meta WHERE key='sequence'").Scan(&maxSeq); err != nil {
		return result, err
	}
	if err = s.db.QueryRowContext(ctx, "SELECT value FROM packet_meta WHERE key='retired'").Scan(&retired); err != nil {
		return result, err
	}
	cur := cursor{s.epoch, maxSeq + 1, "before"}
	if q.Cursor != "" {
		cur, err = parseCursor(q.Cursor)
		if err != nil {
			return result, err
		}
		if cur.Epoch != s.epoch {
			result.gap = true
			result.reasons = append(result.reasons, "archive_epoch_changed")
			cur = cursor{s.epoch, maxSeq + 1, "before"}
		}
	}
	comparison := "<"
	if cur.Direction == "after" {
		comparison = ">"
	}
	where = append(where, "p.sequence"+comparison+"?")
	args = append(args, cur.Sequence, flows.MaxPackets+1)
	if retired > 0 {
		result.gap = true
		result.reasons = append(result.reasons, "archive_rotation_may_have_removed_packets")
	}
	q.Cursor = s.cursor(cur.Sequence, cur.Direction)
	result.query = q
	rows, err := s.db.QueryContext(ctx, "SELECT p.metadata,p.payload FROM packets p WHERE "+strings.Join(where, " AND ")+" ORDER BY p.sequence DESC LIMIT ?", args...)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		var meta, data []byte
		if err = rows.Scan(&meta, &data); err != nil {
			return result, err
		}
		if len(result.packets) >= flows.MaxPackets || result.bytes+len(meta)+len(data) > flows.MaxBytes {
			result.truncated = true
			result.gap = true
			result.reasons = append(result.reasons, "archive_scan_budget_reached")
			break
		}
		var m Metadata
		if err = json.Unmarshal(meta, &m); err != nil {
			return result, err
		}
		result.bytes += len(meta) + len(data)
		result.original[m.PacketID] = m
		p := flows.Packet{ID: m.PacketID, Sequence: m.Sequence, At: m.At, CollectorEpoch: m.CollectorEpoch, PolicyRevision: m.PolicyRevision, Interface: m.Interface, IfIndex: m.IfIndex, ServiceID: m.ServiceID, Component: m.Component, Protocol: m.Protocol, SourceIP: m.SourceIP, DestinationIP: m.DestinationIP, SourcePort: m.SourcePort, DestinationPort: m.DestinationPort, TCPFlags: m.TCPFlags, WireLength: m.WireLength, CapturedLength: m.CapturedLength, Truncated: m.Truncated, Data: data}
		for _, v := range m.Candidates {
			p.Candidates = append(p.Candidates, flows.Candidate{ServiceID: v.ServiceID, Component: v.Component})
		}
		for _, v := range m.VersionBindings {
			p.VersionBindings = append(p.VersionBindings, flows.VersionBinding{ServiceID: v.ServiceID, Component: v.Component, ReleaseID: v.ReleaseID, SourceDigest: v.SourceDigest})
		}
		result.packets = append(result.packets, p)
	}
	if err = rows.Err(); err != nil {
		return result, err
	}
	sort.Slice(result.packets, func(i, j int) bool { return result.packets[i].Sequence < result.packets[j].Sequence })
	return result, nil
}
func (s *Store) flowSnapshot(ctx context.Context, q Query) (flows.Snapshot, flowScan, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	select {
	case flowAnalysisSlots <- struct{}{}:
		defer func() { <-flowAnalysisSlots }()
	case <-ctx.Done():
		return flows.Snapshot{}, flowScan{}, ctx.Err()
	default:
		return flows.Snapshot{}, flowScan{}, ErrFlowBusy
	}
	scan, err := s.readFlowWindow(ctx, q)
	if err != nil {
		return flows.Snapshot{}, scan, err
	}
	snapshot, err := flows.Analyze(ctx, scan.packets, flows.Options{})
	if err != nil {
		return snapshot, scan, err
	}
	if q.Direction != "" || q.SourcePort > 0 || q.DestinationPort > 0 {
		filtered := []flows.Detail{}
		for _, detail := range snapshot.Details {
			matched := false
			for _, id := range detail.PacketIDs {
				m := scan.original[id]
				if (q.Direction == "" || q.Direction == m.Direction) && (q.SourcePort == 0 || q.SourcePort == m.SourcePort) && (q.DestinationPort == 0 || q.DestinationPort == m.DestinationPort) {
					matched = true
					break
				}
			}
			if matched {
				filtered = append(filtered, detail)
			}
		}
		snapshot.Details = filtered
		snapshot.Flows = []flows.Metadata{}
		for _, d := range filtered {
			snapshot.Flows = append(snapshot.Flows, d.Metadata)
		}
	}
	if scan.gap || scan.truncated || snapshot.Truncated {
		for n := range snapshot.Details {
			snapshot.Details[n].Incomplete = true
			snapshot.Details[n].Reasons = append(snapshot.Details[n].Reasons, "archive_window_incomplete")
			snapshot.Flows[n] = snapshot.Details[n].Metadata
		}
	}
	return snapshot, scan, nil
}
func (s *Store) FlowList(ctx context.Context, q Query) (FlowPage, error) {
	snapshot, scan, err := s.flowSnapshot(ctx, q)
	if err != nil {
		return FlowPage{}, err
	}
	page := FlowPage{Flows: []flows.Metadata{}, Epoch: scan.epoch, ScannedPackets: snapshot.ScannedPackets, ScannedBytes: scan.bytes, Truncated: scan.truncated || snapshot.Truncated, Gap: scan.gap, Reasons: append(scan.reasons, snapshot.Reasons...), Query: scan.query, SnapshotCursor: scan.query.Cursor}
	limit := q.Limit
	if limit == 0 {
		limit = 50
	}
	size := 0
	for _, m := range snapshot.Flows {
		raw, _ := json.Marshal(m)
		if len(page.Flows) >= limit || size+len(raw) > 2<<20 {
			page.Truncated = true
			page.Reasons = append(page.Reasons, "flow_metadata_page_limit")
			break
		}
		page.Flows = append(page.Flows, m)
		size += len(raw)
	}
	return page, nil
}
func (s *Store) FlowDetail(ctx context.Context, q FlowDetailRequest) (flows.Detail, error) {
	if !validID(q.FlowID) || !strings.HasPrefix(q.FlowID, "flow-") {
		return flows.Detail{}, errors.New("invalid flow ID")
	}
	snapshot, _, err := s.flowSnapshot(ctx, q.Query)
	if err != nil {
		return flows.Detail{}, err
	}
	if detail, ok := snapshot.Detail(q.FlowID); ok {
		return detail, nil
	}
	return flows.Detail{}, ErrNotFound
}
func (s *Store) flowHTTP(w http.ResponseWriter, r *http.Request) bool {
	switch {
	case r.URL.Path == "/v1/flows" && r.Method == http.MethodGet:
		q, err := ParseRawQuery(r.URL.RawQuery)
		if err != nil {
			httpError(w, 400, "invalid_flow_query")
			return true
		}
		page, err := s.FlowList(r.Context(), q)
		if errors.Is(err, ErrFlowBusy) || errors.Is(err, context.DeadlineExceeded) {
			httpError(w, 503, "flow_analysis_busy_or_timeout")
			return true
		}
		if err != nil {
			httpError(w, 400, "invalid_flow_query_or_analysis_unavailable")
			return true
		}
		respond(w, 200, page)
		return true
	case r.URL.Path == "/v1/flows/detail" && r.Method == http.MethodPost:
		var q FlowDetailRequest
		if decodeBody(w, r, &q, 16<<10) != nil {
			httpError(w, 400, "invalid_flow_detail")
			return true
		}
		detail, err := s.FlowDetail(r.Context(), q)
		if errors.Is(err, ErrFlowBusy) || errors.Is(err, context.DeadlineExceeded) {
			httpError(w, 503, "flow_analysis_busy_or_timeout")
			return true
		}
		if errors.Is(err, ErrNotFound) {
			httpError(w, 404, "not_found")
			return true
		}
		if err != nil {
			httpError(w, 400, "invalid_flow_query_or_analysis_unavailable")
			return true
		}
		respond(w, 200, detail)
		return true
	}
	return false
}
func (c *Client) FlowList(ctx context.Context, q Query) (FlowPage, error) {
	var out FlowPage
	values := QueryValues(q)
	if _, err := ParseQuery(values); err != nil {
		return out, err
	}
	path := "/v1/flows"
	if len(values) > 0 {
		path += "?" + values.Encode()
	}
	err := c.request(ctx, http.MethodGet, path, nil, &out, 200)
	return out, err
}
func (c *Client) FlowDetail(ctx context.Context, q FlowDetailRequest) (flows.Detail, error) {
	var out flows.Detail
	if !validID(q.FlowID) {
		return out, fmt.Errorf("invalid flow ID")
	}
	err := c.request(ctx, http.MethodPost, "/v1/flows/detail", q, &out, 200)
	return out, err
}
