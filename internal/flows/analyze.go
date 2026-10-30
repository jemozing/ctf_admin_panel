package flows

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"time"
)

type assembly struct {
	detail     Detail
	dirs       [2]directionState
	last       time.Time
	candidates map[string]Candidate
	points     map[string]ObservationPoint
	packetIDs  map[string]bool
	versions   map[string]VersionBinding
}
type directionState struct {
	Direction
	baseKnown   bool
	synSequence uint32
	wireEnd     int64
	packetCount int
	reasons     []string
}

func normalizeOptions(o Options) (Options, error) {
	if o.MaxPackets == 0 {
		o.MaxPackets = MaxPackets
	}
	if o.MaxBytes == 0 {
		o.MaxBytes = MaxBytes
	}
	if o.MaxFlows == 0 {
		o.MaxFlows = MaxFlows
	}
	if o.MaxDirectionBytes == 0 {
		o.MaxDirectionBytes = MaxDirectionBytes
	}
	if o.IdleTimeout == 0 {
		o.IdleTimeout = 2 * time.Minute
	}
	if o.MaxPackets < 1 || o.MaxPackets > MaxPackets || o.MaxBytes < 1 || o.MaxBytes > MaxBytes || o.MaxFlows < 1 || o.MaxFlows > MaxFlows || o.MaxDirectionBytes < 1 || o.MaxDirectionBytes > MaxDirectionBytes || o.IdleTimeout < time.Second || o.IdleTimeout > time.Hour {
		return o, errors.New("invalid flow analysis bounds")
	}
	return o, nil
}

// Analyze consumes a chronological capture window. It never fills holes with
// fabricated bytes: missing intervals and conflicting overlaps remain explicit.
// TCP first-observed bytes win overlapping ranges; UDP observations are never
// deduplicated by content, even when two observation points saw one datagram.
func Analyze(ctx context.Context, packets []Packet, options Options) (Snapshot, error) {
	out := Snapshot{Flows: []Metadata{}, Details: []Detail{}, Reasons: []string{"capture_completeness_unknown"}}
	o, err := normalizeOptions(options)
	if err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	active := map[string]*assembly{}
	all := []*assembly{}
	// Record input order is the capture sequence, including out-of-order TCP.
	for index, p := range packets {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if index >= o.MaxPackets || out.ScannedBytes+packetCost(p) > o.MaxBytes {
			out.Truncated = true
			out.Reasons = add(out.Reasons, "scan_budget_reached")
			break
		}
		out.ScannedPackets++
		out.ScannedBytes += packetCost(p)
		a, b, from, scope, ok := packetScope(p)
		if !ok {
			out.Reasons = add(out.Reasons, "invalid_packet_metadata")
			continue
		}
		parsed, headers := parsePacket(p.Data)
		if headers && (parsed.protocol != p.Protocol || parsed.source.String() != canonicalIP(p.SourceIP) || parsed.destination.String() != canonicalIP(p.DestinationIP) || parsed.sourcePort != p.SourcePort || parsed.destinationPort != p.DestinationPort) {
			out.Reasons = add(out.Reasons, "packet_header_metadata_mismatch")
			continue
		}
		flags := p.TCPFlags
		if headers {
			flags = parsed.flags
		}
		f := active[scope]
		fresh := false
		idle := o.IdleTimeout
		if p.Protocol == "udp" && idle > 30*time.Second {
			idle = 30 * time.Second
		}
		if f == nil || p.At.Sub(f.last) > idle {
			fresh = true
		} else if p.Protocol == "tcp" {
			syn := flags&2 != 0 && flags&16 == 0
			if syn {
				d := &f.dirs[from]
				fresh = f.detail.Closed || !headers || !d.SYNSeen || d.synSequence != parsed.seq || f.dirs[0].WirePayloadBytes > 0 || f.dirs[1].WirePayloadBytes > 0
			}
			if f.detail.Closed && headers && len(parsed.payload) > 0 && !syn {
				fresh = true
			}
		}
		if fresh {
			if len(all) >= o.MaxFlows {
				out.Truncated = true
				out.Reasons = add(out.Reasons, "flow_budget_reached")
				continue
			}
			hash := sha256.Sum256([]byte(scope + "/" + p.ID))
			id := "flow-" + hex.EncodeToString(hash[:])
			f = &assembly{detail: Detail{Metadata: Metadata{ID: id, Protocol: p.Protocol, CollectorEpoch: p.CollectorEpoch, PolicyRevision: p.PolicyRevision, Interface: p.Interface, IfIndex: p.IfIndex, A: a, B: b, FirstAt: p.At, LastAt: p.At, Reasons: []string{}}, Directions: []Direction{}, Datagrams: []Datagram{}, PacketIDs: []string{}}, last: p.At, candidates: map[string]Candidate{}, points: map[string]ObservationPoint{}, packetIDs: map[string]bool{}, versions: map[string]VersionBinding{}}
			for n := range f.dirs {
				f.dirs[n].Direction = Direction{From: directionName(n), Chunks: []Chunk{}, Gaps: []Gap{}}
			}
			active[scope] = f
			all = append(all, f)
			if p.Protocol == "udp" {
				f.detail.Reasons = add(f.detail.Reasons, "udp_conversation_has_no_connection_guarantee")
			}
		}
		if p.At.Before(f.last) {
			f.detail.Incomplete = true
			f.detail.Reasons = add(f.detail.Reasons, "capture_timestamp_regressed")
		}
		if p.At.After(f.last) {
			f.last = p.At
		}
		if p.At.Before(f.detail.FirstAt) {
			f.detail.FirstAt = p.At
		}
		if p.At.After(f.detail.LastAt) {
			f.detail.LastAt = p.At
		}
		f.detail.PacketCount++
		for _, v := range p.VersionBindings {
			key := v.ServiceID + "/" + v.Component + "/" + v.ReleaseID + "/" + v.SourceDigest
			if len(f.versions) < 256 {
				f.versions[key] = v
			} else {
				f.detail.Incomplete = true
				f.detail.Reasons = add(f.detail.Reasons, "version_binding_budget_reached")
			}
		}
		pointKey := p.Interface + "/" + strconv.Itoa(p.IfIndex)
		f.points[pointKey] = ObservationPoint{p.Interface, p.IfIndex}
		if p.ServiceID != "" {
			f.addCandidate(Candidate{p.ServiceID, p.Component})
		}
		for _, v := range p.Candidates {
			f.addCandidate(v)
		}
		if !f.packetIDs[p.ID] {
			f.packetIDs[p.ID] = true
			f.detail.PacketIDs = append(f.detail.PacketIDs, p.ID)
		}
		if headers && len(parsed.payload) > 0 && len(p.VersionBindings) == 0 {
			f.detail.MissingVersionBindings = true
			f.detail.Reasons = add(f.detail.Reasons, "packet_version_binding_missing")
		}
		f.detail.Truncated = f.detail.Truncated || p.Truncated
		if !headers {
			f.detail.Incomplete = true
			f.detail.Reasons = add(f.detail.Reasons, "transport_header_not_captured")
		}
		if p.Protocol == "udp" {
			if len(f.detail.Datagrams) >= MaxDatagrams || f.detail.PayloadBytes+len(parsed.payload) > 2*MaxDirectionBytes {
				f.detail.Truncated = true
				f.detail.Incomplete = true
				f.detail.Reasons = add(f.detail.Reasons, "datagram_budget_reached")
				continue
			}
			d := Datagram{PacketID: p.ID, From: directionName(from), At: p.At, Data: []byte{}, PacketWireLength: p.WireLength, Truncated: !headers || p.Truncated, PayloadLengthKnown: headers}
			if headers {
				d.Data = append([]byte{}, parsed.payload...)
				d.WireLength = parsed.wirePayload
				d.CapturedLength = len(d.Data)
				d.Truncated = d.Truncated || len(d.Data) < d.WireLength
			}
			f.detail.PayloadBytes += len(d.Data)
			f.detail.Datagrams = append(f.detail.Datagrams, d)
			f.detail.Incomplete = f.detail.Incomplete || d.Truncated
			continue
		}
		d := &f.dirs[from]
		d.packetCount++
		if flags&1 != 0 {
			d.FINSeen = true
		}
		if flags&4 != 0 {
			f.detail.Reset = true
			f.detail.Closed = true
			f.detail.Reasons = add(f.detail.Reasons, "tcp_reset")
		}
		if f.dirs[0].FINSeen && f.dirs[1].FINSeen {
			f.detail.Closed = true
		}
		if !headers {
			d.Incomplete = true
			d.Truncated = true
			d.reasons = add(d.reasons, "transport_header_not_captured")
			continue
		}
		d.ingest(parsed, p.ID, o.MaxDirectionBytes)
		// A peer ACK can prove a tail was received even if its data packet was
		// lost from this capture. Infer only relative to an observed SYN; no
		// origin is guessed for midstream directions.
		other := &f.dirs[1-from]
		if flags&16 != 0 && other.SYNSeen {
			ackEnd := int64(int32(parsed.ack - other.StartSequence))
			if other.FINSeen && ackEnd > 0 {
				ackEnd--
			}
			if ackEnd > other.wireEnd {
				other.wireEnd = ackEnd
			}
		}
		if flags&4 != 0 {
			f.detail.Reset = true
			f.detail.Closed = true
			f.detail.Reasons = add(f.detail.Reasons, "tcp_reset")
		}
		if f.dirs[0].FINSeen && f.dirs[1].FINSeen {
			f.detail.Closed = true
		}
	}
	for _, f := range all {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		f.finish(o.MaxDirectionBytes)
		out.Flows = append(out.Flows, f.detail.Metadata)
		out.Details = append(out.Details, f.detail)
	}
	sort.Slice(out.Details, func(i, j int) bool {
		a, b := out.Details[i], out.Details[j]
		if !a.LastAt.Equal(b.LastAt) {
			return a.LastAt.After(b.LastAt)
		}
		return a.ID < b.ID
	})
	out.Flows = out.Flows[:0]
	for _, d := range out.Details {
		out.Flows = append(out.Flows, d.Metadata)
	}
	if out.Truncated {
		for n := range out.Details {
			out.Details[n].Incomplete = true
			out.Details[n].Truncated = true
			out.Details[n].Reasons = add(out.Details[n].Reasons, "analysis_window_truncated")
			out.Flows[n] = out.Details[n].Metadata
		}
	}
	return out, nil
}
func packetScope(p Packet) (Endpoint, Endpoint, int, string, bool) {
	src, e := netip.ParseAddr(p.SourceIP)
	dst, f := netip.ParseAddr(p.DestinationIP)
	if e != nil || f != nil || src.Zone() != "" || dst.Zone() != "" || (p.Protocol != "tcp" && p.Protocol != "udp") || p.SourcePort < 0 || p.SourcePort > 65535 || p.DestinationPort < 0 || p.DestinationPort > 65535 || len(p.ID) == 0 || len(p.ID) > 128 || len(p.CollectorEpoch) == 0 || len(p.CollectorEpoch) > 128 || p.PolicyRevision == 0 || len(p.Data) > 65535 {
		return Endpoint{}, Endpoint{}, 0, "", false
	}
	src = src.Unmap()
	dst = dst.Unmap()
	a, b := Endpoint{src.String(), p.SourcePort}, Endpoint{dst.String(), p.DestinationPort}
	from := 0
	if src.Compare(dst) > 0 || src == dst && p.SourcePort > p.DestinationPort {
		a, b = b, a
		from = 1
	}
	raw, _ := json.Marshal([]any{p.CollectorEpoch, p.PolicyRevision, p.Protocol, a, b})
	return a, b, from, string(raw), true
}
func canonicalIP(s string) string {
	a, e := netip.ParseAddr(s)
	if e != nil {
		return ""
	}
	return a.Unmap().String()
}
func directionName(n int) string {
	if n == 0 {
		return "a"
	}
	return "b"
}
func add(values []string, v string) []string {
	for _, old := range values {
		if old == v {
			return values
		}
	}
	return append(values, v)
}
func (d *directionState) ingest(p transportPacket, id string, limit int) {
	seq := p.seq
	if p.flags&2 != 0 {
		seq++
	}
	if !d.baseKnown {
		d.baseKnown = true
		d.StartSequence = seq
	}
	if p.flags&2 != 0 {
		if !d.SYNSeen {
			newBase := p.seq + 1
			shift := int64(int32(d.StartSequence - newBase))
			d.shiftChunks(shift, limit)
			d.wireEnd += shift
			d.StartSequence = newBase
		}
		d.SYNSeen = true
		d.synSequence = p.seq
	}
	offset := int64(int32(seq - d.StartSequence))
	if offset < 0 && !d.SYNSeen {
		shift := -offset
		d.shiftChunks(shift, limit)
		d.wireEnd += shift
		d.StartSequence = seq
		offset = 0
	}
	if offset < 0 {
		d.Incomplete = true
		d.reasons = add(d.reasons, "sequence_before_syn")
		return
	}
	wireEnd := offset + int64(p.wirePayload)
	d.WirePayloadBytes += int64(p.wirePayload)
	if wireEnd > d.wireEnd {
		d.wireEnd = wireEnd
	}
	if p.flags&1 != 0 {
		d.FINSeen = true
	}
	if p.reason != "" {
		d.Truncated = true
		d.reasons = add(d.reasons, p.reason)
	}
	if len(p.payload) == 0 {
		return
	}
	if offset >= int64(limit) {
		d.Truncated = true
		d.Incomplete = true
		d.reasons = add(d.reasons, "direction_byte_limit")
		return
	}
	data := p.payload
	if len(data) > limit-int(offset) {
		data = data[:limit-int(offset)]
		d.Truncated = true
		d.Incomplete = true
		d.reasons = add(d.reasons, "direction_byte_limit")
	}
	parts := []Chunk{{Offset: offset, Data: append([]byte{}, data...), PacketIDs: []string{id}}}
	overlap, conflict := false, false
	previousEnd := int64(0)
	for _, old := range d.Chunks {
		previousEnd = max(previousEnd, old.Offset+int64(len(old.Data)))
	}
	for i := range d.Chunks {
		old := &d.Chunks[i]
		end := old.Offset + int64(len(old.Data))
		lo, hi := max(offset, old.Offset), min(offset+int64(len(data)), end)
		if hi > lo {
			overlap = true
			if !bytes.Equal(data[lo-offset:hi-offset], old.Data[lo-old.Offset:hi-old.Offset]) {
				conflict = true
			}
			if len(old.PacketIDs) < 8 {
				old.PacketIDs = add(old.PacketIDs, id)
			} else {
				d.reasons = add(d.reasons, "chunk_provenance_truncated")
			}
		}
		next := []Chunk{}
		for _, part := range parts {
			partEnd := part.Offset + int64(len(part.Data))
			if partEnd <= old.Offset || part.Offset >= end {
				next = append(next, part)
				continue
			}
			if part.Offset < old.Offset {
				next = append(next, Chunk{Offset: part.Offset, Data: part.Data[:old.Offset-part.Offset], PacketIDs: part.PacketIDs})
			}
			if partEnd > end {
				next = append(next, Chunk{Offset: end, Data: part.Data[end-part.Offset:], PacketIDs: part.PacketIDs})
			}
		}
		parts = next
	}
	if overlap {
		d.Retransmissions++
	}
	if conflict {
		d.ConflictingOverlaps++
		d.Incomplete = true
		d.reasons = add(d.reasons, "conflicting_overlap_first_observed_bytes_kept")
	}
	if offset < previousEnd && len(parts) > 0 {
		d.OutOfOrder++
	}
	for _, part := range parts {
		if len(d.Chunks) >= MaxDirectionChunks {
			d.Truncated = true
			d.Incomplete = true
			d.reasons = add(d.reasons, "direction_chunk_limit")
			break
		}
		d.Chunks = append(d.Chunks, part)
	}
	sort.Slice(d.Chunks, func(i, j int) bool { return d.Chunks[i].Offset < d.Chunks[j].Offset })
}
func (f *assembly) finish(limit int) {
	seenVersion := map[string]string{}
	for _, v := range f.versions {
		f.detail.VersionBindings = append(f.detail.VersionBindings, v)
		key := v.ServiceID + "/" + v.Component
		version := v.ReleaseID + "/" + v.SourceDigest
		if old, ok := seenVersion[key]; ok && old != version {
			f.detail.Incomplete = true
			f.detail.Reasons = add(f.detail.Reasons, "multiple_release_versions_observed")
		}
		seenVersion[key] = version
	}
	sort.Slice(f.detail.VersionBindings, func(i, j int) bool {
		a, _ := json.Marshal(f.detail.VersionBindings[i])
		b, _ := json.Marshal(f.detail.VersionBindings[j])
		return string(a) < string(b)
	})
	f.detail.ObservationPoints = []ObservationPoint{}
	for _, v := range f.points {
		f.detail.ObservationPoints = append(f.detail.ObservationPoints, v)
	}
	sort.Slice(f.detail.ObservationPoints, func(i, j int) bool {
		a, b := f.detail.ObservationPoints[i], f.detail.ObservationPoints[j]
		return a.Interface+strconv.Itoa(a.IfIndex) < b.Interface+strconv.Itoa(b.IfIndex)
	})
	candidates := []Candidate{}
	for _, v := range f.candidates {
		candidates = append(candidates, v)
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].ServiceID+"/"+candidates[i].Component < candidates[j].ServiceID+"/"+candidates[j].Component
	})
	if len(candidates) == 1 {
		f.detail.ServiceID = candidates[0].ServiceID
		f.detail.Component = candidates[0].Component
	} else {
		f.detail.Candidates = candidates
	}
	if f.detail.Protocol == "udp" {
		return
	}
	if f.detail.Reset {
		f.detail.Incomplete = true
	}
	for n := range f.dirs {
		d := &f.dirs[n]
		d.Midstream = !d.SYNSeen
		d.Incomplete = d.Incomplete || d.Midstream
		if d.packetCount == 0 {
			d.reasons = add(d.reasons, "direction_not_observed")
		}
		if d.Midstream {
			d.reasons = add(d.reasons, "capture_started_midstream")
		}
		cursor := int64(0)
		for _, chunk := range d.Chunks {
			if chunk.Offset > cursor {
				d.Gaps = append(d.Gaps, Gap{cursor, chunk.Offset - cursor, "not_captured_or_missing"})
			}
			cursor = max(cursor, chunk.Offset+int64(len(chunk.Data)))
			d.CapturedBytes += len(chunk.Data)
		}
		if d.wireEnd > cursor {
			d.Gaps = append(d.Gaps, Gap{cursor, d.wireEnd - cursor, "not_captured_or_missing"})
		}
		if len(d.Gaps) > 0 {
			d.Incomplete = true
			d.reasons = add(d.reasons, "stream_has_gaps")
		}
		if d.wireEnd > int64(limit) {
			d.Truncated = true
			d.Incomplete = true
			d.reasons = add(d.reasons, "direction_byte_limit")
		}
		f.detail.Midstream = f.detail.Midstream || d.Midstream
		f.detail.Incomplete = f.detail.Incomplete || d.Incomplete
		f.detail.Truncated = f.detail.Truncated || d.Truncated
		f.detail.Retransmissions += d.Retransmissions
		f.detail.OutOfOrder += d.OutOfOrder
		f.detail.ConflictingOverlaps += d.ConflictingOverlaps
		f.detail.PayloadBytes += d.CapturedBytes
		for _, reason := range d.reasons {
			f.detail.Reasons = add(f.detail.Reasons, reason)
		}
		f.detail.Directions = append(f.detail.Directions, d.Direction)
	}
	if !f.detail.Closed {
		f.detail.Incomplete = true
		f.detail.Reasons = add(f.detail.Reasons, "connection_end_not_observed")
	}
}

func packetCost(p Packet) int {
	n := 256 + len(p.Data) + len(p.ID) + len(p.CollectorEpoch) + len(p.Interface) + len(p.ServiceID) + len(p.Component) + len(p.SourceIP) + len(p.DestinationIP)
	for _, v := range p.Candidates {
		n += len(v.ServiceID) + len(v.Component) + 32
	}
	for _, v := range p.VersionBindings {
		n += len(v.ServiceID) + len(v.Component) + len(v.ReleaseID) + len(v.SourceDigest) + 64
	}
	return n
}
func (f *assembly) addCandidate(v Candidate) {
	key := v.ServiceID + "/" + v.Component
	if _, ok := f.candidates[key]; ok {
		return
	}
	if len(f.candidates) >= 256 {
		f.detail.Incomplete = true
		f.detail.Reasons = add(f.detail.Reasons, "candidate_budget_reached")
		return
	}
	f.candidates[key] = v
}

func (d *directionState) shiftChunks(shift int64, limit int) {
	kept := []Chunk{}
	for _, c := range d.Chunks {
		c.Offset += shift
		if c.Offset < 0 {
			n := min(int64(len(c.Data)), -c.Offset)
			c.Data = c.Data[n:]
			c.Offset += n
			d.Incomplete = true
			d.reasons = add(d.reasons, "sequence_before_syn")
		}
		if c.Offset >= int64(limit) {
			d.Truncated = true
			d.Incomplete = true
			d.reasons = add(d.reasons, "direction_byte_limit")
			continue
		}
		if int64(len(c.Data))+c.Offset > int64(limit) {
			c.Data = c.Data[:int64(limit)-c.Offset]
			d.Truncated = true
			d.Incomplete = true
			d.reasons = add(d.reasons, "direction_byte_limit")
		}
		if len(c.Data) > 0 {
			kept = append(kept, c)
		}
	}
	d.Chunks = kept
}
