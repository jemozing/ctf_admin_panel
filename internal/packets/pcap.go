package packets

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
)

// ExportPCAP returns an in-memory, bounded classic Ethernet PCAP. Packet order
// follows capture sequence, including genuine retransmissions. There is no
// flow reassembly, packet injection, TLS decryption, or temporary export file.
func (s *Store) ExportPCAP(ctx context.Context, request ExportRequest) (Export, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := Export{Epoch: s.epoch}
	if s.closed {
		return out, errors.New("packet archive closed")
	}
	q := request.Query
	// A page limit has no second, conflicting meaning for an export.
	if q.Limit != 0 {
		return out, errors.New("export uses max_packets rather than query limit")
	}
	where, args, err := querySQL(q)
	if err != nil {
		return out, err
	}
	maxPackets, maxBytes := request.MaxPackets, request.MaxBytes
	if maxPackets == 0 {
		maxPackets = MaxExportPackets
	}
	if maxBytes == 0 {
		maxBytes = MaxExportBytes
	}
	if maxPackets < 1 || maxPackets > MaxExportPackets || maxBytes < 24 || maxBytes > MaxExportBytes {
		return out, errors.New("invalid PCAP export bounds")
	}
	if !s.storageFailed {
		if err := s.rotateLocked(ctx); err != nil {
			return out, s.writeError(err)
		}
	}
	where = append(where, "p.at>=?")
	args = append(args, s.config.Now().Add(-s.config.Retention).UnixNano())
	if q.Cursor != "" {
		cur, e := parseCursor(q.Cursor)
		if e != nil {
			return out, e
		}
		var retired int64
		if err := s.db.QueryRowContext(ctx, "SELECT value FROM packet_meta WHERE key='retired'").Scan(&retired); err != nil {
			return out, err
		}
		if cur.Epoch != s.epoch {
			out.Gap = true
		} else {
			op := "<"
			if cur.Direction == "after" {
				op = ">"
			}
			where = append(where, "p.sequence"+op+"?")
			args = append(args, cur.Sequence)
			out.Gap = retired > 0 && cur.Sequence <= retired
		}
	}
	args = append(args, maxPackets+1)
	rows, err := s.db.QueryContext(ctx, "SELECT p.metadata,p.payload FROM packets p WHERE "+strings.Join(where, " AND ")+" ORDER BY p.sequence ASC LIMIT ?", args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	out.Data = make([]byte, 24)
	binary.LittleEndian.PutUint32(out.Data[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(out.Data[4:6], 2)
	binary.LittleEndian.PutUint16(out.Data[6:8], 4)
	binary.LittleEndian.PutUint32(out.Data[16:20], MaxPacketBytes)
	binary.LittleEndian.PutUint32(out.Data[20:24], 1)
	for rows.Next() {
		var meta, data []byte
		if err := rows.Scan(&meta, &data); err != nil {
			return Export{}, err
		}
		if out.Packets == maxPackets || len(out.Data)+16+len(data) > maxBytes {
			out.Truncated = true
			break
		}
		var m Metadata
		if err := json.Unmarshal(meta, &m); err != nil {
			return Export{}, err
		}
		if m.LinkType != 1 || m.CapturedLength != len(data) || m.CapturedLength > m.WireLength {
			return Export{}, errors.New("invalid stored PCAP record")
		}
		header := make([]byte, 16)
		binary.LittleEndian.PutUint32(header[0:4], uint32(m.At.Unix()))
		binary.LittleEndian.PutUint32(header[4:8], uint32(m.At.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(header[8:12], uint32(len(data)))
		binary.LittleEndian.PutUint32(header[12:16], uint32(m.WireLength))
		out.Data = append(out.Data, header...)
		out.Data = append(out.Data, data...)
		out.Packets++
	}
	return out, rows.Err()
}
