package packets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type cursor struct {
	Epoch     string `json:"e"`
	Sequence  int64  `json:"s"`
	Direction string `json:"d"`
}

func (s *Store) cursor(sequence int64, direction string) string {
	b, _ := json.Marshal(cursor{s.epoch, sequence, direction})
	return base64.RawURLEncoding.EncodeToString(b)
}
func parseCursor(text string) (cursor, error) {
	var c cursor
	if len(text) > 512 {
		return c, errors.New("invalid packet cursor")
	}
	b, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		return c, errors.New("invalid packet cursor")
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || c.Sequence < 0 || !validID(c.Epoch) || (c.Direction != "before" && c.Direction != "after") {
		return c, errors.New("invalid packet cursor")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("invalid packet cursor")
	}
	return c, nil
}

func (s *Store) List(ctx context.Context, q Query) (Page, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := Page{Records: []Metadata{}, Epoch: s.epoch}
	if s.closed {
		return out, errors.New("packet archive closed")
	}
	where, args, err := querySQL(q)
	if err != nil {
		return out, err
	}
	if q.Limit < 0 || q.Limit > 200 {
		return out, errors.New("packet limit must be 1..200")
	}
	limit := q.Limit
	if limit == 0 {
		limit = 50
	}
	if !s.storageFailed {
		if err := s.rotateLocked(ctx); err != nil {
			return out, s.writeError(err)
		}
	}
	where = append(where, "p.at>=?")
	args = append(args, s.config.Now().Add(-s.config.Retention).UnixNano())
	var maxSeq, retired int64
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM packet_meta WHERE key='sequence'").Scan(&maxSeq); err != nil {
		return out, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM packet_meta WHERE key='retired'").Scan(&retired); err != nil {
		return out, err
	}
	cur := cursor{s.epoch, maxSeq + 1, "before"}
	if q.Cursor != "" {
		cur, err = parseCursor(q.Cursor)
		if err != nil {
			return out, err
		}
		if cur.Epoch != s.epoch {
			out.Gap = true
			cur = cursor{s.epoch, maxSeq + 1, "before"}
		}
		if retired > 0 && cur.Sequence <= retired {
			out.Gap = true
		}
	}
	order, comparison := "DESC", "<"
	if cur.Direction == "after" {
		order, comparison = "ASC", ">"
	}
	where = append(where, "p.sequence"+comparison+"?")
	args = append(args, cur.Sequence, limit+1)
	rows, err := s.db.QueryContext(ctx, "SELECT p.metadata FROM packets p WHERE "+strings.Join(where, " AND ")+" ORDER BY p.sequence "+order+" LIMIT ?", args...)
	if err != nil {
		return out, err
	}
	metadataBytes := 0
	for rows.Next() {
		var b []byte
		var m Metadata
		if err := rows.Scan(&b); err != nil {
			rows.Close()
			return out, err
		}
		// An ambiguous packet can have many policy-derived candidates. Bound
		// response memory independently of the requested record count.
		if metadataBytes+len(b) > 2<<20 {
			out.HasMore = true
			break
		}
		if err := json.Unmarshal(b, &m); err != nil {
			rows.Close()
			return out, err
		}
		out.Records = append(out.Records, m)
		metadataBytes += len(b)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	out.HasMore = out.HasMore || len(out.Records) > limit
	if len(out.Records) > limit {
		out.Records = out.Records[:limit]
	}
	if len(out.Records) > 0 {
		last := out.Records[len(out.Records)-1].Sequence
		if cur.Direction == "after" {
			out.LiveCursor = s.cursor(last, "after")
			if out.HasMore {
				out.NextCursor = out.LiveCursor
			}
		} else {
			out.NextCursor = s.cursor(last, "before")
			out.LiveCursor = s.cursor(maxSeq, "after")
			if retired >= last && retired < cur.Sequence {
				out.Gap = true
			}
		}
	} else if cur.Direction == "after" {
		out.LiveCursor = s.cursor(cur.Sequence, "after")
	} else {
		out.LiveCursor = s.cursor(maxSeq, "after")
		if q.Cursor != "" && retired > 0 && retired < cur.Sequence {
			out.Gap = true
		}
	}
	out.Counters, err = s.statusLocked(ctx)
	return out, err
}

func querySQL(q Query) ([]string, []any, error) {
	where, args := []string{"1=1"}, []any{}
	if len(q.ServiceIDs) > 32 {
		return nil, nil, errors.New("too many service filters")
	}
	if len(q.ServiceIDs) > 0 || q.Component != "" {
		clause := "EXISTS(SELECT 1 FROM packet_services ps WHERE ps.packet_id=p.packet_id"
		if len(q.ServiceIDs) > 0 {
			ids := append([]string(nil), q.ServiceIDs...)
			sort.Strings(ids)
			marks := []string{}
			last := ""
			for _, id := range ids {
				if !validID(id) {
					return nil, nil, errors.New("invalid service filter")
				}
				if id != last {
					marks = append(marks, "?")
					args = append(args, id)
					last = id
				}
			}
			clause += " AND ps.service_id IN (" + strings.Join(marks, ",") + ")"
		}
		if q.Component != "" {
			if !validID(q.Component) {
				return nil, nil, errors.New("invalid component filter")
			}
			clause += " AND ps.component=?"
			args = append(args, q.Component)
		}
		where = append(where, clause+")")
	}
	for _, item := range []struct {
		column, value string
		allowed       []string
	}{{"protocol", q.Protocol, []string{"tcp", "udp"}}, {"direction", q.Direction, []string{"ingress", "egress", "ambiguous"}}} {
		if item.value != "" {
			ok := false
			for _, v := range item.allowed {
				ok = ok || v == item.value
			}
			if !ok {
				return nil, nil, errors.New("invalid packet transport filter")
			}
			where = append(where, "p."+item.column+"=?")
			args = append(args, item.value)
		}
	}
	for _, item := range []struct {
		column string
		value  int
	}{{"source_port", q.SourcePort}, {"destination_port", q.DestinationPort}} {
		if item.value < 0 || item.value > 65535 {
			return nil, nil, errors.New("invalid packet port filter")
		}
		if item.value > 0 {
			where = append(where, "p."+item.column+"=?")
			args = append(args, item.value)
		}
	}
	var from, until time.Time
	for _, item := range []struct{ text, op string }{{q.From, ">="}, {q.Until, "<="}} {
		if item.text != "" {
			at, err := time.Parse(time.RFC3339Nano, item.text)
			if err != nil || at.Unix() < 0 || at.Unix() > 4294967295 {
				return nil, nil, errors.New("invalid packet time filter")
			}
			where = append(where, "p.at"+item.op+"?")
			args = append(args, at.UnixNano())
			if item.op == ">=" {
				from = at
			} else {
				until = at
			}
		}
	}
	if !from.IsZero() && !until.IsZero() && from.After(until) {
		return nil, nil, errors.New("packet from is after until")
	}
	if q.IP != "" {
		family, lo, hi, err := ipRange(q.IP)
		if err != nil {
			return nil, nil, err
		}
		where = append(where, "((p.source_family=? AND p.source_ip>=? AND p.source_ip<=?) OR (p.destination_family=? AND p.destination_ip>=? AND p.destination_ip<=?))")
		args = append(args, family, lo, hi, family, lo, hi)
	}
	if q.Cursor != "" {
		if _, err := parseCursor(q.Cursor); err != nil {
			return nil, nil, err
		}
	}
	return where, args, nil
}

func ipRange(text string) (int, []byte, []byte, error) {
	prefix, err := netip.ParsePrefix(text)
	if err != nil {
		a, e := netip.ParseAddr(text)
		if e != nil || a.Zone() != "" {
			return 0, nil, nil, errors.New("invalid IP/CIDR filter")
		}
		a = a.Unmap()
		prefix = netip.PrefixFrom(a, a.BitLen())
	}
	a, bits := prefix.Addr(), prefix.Bits()
	if a.Zone() != "" {
		return 0, nil, nil, errors.New("invalid IP/CIDR filter")
	}
	if a.Is4In6() {
		if bits < 96 {
			return 0, nil, nil, errors.New("ambiguous mapped IP prefix")
		}
		prefix = netip.PrefixFrom(a.Unmap(), bits-96)
	}
	prefix = prefix.Masked()
	lo := prefix.Addr().As16()
	hi := lo
	family, offset := 6, 0
	if prefix.Addr().Is4() {
		family, offset = 4, 96
	}
	for bit := offset + prefix.Bits(); bit < 128; bit++ {
		hi[bit/8] |= 1 << uint(7-bit%8)
	}
	return family, lo[:], hi[:], nil
}

func ParseRawQuery(raw string) (Query, error) {
	v, err := url.ParseQuery(raw)
	if err != nil {
		return Query{}, err
	}
	return ParseQuery(v)
}
func ParseQuery(v url.Values) (Query, error) {
	var q Query
	allowed := map[string]bool{"service_id": true, "component": true, "protocol": true, "ip": true, "source_port": true, "destination_port": true, "direction": true, "from": true, "until": true, "cursor": true, "limit": true}
	for key, list := range v {
		if !allowed[key] || (key != "service_id" && len(list) != 1) {
			return q, errors.New("unknown or duplicated packet query option")
		}
		for _, value := range list {
			if value == "" {
				return q, errors.New("empty packet query option")
			}
		}
	}
	q.ServiceIDs = v["service_id"]
	q.Component = v.Get("component")
	q.Protocol = v.Get("protocol")
	q.IP = v.Get("ip")
	q.Direction = v.Get("direction")
	q.From = v.Get("from")
	q.Until = v.Get("until")
	q.Cursor = v.Get("cursor")
	for _, item := range []struct {
		key   string
		value *int
	}{{"source_port", &q.SourcePort}, {"destination_port", &q.DestinationPort}, {"limit", &q.Limit}} {
		if v.Has(item.key) {
			n, err := strconv.Atoi(v.Get(item.key))
			if err != nil || n < 1 {
				return q, errors.New("invalid packet number filter")
			}
			*item.value = n
		}
	}
	if q.Limit > 200 {
		return q, errors.New("invalid packet limit")
	}
	_, _, err := querySQL(q)
	return q, err
}
func QueryValues(q Query) url.Values {
	v := url.Values{}
	for _, id := range q.ServiceIDs {
		v.Add("service_id", id)
	}
	for key, value := range map[string]string{"component": q.Component, "protocol": q.Protocol, "ip": q.IP, "direction": q.Direction, "from": q.From, "until": q.Until, "cursor": q.Cursor} {
		if value != "" {
			v.Set(key, value)
		}
	}
	for key, value := range map[string]int{"source_port": q.SourcePort, "destination_port": q.DestinationPort, "limit": q.Limit} {
		if value != 0 {
			v.Set(key, strconv.Itoa(value))
		}
	}
	return v
}
