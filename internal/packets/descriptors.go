package packets

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/protocols"
)

const MaxDescriptorRequestBytes = 3 << 20
const MaxDescriptorTotalBytes = 8 << 20
const MaxDescriptors = 32

var descriptorParseSlots = make(chan struct{}, 2)

func parseArchiveDescriptor(ctx context.Context, data []byte, binding protocols.Binding) (*protocols.Descriptor, error) {
	select {
	case descriptorParseSlots <- struct{}{}:
		defer func() { <-descriptorParseSlots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, errors.New("descriptor parser busy")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return protocols.NewDescriptor(data, binding)
}

type DescriptorPreviewRequest struct {
	Binding protocols.Binding `json:"binding"`
	Data    []byte            `json:"data"`
	Actor   string            `json:"actor"`
}
type DescriptorConfirmRequest struct {
	ProposalID string `json:"proposal_id"`
	Digest     string `json:"digest"`
	Actor      string `json:"actor"`
}
type DescriptorView struct {
	MethodCount int                      `json:"method_count"`
	ID          string                   `json:"id"`
	Info        protocols.DescriptorInfo `json:"info"`
	CreatedAt   time.Time                `json:"created_at"`
	Confirmed   bool                     `json:"confirmed"`
}
type DescriptorPreview struct {
	DescriptorView
	ProposalID string    `json:"proposal_id"`
	Digest     string    `json:"digest"`
	ExpiresAt  time.Time `json:"expires_at"`
}
type FlowDecodeRequest struct {
	Query        Query  `json:"query"`
	FlowID       string `json:"flow_id"`
	DescriptorID string `json:"descriptor_id,omitempty"`
}
type ExchangeDecodeRequest struct {
	Exchange     protocols.Exchange `json:"exchange"`
	Binding      protocols.Binding  `json:"binding"`
	DescriptorID string             `json:"descriptor_id,omitempty"`
}

func (s *Store) descriptorSchema(ctx context.Context) error {
	_, e := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS packet_descriptors(id TEXT PRIMARY KEY,proposal_id TEXT NOT NULL UNIQUE,digest TEXT NOT NULL,actor TEXT NOT NULL,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,confirmed INTEGER NOT NULL,info BLOB NOT NULL,data BLOB NOT NULL);`)
	return e
}
func descriptorHash(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func (s *Store) DescriptorPreview(ctx context.Context, in DescriptorPreviewRequest) (DescriptorPreview, error) {
	var out DescriptorPreview
	if !validID(in.Actor) {
		return out, errors.New("authenticated descriptor actor required")
	}
	descriptor, e := parseArchiveDescriptor(ctx, in.Data, in.Binding)
	if e != nil {
		return out, e
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	info := descriptor.Info()
	id := "descriptor-" + descriptorHash(struct {
		Binding protocols.Binding
		Digest  string
	}{in.Binding, info.Digest})
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return out, errors.New("archive closed")
	}
	if e = s.descriptorSchema(ctx); e != nil {
		return out, e
	}
	now := s.config.Now().UTC()
	if _, e = s.db.ExecContext(ctx, "DELETE FROM packet_descriptors WHERE confirmed=0 AND expires_at<=?", now.UnixNano()); e != nil {
		return out, e
	}
	var raw, existingData []byte
	var proposal, digest, actor string
	var created, expires int64
	var confirmed bool
	e = s.db.QueryRowContext(ctx, "SELECT proposal_id,digest,actor,created_at,expires_at,confirmed,info,data FROM packet_descriptors WHERE id=?", id).Scan(&proposal, &digest, &actor, &created, &expires, &confirmed, &raw, &existingData)
	if e == nil {
		if !bytes.Equal(existingData, in.Data) {
			return out, ErrConflict
		}
		if !confirmed && actor != in.Actor {
			return out, ErrConflict
		}
		if json.Unmarshal(raw, &info) != nil {
			return out, errors.New("invalid descriptor metadata")
		}
		return DescriptorPreview{DescriptorView: DescriptorView{ID: id, Info: info, CreatedAt: time.Unix(0, created).UTC(), Confirmed: confirmed}, ProposalID: proposal, Digest: digest, ExpiresAt: time.Unix(0, expires).UTC()}, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return out, e
	}
	var count, total int64
	if e = s.db.QueryRowContext(ctx, "SELECT count(*),COALESCE(sum(length(data)+length(info)),0) FROM packet_descriptors").Scan(&count, &total); e != nil {
		return out, e
	}
	raw, e = json.Marshal(info)
	if e != nil {
		return out, e
	}
	if count >= MaxDescriptors || total+int64(len(raw)+len(in.Data)) > MaxDescriptorTotalBytes {
		return out, ErrQuota
	}
	if s.reserveLocked() != nil {
		return out, ErrQuota
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return out, e
	}
	proposal = "descriptor-preview-" + hex.EncodeToString(nonce[:])
	expires = now.Add(5 * time.Minute).UnixNano()
	digest = "sha256:" + descriptorHash(struct {
		ID, Proposal, Actor string
		Expires             int64
	}{id, proposal, in.Actor, expires})
	_, e = s.db.ExecContext(ctx, "INSERT INTO packet_descriptors(id,proposal_id,digest,actor,created_at,expires_at,confirmed,info,data) VALUES(?,?,?,?,?,?,0,?,?)", id, proposal, digest, in.Actor, now.UnixNano(), expires, raw, in.Data)
	if e != nil {
		return out, e
	}
	return DescriptorPreview{DescriptorView: DescriptorView{ID: id, Info: info, CreatedAt: now}, ProposalID: proposal, Digest: digest, ExpiresAt: time.Unix(0, expires).UTC()}, nil
}
func (s *Store) DescriptorConfirm(ctx context.Context, in DescriptorConfirmRequest) (DescriptorView, error) {
	var out DescriptorView
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return out, errors.New("archive closed")
	}
	if !validID(in.Actor) || !validID(in.ProposalID) {
		return out, errors.New("invalid descriptor confirmation")
	}
	if e := s.descriptorSchema(ctx); e != nil {
		return out, e
	}
	var digest, actor string
	var raw, storedData []byte
	var at, expires int64
	var confirmed bool
	e := s.db.QueryRowContext(ctx, "SELECT id,digest,actor,created_at,expires_at,confirmed,info,data FROM packet_descriptors WHERE proposal_id=?", in.ProposalID).Scan(&out.ID, &digest, &actor, &at, &expires, &confirmed, &raw, &storedData)
	if errors.Is(e, sql.ErrNoRows) {
		return out, ErrNotFound
	}
	if e != nil {
		return out, e
	}
	if digest != in.Digest || actor != in.Actor {
		return out, ErrConflict
	}
	if !confirmed && expires <= s.config.Now().UnixNano() {
		return out, ErrExpired
	}
	if json.Unmarshal(raw, &out.Info) != nil {
		return out, errors.New("invalid descriptor metadata")
	}
	verified, e := parseArchiveDescriptor(ctx, storedData, out.Info.Binding)
	if e != nil {
		return out, e
	}
	actual := verified.Info()
	if actual.Digest != out.Info.Digest || out.ID != "descriptor-"+descriptorHash(struct {
		Binding protocols.Binding
		Digest  string
	}{actual.Binding, actual.Digest}) {
		return out, ErrConflict
	}
	if _, e = s.db.ExecContext(ctx, "UPDATE packet_descriptors SET confirmed=1 WHERE id=?", out.ID); e != nil {
		return out, e
	}
	out.CreatedAt = time.Unix(0, at).UTC()
	out.Confirmed = true
	return out, nil
}
func (s *Store) Descriptors(ctx context.Context) ([]DescriptorView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []DescriptorView{}
	if s.closed {
		return out, errors.New("archive closed")
	}
	if e := s.descriptorSchema(ctx); e != nil {
		return out, e
	}
	rows, e := s.db.QueryContext(ctx, "SELECT id,created_at,info FROM packet_descriptors WHERE confirmed=1 ORDER BY created_at DESC LIMIT ?", MaxDescriptors)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var v DescriptorView
		var at int64
		var raw []byte
		if e = rows.Scan(&v.ID, &at, &raw); e != nil {
			return out, e
		}
		if json.Unmarshal(raw, &v.Info) != nil {
			return out, errors.New("invalid descriptor metadata")
		}
		v.MethodCount = len(v.Info.Methods)
		v.Info.Methods = []protocols.MethodInfo{}
		v.CreatedAt = time.Unix(0, at).UTC()
		v.Confirmed = true
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) DescriptorDelete(ctx context.Context, id string) error {
	if !validID(id) {
		return ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("archive closed")
	}
	if e := s.descriptorSchema(ctx); e != nil {
		return e
	}
	result, e := s.db.ExecContext(ctx, "DELETE FROM packet_descriptors WHERE id=?", id)
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e == nil && n == 0 {
		return ErrNotFound
	}
	return e
}
func (s *Store) loadDescriptor(ctx context.Context, id string) (*protocols.Descriptor, error) {
	if !validID(id) {
		return nil, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("archive closed")
	}
	if e := s.descriptorSchema(ctx); e != nil {
		return nil, e
	}
	var info protocols.DescriptorInfo
	var raw, data []byte
	e := s.db.QueryRowContext(ctx, "SELECT info,data FROM packet_descriptors WHERE id=? AND confirmed=1", id).Scan(&raw, &data)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if e != nil {
		return nil, e
	}
	if json.Unmarshal(raw, &info) != nil {
		return nil, errors.New("invalid descriptor metadata")
	}
	descriptor, e := parseArchiveDescriptor(ctx, data, info.Binding)
	if e != nil {
		return nil, e
	}
	actual := descriptor.Info()
	expectedID := "descriptor-" + descriptorHash(struct {
		Binding protocols.Binding
		Digest  string
	}{actual.Binding, actual.Digest})
	if actual.Digest != info.Digest || expectedID != id {
		return nil, ErrConflict
	}
	return descriptor, nil
}
func (s *Store) descriptorHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var v any
	var e error
	switch {
	case r.Method == "GET" && r.URL.Path == "/v1/descriptors":
		v, e = s.Descriptors(ctx)
	case r.Method == "POST" && r.URL.Path == "/v1/descriptors/preview":
		var in DescriptorPreviewRequest
		if decodeBody(w, r, &in, MaxDescriptorRequestBytes) != nil {
			httpError(w, 400, "invalid_descriptor")
			return
		}
		v, e = s.DescriptorPreview(ctx, in)
	case r.Method == "POST" && r.URL.Path == "/v1/descriptors/confirm":
		var in DescriptorConfirmRequest
		if decodeBody(w, r, &in, 16384) != nil {
			httpError(w, 400, "invalid_descriptor_confirmation")
			return
		}
		v, e = s.DescriptorConfirm(ctx, in)
	case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/v1/descriptors/"):
		e = s.DescriptorDelete(ctx, strings.TrimPrefix(r.URL.Path, "/v1/descriptors/"))
		v = map[string]bool{"ok": e == nil}
	default:
		httpError(w, 404, "not_found")
		return
	}
	if e != nil {
		status := 400
		if errors.Is(e, ErrNotFound) {
			status = 404
		}
		if errors.Is(e, ErrConflict) || errors.Is(e, ErrExpired) {
			status = 409
		}
		if errors.Is(e, ErrQuota) {
			status = 507
		}
		httpError(w, status, "descriptor_unavailable_or_invalid")
		return
	}
	respond(w, 200, v)
}
func (c *Client) descriptorRequest(ctx context.Context, method, path string, input, out any) error {
	raw, e := json.Marshal(input)
	if input == nil {
		raw = nil
	}
	if e != nil || len(raw) > MaxDescriptorRequestBytes {
		return errors.New("descriptor request exceeds bound")
	}
	r, e := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(raw))
	if e != nil {
		return e
	}
	r.Header.Set("Authorization", "Bearer "+c.token)
	r.Header.Set("Content-Type", "application/json")
	res, e := c.http.Do(r)
	if e != nil {
		return errors.New("descriptor archive transport unavailable")
	}
	defer res.Body.Close()
	data, e := io.ReadAll(io.LimitReader(res.Body, 4<<20+1))
	if e != nil || len(data) > 4<<20 {
		return errors.New("descriptor archive response too large")
	}
	if res.StatusCode != 200 {
		if res.StatusCode == 400 {
			return ErrInvalid
		}
		if res.StatusCode == 404 {
			return ErrNotFound
		}
		if res.StatusCode == 409 {
			return ErrConflict
		}
		if res.StatusCode == 507 {
			return ErrQuota
		}
		return errors.New("descriptor archive rejected request")
	}
	if json.Unmarshal(data, out) != nil {
		return errors.New("invalid descriptor response")
	}
	return nil
}
func (c *Client) Descriptors(ctx context.Context) (v []DescriptorView, e error) {
	e = c.descriptorRequest(ctx, "GET", "/v1/descriptors", nil, &v)
	return
}
func (c *Client) DescriptorPreview(ctx context.Context, in DescriptorPreviewRequest) (v DescriptorPreview, e error) {
	e = c.descriptorRequest(ctx, "POST", "/v1/descriptors/preview", in, &v)
	return
}
func (c *Client) DescriptorConfirm(ctx context.Context, in DescriptorConfirmRequest) (v DescriptorView, e error) {
	e = c.descriptorRequest(ctx, "POST", "/v1/descriptors/confirm", in, &v)
	return
}
func (c *Client) DescriptorDelete(ctx context.Context, id string) error {
	if !validID(id) {
		return ErrNotFound
	}
	var out any
	return c.descriptorRequest(ctx, "DELETE", "/v1/descriptors/"+id, nil, &out)
}
