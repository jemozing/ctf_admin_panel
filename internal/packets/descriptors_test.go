package packets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/protocols"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func archiveDescriptorBytes(t *testing.T, padding int) []byte {
	t.Helper()
	optional := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	str := descriptorpb.FieldDescriptorProto_TYPE_STRING
	file := &descriptorpb.FileDescriptorProto{Name: proto.String("archive.proto"), Package: proto.String("game"), Syntax: proto.String("proto3"), MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Request"), Field: []*descriptorpb.FieldDescriptorProto{{Name: proto.String("flag"), Number: proto.Int32(1), Label: &optional, Type: &str}}}, {Name: proto.String("Response"), Field: []*descriptorpb.FieldDescriptorProto{{Name: proto.String("result"), Number: proto.Int32(1), Label: &optional, Type: &str}}}}, Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("Service"), Method: []*descriptorpb.MethodDescriptorProto{{Name: proto.String("Check"), InputType: proto.String(".game.Request"), OutputType: proto.String(".game.Response")}}}}}
	if padding > 0 {
		file.SourceCodeInfo = &descriptorpb.SourceCodeInfo{Location: []*descriptorpb.SourceCodeInfo_Location{{Path: []int32{4, 0}, Span: []int32{0, 0, 1}, LeadingComments: proto.String(strings.Repeat("x", padding))}}}
	}
	raw, err := proto.Marshal(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{file}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func archiveDescriptorBinding(release string) protocols.Binding {
	return protocols.Binding{ServiceID: "game", ReleaseID: release, SourceDigest: "sha256:" + strings.Repeat("a", 64)}
}
func confirmArchiveDescriptor(t *testing.T, s *Store, binding protocols.Binding) DescriptorView {
	t.Helper()
	p, err := s.DescriptorPreview(context.Background(), DescriptorPreviewRequest{Binding: binding, Data: archiveDescriptorBytes(t, 0), Actor: "admin-one"})
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.DescriptorConfirm(context.Background(), DescriptorConfirmRequest{ProposalID: p.ProposalID, Digest: p.Digest, Actor: "admin-one"})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestDescriptorPreviewConfirmationActorDigestIdempotenceAndDelete(t *testing.T) {
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, nil)
	ctx := context.Background()
	input := DescriptorPreviewRequest{Binding: archiveDescriptorBinding("release-one"), Data: archiveDescriptorBytes(t, 0), Actor: "admin-one"}
	p, err := s.DescriptorPreview(ctx, input)
	if err != nil || p.Confirmed || p.Info.Digest == "" || p.ProposalID == "" || len(p.Info.Methods) != 1 || p.ExpiresAt.Sub(now) != 5*time.Minute {
		t.Fatalf("preview: %+v %v", p, err)
	}
	list, err := s.Descriptors(ctx)
	if err != nil || len(list) != 0 {
		t.Fatal("unconfirmed descriptor visible")
	}
	if _, err := s.loadDescriptor(ctx, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("unconfirmed descriptor usable")
	}
	repeat, err := s.DescriptorPreview(ctx, input)
	if err != nil || repeat.ProposalID != p.ProposalID || repeat.Digest != p.Digest {
		t.Fatal("identical pending preview duplicated")
	}
	other := input
	other.Actor = "admin-two"
	if _, err := s.DescriptorPreview(ctx, other); !errors.Is(err, ErrConflict) {
		t.Fatal("other actor took pending preview")
	}
	valid := DescriptorConfirmRequest{ProposalID: p.ProposalID, Digest: p.Digest, Actor: input.Actor}
	for _, bad := range []DescriptorConfirmRequest{{ProposalID: p.ProposalID, Digest: p.Digest, Actor: "admin-two"}, {ProposalID: p.ProposalID, Digest: "sha256:" + strings.Repeat("b", 64), Actor: input.Actor}} {
		if _, err := s.DescriptorConfirm(ctx, bad); !errors.Is(err, ErrConflict) {
			t.Fatal("actor/digest not bound")
		}
	}
	v, err := s.DescriptorConfirm(ctx, valid)
	if err != nil || !v.Confirmed || v.ID != p.ID || v.Info.Binding != input.Binding {
		t.Fatalf("confirm: %+v %v", v, err)
	}
	now = now.Add(time.Hour)
	again, err := s.DescriptorConfirm(ctx, valid)
	if err != nil || again.ID != v.ID {
		t.Fatal("confirmed retry expired or duplicated")
	}
	list, err = s.Descriptors(ctx)
	if err != nil || len(list) != 1 || !list[0].Confirmed {
		t.Fatal("confirmed inventory lost")
	}
	encoded, _ := json.Marshal(list)
	if bytes.Contains(encoded, []byte(`"data":`)) || bytes.Contains(encoded, input.Data) {
		t.Fatal("descriptor inventory leaked binary data")
	}
	if _, err := s.loadDescriptor(ctx, v.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DescriptorDelete(ctx, v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.loadDescriptor(ctx, v.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted descriptor remained usable")
	}
	if err := s.DescriptorDelete(ctx, v.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("delete missing descriptor accepted")
	}
}
func TestDescriptorExpiryAtDeadlineAndRenewal(t *testing.T) {
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, nil)
	ctx := context.Background()
	input := DescriptorPreviewRequest{Binding: archiveDescriptorBinding("release-one"), Data: archiveDescriptorBytes(t, 0), Actor: "admin-one"}
	p, err := s.DescriptorPreview(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	now = p.ExpiresAt
	if _, err := s.DescriptorConfirm(ctx, DescriptorConfirmRequest{ProposalID: p.ProposalID, Digest: p.Digest, Actor: input.Actor}); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired preview accepted at exact deadline: %v", err)
	}
	now = now.Add(time.Nanosecond)
	fresh, err := s.DescriptorPreview(ctx, input)
	if err != nil || fresh.ID != p.ID || fresh.ProposalID == p.ProposalID {
		t.Fatalf("expired preview not replaced safely: %+v %v", fresh, err)
	}
}
func TestDescriptorCountAndTotalQuotaAndExpiredReclaim(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	small := archiveDescriptorBytes(t, 0)
	t.Run("count", func(t *testing.T) {
		s := openTest(t, func() time.Time { return now }, func(c *Config) { c.QuotaBytes = 64 << 20; c.PerServiceBytes = 1 << 20 })
		for i := 0; i < MaxDescriptors; i++ {
			if _, err := s.DescriptorPreview(ctx, DescriptorPreviewRequest{Binding: archiveDescriptorBinding(fmt.Sprintf("release-%02d", i)), Data: small, Actor: "admin"}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.DescriptorPreview(ctx, DescriptorPreviewRequest{Binding: archiveDescriptorBinding("extra"), Data: small, Actor: "admin"}); !errors.Is(err, ErrQuota) {
			t.Fatalf("descriptor count budget bypassed: %v", err)
		}
		now = now.Add(6 * time.Minute)
		if _, err := s.DescriptorPreview(ctx, DescriptorPreviewRequest{Binding: archiveDescriptorBinding("new-after-expiry"), Data: small, Actor: "admin"}); err != nil {
			t.Fatal("expired proposals pinned capacity", err)
		}
	})
	t.Run("total", func(t *testing.T) {
		s := openTest(t, func() time.Time { return now }, func(c *Config) { c.QuotaBytes = 64 << 20; c.PerServiceBytes = 1 << 20 })
		raw := archiveDescriptorBytes(t, 1<<20)
		inserted := 0
		for i := 0; i < 12; i++ {
			_, err := s.DescriptorPreview(ctx, DescriptorPreviewRequest{Binding: archiveDescriptorBinding(fmt.Sprintf("large-%02d", i)), Data: raw, Actor: "admin"})
			if errors.Is(err, ErrQuota) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			inserted++
		}
		if inserted < 2 || inserted >= 8 {
			t.Fatalf("8MiB aggregate descriptor quota wrong, accepted %d MiB files", inserted)
		}
	})
}
func TestDescriptorReserveAndPrivatePersistence(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	directory := filepath.Join(t.TempDir(), "archive")
	config := Config{StateDirectory: directory, QuotaBytes: 8 << 20, PerServiceBytes: 1 << 20, MinimumFreeBytes: 1, Retention: time.Hour, MaxRecords: 100, Now: func() time.Time { return now }}
	s, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	v := confirmArchiveDescriptor(t, s, archiveDescriptorBinding("release"))
	s.config.MinimumFreeBytes = 1 << 60
	if _, err := s.DescriptorPreview(ctx, DescriptorPreviewRequest{Binding: archiveDescriptorBinding("low-space"), Data: archiveDescriptorBytes(t, 0), Actor: "admin"}); !errors.Is(err, ErrQuota) {
		t.Fatal("descriptor ignored reserve", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(config)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	list, err := s.Descriptors(ctx)
	if err != nil || len(list) != 1 || list[0].ID != v.ID {
		t.Fatal("descriptor lost on restart", err)
	}
	if _, err := s.loadDescriptor(ctx, v.ID); err != nil {
		t.Fatal("persisted descriptor cannot load", err)
	}
	if _, err := Open(config); err == nil {
		t.Fatal("two descriptor archive owners allowed")
	}
}
func TestDescriptorPrivateHTTPTokenSeparationAndStrictInput(t *testing.T) {
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, nil)
	tokens := Tokens{Ingest: strings.Repeat("i", 40), Read: strings.Repeat("r", 40)}
	handler, err := Handler(s, tokens)
	if err != nil {
		t.Fatal(err)
	}
	call := func(h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://archive"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, methodPath := range [][2]string{{"GET", "/v1/descriptors"}, {"POST", "/v1/descriptors/preview"}, {"POST", "/v1/descriptors/confirm"}, {"POST", "/v1/flows/decode"}, {"POST", "/v1/exchange/decode"}} {
		if w := call(handler, methodPath[0], methodPath[1], tokens.Ingest, `{}`); w.Code != 401 {
			t.Fatalf("ingest token accessed private descriptor/decode API %s: %d", methodPath[1], w.Code)
		}
		if w := call(IngestOnly(handler), methodPath[0], methodPath[1], tokens.Read, `{}`); w.Code != 404 {
			t.Fatalf("network listener exposed private API %s", methodPath[1])
		}
	}
	raw, _ := json.Marshal(DescriptorPreviewRequest{Binding: archiveDescriptorBinding("release"), Data: archiveDescriptorBytes(t, 0), Actor: "admin"})
	w := call(ReadOnly(handler), "POST", "/v1/descriptors/preview", tokens.Read, string(raw))
	if w.Code != 200 || strings.Contains(w.Body.String(), `"data":`) {
		t.Fatalf("private preview: %d %s", w.Code, w.Body.String())
	}
	for _, body := range []string{`{"actor":"admin","command":"shell"}`, `{} {}`, `null`, `[]`} {
		if w := call(ReadOnly(handler), "POST", "/v1/descriptors/preview", tokens.Read, body); w.Code != 400 {
			t.Fatalf("invalid descriptor body accepted: %d %s", w.Code, body)
		}
	}
	if w := call(ReadOnly(handler), "GET", "/v1/descriptors?data=1", tokens.Read, ""); w.Code != 400 {
		t.Fatal("unexpected descriptor query accepted")
	}
}

func TestDescriptorStoredBlobDigestIsRecheckedBeforeUse(t *testing.T) {
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, nil)
	v := confirmArchiveDescriptor(t, s, archiveDescriptorBinding("release"))
	set := new(descriptorpb.FileDescriptorSet)
	if err := proto.Unmarshal(archiveDescriptorBytes(t, 0), set); err != nil {
		t.Fatal(err)
	}
	set.File[0].MessageType[0].Field[0].Name = proto.String("changed_after_confirmation")
	raw, err := proto.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE packet_descriptors SET data=? WHERE id=?", raw, v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.loadDescriptor(context.Background(), v.ID); err == nil {
		t.Fatal("changed descriptor bytes reused an already confirmed digest")
	}
}

func TestDescriptorPendingBlobMutationCannotBeConfirmed(t *testing.T) {
	now := time.Now().UTC()
	s := openTest(t, func() time.Time { return now }, nil)
	ctx := context.Background()
	p, err := s.DescriptorPreview(ctx, DescriptorPreviewRequest{Binding: archiveDescriptorBinding("release"), Data: archiveDescriptorBytes(t, 0), Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	set := new(descriptorpb.FileDescriptorSet)
	if err = proto.Unmarshal(archiveDescriptorBytes(t, 0), set); err != nil {
		t.Fatal(err)
	}
	set.File[0].MessageType[0].Field[0].Name = proto.String("different_reviewed_schema")
	changed, err := proto.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("UPDATE packet_descriptors SET data=? WHERE id=?", changed, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DescriptorConfirm(ctx, DescriptorConfirmRequest{ProposalID: p.ProposalID, Digest: p.Digest, Actor: "admin"}); err == nil {
		t.Fatal("confirmation used bytes different from reviewed digest")
	}
	list, err := s.Descriptors(ctx)
	if err != nil || len(list) != 0 {
		t.Fatal("corrupted proposal entered confirmed inventory", err)
	}
}
