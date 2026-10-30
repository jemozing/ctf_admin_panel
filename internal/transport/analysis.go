package transport

import (
	"context"
	"io"
	"mime"
	"net/http"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/flows"
	"github.com/ctf-service-manager/ctf-service-manager/internal/packets"
	"github.com/ctf-service-manager/ctf-service-manager/internal/protocols"
)

type DescriptorPreviewRequest struct {
	ServiceID domain.ID `json:"service_id"`
	ReleaseID domain.ID `json:"release_id,omitempty"`
	Data      []byte    `json:"data"`
	Initiator domain.ID `json:"initiator,omitempty"`
}
type DescriptorConfirmRequest struct {
	ProposalID domain.ID     `json:"proposal_id"`
	Digest     domain.Digest `json:"digest"`
	Initiator  domain.ID     `json:"initiator,omitempty"`
}
type DescriptorDeleteRequest struct {
	ID        string    `json:"id"`
	Initiator domain.ID `json:"initiator,omitempty"`
}
type ExchangeDecodeRequest struct {
	RequestID    string `json:"request_id"`
	DescriptorID string `json:"descriptor_id,omitempty"`
}
type AnalysisBackend interface {
	FlowList(context.Context, packets.Query) (packets.FlowPage, error)
	FlowDetail(context.Context, packets.FlowDetailRequest) (flows.Detail, error)
	FlowDecode(context.Context, packets.FlowDecodeRequest) (protocols.Result, error)
	ExchangeDecode(context.Context, ExchangeDecodeRequest) (protocols.Result, error)
	DescriptorList(context.Context) ([]packets.DescriptorView, error)
	DescriptorPreview(context.Context, DescriptorPreviewRequest) (packets.DescriptorPreview, error)
	DescriptorConfirm(context.Context, DescriptorConfirmRequest) (packets.DescriptorView, error)
	DescriptorDelete(context.Context, DescriptorDeleteRequest) error
}

func (s *Server) analysisEndpoint(w http.ResponseWriter, r *http.Request) {
	b, ok := s.options.Backend.(AnalysisBackend)
	if !ok {
		writeError(w, 501, "not_implemented", "analysis module unavailable")
		return
	}
	var v any
	var e error
	switch {
	case r.Method == "GET" && r.URL.Path == "/v1/flows":
		var q packets.Query
		q, e = packets.ParseRawQuery(r.URL.RawQuery)
		if e != nil {
			writeError(w, 400, "invalid_query", "invalid flow query")
			return
		}
		v, e = b.FlowList(r.Context(), q)
	case r.Method == "POST" && r.URL.Path == "/v1/flows/detail":
		var in packets.FlowDetailRequest
		if !decodeProxyInput(w, r, &in) {
			return
		}
		v, e = b.FlowDetail(r.Context(), in)
	case r.Method == "POST" && r.URL.Path == "/v1/flows/decode":
		var in packets.FlowDecodeRequest
		if !decodeProxyInput(w, r, &in) {
			return
		}
		v, e = b.FlowDecode(r.Context(), in)
	case r.Method == "POST" && r.URL.Path == "/v1/exchange/decode":
		var in ExchangeDecodeRequest
		if !decodeProxyInput(w, r, &in) {
			return
		}
		v, e = b.ExchangeDecode(r.Context(), in)
	case r.Method == "GET" && r.URL.Path == "/v1/descriptors":
		v, e = b.DescriptorList(r.Context())
	case r.Method == "POST" && r.URL.Path == "/v1/descriptors/preview":
		var in DescriptorPreviewRequest
		if !decodeDescriptorIPC(w, r, &in) {
			return
		}
		if in.Initiator.Validate() != nil || in.ServiceID.Validate() != nil || in.ReleaseID != "" && in.ReleaseID.Validate() != nil || len(in.Data) == 0 || len(in.Data) > protocols.MaxDescriptorBytes {
			writeError(w, 400, "invalid_request", "valid actor, service and bounded descriptor required")
			return
		}
		v, e = b.DescriptorPreview(r.Context(), in)
	case r.Method == "POST" && r.URL.Path == "/v1/descriptors/confirm":
		var in DescriptorConfirmRequest
		if !decodeProxyInput(w, r, &in) {
			return
		}
		if in.Initiator.Validate() != nil || in.ProposalID.Validate() != nil || in.Digest.Validate() != nil {
			writeError(w, 400, "invalid_request", "valid descriptor confirmation required")
			return
		}
		v, e = b.DescriptorConfirm(r.Context(), in)
	case r.Method == "POST" && r.URL.Path == "/v1/descriptors/delete":
		var in DescriptorDeleteRequest
		if !decodeProxyInput(w, r, &in) {
			return
		}
		if in.Initiator.Validate() != nil || !validPacketID(in.ID) {
			writeError(w, 400, "invalid_request", "valid descriptor and actor required")
			return
		}
		e = b.DescriptorDelete(r.Context(), in)
		v = map[string]bool{"ok": e == nil}
	default:
		writeError(w, 404, "not_found", "unknown analysis endpoint")
		return
	}
	if e != nil {
		proxyBackendError(w, e)
		return
	}
	writeJSON(w, 200, v)
}
func decodeDescriptorIPC(w http.ResponseWriter, r *http.Request, out any) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		writeError(w, 415, "invalid_content_type", "JSON required")
		return false
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, packets.MaxDescriptorRequestBytes))
	if e != nil || DecodeRegistrationJSON(raw, out) != nil {
		writeError(w, 400, "invalid_request", "one bounded typed descriptor object required")
		return false
	}
	return true
}
func (c *Client) FlowList(ctx context.Context, q packets.Query) (v packets.FlowPage, e error) {
	e = c.request(ctx, "GET", "/v1/flows?"+packets.QueryValues(q).Encode(), nil, &v)
	return
}
func (c *Client) FlowDetail(ctx context.Context, in packets.FlowDetailRequest) (v flows.Detail, e error) {
	e = c.request(ctx, "POST", "/v1/flows/detail", in, &v)
	return
}
func (c *Client) FlowDecode(ctx context.Context, in packets.FlowDecodeRequest) (v protocols.Result, e error) {
	e = c.request(ctx, "POST", "/v1/flows/decode", in, &v)
	return
}
func (c *Client) ExchangeDecode(ctx context.Context, in ExchangeDecodeRequest) (v protocols.Result, e error) {
	e = c.request(ctx, "POST", "/v1/exchange/decode", in, &v)
	return
}
func (c *Client) DescriptorList(ctx context.Context) (v []packets.DescriptorView, e error) {
	e = c.request(ctx, "GET", "/v1/descriptors", nil, &v)
	return
}
func (c *Client) DescriptorPreview(ctx context.Context, in DescriptorPreviewRequest) (v packets.DescriptorPreview, e error) {
	e = c.requestLimits(ctx, "POST", "/v1/descriptors/preview", in, &v, packets.MaxDescriptorRequestBytes, 4<<20)
	return
}
func (c *Client) DescriptorConfirm(ctx context.Context, in DescriptorConfirmRequest) (v packets.DescriptorView, e error) {
	e = c.request(ctx, "POST", "/v1/descriptors/confirm", in, &v)
	return
}
func (c *Client) DescriptorDelete(ctx context.Context, in DescriptorDeleteRequest) error {
	var v any
	return c.request(ctx, "POST", "/v1/descriptors/delete", in, &v)
}
