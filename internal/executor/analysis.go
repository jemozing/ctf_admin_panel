package executor

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ctf-service-manager/ctf-service-manager/internal/flows"
	"github.com/ctf-service-manager/ctf-service-manager/internal/packets"
	"github.com/ctf-service-manager/ctf-service-manager/internal/protocols"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/traffic"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func (m *Manager) FlowList(ctx context.Context, q packets.Query) (packets.FlowPage, error) {
	c, e := m.packetsClient()
	if e != nil {
		return packets.FlowPage{}, e
	}
	defer c.Close()
	v, e := c.FlowList(ctx, q)
	return v, analysisArchiveError(e)
}
func (m *Manager) FlowDetail(ctx context.Context, in packets.FlowDetailRequest) (flows.Detail, error) {
	c, e := m.packetsClient()
	if e != nil {
		return flows.Detail{}, e
	}
	defer c.Close()
	v, e := c.FlowDetail(ctx, in)
	return v, analysisArchiveError(e)
}
func (m *Manager) FlowDecode(ctx context.Context, in packets.FlowDecodeRequest) (protocols.Result, error) {
	c, e := m.packetsClient()
	if e != nil {
		return protocols.Result{}, e
	}
	defer c.Close()
	v, e := c.FlowDecode(ctx, in)
	return v, analysisArchiveError(e)
}
func (m *Manager) DescriptorList(ctx context.Context) ([]packets.DescriptorView, error) {
	c, e := m.packetsClient()
	if e != nil {
		return nil, e
	}
	defer c.Close()
	v, e := c.Descriptors(ctx)
	return v, analysisArchiveError(e)
}
func (m *Manager) DescriptorPreview(ctx context.Context, in transport.DescriptorPreviewRequest) (packets.DescriptorPreview, error) {
	var empty packets.DescriptorPreview
	if in.Initiator.Validate() != nil || in.ServiceID.Validate() != nil {
		return empty, proxyInput("Authenticated descriptor actor and service required")
	}
	s, e := m.Store.GetService(ctx, in.ServiceID)
	if e != nil {
		return empty, e
	}
	releaseID := in.ReleaseID
	if releaseID == "" {
		state, e := m.state(ctx, s)
		if e != nil {
			return empty, e
		}
		releaseID = state.CurrentReleaseID
	}
	release, e := m.loadRelease(ctx, s, releaseID)
	if e != nil {
		return empty, e
	}
	binding := protocols.Binding{ServiceID: string(s.ID), ReleaseID: string(releaseID), SourceDigest: string(release.Spec().TreeDigest)}
	c, e := m.packetsClient()
	if e != nil {
		return empty, e
	}
	defer c.Close()
	v, e := c.DescriptorPreview(ctx, packets.DescriptorPreviewRequest{Binding: binding, Data: in.Data, Actor: string(in.Initiator)})
	return v, analysisArchiveError(e)
}
func (m *Manager) DescriptorConfirm(ctx context.Context, in transport.DescriptorConfirmRequest) (packets.DescriptorView, error) {
	if in.Initiator.Validate() != nil {
		return packets.DescriptorView{}, proxyInput("Authenticated descriptor actor required")
	}
	c, e := m.packetsClient()
	if e != nil {
		return packets.DescriptorView{}, e
	}
	defer c.Close()
	v, e := c.DescriptorConfirm(ctx, packets.DescriptorConfirmRequest{ProposalID: string(in.ProposalID), Digest: string(in.Digest), Actor: string(in.Initiator)})
	return v, analysisArchiveError(e)
}
func (m *Manager) DescriptorDelete(ctx context.Context, in transport.DescriptorDeleteRequest) error {
	if in.Initiator.Validate() != nil {
		return proxyInput("Authenticated descriptor actor required")
	}
	c, e := m.packetsClient()
	if e != nil {
		return e
	}
	defer c.Close()
	return analysisArchiveError(c.DescriptorDelete(ctx, in.ID))
}
func protocolHeaders(in http.Header) []protocols.Header {
	out := []protocols.Header{}
	for name, values := range in {
		for _, value := range values {
			out = append(out, protocols.Header{Name: strings.ToLower(name), Value: value})
		}
	}
	return out
}
func protocolBody(in traffic.Body) ([]byte, error) {
	if in.NotCapturedReason != "" {
		return nil, nil
	}
	if in.Encoding == "base64" {
		if len(in.Data) > 3<<20 {
			return nil, errors.New("captured exchange body exceeds decode limit")
		}
		return base64.StdEncoding.DecodeString(in.Data)
	}
	if in.Encoding == "utf8" || in.Encoding == "" {
		return []byte(in.Data), nil
	}
	return nil, errors.New("unsupported captured body encoding")
}
func (m *Manager) ExchangeDecode(ctx context.Context, in transport.ExchangeDecodeRequest) (protocols.Result, error) {
	v, e := m.TrafficDetail(ctx, in.RequestID)
	if e != nil {
		return protocols.Result{}, e
	}
	if v.HTTPProtocol != "h2" {
		return protocols.Result{}, proxyInput("Only explicit HTTP/2 terminated exchanges can use the gRPC decoder")
	}
	// Termination exchanges have no trusted container-release observation. Never
	// substitute the CURRENT release for historical traffic. A version-pinned
	// backend packet flow can provide protobuf field names when capture is enabled.
	if in.DescriptorID != "" {
		return protocols.Result{}, proxyInput("This HTTP exchange has no captured release binding; select its version-pinned backend TCP flow for descriptor decoding")
	}
	request, e := protocolBody(v.RequestBody)
	if e != nil {
		return protocols.Result{}, e
	}
	response, e := protocolBody(v.ResponseBody)
	if e != nil {
		return protocols.Result{}, e
	}
	ex := protocols.Exchange{RequestHeaders: protocolHeaders(v.RequestHeaders), ResponseHeaders: protocolHeaders(v.ResponseHeaders), RequestTrailers: protocolHeaders(v.RequestTrailers), ResponseTrailers: protocolHeaders(v.ResponseTrailers), RequestBody: request, ResponseBody: response, RequestComplete: v.State == "completed", ResponseComplete: v.State == "completed", RequestTruncated: v.RequestBody.Truncated || v.RequestBody.NotCapturedReason != "", ResponseTruncated: v.ResponseBody.Truncated || v.ResponseBody.NotCapturedReason != ""}
	path := v.URL
	if parsed, e := url.Parse(path); e == nil {
		path = parsed.Path
	}
	ex.RequestHeaders = append(ex.RequestHeaders, protocols.Header{Name: ":method", Value: v.Method}, protocols.Header{Name: ":path", Value: path})
	ex.ResponseHeaders = append(ex.ResponseHeaders, protocols.Header{Name: ":status", Value: strconv.Itoa(v.Status)})
	c, e := m.packetsClient()
	if e != nil {
		return protocols.Result{}, e
	}
	defer c.Close()
	decoded, e := c.ExchangeDecode(ctx, packets.ExchangeDecodeRequest{Exchange: ex, Binding: protocols.Binding{ServiceID: v.ServiceID}})
	return decoded, analysisArchiveError(e)
}

func analysisArchiveError(e error) error {
	if e == nil {
		return nil
	}
	switch {
	case errors.Is(e, packets.ErrNotFound):
		return store.ErrNotFound
	case errors.Is(e, packets.ErrConflict) || errors.Is(e, packets.ErrExpired):
		return store.ErrConflict
	case errors.Is(e, packets.ErrInvalid):
		return proxyInput("Archive rejected analysis: check the captured version, selected descriptor and query scope")
	case errors.Is(e, packets.ErrQuota):
		return proxyInput("Descriptor archive quota or free-space reserve exceeded")
	}
	return e
}
