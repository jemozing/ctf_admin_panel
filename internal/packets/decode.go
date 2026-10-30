package packets

import (
	"context"
	"errors"
	"net/http"

	"github.com/ctf-service-manager/ctf-service-manager/internal/flows"
	"github.com/ctf-service-manager/ctf-service-manager/internal/protocols"
)

func protocolDirection(d flows.Direction) protocols.DirectionInput {
	out := protocols.DirectionInput{PrefixMissing: d.Midstream, Gap: len(d.Gaps) > 0, Truncated: d.Truncated}
	if d.ConflictingOverlaps > 0 {
		out.Gap = true
		out.Truncated = true
		return out
	}
	var end int64
	for _, c := range d.Chunks {
		if c.Offset != end {
			out.Gap = true
			break
		}
		if len(out.Data)+len(c.Data) > protocols.MaxInputBytes {
			out.Truncated = true
			break
		}
		out.Data = append(out.Data, c.Data...)
		end += int64(len(c.Data))
	}
	return out
}
func (s *Store) FlowDecode(ctx context.Context, in FlowDecodeRequest) (protocols.Result, error) {
	d, e := s.FlowDetail(ctx, FlowDetailRequest{Query: in.Query, FlowID: in.FlowID})
	if e != nil {
		return protocols.Result{}, e
	}
	if d.Protocol != "tcp" {
		return protocols.Result{Protocol: "unknown", Status: "unsupported", Reasons: []string{"UDP datagrams are not an HTTP/2 TCP stream"}, RPCs: []protocols.RPC{}}, nil
	}
	if d.ConflictingOverlaps > 0 {
		return protocols.Result{Protocol: "unknown", Status: "invalid", Incomplete: true, Reasons: []string{"tcp_conflicting_overlap_decode_refused"}, RPCs: []protocols.RPC{}}, nil
	}
	input := protocols.Input{}
	for _, direction := range d.Directions {
		if direction.From == "a" {
			input.AToB = protocolDirection(direction)
		} else {
			input.BToA = protocolDirection(direction)
		}
	}
	options := protocols.Options{}
	if in.DescriptorID != "" {
		if d.MissingVersionBindings {
			return protocols.Result{}, errors.New("descriptor cannot name legacy or unbound contributing payload")
		}
		descriptor, e := s.loadDescriptor(ctx, in.DescriptorID)
		if e != nil {
			return protocols.Result{}, e
		}
		binding := descriptor.Info().Binding
		pins := map[string]string{}
		for _, v := range d.VersionBindings {
			if v.ServiceID != binding.ServiceID {
				continue
			}
			key := v.ServiceID + "/" + v.Component
			pin := v.ReleaseID + "/" + v.SourceDigest
			if previous, ok := pins[key]; ok && previous != pin {
				return protocols.Result{}, errors.New("descriptor cannot name a flow with conflicting captured code versions")
			}
			pins[key] = pin
		}
		found := false
		for _, v := range d.VersionBindings {
			if v.ServiceID == binding.ServiceID && (binding.ReleaseID == "" || v.ReleaseID == binding.ReleaseID) && (binding.SourceDigest == "" || v.SourceDigest == binding.SourceDigest) {
				options.Binding = protocols.Binding{ServiceID: v.ServiceID, ReleaseID: v.ReleaseID, SourceDigest: v.SourceDigest}
				found = true
				break
			}
		}
		if !found {
			return protocols.Result{}, errors.New("descriptor is not bound to this captured service version")
		}
		options.Descriptor = descriptor
	}
	result, e := protocols.Decode(ctx, input, options)
	if d.Incomplete {
		result.Incomplete = true
		result.Reasons = append(result.Reasons, "capture_window_incomplete")
	}
	return result, e
}
func (s *Store) ExchangeDecode(ctx context.Context, in ExchangeDecodeRequest) (protocols.Result, error) {
	options := protocols.Options{Binding: in.Binding}
	if in.DescriptorID != "" {
		descriptor, e := s.loadDescriptor(ctx, in.DescriptorID)
		if e != nil {
			return protocols.Result{}, e
		}
		options.Descriptor = descriptor
	}
	return protocols.DecodeExchange(ctx, in.Exchange, options)
}
func (s *Store) decodeHTTP(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/v1/flows/decode" && r.URL.Path != "/v1/exchange/decode" {
		return false
	}
	if r.Method != "POST" {
		httpError(w, 405, "method_not_allowed")
		return true
	}
	var out protocols.Result
	var e error
	if r.URL.Path == "/v1/flows/decode" {
		var in FlowDecodeRequest
		if decodeBody(w, r, &in, 16384) != nil {
			httpError(w, 400, "invalid_decode")
			return true
		}
		out, e = s.FlowDecode(r.Context(), in)
	} else {
		var in ExchangeDecodeRequest
		if decodeBody(w, r, &in, MaxDescriptorRequestBytes) != nil {
			httpError(w, 400, "invalid_decode")
			return true
		}
		out, e = s.ExchangeDecode(r.Context(), in)
	}
	if e != nil {
		httpError(w, 400, "decode_unavailable_or_binding_mismatch")
		return true
	}
	respond(w, 200, out)
	return true
}
func (c *Client) FlowDecode(ctx context.Context, in FlowDecodeRequest) (v protocols.Result, e error) {
	e = c.request(ctx, "POST", "/v1/flows/decode", in, &v, 200)
	return
}
func (c *Client) ExchangeDecode(ctx context.Context, in ExchangeDecodeRequest) (v protocols.Result, e error) {
	e = c.descriptorRequest(ctx, "POST", "/v1/exchange/decode", in, &v)
	return
}
