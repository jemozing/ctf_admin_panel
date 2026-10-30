package protocols

import (
	"bytes"
	"context"
	"io"
	"sort"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const clientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

type rpcState struct {
	rpc                             RPC
	request, response               []byte
	requestHeaders, responseHeaders bool
	headerBytes                     int
}
type analysis struct {
	ctx       context.Context
	result    Result
	streams   map[uint32]*rpcState
	bodyBytes int
}

// Decode requires a captured HTTP/2 client preface and independently decodes
// the two HPACK contexts. Gaps must be removed by stopping at the first hole,
// not by joining bytes that were never contiguous on the wire.
func Decode(parent context.Context, input Input, opts Options) (Result, error) {
	ctx, cancel := contextBound(parent)
	defer cancel()
	a := &analysis{ctx: ctx, result: Result{Protocol: "unknown", Status: "unsupported", RPCs: []RPC{}, Reasons: []string{}, InputBytes: len(input.AToB.Data) + len(input.BToA.Data)}, streams: map[uint32]*rpcState{}}
	if a.result.InputBytes > MaxInputBytes {
		a.result.Status = "limit"
		a.result.Truncated = true
		addReason(&a.result.Reasons, "input_byte_limit")
		return a.result, nil
	}
	client, server := input.AToB, input.BToA
	if bytes.HasPrefix(client.Data, []byte(clientPreface)) {
		a.result.ClientDirection = "a_to_b"
	} else if bytes.HasPrefix(server.Data, []byte(clientPreface)) {
		client, server = server, client
		a.result.ClientDirection = "b_to_a"
	} else {
		if looksTLS(client.Data) || looksTLS(server.Data) {
			a.result.Protocol = "tls_encrypted"
			addReason(&a.result.Reasons, "tls_payload_requires_explicit_termination_or_session_secrets")
		} else {
			addReason(&a.result.Reasons, "http2_client_preface_missing")
		}
		if client.Gap || server.Gap || client.PrefixMissing || server.PrefixMissing || client.Truncated || server.Truncated || partialPreface(client.Data) || partialPreface(server.Data) {
			a.result.Status = "incomplete"
			a.result.Incomplete = true
		}
		return a.result, nil
	}
	a.result.Protocol, a.result.Status = "http2", "decoded"
	if client.PrefixMissing || server.PrefixMissing {
		a.result.Incomplete = true
		addReason(&a.result.Reasons, "tcp_prefix_not_observed")
	}
	if client.Gap || server.Gap {
		a.result.Incomplete = true
		addReason(&a.result.Reasons, "tcp_gap_stopped_decode")
	}
	if client.Truncated || server.Truncated {
		a.result.Truncated = true
		a.result.Incomplete = true
		addReason(&a.result.Reasons, "tcp_capture_truncated_or_conflicting")
	}
	a.parseDirection(client.Data[len(clientPreface):], false)
	if ctx.Err() == nil {
		a.parseDirection(server.Data, true)
	}
	ids := []int{}
	for id := range a.streams {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	transportIncomplete := a.result.Incomplete
	for _, id := range ids {
		state := a.streams[uint32(id)]
		if transportIncomplete {
			state.rpc.Incomplete = true
		}
		finishRPC(ctx, &state.rpc, state.request, state.response, opts, &a.result)
		if state.rpc.IsGRPC {
			a.result.Protocol = "grpc"
		}
		a.result.Incomplete = a.result.Incomplete || state.rpc.Incomplete
		a.result.RPCs = append(a.result.RPCs, state.rpc)
	}
	if opts.Descriptor != nil {
		a.result.DescriptorDigest = opts.Descriptor.info.Digest
	}
	if a.result.Status == "decoded" && a.result.Incomplete {
		a.result.Status = "incomplete"
	}
	if a.result.Truncated {
		a.result.Status = "limit"
	}
	if err := ctx.Err(); err != nil {
		addReason(&a.result.Reasons, "analysis_timeout")
		a.result.Incomplete = true
		return a.result, err
	}
	return a.result, nil
}
func looksTLS(data []byte) bool {
	return len(data) >= 3 && (data[0] == 20 || data[0] == 21 || data[0] == 22 || data[0] == 23) && data[1] == 3 && data[2] <= 4
}
func partialPreface(data []byte) bool {
	return len(data) > 0 && len(data) < len(clientPreface) && bytes.HasPrefix([]byte(clientPreface), data)
}
func (a *analysis) fail(reason string, limit bool) {
	addReason(&a.result.Reasons, reason)
	a.result.Incomplete = true
	if limit {
		a.result.Truncated = true
		a.result.Status = "limit"
	} else {
		a.result.Status = "invalid"
	}
}
func (a *analysis) stream(id uint32) *rpcState {
	if id == 0 || id&1 == 0 {
		a.fail("unsupported_even_or_zero_rpc_stream", false)
		return nil
	}
	if old := a.streams[id]; old != nil {
		return old
	}
	if len(a.streams) >= MaxStreams {
		a.fail("http2_stream_limit", true)
		return nil
	}
	state := &rpcState{rpc: RPC{StreamID: id, RequestHeaders: []Header{}, ResponseHeaders: []Header{}, RequestTrailers: []Header{}, ResponseTrailers: []Header{}, RequestMessages: []Message{}, ResponseMessages: []Message{}, Errors: []string{}}}
	a.streams[id] = state
	return state
}
func (a *analysis) parseDirection(data []byte, response bool) {
	reader := bytes.NewReader(data)
	framer := http2.NewFramer(io.Discard, reader)
	framer.SetMaxReadFrameSize(MaxFrameBytes)
	fields := []Header{}
	headerBytes := 0
	invalidHeaders := false
	decoder := hpack.NewDecoder(4096, func(field hpack.HeaderField) {
		headerBytes += len(field.Name) + len(field.Value) + 32
		if len(fields) >= MaxHeaderFields || headerBytes > MaxHeaderBytes {
			invalidHeaders = true
			return
		}
		fields = append(fields, Header{Name: field.Name, Value: field.Value})
	})
	decoder.SetAllowedMaxDynamicTableSize(4096)
	decoder.SetMaxDynamicTableSize(4096)
	decoder.SetMaxStringLength(8192)
	var pending []byte
	var pendingID uint32
	var pendingEnd bool
	finish := func() bool {
		fields = []Header{}
		headerBytes = 0
		invalidHeaders = false
		if _, err := decoder.Write(pending); err != nil {
			a.fail("hpack_invalid_or_budget", false)
			return false
		}
		if err := decoder.Close(); err != nil {
			a.fail("hpack_incomplete", false)
			return false
		}
		if invalidHeaders || !validateHeaderList(fields) {
			a.fail("http2_header_limit_or_invalid", true)
			return false
		}
		if a.result.DecodedBytes+headerEstimate(fields) > MaxDecodedBytes {
			a.fail("header_output_limit", true)
			return false
		}
		a.result.DecodedBytes += headerEstimate(fields)
		state := a.stream(pendingID)
		if state == nil {
			return false
		}
		state.headerBytes += headerBytes
		if state.headerBytes > MaxHeaderBytes*2 {
			a.fail("rpc_header_budget", true)
			return false
		}
		seen := state.requestHeaders
		if response {
			seen = state.responseHeaders
		}
		// Pseudo fields belong only in the initial header block, before regular
		// fields, and never repeat. No value is used to select a network endpoint.
		regular := false
		pseudo := map[string]bool{}
		for _, h := range fields {
			if strings.HasPrefix(h.Name, ":") {
				if seen || regular || pseudo[h.Name] {
					a.fail("http2_pseudo_header_order", false)
					return false
				}
				pseudo[h.Name] = true
				if response && h.Name != ":status" || !response && h.Name != ":method" && h.Name != ":path" && h.Name != ":scheme" && h.Name != ":authority" {
					a.fail("http2_pseudo_header_invalid", false)
					return false
				}
			} else {
				regular = true
			}
		}
		if response {
			if state.rpc.ResponseEnded {
				a.fail("http2_headers_after_end_stream", false)
				return false
			}
			if !state.responseHeaders {
				state.rpc.ResponseHeaders = copyHeaders(fields)
				state.responseHeaders = true
			} else {
				state.rpc.ResponseTrailers = append(state.rpc.ResponseTrailers, fields...)
			}
			state.rpc.ResponseEnded = pendingEnd
		} else {
			if state.rpc.RequestEnded {
				a.fail("http2_headers_after_end_stream", false)
				return false
			}
			if !state.requestHeaders {
				state.rpc.RequestHeaders = copyHeaders(fields)
				state.requestHeaders = true
			} else {
				state.rpc.RequestTrailers = append(state.rpc.RequestTrailers, fields...)
			}
			state.rpc.RequestEnded = pendingEnd
		}
		pending = nil
		pendingID = 0
		return true
	}
	for reader.Len() > 0 {
		if a.ctx.Err() != nil {
			return
		}
		if a.result.Frames >= MaxFrames {
			a.fail("http2_frame_count_limit", true)
			return
		}
		frame, err := framer.ReadFrame()
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				addReason(&a.result.Reasons, "http2_frame_incomplete")
				a.result.Incomplete = true
			} else {
				a.fail("http2_frame_invalid_or_size_limit", false)
			}
			return
		}
		a.result.Frames++
		switch f := frame.(type) {
		case *http2.HeadersFrame:
			if pendingID != 0 {
				a.fail("http2_continuation_required", false)
				return
			}
			pendingID = f.StreamID
			pendingEnd = f.StreamEnded()
			pending = append([]byte{}, f.HeaderBlockFragment()...)
			if len(pending) > MaxHeaderBlockBytes {
				a.fail("http2_header_block_limit", true)
				return
			}
			if f.HeadersEnded() && !finish() {
				return
			}
		case *http2.ContinuationFrame:
			if pendingID == 0 || pendingID != f.StreamID {
				a.fail("http2_unexpected_continuation", false)
				return
			}
			if len(pending)+len(f.HeaderBlockFragment()) > MaxHeaderBlockBytes {
				a.fail("http2_header_block_limit", true)
				return
			}
			pending = append(pending, f.HeaderBlockFragment()...)
			if f.HeadersEnded() && !finish() {
				return
			}
		case *http2.DataFrame:
			state := a.stream(f.StreamID)
			if state == nil {
				return
			}
			if response && !state.responseHeaders || !response && !state.requestHeaders {
				addReason(&state.rpc.Errors, "http2_data_before_headers")
				state.rpc.Incomplete = true
				continue
			}
			if response && state.rpc.ResponseEnded || !response && state.rpc.RequestEnded {
				a.fail("http2_data_after_end_stream", false)
				return
			}
			payload := f.Data()
			if a.bodyBytes+len(payload) > MaxInputBytes {
				a.fail("http2_body_budget", true)
				return
			}
			a.bodyBytes += len(payload)
			if response {
				state.response = append(state.response, payload...)
				state.rpc.ResponseEnded = f.StreamEnded()
			} else {
				state.request = append(state.request, payload...)
				state.rpc.RequestEnded = f.StreamEnded()
			}
		case *http2.RSTStreamFrame:
			state := a.stream(f.StreamID)
			if state == nil {
				return
			}
			code := uint32(f.ErrCode)
			state.rpc.ResetCode = &code
			state.rpc.Incomplete = true
			addReason(&state.rpc.Errors, "http2_stream_reset")
		case *http2.PushPromiseFrame:
			a.fail("http2_push_promise_unsupported", false)
			return
		case *http2.GoAwayFrame:
			addReason(&a.result.Reasons, "http2_goaway_observed")
		}
	}
	if pendingID != 0 {
		addReason(&a.result.Reasons, "http2_headers_incomplete")
		a.result.Incomplete = true
	}
}
