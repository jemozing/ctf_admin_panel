package protocols

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func headerValue(headers []Header, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}
func headerValues(headers []Header, name string) []string {
	values := []string{}
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			values = append(values, h.Value)
		}
	}
	return values
}
func isGRPC(headers []Header) bool {
	value := strings.ToLower(strings.TrimSpace(strings.Split(headerValue(headers, "content-type"), ";")[0]))
	return value == "application/grpc" || strings.HasPrefix(value, "application/grpc+")
}
func addReason(list *[]string, value string) {
	for _, old := range *list {
		if old == value {
			return
		}
	}
	if len(*list) < 32 {
		*list = append(*list, value)
	}
}
func contextBound(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 2*time.Second)
}

func validateHeaderList(headers []Header) bool {
	if len(headers) > MaxHeaderFields {
		return false
	}
	total := 0
	for _, h := range headers {
		total += len(h.Name) + len(h.Value) + 32
		if total > MaxHeaderBytes || h.Name == "" || len(h.Name) > 128 || len(h.Value) > 8192 || h.Name != strings.ToLower(h.Name) || strings.ContainsAny(h.Value, "\r\n\x00") {
			return false
		}
		for i, r := range h.Name {
			if r == ':' && i == 0 {
				continue
			}
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r) {
				continue
			}
			return false
		}
	}
	return true
}
func headerEstimate(headers []Header) int {
	total := 0
	for _, h := range headers {
		total += (len(h.Name)+len(h.Value))*6 + 64
	}
	return total
}
func copyHeaders(headers []Header) []Header { return append([]Header{}, headers...) }

func finishRPC(ctx context.Context, rpc *RPC, request, response []byte, opts Options, result *Result) {
	rpc.Path = headerValue(rpc.RequestHeaders, ":path")
	rpc.IsGRPC = isGRPC(rpc.RequestHeaders) || isGRPC(rpc.ResponseHeaders)
	if value := headerValue(rpc.ResponseHeaders, ":status"); value != "" {
		rpc.HTTPStatus, _ = strconv.Atoi(value)
	}
	if !rpc.IsGRPC {
		return
	}
	if headerValue(rpc.RequestHeaders, ":method") != "POST" {
		addReason(&rpc.Errors, "grpc_requires_post")
	}
	if rpc.Path == "" {
		addReason(&rpc.Errors, "grpc_method_path_missing")
	}
	if opts.Descriptor != nil {
		if !opts.Descriptor.matches(opts.Binding) {
			addReason(&rpc.Errors, "descriptor_binding_mismatch")
		} else if method := opts.Descriptor.method(rpc.Path); method != nil {
			client, server := method.IsStreamingClient(), method.IsStreamingServer()
			rpc.ClientStreaming = &client
			rpc.ServerStreaming = &server
		}
	}
	requestEncoding := strings.ToLower(headerValue(rpc.RequestHeaders, "grpc-encoding"))
	responseEncoding := strings.ToLower(headerValue(rpc.ResponseHeaders, "grpc-encoding"))
	if len(headerValues(rpc.RequestHeaders, "grpc-encoding")) > 1 {
		requestEncoding = "ambiguous"
		addReason(&rpc.Errors, "grpc_encoding_ambiguous")
	}
	if len(headerValues(rpc.ResponseHeaders, "grpc-encoding")) > 1 {
		responseEncoding = "ambiguous"
		addReason(&rpc.Errors, "grpc_encoding_ambiguous")
	}
	rpc.RequestMessages = parseMessages(ctx, request, requestEncoding, rpc.Path, false, opts, result, &rpc.Errors, MaxMessages)
	rpc.ResponseMessages = parseMessages(ctx, response, responseEncoding, rpc.Path, true, opts, result, &rpc.Errors, MaxMessages-len(rpc.RequestMessages))
	statuses := append(headerValues(rpc.ResponseHeaders, "grpc-status"), headerValues(rpc.ResponseTrailers, "grpc-status")...)
	if len(statuses) > 1 {
		addReason(&rpc.Errors, "grpc_status_ambiguous")
	} else if len(statuses) == 1 {
		number, err := strconv.Atoi(statuses[0])
		if err != nil || number < 0 || number > 16 {
			addReason(&rpc.Errors, "grpc_status_invalid")
		} else {
			rpc.GRPCStatus = &number
		}
	} else {
		addReason(&rpc.Errors, "grpc_status_missing")
	}
	message := headerValue(rpc.ResponseTrailers, "grpc-message")
	if message == "" {
		message = headerValue(rpc.ResponseHeaders, "grpc-message")
	}
	if decoded, err := url.PathUnescape(message); err == nil {
		rpc.GRPCMessage = decoded
	} else {
		rpc.GRPCMessage = message
		addReason(&rpc.Errors, "grpc_message_invalid_escape")
	}
	rpc.Incomplete = rpc.Incomplete || !rpc.RequestEnded || !rpc.ResponseEnded || len(rpc.Errors) > 0
}
func parseMessages(ctx context.Context, body []byte, encoding, path string, response bool, opts Options, result *Result, issues *[]string, messageLimit int) []Message {
	messages := []Message{}
	if encoding == "" {
		encoding = "identity"
	}
	for len(body) > 0 {
		if ctx.Err() != nil {
			addReason(issues, "analysis_timeout")
			result.Truncated = true
			break
		}
		if len(messages) == messageLimit {
			addReason(issues, "grpc_message_count_limit")
			result.Truncated = true
			break
		}
		if len(body) < 5 {
			addReason(issues, "grpc_frame_prefix_incomplete")
			break
		}
		compressed := body[0]
		length := int64(binary.BigEndian.Uint32(body[1:5]))
		body = body[5:]
		if compressed > 1 {
			addReason(issues, "grpc_compression_flag_invalid")
			break
		}
		if length > MaxMessageBytes {
			addReason(issues, "grpc_message_size_limit")
			result.Truncated = true
			break
		}
		if length > int64(len(body)) {
			addReason(issues, "grpc_message_incomplete")
			break
		}
		wire := body[:int(length)]
		body = body[int(length):]
		msg := Message{Index: len(messages), Compressed: compressed == 1, Encoding: "identity", WireLength: len(wire)}
		data := wire
		if compressed == 1 {
			msg.Encoding = encoding
			if encoding != "gzip" {
				msg.Error = "unsupported_grpc_encoding"
			} else {
				value, err := inflate(ctx, wire)
				if err != nil {
					msg.Error = "grpc_gzip_invalid_or_limit"
					if errors.Is(err, errGzipLimit) {
						msg.Error = "grpc_gzip_limit"
						result.Truncated = true
					}
				} else {
					data = value
				}
			}
		}
		if result.DecodedBytes+len(data) > MaxDecodedBytes {
			addReason(issues, "decoded_byte_limit")
			result.Truncated = true
			break
		}
		msg.Data = append([]byte(nil), data...)
		if msg.Error == "" {
			msg.DecodedLength = len(data)
		}
		result.DecodedBytes += len(data)
		if opts.Descriptor != nil && msg.Error == "" {
			msg.Type, msg.JSON, msg.Error = opts.Descriptor.decode(data, path, response, opts.Binding)
			if result.DecodedBytes+len(msg.JSON) > MaxDecodedBytes {
				msg.JSON = nil
				msg.Error = "decoded_byte_limit"
				result.Truncated = true
			} else {
				result.DecodedBytes += len(msg.JSON)
			}
		}
		if msg.Error != "" {
			addReason(issues, msg.Error)
		}
		messages = append(messages, msg)
	}
	return messages
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

var errGzipLimit = errors.New("gzip resource limit")

func inflate(ctx context.Context, raw []byte) ([]byte, error) {
	source := bytes.NewReader(raw)
	z, err := gzip.NewReader(source)
	if err != nil {
		return nil, err
	}
	defer z.Close()
	z.Multistream(false)
	limit := min(MaxMessageBytes, len(raw)*128+1024)
	value, err := io.ReadAll(io.LimitReader(contextReader{ctx, z}, int64(limit)+1))
	if len(value) > limit {
		return nil, errGzipLimit
	}
	if err != nil || source.Len() != 0 {
		return nil, errors.New("gzip invalid or resource limit")
	}
	return value, nil
}

// DecodeExchange analyzes HTTP/2 already terminated by an explicitly selected
// proxy profile. It never accepts a key log or contacts a service.
func DecodeExchange(parent context.Context, exchange Exchange, opts Options) (Result, error) {
	ctx, cancel := contextBound(parent)
	defer cancel()
	result := Result{Protocol: "http2", Status: "decoded", RPCs: []RPC{}, Reasons: []string{}, InputBytes: len(exchange.RequestBody) + len(exchange.ResponseBody)}
	if result.InputBytes > MaxInputBytes {
		result.Status = "limit"
		result.Truncated = true
		addReason(&result.Reasons, "input_byte_limit")
		return result, nil
	}
	for _, headers := range [][]Header{exchange.RequestHeaders, exchange.ResponseHeaders, exchange.RequestTrailers, exchange.ResponseTrailers} {
		if result.DecodedBytes+headerEstimate(headers) > MaxDecodedBytes {
			result.Status = "limit"
			result.Truncated = true
			addReason(&result.Reasons, "header_output_limit")
			return result, nil
		}
		result.DecodedBytes += headerEstimate(headers)
		if !validateHeaderList(headers) {
			result.Status = "invalid"
			addReason(&result.Reasons, "header_limit_or_invalid")
			return result, nil
		}
	}
	rpc := RPC{StreamID: 1, RequestHeaders: copyHeaders(exchange.RequestHeaders), ResponseHeaders: copyHeaders(exchange.ResponseHeaders), RequestTrailers: copyHeaders(exchange.RequestTrailers), ResponseTrailers: copyHeaders(exchange.ResponseTrailers), RequestMessages: []Message{}, ResponseMessages: []Message{}, RequestEnded: exchange.RequestComplete, ResponseEnded: exchange.ResponseComplete, Incomplete: exchange.RequestTruncated || exchange.ResponseTruncated, Errors: []string{}}
	if exchange.RequestTruncated || exchange.ResponseTruncated {
		addReason(&rpc.Errors, "captured_body_truncated")
	}
	finishRPC(ctx, &rpc, exchange.RequestBody, exchange.ResponseBody, opts, &result)
	result.RPCs = append(result.RPCs, rpc)
	if rpc.IsGRPC {
		result.Protocol = "grpc"
	}
	result.Incomplete = rpc.Incomplete
	result.Truncated = result.Truncated || exchange.RequestTruncated || exchange.ResponseTruncated
	if result.Incomplete {
		result.Status = "incomplete"
	}
	if result.Truncated {
		result.Status = "limit"
	}
	if opts.Descriptor != nil {
		result.DescriptorDigest = opts.Descriptor.info.Digest
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	return result, nil
}
