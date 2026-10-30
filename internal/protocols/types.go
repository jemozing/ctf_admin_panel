// Package protocols performs bounded, offline protocol analysis. It has no
// sockets, filesystem access, reflection client, plugin loader or raw-socket
// capabilities. All returned bytes and metadata are sensitive traffic content.
package protocols

import (
	"encoding/json"
)

const (
	MaxInputBytes       = 8 << 20
	MaxDescriptorBytes  = 2 << 20
	MaxStreams          = 128
	MaxMessages         = 32
	MaxMessageBytes     = 1 << 20
	MaxDecodedBytes     = 2 << 20
	MaxHeaderBytes      = 16 << 10
	MaxHeaderBlockBytes = 64 << 10
	MaxHeaderFields     = 128
	MaxFrameBytes       = 1 << 20
	MaxFrames           = 8192
)

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type Binding struct {
	ServiceID    string `json:"service_id"`
	ReleaseID    string `json:"release_id,omitempty"`
	SourceDigest string `json:"source_digest,omitempty"`
}

// Data must contain only the contiguous prefix before the first gap. A caller
// must never concatenate separated TCP chunks and present them as contiguous.
type DirectionInput struct {
	Data          []byte `json:"data,omitempty"`
	PrefixMissing bool   `json:"prefix_missing"`
	Gap           bool   `json:"gap"`
	Truncated     bool   `json:"truncated"`
}
type Input struct {
	AToB DirectionInput `json:"a_to_b"`
	BToA DirectionInput `json:"b_to_a"`
}
type Options struct {
	Descriptor *Descriptor
	Binding    Binding
}
type Message struct {
	Index         int             `json:"index"`
	Compressed    bool            `json:"compressed"`
	Encoding      string          `json:"encoding"`
	WireLength    int             `json:"wire_length"`
	DecodedLength int             `json:"decoded_length"`
	Data          []byte          `json:"data,omitempty"`
	Type          string          `json:"type,omitempty"`
	JSON          json.RawMessage `json:"json,omitempty"`
	Error         string          `json:"error,omitempty"`
}
type RPC struct {
	StreamID         uint32    `json:"stream_id"`
	Path             string    `json:"path,omitempty"`
	RequestHeaders   []Header  `json:"request_headers"`
	ResponseHeaders  []Header  `json:"response_headers"`
	RequestTrailers  []Header  `json:"request_trailers"`
	ResponseTrailers []Header  `json:"response_trailers"`
	RequestMessages  []Message `json:"request_messages"`
	ResponseMessages []Message `json:"response_messages"`
	RequestEnded     bool      `json:"request_ended"`
	ResponseEnded    bool      `json:"response_ended"`
	GRPCStatus       *int      `json:"grpc_status,omitempty"`
	GRPCMessage      string    `json:"grpc_message,omitempty"`
	HTTPStatus       int       `json:"http_status,omitempty"`
	ResetCode        *uint32   `json:"reset_code,omitempty"`
	ClientStreaming  *bool     `json:"client_streaming,omitempty"`
	ServerStreaming  *bool     `json:"server_streaming,omitempty"`
	IsGRPC           bool      `json:"is_grpc"`
	Incomplete       bool      `json:"incomplete"`
	Errors           []string  `json:"errors"`
}
type Result struct {
	Protocol         string   `json:"protocol"` // grpc, http2, tls_encrypted, unknown
	Status           string   `json:"status"`   // decoded, incomplete, unsupported, invalid, limit
	ClientDirection  string   `json:"client_direction,omitempty"`
	RPCs             []RPC    `json:"rpcs"`
	Frames           int      `json:"frames"`
	InputBytes       int      `json:"input_bytes"`
	DecodedBytes     int      `json:"decoded_bytes"`
	DescriptorDigest string   `json:"descriptor_digest,omitempty"`
	Incomplete       bool     `json:"incomplete"`
	Truncated        bool     `json:"truncated"`
	Reasons          []string `json:"reasons"`
}

// Exchange describes already terminated HTTP/2 traffic. It does not accept TLS
// keys and does not pretend its bodies are captured wire HTTP/2 frames.
type Exchange struct {
	RequestHeaders    []Header `json:"request_headers"`
	ResponseHeaders   []Header `json:"response_headers"`
	RequestTrailers   []Header `json:"request_trailers"`
	ResponseTrailers  []Header `json:"response_trailers"`
	RequestBody       []byte   `json:"request_body,omitempty"`
	ResponseBody      []byte   `json:"response_body,omitempty"`
	RequestComplete   bool     `json:"request_complete"`
	ResponseComplete  bool     `json:"response_complete"`
	RequestTruncated  bool     `json:"request_truncated"`
	ResponseTruncated bool     `json:"response_truncated"`
}
type MethodInfo struct {
	Path            string `json:"path"`
	InputType       string `json:"input_type"`
	OutputType      string `json:"output_type"`
	ClientStreaming bool   `json:"client_streaming"`
	ServerStreaming bool   `json:"server_streaming"`
}
type DescriptorInfo struct {
	Digest  string       `json:"digest"`
	Binding Binding      `json:"binding"`
	Bytes   int          `json:"bytes"`
	Files   int          `json:"files"`
	Methods []MethodInfo `json:"methods"`
}
