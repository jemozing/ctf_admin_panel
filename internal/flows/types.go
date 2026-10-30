// Package flows reconstructs bounded observations of TCP byte streams and UDP
// datagrams. It never opens sockets and has no container or filesystem access.
package flows

import (
	"context"
	"time"
)

const (
	MaxPackets         = 10000
	MaxBytes           = 8 << 20
	MaxFlows           = 256
	MaxDirectionBytes  = 1 << 20
	MaxDirectionChunks = 512
	MaxDatagrams       = 1024
)

type Candidate struct {
	ServiceID string `json:"service_id"`
	Component string `json:"component"`
}

// Packet is the narrow neutral input contract; archive metadata stays outside
// this package to avoid a dependency on storage or capture capabilities.
type VersionBinding struct {
	ServiceID    string `json:"service_id"`
	Component    string `json:"component"`
	ReleaseID    string `json:"release_id"`
	SourceDigest string `json:"source_digest"`
}
type Packet struct {
	VersionBindings []VersionBinding
	ID              string
	Sequence        int64
	At              time.Time
	CollectorEpoch  string
	PolicyRevision  uint64
	Interface       string
	IfIndex         int
	ServiceID       string
	Component       string
	Candidates      []Candidate
	Protocol        string
	SourceIP        string
	DestinationIP   string
	SourcePort      int
	DestinationPort int
	TCPFlags        uint8
	WireLength      int
	CapturedLength  int
	Truncated       bool
	Data            []byte
}
type Endpoint struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}
type ObservationPoint struct {
	Interface string `json:"interface"`
	IfIndex   int    `json:"if_index"`
}
type Metadata struct {
	MissingVersionBindings bool               `json:"missing_version_bindings"`
	VersionBindings        []VersionBinding   `json:"version_bindings,omitempty"`
	ID                     string             `json:"id"`
	Protocol               string             `json:"protocol"`
	CollectorEpoch         string             `json:"collector_epoch"`
	PolicyRevision         uint64             `json:"policy_revision"`
	Interface              string             `json:"interface"`
	IfIndex                int                `json:"if_index"`
	ObservationPoints      []ObservationPoint `json:"observation_points"`
	A                      Endpoint           `json:"a"`
	B                      Endpoint           `json:"b"`
	ServiceID              string             `json:"service_id,omitempty"`
	Component              string             `json:"component,omitempty"`
	Candidates             []Candidate        `json:"candidates,omitempty"`
	FirstAt                time.Time          `json:"first_at"`
	LastAt                 time.Time          `json:"last_at"`
	PacketCount            int                `json:"packet_count"`
	PayloadBytes           int                `json:"payload_bytes"`
	Midstream              bool               `json:"midstream"`
	Incomplete             bool               `json:"incomplete"`
	Truncated              bool               `json:"truncated"`
	Closed                 bool               `json:"closed"`
	Reset                  bool               `json:"reset"`
	Retransmissions        int                `json:"retransmissions"`
	OutOfOrder             int                `json:"out_of_order"`
	ConflictingOverlaps    int                `json:"conflicting_overlaps"`
	Reasons                []string           `json:"reasons"`
}
type Chunk struct {
	Offset    int64    `json:"offset"`
	Data      []byte   `json:"data"`
	PacketIDs []string `json:"packet_ids"`
}
type Gap struct {
	Offset int64  `json:"offset"`
	Length int64  `json:"length"`
	Reason string `json:"reason"`
}
type Direction struct {
	From                string  `json:"from"`
	StartSequence       uint32  `json:"start_sequence"`
	SYNSeen             bool    `json:"syn_seen"`
	FINSeen             bool    `json:"fin_seen"`
	Chunks              []Chunk `json:"chunks"`
	Gaps                []Gap   `json:"gaps"`
	CapturedBytes       int     `json:"captured_bytes"`
	WirePayloadBytes    int64   `json:"wire_payload_bytes"`
	Retransmissions     int     `json:"retransmissions"`
	OutOfOrder          int     `json:"out_of_order"`
	ConflictingOverlaps int     `json:"conflicting_overlaps"`
	Midstream           bool    `json:"midstream"`
	Truncated           bool    `json:"truncated"`
	Incomplete          bool    `json:"incomplete"`
}
type Datagram struct {
	PayloadLengthKnown bool      `json:"payload_length_known"`
	PacketWireLength   int       `json:"packet_wire_length"`
	PacketID           string    `json:"packet_id"`
	From               string    `json:"from"`
	At                 time.Time `json:"at"`
	Data               []byte    `json:"data"`
	WireLength         int       `json:"wire_length"`
	CapturedLength     int       `json:"captured_length"`
	Truncated          bool      `json:"truncated"`
}
type Detail struct {
	PacketIDs []string `json:"packet_ids"`
	Metadata
	Directions []Direction `json:"directions"`
	Datagrams  []Datagram  `json:"datagrams"`
}
type Snapshot struct {
	Flows          []Metadata `json:"flows"`
	Details        []Detail   `json:"-"`
	Truncated      bool       `json:"truncated"`
	Reasons        []string   `json:"reasons"`
	ScannedPackets int        `json:"scanned_packets"`
	ScannedBytes   int        `json:"scanned_bytes"`
}
type Options struct {
	MaxPackets        int
	MaxBytes          int
	MaxFlows          int
	MaxDirectionBytes int
	IdleTimeout       time.Duration
}

func (s Snapshot) Detail(id string) (Detail, bool) {
	for _, d := range s.Details {
		if d.ID == id {
			return d, true
		}
	}
	return Detail{}, false
}

// Analyzer is a narrow reusable function signature for other read-only tools.
type Analyzer func(context.Context, []Packet, Options) (Snapshot, error)
