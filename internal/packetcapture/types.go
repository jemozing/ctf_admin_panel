// Package packetcapture observes selected game endpoints. It never forwards,
// injects, decodes application streams, or connects to game services.
package packetcapture

import (
	"context"
	"errors"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/packets"
)

const (
	SchemaVersion  = 1
	MaxPolicyBytes = 256 << 10
	MaxInterfaces  = 8
	MaxEndpoints   = 256
	QueueCapacity  = 256
)

var ErrUnsupportedLivePlatform = errors.New("live packet capture requires Linux AF_PACKET and CAP_NET_RAW")

type Endpoint struct {
	ServiceID    string `json:"service_id"`
	Component    string `json:"component"`
	Protocol     string `json:"protocol"`
	Address      string `json:"address"`
	Port         int    `json:"port"`
	ReleaseID    string `json:"release_id,omitempty"`
	SourceDigest string `json:"source_digest,omitempty"`
}

type InterfacePolicy struct {
	Name      string     `json:"name"`
	Index     int        `json:"index"`
	Endpoints []Endpoint `json:"endpoints"`
}

type Policy struct {
	SchemaVersion       int               `json:"schema_version"`
	Revision            uint64            `json:"revision"`
	Enabled             bool              `json:"enabled"`
	Snaplen             int               `json:"snaplen"`
	MaxPacketsPerSecond int               `json:"max_packets_per_second"`
	LeaseUntil          time.Time         `json:"lease_until,omitempty"`
	Interfaces          []InterfacePolicy `json:"interfaces"`
}

type Interface struct {
	Name         string   `json:"name"`
	Index        int      `json:"index"`
	MTU          int      `json:"mtu"`
	HardwareAddr string   `json:"hardware_addr"`
	Addresses    []string `json:"addresses"`
	Loopback     bool     `json:"loopback"`
	Up           bool     `json:"up"`
	Supported    bool     `json:"supported"`
	Kind         string   `json:"kind,omitempty"`
	MasterIndex  int      `json:"master_index,omitempty"`
	PeerIndex    int      `json:"peer_index,omitempty"`
}

// Frame contains one Ethernet frame. WireLength includes bytes beyond Data
// when the kernel reports truncation. PacketType is Linux's sll_pkttype. Data
// belongs to its source and remains valid until the next Read call.
type Frame struct {
	Data       []byte
	WireLength int
	At         time.Time
	PacketType uint8
}

type Source interface {
	Read(context.Context) (Frame, error)
	Close() error
}

type Sink interface{ Submit(packets.Record) bool }

type Options struct {
	StateDirectory string
	Sink           Sink
	// OpenSource and Interfaces are injection points for deterministic offline
	// tests. Production leaves both nil and uses Linux AF_PACKET only.
	OpenSource func(Interface) (Source, error)
	Interfaces func() ([]Interface, error)
	Mode       string
}

type Counters struct {
	Observed            uint64 `json:"observed"`
	Matched             uint64 `json:"matched"`
	Enqueued            uint64 `json:"enqueued"`
	Stored              uint64 `json:"stored"`
	Unmatched           uint64 `json:"unmatched"`
	Malformed           uint64 `json:"malformed"`
	Unparsed            uint64 `json:"unparsed"`
	Excluded            uint64 `json:"excluded"`
	RateDropped         uint64 `json:"rate_dropped"`
	QueueDropped        uint64 `json:"queue_dropped"`
	SinkDropped         uint64 `json:"sink_dropped"`
	DuplicateSuppressed uint64 `json:"duplicate_suppressed"`
	SourceErrors        uint64 `json:"source_errors"`
}

type Status struct {
	Available                    bool              `json:"available"`
	Enabled                      bool              `json:"enabled"`
	Running                      bool              `json:"running"`
	Paused                       bool              `json:"paused"`
	LeaseUntil                   time.Time         `json:"lease_until,omitempty"`
	LeaseExpired                 bool              `json:"lease_expired"`
	Mode                         string            `json:"mode"`
	Epoch                        string            `json:"epoch"`
	StartedAt                    time.Time         `json:"started_at"`
	Revision                     uint64            `json:"revision"`
	Digest                       string            `json:"digest"`
	Snaplen                      int               `json:"snaplen"`
	Interfaces                   []InterfacePolicy `json:"interfaces"`
	QueueDepth                   int               `json:"queue_depth"`
	QueueCapacity                int               `json:"queue_capacity"`
	Counters                     Counters          `json:"counters"`
	CountersScope                string            `json:"counters_scope"`
	PreviousEpochCountersUnknown bool              `json:"previous_epoch_counters_unknown"`
	KernelDropsKnown             bool              `json:"kernel_drops_known"`
	Deduplication                string            `json:"deduplication"`
	LastError                    string            `json:"last_error,omitempty"`
}
