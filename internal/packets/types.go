// Package packets stores bounded, passively observed TCP/UDP packets. It has no
// raw sockets, container access, panel state, or game filesystem access.
package packets

import "time"

const (
	MaxPacketBytes   = 65535
	MaxRecordBytes   = 128 << 10
	MaxExportBytes   = 8 << 20
	MaxExportPackets = 10000
)

type Candidate struct {
	ServiceID string `json:"service_id"`
	Component string `json:"component"`
}

// Metadata contains no packet payload. A packet shared by several policy
// endpoints has Candidates rather than an arbitrarily selected ServiceID.
type VersionBinding struct {
	ServiceID    string `json:"service_id"`
	Component    string `json:"component"`
	ReleaseID    string `json:"release_id,omitempty"`
	SourceDigest string `json:"source_digest,omitempty"`
}

type Metadata struct {
	VersionBindings   []VersionBinding `json:"version_bindings,omitempty"`
	Sequence          int64            `json:"sequence"`
	PacketID          string           `json:"packet_id"`
	CollectorEpoch    string           `json:"collector_epoch"`
	PolicyRevision    uint64           `json:"policy_revision"`
	At                time.Time        `json:"at"`
	ServiceID         string           `json:"service_id,omitempty"`
	Component         string           `json:"component,omitempty"`
	Interface         string           `json:"interface"`
	IfIndex           int              `json:"if_index"`
	Direction         string           `json:"direction"`
	Protocol          string           `json:"protocol"`
	SourceIP          string           `json:"source_ip"`
	DestinationIP     string           `json:"destination_ip"`
	SourcePort        int              `json:"source_port"`
	DestinationPort   int              `json:"destination_port"`
	TCPFlags          uint8            `json:"tcp_flags"`
	WireLength        int              `json:"wire_length"`
	CapturedLength    int              `json:"captured_length"`
	Truncated         bool             `json:"truncated"`
	LinkType          uint32           `json:"link_type"`
	Attribution       string           `json:"attribution"`
	Candidates        []Candidate      `json:"candidates,omitempty"`
	NotCapturedReason string           `json:"not_captured_reason,omitempty"`
}

// Record is accepted only on the private capture ingest endpoint. Data is
// base64 in JSON. List and Detail return Metadata; Raw requires a separate call.
type Record struct {
	Metadata
	Data []byte `json:"data,omitempty"`
}

type Query struct {
	ServiceIDs      []string `json:"service_ids,omitempty"`
	Component       string   `json:"component,omitempty"`
	Protocol        string   `json:"protocol,omitempty"`
	IP              string   `json:"ip,omitempty"`
	SourcePort      int      `json:"source_port,omitempty"`
	DestinationPort int      `json:"destination_port,omitempty"`
	Direction       string   `json:"direction,omitempty"`
	From            string   `json:"from,omitempty"`
	Until           string   `json:"until,omitempty"`
	Cursor          string   `json:"cursor,omitempty"`
	Limit           int      `json:"limit,omitempty"`
}

type Counters struct {
	Ingested    uint64 `json:"ingested"`
	Rejected    uint64 `json:"rejected"`
	WriteErrors uint64 `json:"write_errors"`
	Rotated     uint64 `json:"rotated"`
}

type Status struct {
	Available                    bool      `json:"available"`
	Epoch                        string    `json:"epoch"`
	StartedAt                    time.Time `json:"started_at"`
	CountersScope                string    `json:"counters_scope"`
	PreviousEpochCountersUnknown bool      `json:"previous_epoch_counters_unknown"`
	Counters                     Counters  `json:"counters"`
	StoredRecords                int64     `json:"stored_records"`
	StoredBytes                  int64     `json:"stored_bytes"`
	DiskBytes                    int64     `json:"disk_bytes"`
	QuotaBytes                   int64     `json:"quota_bytes"`
	PayloadBudgetBytes           int64     `json:"payload_budget_bytes"`
	PerServiceBytes              int64     `json:"per_service_bytes"`
	RetentionSeconds             int64     `json:"retention_seconds"`
	MaxRecords                   int       `json:"max_records"`
	RetiredSequence              int64     `json:"retired_sequence"`
	LastError                    string    `json:"last_error,omitempty"`
}

type Page struct {
	Records    []Metadata `json:"records"`
	NextCursor string     `json:"next_cursor,omitempty"`
	LiveCursor string     `json:"live_cursor"`
	HasMore    bool       `json:"has_more"`
	Gap        bool       `json:"gap"`
	Epoch      string     `json:"epoch"`
	Counters   Status     `json:"counters"`
}

type ExportRequest struct {
	Query      Query `json:"query"`
	MaxPackets int   `json:"max_packets,omitempty"`
	MaxBytes   int   `json:"max_bytes,omitempty"`
}

type Export struct {
	Data      []byte `json:"data"`
	Packets   int    `json:"packets"`
	Truncated bool   `json:"truncated"`
	Gap       bool   `json:"gap"`
	Epoch     string `json:"epoch"`
}
