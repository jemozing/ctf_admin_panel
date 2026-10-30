package transport

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/packetcapture"
	"github.com/ctf-service-manager/ctf-service-manager/internal/packets"
)

type CaptureTarget struct {
	ID           string    `json:"id"`
	ServiceID    domain.ID `json:"service_id"`
	ServiceName  string    `json:"service_name"`
	Component    string    `json:"component"`
	Protocol     string    `json:"protocol"`
	TargetPort   int       `json:"target_port"`
	ObservedPort int       `json:"observed_port,omitempty"`
	Interface    string    `json:"interface"`
	IfIndex      int       `json:"if_index"`
	Addresses    []string  `json:"addresses"`
	Point        string    `json:"point"`
	PointGroup   string    `json:"point_group,omitempty"`
	ReleaseID    string    `json:"release_id,omitempty"`
	SourceDigest string    `json:"source_digest,omitempty"`
}
type CaptureTargets struct {
	Targets           []CaptureTarget          `json:"targets"`
	Unavailable       []ProxyUnavailableTarget `json:"unavailable"`
	AllowedInterfaces []string                 `json:"allowed_interfaces"`
}
type CapturePreviewRequest struct {
	ExpectedRevision    uint64    `json:"expected_revision"`
	Enabled             bool      `json:"enabled"`
	TargetIDs           []string  `json:"target_ids"`
	Snaplen             int       `json:"snaplen"`
	MaxPacketsPerSecond int       `json:"max_packets_per_second"`
	Initiator           domain.ID `json:"initiator,omitempty"`
}
type CapturePreview struct {
	ProposalID              domain.ID            `json:"proposal_id"`
	Digest                  domain.Digest        `json:"digest"`
	Policy                  packetcapture.Policy `json:"policy"`
	SelectedTargetIDs       []string             `json:"selected_target_ids"`
	Warnings                []string             `json:"warnings"`
	ExpiresAt               time.Time            `json:"expires_at"`
	PreviousPolicy          packetcapture.Policy `json:"previous_policy"`
	ObservedAppliedRevision uint64               `json:"observed_applied_revision"`
}
type CapturePolicyView struct {
	Configured        bool                 `json:"configured"`
	Policy            packetcapture.Policy `json:"policy"`
	SelectedTargetIDs []string             `json:"selected_target_ids"`
	DesiredRevision   uint64               `json:"desired_revision"`
	AppliedRevision   uint64               `json:"applied_revision"`
	Activation        string               `json:"activation"`
	Error             string               `json:"error,omitempty"`
}
type PacketStatus struct {
	Configured bool                 `json:"configured"`
	Capture    packetcapture.Status `json:"capture"`
	Store      packets.Status       `json:"store"`
	Error      string               `json:"error,omitempty"`
}
type PacketBackend interface {
	PacketStatus(context.Context) (PacketStatus, error)
	PacketList(context.Context, packets.Query) (packets.Page, error)
	PacketRaw(context.Context, string) (packets.Record, error)
	PacketExport(context.Context, packets.ExportRequest) (packets.Export, error)
	CapturePolicy(context.Context) (CapturePolicyView, error)
	CaptureTargets(context.Context) (CaptureTargets, error)
	CapturePreview(context.Context, CapturePreviewRequest) (CapturePreview, error)
	CaptureConfirm(context.Context, ProxyConfirmRequest) (CapturePolicyView, error)
}

func (s *Server) packetEndpoint(w http.ResponseWriter, r *http.Request) {
	b, ok := s.options.Backend.(PacketBackend)
	if !ok {
		writeError(w, 501, "not_implemented", "packet capture unavailable")
		return
	}
	var value any
	var err error
	switch {
	case r.Method == "GET" && r.URL.Path == "/v1/packets/status":
		value, err = b.PacketStatus(r.Context())
	case r.Method == "GET" && r.URL.Path == "/v1/packets":
		var q packets.Query
		q, err = packets.ParseRawQuery(r.URL.RawQuery)
		if err != nil {
			writeError(w, 400, "invalid_query", "invalid packet filters")
			return
		}
		value, err = b.PacketList(r.Context(), q)
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/packets/"):
		id := strings.TrimPrefix(r.URL.Path, "/v1/packets/")
		if !validPacketID(id) {
			writeError(w, 400, "invalid_id", "invalid packet ID")
			return
		}
		value, err = b.PacketRaw(r.Context(), id)
	case r.Method == "POST" && r.URL.Path == "/v1/packets/export":
		var in packets.ExportRequest
		if !decodeProxyInput(w, r, &in) {
			return
		}
		value, err = b.PacketExport(r.Context(), in)
	case r.Method == "GET" && r.URL.Path == "/v1/capture/policy":
		value, err = b.CapturePolicy(r.Context())
	case r.Method == "GET" && r.URL.Path == "/v1/capture/targets":
		value, err = b.CaptureTargets(r.Context())
	case r.Method == "POST" && r.URL.Path == "/v1/capture/preview":
		var in CapturePreviewRequest
		if !decodeProxyInput(w, r, &in) {
			return
		}
		if in.Initiator.Validate() != nil {
			writeError(w, 400, "invalid_actor", "authenticated actor required")
			return
		}
		value, err = b.CapturePreview(r.Context(), in)
	case r.Method == "POST" && r.URL.Path == "/v1/capture/confirm":
		var in ProxyConfirmRequest
		if !decodeProxyInput(w, r, &in) {
			return
		}
		if in.Initiator.Validate() != nil || in.ProposalID.Validate() != nil || in.Digest.Validate() != nil {
			writeError(w, 400, "invalid_request", "valid proposal, actor and digest required")
			return
		}
		value, err = b.CaptureConfirm(r.Context(), in)
	default:
		writeError(w, 404, "not_found", "unknown packet endpoint")
		return
	}
	if err != nil {
		proxyBackendError(w, err)
		return
	}
	writeJSON(w, 200, value)
}
func validPacketID(id string) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_.:-", r) {
			continue
		}
		return false
	}
	return true
}
func (c *Client) PacketStatus(ctx context.Context) (v PacketStatus, e error) {
	e = c.request(ctx, "GET", "/v1/packets/status", nil, &v)
	return
}
func (c *Client) PacketList(ctx context.Context, q packets.Query) (v packets.Page, e error) {
	e = c.request(ctx, "GET", "/v1/packets?"+packets.QueryValues(q).Encode(), nil, &v)
	return
}
func (c *Client) PacketRaw(ctx context.Context, id string) (v packets.Record, e error) {
	if !validPacketID(id) {
		return v, proxyInputTransport("invalid packet ID")
	}
	e = c.request(ctx, "GET", "/v1/packets/"+id, nil, &v)
	return
}
func proxyInputTransport(message string) error { return &ProxyInputError{message} }
func (c *Client) PacketExport(ctx context.Context, q packets.ExportRequest) (v packets.Export, e error) {
	e = c.requestBounded(ctx, "POST", "/v1/packets/export", q, &v, 12<<20)
	return
}
func (c *Client) CapturePolicy(ctx context.Context) (v CapturePolicyView, e error) {
	e = c.request(ctx, "GET", "/v1/capture/policy", nil, &v)
	return
}
func (c *Client) CaptureTargets(ctx context.Context) (v CaptureTargets, e error) {
	e = c.request(ctx, "GET", "/v1/capture/targets", nil, &v)
	return
}
func (c *Client) CapturePreview(ctx context.Context, q CapturePreviewRequest) (v CapturePreview, e error) {
	e = c.request(ctx, "POST", "/v1/capture/preview", q, &v)
	return
}
func (c *Client) CaptureConfirm(ctx context.Context, q ProxyConfirmRequest) (v CapturePolicyView, e error) {
	e = c.request(ctx, "POST", "/v1/capture/confirm", q, &v)
	return
}
