package dashboard

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/packets"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

type webCapturePreview struct {
	ExpectedRevision    uint64   `json:"expected_revision"`
	Enabled             bool     `json:"enabled"`
	TargetIDs           []string `json:"target_ids"`
	Snaplen             int      `json:"snaplen"`
	MaxPacketsPerSecond int      `json:"max_packets_per_second"`
}

func (s *Server) packetRoutes(w http.ResponseWriter, r *http.Request, current session) {
	if strings.HasPrefix(r.URL.Path, "/api/capture/") {
		if current.User.Role != RoleAdmin {
			s.deny(w, r, current.User.ID)
			return
		}
		if r.URL.RawQuery != "" {
			apiError(w, 400, "invalid_query", "No query is supported for capture control")
			return
		}
		switch r.URL.Path {
		case "/api/capture/policy", "/api/capture/targets":
			if !method(w, r, "GET") {
				return
			}
			s.proxyCall(w, r, current, "capture.configuration.read", "policy", true, false, func(ctx context.Context) (any, error) {
				if r.URL.Path == "/api/capture/policy" {
					return s.executor.CapturePolicy(ctx)
				}
				return s.executor.CaptureTargets(ctx)
			})
		case "/api/capture/preview":
			if !method(w, r, "POST") {
				return
			}
			var in webCapturePreview
			if !decodeWebProxy(w, r, &in) {
				return
			}
			request := transport.CapturePreviewRequest{ExpectedRevision: in.ExpectedRevision, Enabled: in.Enabled, TargetIDs: in.TargetIDs, Snaplen: in.Snaplen, MaxPacketsPerSecond: in.MaxPacketsPerSecond, Initiator: domain.ID(current.User.ID)}
			s.proxyCall(w, r, current, "capture.policy.preview", "policy", true, false, func(ctx context.Context) (any, error) { return s.executor.CapturePreview(ctx, request) })
		case "/api/capture/confirm":
			if !method(w, r, "POST") {
				return
			}
			var in webProxyConfirm
			if !decodeWebProxy(w, r, &in) {
				return
			}
			if in.ProposalID.Validate() != nil || in.Digest.Validate() != nil {
				apiError(w, 400, "invalid_request", "Valid capture proposal and digest required")
				return
			}
			request := transport.ProxyConfirmRequest{ProposalID: in.ProposalID, Digest: in.Digest, Initiator: domain.ID(current.User.ID)}
			s.proxyCall(w, r, current, "capture.policy.confirm", string(in.ProposalID), true, false, func(ctx context.Context) (any, error) { return s.executor.CaptureConfirm(ctx, request) })
		default:
			apiError(w, 404, "not_found", "Unknown capture endpoint")
		}
		return
	}
	if r.URL.Path == "/api/packets" {
		if !method(w, r, "GET") {
			return
		}
		q, e := packets.ParseRawQuery(r.URL.RawQuery)
		if e != nil {
			apiError(w, 400, "invalid_query", "Packet filters are invalid or duplicated")
			return
		}
		s.proxyCall(w, r, current, "", "", false, false, func(ctx context.Context) (any, error) { return s.executor.PacketList(ctx, q) })
		return
	}
	if r.URL.RawQuery != "" {
		apiError(w, 400, "invalid_query", "No query is supported")
		return
	}
	if r.URL.Path == "/api/packets/status" {
		if !method(w, r, "GET") {
			return
		}
		s.proxyCall(w, r, current, "", "", false, false, func(ctx context.Context) (any, error) { return s.executor.PacketStatus(ctx) })
		return
	}
	if !current.User.SensitiveAccess {
		s.deny(w, r, current.User.ID)
		return
	}
	if r.URL.Path == "/api/packets/export" {
		if !method(w, r, "POST") {
			return
		}
		var in packets.ExportRequest
		if !decodeWebProxy(w, r, &in) {
			return
		}
		s.packetExport(w, r, current, in)
		return
	}
	if !method(w, r, "GET") {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/packets/")
	if !validTrafficRequestID(id) {
		apiError(w, 400, "invalid_id", "Invalid packet ID")
		return
	}
	s.proxyCall(w, r, current, "packets.raw.read", id, false, true, func(ctx context.Context) (any, error) { return s.executor.PacketRaw(ctx, id) })
}
func (s *Server) packetExport(w http.ResponseWriter, r *http.Request, current session, in packets.ExportRequest) {
	if !s.freshProxySession(w, r, current, false, true) {
		return
	}
	if e := s.audit(r.Context(), current.User.ID, "packets.export", "selection", "requested", ""); e != nil {
		internalError(w)
		return
	}
	out, e := s.executor.PacketExport(r.Context(), in)
	if !s.freshProxySession(w, r, current, false, true) {
		_ = s.audit(r.Context(), current.User.ID, "packets.export", "selection", "withheld", "")
		return
	}
	if e != nil {
		_ = s.audit(r.Context(), current.User.ID, "packets.export", "selection", "rejected", "")
		executorError(w, e)
		return
	}
	if len(out.Data) < 24 || len(out.Data) > packets.MaxExportBytes || in.MaxBytes > 0 && len(out.Data) > in.MaxBytes || out.Packets < 0 || out.Packets > packets.MaxExportPackets || in.MaxPackets > 0 && out.Packets > in.MaxPackets || len(out.Epoch) > 128 || strings.ContainsAny(out.Epoch, "\r\n\x00") {
		apiError(w, 502, "invalid_export", "Invalid or oversized packet export")
		return
	}
	if e := s.audit(r.Context(), current.User.ID, "packets.export", "selection", "succeeded", ""); e != nil {
		apiError(w, 502, "audit_incomplete", "Export withheld because audit could not be completed")
		return
	}
	if !s.freshProxySession(w, r, current, false, true) {
		return
	}
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", `attachment; filename="ctfm-packets.pcap"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(out.Data)))
	w.Header().Set("X-Packet-Count", strconv.Itoa(out.Packets))
	w.Header().Set("X-Packets-Truncated", strconv.FormatBool(out.Truncated))
	w.Header().Set("X-Packets-Gap", strconv.FormatBool(out.Gap))
	w.Header().Set("X-Collector-Epoch", out.Epoch)
	w.WriteHeader(200)
	_, _ = w.Write(out.Data)
}
