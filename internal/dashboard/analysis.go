package dashboard

import (
	"context"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/packets"
	"github.com/ctf-service-manager/ctf-service-manager/internal/protocols"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

type webDescriptorPreview struct {
	ServiceID domain.ID `json:"service_id"`
	ReleaseID domain.ID `json:"release_id,omitempty"`
	Data      []byte    `json:"data"`
}
type webDescriptorConfirm struct {
	ProposalID domain.ID     `json:"proposal_id"`
	Digest     domain.Digest `json:"digest"`
}
type webExchangeDecode struct {
	DescriptorID string `json:"descriptor_id,omitempty"`
}

func (s *Server) analysisRoutes(w http.ResponseWriter, r *http.Request, current session) {
	if r.URL.Path == "/api/flows" {
		if !method(w, r, "GET") {
			return
		}
		q, e := packets.ParseRawQuery(r.URL.RawQuery)
		if e != nil {
			apiError(w, 400, "invalid_query", "Invalid flow filters")
			return
		}
		s.proxyCall(w, r, current, "", "", false, false, func(ctx context.Context) (any, error) { return s.executor.FlowList(ctx, q) })
		return
	}
	if r.URL.RawQuery != "" {
		apiError(w, 400, "invalid_query", "No query is supported")
		return
	}
	if !current.User.SensitiveAccess {
		s.deny(w, r, current.User.ID)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/descriptors") {
		admin := current.User.Role == RoleAdmin
		switch {
		case r.URL.Path == "/api/descriptors" && r.Method == "GET":
			s.proxyCall(w, r, current, "descriptors.metadata.read", "descriptors", false, true, func(ctx context.Context) (any, error) { return s.executor.DescriptorList(ctx) })
		case r.URL.Path == "/api/descriptors/preview" && r.Method == "POST":
			if !admin {
				s.deny(w, r, current.User.ID)
				return
			}
			var in webDescriptorPreview
			if !decodeWebDescriptor(w, r, &in) {
				return
			}
			if in.ServiceID.Validate() != nil || in.ReleaseID != "" && in.ReleaseID.Validate() != nil || len(in.Data) == 0 || len(in.Data) > protocols.MaxDescriptorBytes {
				apiError(w, 400, "invalid_descriptor", "Valid service and bounded descriptor set required")
				return
			}
			req := transport.DescriptorPreviewRequest{ServiceID: in.ServiceID, ReleaseID: in.ReleaseID, Data: in.Data, Initiator: domain.ID(current.User.ID)}
			s.proxyCall(w, r, current, "descriptors.preview", string(in.ServiceID), true, true, func(ctx context.Context) (any, error) { return s.executor.DescriptorPreview(ctx, req) })
		case r.URL.Path == "/api/descriptors/confirm" && r.Method == "POST":
			if !admin {
				s.deny(w, r, current.User.ID)
				return
			}
			var in webDescriptorConfirm
			if !decodeWebProxy(w, r, &in) {
				return
			}
			if in.ProposalID.Validate() != nil || in.Digest.Validate() != nil {
				apiError(w, 400, "invalid_request", "Valid descriptor preview and digest required")
				return
			}
			req := transport.DescriptorConfirmRequest{ProposalID: in.ProposalID, Digest: in.Digest, Initiator: domain.ID(current.User.ID)}
			s.proxyCall(w, r, current, "descriptors.confirm", string(in.ProposalID), true, true, func(ctx context.Context) (any, error) { return s.executor.DescriptorConfirm(ctx, req) })
		case strings.HasPrefix(r.URL.Path, "/api/descriptors/") && r.Method == "DELETE":
			if !admin {
				s.deny(w, r, current.User.ID)
				return
			}
			id := strings.TrimPrefix(r.URL.Path, "/api/descriptors/")
			if !validTrafficRequestID(id) {
				apiError(w, 400, "invalid_id", "Invalid descriptor ID")
				return
			}
			s.proxyCall(w, r, current, "descriptors.delete", id, true, true, func(ctx context.Context) (any, error) {
				e := s.executor.DescriptorDelete(ctx, transport.DescriptorDeleteRequest{ID: id, Initiator: domain.ID(current.User.ID)})
				return map[string]bool{"ok": e == nil}, e
			})
		default:
			apiError(w, 404, "not_found", "Unknown descriptor endpoint")
		}
		return
	}
	if !method(w, r, "POST") {
		return
	}
	switch {
	case r.URL.Path == "/api/flows/detail":
		var in packets.FlowDetailRequest
		if !decodeWebProxy(w, r, &in) {
			return
		}
		if !validTrafficRequestID(in.FlowID) {
			apiError(w, 400, "invalid_id", "Invalid flow ID")
			return
		}
		s.proxyCall(w, r, current, "flows.raw.read", in.FlowID, false, true, func(ctx context.Context) (any, error) { return s.executor.FlowDetail(ctx, in) })
	case r.URL.Path == "/api/flows/decode":
		var in packets.FlowDecodeRequest
		if !decodeWebProxy(w, r, &in) {
			return
		}
		if !validTrafficRequestID(in.FlowID) || in.DescriptorID != "" && !validTrafficRequestID(in.DescriptorID) {
			apiError(w, 400, "invalid_id", "Invalid flow or descriptor ID")
			return
		}
		s.proxyCall(w, r, current, "flows.grpc.decode", in.FlowID, false, true, func(ctx context.Context) (any, error) { return s.executor.FlowDecode(ctx, in) })
	case strings.HasPrefix(r.URL.Path, "/api/traffic/") && strings.HasSuffix(r.URL.Path, "/decode"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/traffic/"), "/decode")
		if !validTrafficRequestID(id) {
			apiError(w, 400, "invalid_id", "Invalid exchange ID")
			return
		}
		var in webExchangeDecode
		if !decodeWebProxy(w, r, &in) {
			return
		}
		if in.DescriptorID != "" && !validTrafficRequestID(in.DescriptorID) {
			apiError(w, 400, "invalid_id", "Invalid descriptor ID")
			return
		}
		s.proxyCall(w, r, current, "traffic.grpc.decode", id, false, true, func(ctx context.Context) (any, error) {
			return s.executor.ExchangeDecode(ctx, transport.ExchangeDecodeRequest{RequestID: id, DescriptorID: in.DescriptorID})
		})
	default:
		apiError(w, 404, "not_found", "Unknown analysis endpoint")
	}
}
func decodeWebDescriptor(w http.ResponseWriter, r *http.Request, out any) bool {
	media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/json" {
		apiError(w, 415, "invalid_content_type", "Content-Type must be application/json")
		return false
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, packets.MaxDescriptorRequestBytes))
	if e != nil {
		apiError(w, 413, "body_too_large", "Descriptor exceeds request limit")
		return false
	}
	if transport.DecodeRegistrationJSON(raw, out) != nil {
		apiError(w, 400, "invalid_request", "Descriptor request has invalid, duplicate or unknown fields")
		return false
	}
	return true
}
