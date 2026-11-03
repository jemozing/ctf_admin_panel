package executor

import (
	"encoding/json"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/storage"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func (m *Manager) previewSpace(action domain.OperationKind, current, target domain.Manifest) transport.PreviewSpace {
	p := m.Config.Storage.Effective()
	v := transport.PreviewSpace{EstimateKnown: true, MinimumFreeBytes: p.MinimumFreeBytes, MinimumFreeInodes: p.MinimumFreeInodes}
	snapshotCost := func(tree domain.Manifest) uint64 {
		metadata, _ := json.Marshal(tree)
		return uint64(tree.TotalBytes()) + uint64(len(metadata)) + 4096
	}
	switch action {
	case domain.OperationPrepare, domain.OperationRestoreSnapshot:
		v.SnapshotBytes = snapshotCost(target)
	case domain.OperationSnapshot:
		v.SnapshotBytes = snapshotCost(current)
	case domain.OperationFetchSource:
		v.EstimateKnown = false
	case domain.OperationPrepareCompose:
		v.EstimateKnown = len(target.Entries()) > 0
		if v.EstimateKnown {
			v.SnapshotBytes = snapshotCost(target)
			v.StagingBytes = uint64(target.TotalBytes()) + 4096
		}
		v.DockerReserveBytes = p.BuildReserveBytes
	case domain.OperationBuild:
		v.StagingBytes = uint64(target.TotalBytes()) + 4096
		v.DockerReserveBytes = p.BuildReserveBytes
	case domain.OperationDeploy, domain.OperationRollback, domain.OperationRecover:
		v.SnapshotBytes = snapshotCost(current)
		v.ApplyTemporaryBytes = uint64(target.TotalBytes())
	}
	if capacity, err := storage.Capacity(m.Config.StateDirectory); err == nil {
		v.StateAvailableBytes = &capacity.AvailableBytes
		if capacity.InodesKnown {
			v.StateAvailableInodes = &capacity.AvailableInodes
		}
	}
	return v
}
