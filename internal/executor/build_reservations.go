package executor

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

type dockerBuildReservation struct {
	OperationID domain.ID `json:"operation_id"`
	ReleaseID   domain.ID `json:"release_id"`
	Bytes       uint64    `json:"bytes"`
	Tags        []string  `json:"tags"`
	CreatedAt   time.Time `json:"created_at"`
}

// dockerBuildReservations is called under artifactMu before a heavy allocation.
// Running/interrupted jobs retain their estimate until a confirmed terminal state.
// Real daemon usage is counted in addition to estimates (conservative double
// counting), because BuildKit does not provide a kernel space reservation API.
func (m *Manager) dockerBuildReservations(ctx context.Context, exclude domain.ID) (uint64, map[string]bool, error) {
	records, err := m.Store.List(ctx, "docker_build_reservation", "")
	if err != nil {
		return 0, nil, err
	}
	total := uint64(0)
	tags := map[string]bool{}
	for _, record := range records {
		var r dockerBuildReservation
		if err := json.Unmarshal(record.Payload, &r); err != nil {
			return 0, nil, err
		}
		op, err := m.Store.GetOperation(ctx, r.OperationID)
		if err != nil {
			return 0, nil, err
		}
		if op.State.Terminal() {
			continue
		}
		for _, tag := range r.Tags {
			tags[tag] = true
		}
		if r.OperationID == exclude {
			continue
		}
		if r.Bytes > math.MaxUint64-total {
			return 0, nil, errors.New("Docker reservation accounting overflow")
		}
		total += r.Bytes
	}
	return total, tags, nil
}
func (m *Manager) reserveDockerBuild(ctx context.Context, service, operation, release domain.ID, model map[string]any) error {
	reserve := m.Config.Storage.Effective().BuildReserveBytes
	if err := m.checkDockerBudget(ctx, reserve); err != nil {
		return err
	}
	record := dockerBuildReservation{OperationID: operation, ReleaseID: release, Bytes: reserve, Tags: []string{}, CreatedAt: time.Now().UTC()}
	services, _ := model["services"].(map[string]any)
	for name := range services {
		record.Tags = append(record.Tags, "ctf-manager/"+string(service)+":"+string(release)+"-"+name)
	}
	sort.Strings(record.Tags)
	return m.Store.PutImmutable(ctx, "docker_build_reservation", operation, service, record)
}
