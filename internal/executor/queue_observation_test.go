package executor

import (
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/jobs"
)

func TestOperationAPIQueueViewsExplainLaneAndResourceOwners(t *testing.T) {
	f := newPlanningFixture(t)
	create := func(id, service domain.ID, kind domain.OperationKind, extra string) domain.Operation {
		t.Helper()
		resources := []string{"service:" + string(service)}
		if extra != "" {
			resources = append(resources, extra)
		}
		spec := domain.OperationSpec{ID: id, Kind: kind, Initiator: "defender-a", IdempotencyKey: string(id), ServiceID: service, ExpectedPolicyRevision: 1, ExpectedTreeDigest: f.baseline.ManifestDigest, Resources: resources, TimeoutSeconds: 30}
		op, _, err := jobs.New(f.m.Store).Submit(t.Context(), spec, domain.Hash([]byte(id)))
		if err != nil {
			t.Fatal(err)
		}
		return op
	}
	owner := create("build-owner", "service-a", domain.OperationBuild, "path:/srv/code")
	blocked := create("blocked-copy", "service-b", domain.OperationPrepare, "path:/srv/code/sub")
	laneWait := create("waiting-build", "service-c", domain.OperationBuild, "")
	ready := create("ready-copy", "service-d", domain.OperationPrepare, "")
	if _, err := jobs.New(f.m.Store).Start(t.Context(), owner.Spec.ID); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id      domain.ID
		reason  string
		blocked bool
	}{{blocked.Spec.ID, "resource_locked", true}, {laneWait.Spec.ID, "lane_limit", true}, {ready.Spec.ID, "scheduler", false}} {
		op, err := f.m.GetOperation(t.Context(), tc.id)
		if err != nil {
			t.Fatal(err)
		}
		if op.QueueWait == nil || op.QueueWait.Reason != tc.reason || op.QueueWait.Limit != 1 {
			t.Fatalf("wrong API queue observation: %#v", op.QueueWait)
		}
		if tc.blocked && (len(op.QueueWait.Blockers) != 1 || op.QueueWait.Blockers[0].OperationID != owner.Spec.ID || op.QueueWait.Blockers[0].Actor != "defender-a") {
			t.Fatalf("owner missing: %#v", op.QueueWait)
		}
		raw, err := f.m.Store.GetOperation(t.Context(), tc.id)
		if err != nil || raw.QueueWait != nil {
			t.Fatal("API wrote queue view to durable state", err)
		}
	}
	op, err := f.m.GetOperation(t.Context(), owner.Spec.ID)
	if err != nil || op.QueueWait != nil {
		t.Fatal("running owner has queue wait", err)
	}
}
