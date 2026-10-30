package executor

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/jobs"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func schedulerOperation(t *testing.T, f *planningFixture, id, service domain.ID, kind domain.OperationKind) domain.Operation {
	t.Helper()
	spec := domain.OperationSpec{ID: id, Kind: kind, ServiceID: service, Initiator: "admin", IdempotencyKey: string(id), ExpectedPolicyRevision: 1, ExpectedTreeDigest: f.baseline.ManifestDigest, Resources: []string{"service:" + string(service)}, TimeoutSeconds: 2}
	if kind == domain.OperationRollback {
		spec.ReleaseID = f.release.Spec().ID
	}
	if err := f.m.Store.PutImmutable(t.Context(), "operation_input", id, service, operationInput{Plan: transport.PreviewResult{ServiceID: service}}); err != nil {
		t.Fatal(err)
	}
	op, _, err := jobs.New(f.m.Store).Submit(t.Context(), spec, domain.Hash([]byte(id)))
	if err != nil {
		t.Fatal(err)
	}
	return op
}
func waitSchedulerStart(t *testing.T, started <-chan domain.Operation) domain.Operation {
	t.Helper()
	select {
	case op := <-started:
		return op
	case <-time.After(3 * time.Second):
		t.Fatal("scheduler did not dispatch available lane")
		return domain.Operation{}
	}
}
func TestSchedulerRealIndependentLanesLimitsAndRollbackPriority(t *testing.T) {
	f := newPlanningFixture(t)
	f.m.Config.Scheduler = config.SchedulerPolicy{Builds: 1, Copies: 1, Switches: 1}
	schedulerOperation(t, f, "build-1", "build-service-1", domain.OperationBuild)
	schedulerOperation(t, f, "build-2", "build-service-2", domain.OperationBuild)
	schedulerOperation(t, f, "copy-1", "copy-service-1", domain.OperationPrepare)
	schedulerOperation(t, f, "copy-2", "copy-service-2", domain.OperationSnapshot)
	schedulerOperation(t, f, "rollback-1", "switch-service", domain.OperationRollback)
	started := make(chan domain.Operation, 10)
	release := make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- f.m.runScheduler(ctx, func(ctx context.Context, op domain.Operation) error {
			return f.m.withArtifactReleased(ctx, func(ctx context.Context) error {
				started <- op
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
		})
	}()
	first := waitSchedulerStart(t, started)
	if first.Spec.Kind != domain.OperationRollback {
		t.Fatal("new build bypassed queued rollback", first.Spec.Kind)
	}
	lanes := map[workLane]int{operationLane(first.Spec.Kind): 1}
	for i := 0; i < 2; i++ {
		op := waitSchedulerStart(t, started)
		lanes[operationLane(op.Spec.Kind)]++
	}
	if lanes[laneBuild] != 1 || lanes[laneCopy] != 1 || lanes[laneSwitch] != 1 {
		t.Fatal("independent lanes failed", lanes)
	}
	select {
	case op := <-started:
		t.Fatal("lane concurrency limit exceeded", op.Spec.ID)
	case <-time.After(150 * time.Millisecond):
	}
	for _, id := range []domain.ID{"build-2", "copy-2"} {
		op, err := f.m.Store.GetOperation(t.Context(), id)
		if err != nil || op.State != domain.OperationQueued {
			t.Fatal("blocked job started its timeout", op, err)
		}
	}
	close(release)
	for i := 0; i < 2; i++ {
		waitSchedulerStart(t, started)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("scheduler shutdown leaked workers")
	}
}
func TestSchedulerConfiguredBuildSlotsAndResourceLocks(t *testing.T) {
	f := newPlanningFixture(t)
	f.m.Config.Scheduler = config.SchedulerPolicy{Builds: 2, Copies: 2}
	for i := 1; i <= 3; i++ {
		schedulerOperation(t, f, domain.ID(fmt.Sprintf("build-%d", i)), domain.ID(fmt.Sprintf("service-%d", i)), domain.OperationBuild)
	}
	schedulerOperation(t, f, "copy-conflict", "service-1", domain.OperationPrepare)
	schedulerOperation(t, f, "copy-independent", "another-service", domain.OperationPrepare)
	started := make(chan domain.Operation, 10)
	release := make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- f.m.runScheduler(ctx, func(ctx context.Context, op domain.Operation) error {
			return f.m.withArtifactReleased(ctx, func(ctx context.Context) error {
				started <- op
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
		})
	}()
	got := map[domain.ID]bool{}
	for i := 0; i < 3; i++ {
		got[waitSchedulerStart(t, started).Spec.ID] = true
	}
	if !got["build-1"] || !got["build-2"] || !got["copy-independent"] {
		t.Fatal("limits or resource conflicts ignored", got)
	}
	close(release)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("worker leak")
	}
}
func TestSchedulerKeepsQueuedWhileArtifactGateBusy(t *testing.T) {
	f := newPlanningFixture(t)
	op := schedulerOperation(t, f, "waiting", "waiting-service", domain.OperationPrepare)
	f.m.artifactMu.Lock()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	started := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- f.m.runScheduler(ctx, func(context.Context, domain.Operation) error { started <- struct{}{}; return nil })
	}()
	time.Sleep(250 * time.Millisecond)
	queued, err := f.m.Store.GetOperation(t.Context(), op.Spec.ID)
	if err != nil || queued.State != domain.OperationQueued {
		t.Fatal("job marked running before artifact gate", queued, err)
	}
	f.m.artifactMu.Unlock()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("unblocked job not started")
	}
	cancel()
	<-done
}

func TestSharedGameVolumeDoesNotSerializeIndependentSourceJobs(t *testing.T) {
	for _, kind := range []domain.OperationKind{domain.OperationPrepare, domain.OperationFetchSource, domain.OperationBuild, domain.OperationSnapshot, domain.OperationRestoreSnapshot, domain.OperationDeploy, domain.OperationRollback, domain.OperationRestart} {
		t.Run(string(kind), func(t *testing.T) {
			f := newPlanningFixture(t)
			left := f.s
			left.DataPaths[0].SharedResource = "shared-game-database"
			right := left
			right.ID = "another-service"
			right.ComposeProject = "another-project"
			right.ProjectDirectory = "/srv/another"
			right.SourceDirectory = "/srv/workspaces/another"
			manager := jobs.New(f.m.Store)
			for i, s := range []domain.Service{left, right} {
				id := domain.ID(fmt.Sprintf("shared-%d", i))
				spec := domain.OperationSpec{ID: id, Kind: kind, ServiceID: s.ID, Initiator: "admin", IdempotencyKey: string(id), ExpectedPolicyRevision: 1, ExpectedTreeDigest: f.baseline.ManifestDigest, Resources: operationResources(s, kind), TimeoutSeconds: 10}
				if kind == domain.OperationDeploy || kind == domain.OperationRollback {
					spec.ReleaseID = f.release.Spec().ID
				}
				if kind == domain.OperationRestoreSnapshot {
					spec.SnapshotID = f.baseline.ID
				}
				if _, _, err := manager.Submit(t.Context(), spec, domain.Hash([]byte(id))); err != nil {
					t.Fatal(err)
				}
				_, err := manager.Start(t.Context(), id)
				sourceOnly := operationLane(kind) != laneSwitch
				if i == 0 || sourceOnly {
					if err != nil {
						t.Fatal("independent source job blocked by shared data", err)
					}
				} else if !errors.Is(err, store.ErrBusy) {
					t.Fatal("runtime jobs ignored shared data conflict", err)
				}
			}
		})
	}
}
