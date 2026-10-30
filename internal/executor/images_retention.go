package executor

import (
	"context"
	"errors"
	"fmt"
	"github.com/containerd/errdefs"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
	"github.com/moby/moby/client"
)

// Tags are unique per immutable release. Never delete by image ID, force a
// removal, prune dependencies, or run a daemon-wide image/cache/volume prune.
func (m *Manager) cleanupRetiredImageTags(ctx context.Context) error {
	if m.Engine == nil {
		return nil
	} // filesystem-only tests do not construct an Engine
	_, inflightTags, err := m.dockerBuildReservations(ctx, "")
	if err != nil {
		return err
	}
	retired, err := m.Store.List(ctx, "retired_release", "")
	if err != nil {
		return err
	}
	for _, record := range retired {
		needs, err := m.Store.MetadataRestoreNeedsReview(ctx, record.ServiceID)
		if err != nil {
			return err
		}
		if needs {
			continue
		}
		var completed bool
		err = m.Store.Get(ctx, "retired_images_cleaned", record.ID, &completed)
		if err == nil {
			continue
		}
		if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		var release domain.Release
		if err := m.Store.Get(ctx, "release", record.ID, &release); err != nil {
			return err
		}
		spec := release.Spec()
		if spec.Source == domain.ReleaseImported {
			return errors.New("imported release cannot be garbage collected")
		}
		for _, image := range spec.Images {
			expected := "ctf-manager/" + string(spec.ServiceID) + ":" + string(spec.ID) + "-" + image.Component
			if inflightTags[image.RetentionTag] {
				return errors.New("in-flight build image cannot be garbage collected")
			}
			if image.RetentionTag != expected {
				return errors.New("image retention tag is outside its immutable release namespace")
			}
			inspected, err := m.Engine.Client.ImageInspect(ctx, image.RetentionTag)
			if errdefs.IsNotFound(err) {
				continue
			}
			if err != nil {
				return err
			}
			if inspected.ID != string(image.ImageID) {
				return fmt.Errorf("retention tag was externally retargeted for release %s; refusing cleanup", spec.ID)
			}
			if _, err := m.Engine.Client.ImageRemove(ctx, image.RetentionTag, client.ImageRemoveOptions{Force: false, PruneChildren: false}); err != nil && !errdefs.IsNotFound(err) {
				return err
			}
		}
		if err := m.Store.PutImmutable(ctx, "retired_images_cleaned", spec.ID, spec.ServiceID, true); err != nil {
			return err
		}
	}
	return nil
}
