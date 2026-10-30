package executor

import (
	"context"
	"fmt"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/filesystem"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"path"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

func manifestDifferences(before, after domain.Manifest) []transport.FileDifference {
	a, b := map[string]domain.ManifestEntry{}, map[string]domain.ManifestEntry{}
	for _, e := range before.Entries() {
		a[e.Path] = e
	}
	for _, e := range after.Entries() {
		b[e.Path] = e
	}
	out := []transport.FileDifference{}
	for name, old := range a {
		next, exists := b[name]
		if exists && old == next {
			continue
		}
		copyOld := old
		d := transport.FileDifference{Path: name, Change: "deleted", Before: &copyOld}
		if exists {
			copyNext := next
			d.Change = "modified"
			d.After = &copyNext
		}
		out = append(out, d)
	}
	for name, next := range b {
		if _, exists := a[name]; !exists {
			copyNext := next
			out = append(out, transport.FileDifference{Path: name, Change: "added", After: &copyNext})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
func fileTextAllowed(s domain.Service, name string) bool {
	lower := strings.ToLower(name)
	for _, part := range strings.Split(lower, "/") {
		if part == ".env" || strings.HasPrefix(part, ".env.") || part == "secrets" || part == ".ssh" || strings.HasSuffix(part, ".pem") || strings.HasSuffix(part, ".key") {
			return false
		}
	}
	for _, m := range s.ManagedPaths {
		if (name == m.Path || strings.HasPrefix(name, m.Path+"/")) && m.Kind == domain.ManagedCode {
			return true
		}
	}
	return false
}
func previewText(ctx context.Context, root string, e *domain.ManifestEntry, allowed bool, redact func(string) string) (*string, string) {
	if e == nil {
		return nil, "file absent"
	}
	if !allowed {
		return nil, "configuration or sensitive path: content hidden"
	}
	if e.Type != domain.EntryFile {
		return nil, "metadata only: not a regular file"
	}
	if e.Size > 65536 {
		return nil, "metadata only: file exceeds 64 KiB"
	}
	data, err := filesystem.ReadVerifiedFile(ctx, root, *e, 65536)
	if err != nil {
		return nil, "file changed or cannot be read safely; refresh comparison"
	}
	if !utf8.Valid(data) || strings.ContainsRune(string(data), 0) {
		return nil, "metadata only: binary content"
	}
	text := safeLogTextForFile(redact(string(data)))
	return &text, ""
}
func safeLogTextForFile(text string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || unicode.IsPrint(r) {
			return r
		}
		return '�'
	}, text)
}
func (m *Manager) Files(ctx context.Context, id domain.ID, q transport.FilesQuery) (transport.FilesResult, error) {
	result := transport.FilesResult{Comparison: q.Comparison, Changes: []transport.FileDifference{}, At: time.Now().UTC()}
	if err := q.Validate(); err != nil {
		return result, err
	}
	s, err := m.Store.GetService(ctx, id)
	if err != nil {
		return result, err
	}
	st, err := m.state(ctx, s)
	if err != nil {
		return result, err
	}
	active, err := filesystem.Observe(ctx, s.ProjectDirectory, s.ManagedPaths, nil)
	if err != nil {
		return result, fmt.Errorf("active managed tree cannot be observed safely")
	}
	before, after := active, domain.Manifest{}
	beforeRoot, afterRoot := s.ProjectDirectory, ""
	switch q.Comparison {
	case "workspace":
		after, err = filesystem.Observe(ctx, s.SourceDirectory, s.ManagedPaths, nil)
		afterRoot = s.SourceDirectory
	case "candidate", "release", "drift":
		snapshotID := st.CandidateID
		if q.Comparison == "release" {
			release, e := m.loadRelease(ctx, s, q.ReleaseID)
			if e != nil {
				return result, e
			}
			snapshotID = release.Spec().SnapshotID
		}
		if q.Comparison == "drift" {
			snapshotID = st.ActiveSnapshotID
		}
		if snapshotID == "" {
			return result, fmt.Errorf("comparison snapshot is not available")
		}
		snap, e := m.loadSnapshot(ctx, snapshotID)
		if e != nil {
			return result, e
		}
		if snap.ServiceID != s.ID || snap.FileMapRevision != s.FileMapRevision {
			return result, fmt.Errorf("snapshot does not belong to current service file policy")
		}
		snapshotRoot, e := m.Snapshots.ContentPath(snapshotID)
		if e != nil {
			return result, e
		}
		result.SnapshotID = snapshotID
		if q.Comparison == "drift" {
			before = snap.Manifest
			beforeRoot = snapshotRoot
			after = active
			afterRoot = s.ProjectDirectory
		} else {
			after = snap.Manifest
			afterRoot = snapshotRoot
		}
	}
	if err != nil {
		return result, fmt.Errorf("comparison tree cannot be observed safely")
	}
	result.BeforeDigest = before.Digest()
	result.AfterDigest = after.Digest()
	all := manifestDifferences(before, after)
	result.Changes = all
	if len(result.Changes) > 2000 {
		result.Changes = result.Changes[:2000]
		result.Truncated = true
	}
	if q.Path != "" {
		var selected *transport.FileDifference
		for _, d := range all {
			if d.Path == q.Path {
				copy := d
				selected = &copy
				break
			}
		}
		if selected == nil {
			return result, fmt.Errorf("selected file is outside the displayed changes")
		}
		redact, e := m.displayRedactor(ctx, s)
		if e != nil {
			return result, e
		}
		allowed := fileTextAllowed(s, q.Path) && path.Clean(q.Path) == q.Path
		file := &transport.FileText{Path: q.Path}
		file.Before, file.BeforeReason = previewText(ctx, beforeRoot, selected.Before, allowed, redact)
		file.After, file.AfterReason = previewText(ctx, afterRoot, selected.After, allowed, redact)
		result.File = file
	}
	return result, nil
}
