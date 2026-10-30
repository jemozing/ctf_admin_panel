package packets

import (
	"errors"
	"strings"
)

func validateVersionBindings(r *Record) error {
	if len(r.VersionBindings) > 256 {
		return errors.New("capture version binding budget exceeded")
	}
	seen := map[VersionBinding]bool{}
	for _, v := range r.VersionBindings {
		associated := r.ServiceID != "" && v.ServiceID == r.ServiceID && v.Component == r.Component
		for _, c := range r.Candidates {
			associated = associated || (v.ServiceID == c.ServiceID && v.Component == c.Component)
		}
		if !validID(v.ServiceID) || !validID(v.Component) || !associated || seen[v] || v.ReleaseID == "" && v.SourceDigest == "" || v.ReleaseID != "" && !validID(v.ReleaseID) {
			return errors.New("invalid capture version binding")
		}
		if v.SourceDigest != "" {
			if !strings.HasPrefix(v.SourceDigest, "sha256:") || len(v.SourceDigest) != 71 {
				return errors.New("invalid capture source digest")
			}
			for _, ch := range v.SourceDigest[7:] {
				if !strings.ContainsRune("abcdef0123456789", ch) {
					return errors.New("invalid capture source digest")
				}
			}
		}
		seen[v] = true
	}
	return nil
}
