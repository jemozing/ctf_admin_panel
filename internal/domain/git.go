package domain

import (
	"encoding/hex"
	"errors"
	"net/url"
)

// GitProvenance identifies the exact fetched tree. It contains no credentials;
// repository configuration changes cannot rewrite an existing candidate/release.
type GitProvenance struct {
	URL            string `json:"url"`
	Ref            string `json:"ref"`
	Subdirectory   string `json:"subdirectory,omitempty"`
	Commit         string `json:"commit"`
	SourceRevision uint64 `json:"source_revision"`
}

func (g GitProvenance) Validate() error {
	u, err := url.Parse(g.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(g.URL) > 2048 {
		return errors.New("invalid Git provenance URL")
	}
	if g.SourceRevision == 0 || len(g.Commit) != 40 && len(g.Commit) != 64 {
		return errors.New("invalid Git provenance commit or revision")
	}
	if _, err := hex.DecodeString(g.Commit); err != nil {
		return errors.New("invalid Git provenance commit")
	}
	if err := validateText(g.Ref, "Git ref", 255); err != nil {
		return err
	}
	if g.Subdirectory != "" {
		return ValidateRelativePath(g.Subdirectory)
	}
	return nil
}
