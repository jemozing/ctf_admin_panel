package proxy

import (
	"errors"
	"os"
	"path/filepath"
	"time"
)

type auditEvent struct {
	At        time.Time `json:"at"`
	Action    string    `json:"action"`
	ServiceID string    `json:"service_id,omitempty"`
	IP        string    `json:"ip,omitempty"`
	Comment   string    `json:"comment"`
	Revision  uint64    `json:"revision,omitempty"`
}
type auditFile struct {
	SchemaVersion int          `json:"schema_version"`
	Events        []auditEvent `json:"events"`
}

func appendAudit(directory, name string, event auditEvent) error {
	var value auditFile
	err := readJSON(filepath.Join(directory, name), &value)
	if err != nil && !os.IsNotExist(err) {
		return errors.New("private control audit unavailable")
	}
	if err == nil && (value.SchemaVersion != 1 || len(value.Events) > 256) {
		return errors.New("private control audit is invalid")
	}
	value.SchemaVersion = 1
	value.Events = append(value.Events, event)
	if len(value.Events) > 256 {
		value.Events = value.Events[len(value.Events)-256:]
	}
	if err := atomicJSON(directory, name, value); err != nil {
		return errors.New("private control audit cannot be recorded")
	}
	return nil
}

// RecordEmergencyAudit is called under the desired policy directory lock by
// the local CLI. Runtime control events use a separate single-writer audit file.
func RecordEmergencyAudit(directory, action, service, comment string, revision uint64) error {
	if len(action) > 64 || len(comment) > 500 || comment == "" {
		return errors.New("invalid emergency audit event")
	}
	return appendAudit(directory, "emergency-audit.json", auditEvent{At: time.Now().UTC(), Action: action, ServiceID: service, Comment: comment, Revision: revision})
}

func (e *Engine) audit(action, service, ip, comment string) error {
	e.auditMu.Lock()
	defer e.auditMu.Unlock()
	return appendAudit(e.options.StateDirectory, "control-audit.json", auditEvent{At: e.options.Now(), Action: action, ServiceID: service, IP: ip, Comment: comment})
}
