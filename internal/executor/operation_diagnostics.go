package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ctf-service-manager/ctf-service-manager/internal/docker"
	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
)

func (m *Manager) OperationDiagnostics(ctx context.Context, id domain.ID, after uint64) (store.DiagnosticLog, error) {
	return m.Store.DiagnosticsPage(ctx, id, after)
}

// A stream keeps enough trailing bytes to recognize a secret split over any
// number of stdout/stderr writes. Only redacted text reaches durable storage.
// Command output remains sensitive: unknown/generated/encoded secrets cannot
// be exhaustively recognized and require the existing sensitive_access gate.
type diagnosticWriter struct {
	mu              sync.Mutex
	pending         []byte
	secrets         [][]byte
	longest         int
	append          func(string) error
	err             error
	closed          bool
	withheld        bool
	withheldWritten bool
}

func newDiagnosticWriter(appendChunk func(string) error, known []string) *diagnosticWriter {
	w := &diagnosticWriter{append: appendChunk, longest: 1}
	seen := map[string]bool{}
	var total int
	for _, value := range known {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		total += len(value)
		if len(seen) > 512 || total > 4<<20 {
			w.withheld = true
			w.secrets = nil
			return w
		}
		w.secrets = append(w.secrets, []byte(value))
		if len(value) > w.longest {
			w.longest = len(value)
		}
	}
	sort.Slice(w.secrets, func(i, j int) bool { return len(w.secrets[i]) > len(w.secrets[j]) })
	return w
}

func (w *diagnosticWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, errors.New("diagnostic writer closed")
	}
	if w.err != nil {
		return 0, w.err
	}
	if w.withheld {
		if !w.withheldWritten {
			w.err = w.append("[command output withheld: known-secret redaction set exceeds bounded processing limits]\n")
			w.withheldWritten = true
		}
		if w.err != nil {
			return 0, w.err
		}
		return len(data), nil
	}
	// exec usually writes small chunks; cap work even for a custom large Writer
	// caller so an untrusted output line cannot allocate an unbounded buffer.
	for offset := 0; offset < len(data); {
		end := min(offset+store.DiagnosticChunkLimit, len(data))
		w.pending = append(w.pending, data[offset:end]...)
		if err := w.flush(false); err != nil {
			w.err = err
			return offset, err
		}
		offset = end
	}
	return len(data), nil
}

func (w *diagnosticWriter) flush(final bool) error {
	safe := len(w.pending) - w.longest + 1
	if final {
		safe = len(w.pending)
	}
	if safe <= 0 {
		return nil
	}
	var redacted bytes.Buffer
	i := 0
	for i < safe {
		match := false
		for _, secret := range w.secrets {
			if bytes.HasPrefix(w.pending[i:], secret) {
				redacted.WriteString("[REDACTED]")
				i += len(secret)
				match = true
				break
			}
		}
		if !match {
			redacted.WriteByte(w.pending[i])
			i++
		}
	}
	w.pending = append(w.pending[:0], w.pending[i:]...)
	text := strings.Map(func(r rune) rune {
		if r == '\r' {
			return '\n'
		}
		if r == '\n' || r == '\t' || r >= 32 && (r < 127 || r > 159) {
			return r
		}
		return -1
	}, strings.ToValidUTF8(redacted.String(), "�"))
	for len(text) > 0 {
		n := min(len(text), store.DiagnosticChunkLimit)
		for n > 0 && !utf8.ValidString(text[:n]) {
			n--
		}
		if n == 0 {
			return errors.New("invalid diagnostic encoding")
		}
		if err := w.append(text[:n]); err != nil {
			return err
		}
		text = text[n:]
	}
	return nil
}

func (w *diagnosticWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.err
	}
	w.closed = true
	if w.err == nil {
		w.err = w.flush(true)
	}
	clear(w.pending)
	for _, value := range w.secrets {
		clear(value)
	}
	w.pending = nil
	w.secrets = nil
	return w.err
}

func (m *Manager) commandDiagnosticWriter(ctx context.Context, operation domain.ID, stage string, configuration Configuration) (*diagnosticWriter, error) {
	known := []string{}
	add := func(data []byte) {
		known = append(known, string(data))
		for _, line := range strings.Split(string(data), "\n") {
			if value := strings.TrimSpace(line); value != "" {
				known = append(known, value)
			}
		}
	}
	if (len(configuration.Environment) > 0 || len(configuration.FileInputs) > 0) && m.Vault == nil {
		return nil, errors.New("secret vault unavailable for command redaction")
	}
	for _, ref := range configuration.Environment {
		data, err := m.Vault.Read(ref)
		if err != nil {
			return nil, errors.New("required environment unavailable for command redaction")
		}
		var values map[string]any
		if err := json.Unmarshal(data, &values); err != nil {
			clear(data)
			return nil, errors.New("invalid environment for command redaction")
		}
		for _, raw := range values {
			if value, ok := raw.(string); ok && value != "" {
				known = append(known, value)
				encoded, _ := json.Marshal(value)
				if len(encoded) > 2 {
					known = append(known, string(encoded[1:len(encoded)-1]))
				}
			}
		}
		clear(data)
	}
	for _, ref := range configuration.FileInputs {
		data, err := m.Vault.Read(ref)
		if err != nil {
			return nil, errors.New("required file input unavailable for command redaction")
		}
		add(data)
		clear(data)
	}
	// Keep only string values referenced by this command; no vault scan and no
	// unrelated service secrets are read for diagnostic rendering.
	return newDiagnosticWriter(func(content string) error {
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return m.Store.AppendDiagnostic(writeCtx, operation, stage, content)
	}, known), nil
}

func (m *Manager) composeActionWithDiagnostics(ctx context.Context, s domain.Service, operation domain.ID, configuration Configuration, model map[string]any, action string, targets []string, extra io.Writer) error {
	stage := "compose_" + action
	w, err := m.commandDiagnosticWriter(ctx, operation, stage, configuration)
	if err != nil {
		return err
	}
	output := io.Writer(w)
	if extra != nil {
		output = io.MultiWriter(extra, w)
	}
	commandErr := docker.ComposeAction(ctx, m.Config, s.ComposeProject, s.ProjectDirectory, model, action, targets, output)
	if closeErr := w.Close(); closeErr != nil {
		return errors.Join(commandErr, fmt.Errorf("operation diagnostics persistence failed: %w", closeErr))
	}
	return commandErr
}
