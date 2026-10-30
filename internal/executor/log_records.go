package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
	"github.com/moby/moby/client"
)

const logTextBudget = 96 << 10
const logRecordLimit = 500

// displayRedactor applies known private input values before filtering or sending
// any text to the dashboard. It intentionally errs on the side of redaction.
func (m *Manager) displayRedactor(ctx context.Context, s domain.Service) (func(string) string, error) {
	values := []string{}
	if m.Store != nil {
		healthValues, err := m.healthDisplaySecrets(ctx, s)
		if err != nil {
			return nil, fmt.Errorf("private probe input redaction unavailable")
		}
		values = append(values, healthValues...)
	}
	if len(s.SecretVersions) > 0 && m.Vault == nil {
		return nil, fmt.Errorf("private input redaction unavailable")
	}
	for _, ref := range s.SecretVersions {
		data, err := m.Vault.Read(ref)
		if err != nil {
			return nil, fmt.Errorf("private input redaction unavailable")
		}
		var env map[string]any
		if json.Unmarshal(data, &env) == nil && env != nil {
			for _, value := range env {
				if v, ok := value.(string); ok && v != "" {
					values = append(values, v)
				}
			}
		} else if len(data) > 0 {
			values = append(values, string(data))
		}
		clear(data)
	}
	// A multiline value may be printed as several Docker records. Redact its
	// nonempty lines as well as the exact full value.
	for _, value := range append([]string{}, values...) {
		for _, line := range strings.Split(value, "\n") {
			if line != "" {
				values = append(values, line)
			}
		}
	}
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	return func(text string) string {
		for _, value := range values {
			text = strings.ReplaceAll(text, value, "[REDACTED]")
		}
		return text
	}, nil
}

func safeLogText(text string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' || unicode.IsPrint(r) {
			return r
		}
		if r == 0x1b {
			return '␛'
		}
		return '�'
	}, text)
}

func decodeLogLines(data []byte, component, container, stream string, redact func(string) string, q transport.LogQuery) []transport.LogRecord {
	include, _ := regexp.Compile(q.Include)
	exclude, _ := regexp.Compile(q.Exclude)
	out := []transport.LogRecord{}
	occurrences := map[string]int{}
	lines := strings.Split(string(data), "\n")
	// A frame can contain many newlines. Bound record objects and identity map
	// independently of Docker's tail count and the bounded raw byte reader.
	if len(lines) > logRecordLimit+1 {
		lines = lines[len(lines)-logRecordLimit-1:]
	}
	for _, line := range lines {
		if line == "" {
			continue
		}
		at, text, found := strings.Cut(line, " ")
		if _, err := time.Parse(time.RFC3339Nano, at); err != nil || !found {
			at = ""
			text = line
		}
		text = safeLogText(redact(text))
		truncated := len(text) > 16384
		if truncated {
			text = text[:16384]
			for !utf8.ValidString(text) {
				text = text[:len(text)-1]
			}
		}
		if q.Search != "" && !strings.Contains(strings.ToLower(text), strings.ToLower(q.Search)) {
			continue
		}
		if q.Include != "" && !include.MatchString(text) {
			continue
		}
		if q.Exclude != "" && exclude.MatchString(text) {
			continue
		}
		identity := container + "\x00" + stream + "\x00" + at + "\x00" + text
		occurrences[identity]++
		out = append(out, transport.LogRecord{ID: string(domain.Hash([]byte(identity + "\x00" + strconv.Itoa(occurrences[identity])))), At: at, Component: component, ContainerID: container, Stream: stream, Text: text, Truncated: truncated})
	}
	return out
}

func (m *Manager) LogRecords(ctx context.Context, id domain.ID, q transport.LogQuery) (transport.LogPage, error) {
	result := transport.LogPage{At: time.Now().UTC(), Records: []transport.LogRecord{}, Sources: []transport.LogSource{}, Limit: logRecordLimit}
	if err := q.Validate(); err != nil {
		return result, err
	}
	s, err := m.Store.GetService(ctx, id)
	if err != nil {
		return result, err
	}
	known := q.Component == "*"
	for _, ref := range s.Containers {
		known = known || ref.Component == q.Component
	}
	if !known {
		return result, fmt.Errorf("component is outside service policy")
	}
	redact, err := m.displayRedactor(ctx, s)
	if err != nil {
		return result, err
	}
	inventory, err := m.Engine.Inventory(ctx, s.ComposeProject)
	if err != nil {
		return result, err
	}
	allowed := map[string]bool{}
	for _, ref := range s.Containers {
		allowed[ref.Component] = true
	}
	for component := range allowed {
		if q.Component != "*" && q.Component != component {
			continue
		}
		found := false
		for _, c := range inventory {
			found = found || c.Component == component
		}
		if !found {
			result.Sources = append(result.Sources, transport.LogSource{Component: component, Error: "registered component has no current container; historical logs may be unavailable"})
		}
	}
	rawBudget := 1 << 20
	for _, c := range inventory {
		if !allowed[c.Component] || q.Component != "*" && q.Component != c.Component {
			continue
		}
		source := transport.LogSource{Component: c.Component, ContainerID: c.ID}
		inspection, err := m.Engine.Client.ContainerInspect(ctx, c.ID, client.ContainerInspectOptions{})
		if err != nil {
			source.Error = "container inspection unavailable"
			result.Sources = append(result.Sources, source)
			continue
		}
		info := inspection.Container
		if info.HostConfig != nil {
			source.Driver = info.HostConfig.LogConfig.Type
		}
		if info.Config != nil {
			source.TTY = info.Config.Tty
		}
		if rawBudget <= 0 {
			result.Truncated = true
			source.Error = "aggregate log read budget exhausted"
			result.Sources = append(result.Sources, source)
			continue
		}
		if source.Driver == "none" {
			source.Error = "logging driver does not retain container output"
			result.Sources = append(result.Sources, source)
			continue
		}
		reader, err := m.Engine.Client.ContainerLogs(ctx, c.ID, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Timestamps: true, Tail: strconv.Itoa(q.Tail), Since: q.Since, Until: q.Until})
		if err != nil {
			source.Error = "logs unavailable: driver, deleted container, or Docker API limitation"
			result.Sources = append(result.Sources, source)
			continue
		}
		stdout := &boundedBuffer{limit: rawBudget}
		stderr := &boundedBuffer{limit: rawBudget}
		boundedRaw := &io.LimitedReader{R: reader, N: int64(rawBudget + 65536)}
		if source.TTY {
			_, err = io.Copy(stdout, io.LimitReader(reader, int64(rawBudget+1)))
		} else {
			_, err = copyDockerLogs(stdout, stderr, boundedRaw)
		}
		reader.Close()
		rawBudget -= len(stdout.data) + len(stderr.data)
		result.Truncated = result.Truncated || stdout.truncated || stderr.truncated || rawBudget < 0 || boundedRaw.N == 0
		if err != nil && !stdout.truncated && !stderr.truncated {
			source.Error = "log stream incomplete"
			result.Truncated = true
		}
		// Never expose a partial terminal record: a private value can cross the
		// byte limit and therefore cannot be recognized by literal redaction.
		if stdout.truncated || stderr.truncated || rawBudget < 0 || err != nil || boundedRaw.N == 0 {
			stdout.data = completeLogPrefix(stdout.data)
			stderr.data = completeLogPrefix(stderr.data)
		}
		stream := "stdout"
		if source.TTY {
			stream = "combined"
		}
		if strings.Count(string(stdout.data), "\n") > logRecordLimit || strings.Count(string(stderr.data), "\n") > logRecordLimit {
			result.Truncated = true
		}
		result.Records = append(result.Records, decodeLogLines(stdout.data, c.Component, c.ID, stream, redact, q)...)
		result.Records = append(result.Records, decodeLogLines(stderr.data, c.Component, c.ID, "stderr", redact, q)...)
		result.Sources = append(result.Sources, source)
	}
	// Docker timestamps establish a display order, not a global causality order.
	sort.SliceStable(result.Records, func(i, j int) bool {
		a, b := result.Records[i], result.Records[j]
		aa, _ := time.Parse(time.RFC3339Nano, a.At)
		bb, _ := time.Parse(time.RFC3339Nano, b.At)
		if aa.Equal(bb) {
			return a.ID < b.ID
		}
		return aa.Before(bb)
	})
	bytes := 0
	start := len(result.Records)
	for start > 0 {
		r := result.Records[start-1]
		if len(result.Records)-start >= logRecordLimit || bytes+len(r.Text) > logTextBudget {
			result.Truncated = true
			break
		}
		bytes += len(r.Text)
		start--
	}
	if start > 0 {
		result.Records = append([]transport.LogRecord{}, result.Records[start:]...)
	}
	return result, nil
}

func completeLogPrefix(data []byte) []byte {
	last := strings.LastIndexByte(string(data), '\n')
	if last < 0 {
		return nil
	}
	return data[:last+1]
}
