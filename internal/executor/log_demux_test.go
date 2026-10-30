package executor

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

func TestDockerLogDemuxRejectsForgedLengthBeforeReadingPayload(t *testing.T) {
	header := make([]byte, 8)
	header[0] = 1
	binary.BigEndian.PutUint32(header[4:], 0xffffffff)
	reader := bytes.NewReader(append(header, []byte("private-payload")...))
	var stdout, stderr strings.Builder
	if _, err := copyDockerLogs(&stdout, &stderr, reader); err == nil || reader.Len() != len("private-payload") || stdout.Len() != 0 {
		t.Fatal("forged frame allocated/read payload or leaked data")
	}
	if _, err := copyDockerLogs(io.Discard, io.Discard, bytes.NewReader([]byte{1, 0, 0})); err == nil {
		t.Fatal("partial header silently accepted")
	}
	binary.BigEndian.PutUint32(header[4:], 10)
	if _, err := copyDockerLogs(io.Discard, io.Discard, bytes.NewReader(append(header, []byte("short")...))); err == nil {
		t.Fatal("partial frame silently accepted")
	}
}
