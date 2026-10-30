package executor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// copyDockerLogs never allocates from the untrusted mux length. The upstream
// stdcopy helper grows its buffer to frameSize even for a bounded input reader.
func copyDockerLogs(stdout, stderr io.Writer, reader io.Reader) (int64, error) {
	var total int64
	header := make([]byte, 8)
	buffer := make([]byte, 32<<10)
	for {
		_, err := io.ReadFull(reader, header)
		if errors.Is(err, io.EOF) {
			return total, nil
		}
		if err != nil {
			return total, fmt.Errorf("incomplete Docker log header")
		}
		if header[1] != 0 || header[2] != 0 || header[3] != 0 {
			return total, fmt.Errorf("invalid Docker log frame")
		}
		length := int64(binary.BigEndian.Uint32(header[4:]))
		if length > 1<<20 {
			return total, fmt.Errorf("Docker log frame exceeds read budget")
		}
		var writer io.Writer
		switch header[0] {
		case 0, 1:
			writer = stdout
		case 2:
			writer = stderr
		default:
			return total, fmt.Errorf("unsupported Docker log stream")
		}
		written, err := io.CopyBuffer(writer, io.LimitReader(reader, length), buffer)
		total += written
		if err != nil || written != length {
			return total, fmt.Errorf("incomplete Docker log frame")
		}
	}
}
