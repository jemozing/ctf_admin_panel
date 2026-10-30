package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

const encryptedMagic = "CTFMBK1\n"
const chunkSize = 1 << 20
const cryptoHeaderSize = len(encryptedMagic) + 16 + 4

// Each chunk and the mandatory final empty record are authenticated. Removing,
// appending, truncating or reordering records cannot produce a valid archive.
type encryptWriter struct {
	w        io.Writer
	aead     cipher.AEAD
	header   []byte
	buffer   []byte
	sequence uint64
	closed   bool
}

func newEncryptWriter(w io.Writer, password []byte) (*encryptWriter, error) {
	if len(password) < 16 || len(password) > 4096 {
		return nil, errors.New("backup passphrase must contain 16..4096 bytes")
	}
	header := make([]byte, cryptoHeaderSize)
	copy(header, encryptedMagic)
	if _, err := rand.Read(header[len(encryptedMagic):]); err != nil {
		return nil, err
	}
	aead, err := backupCipher(password, header)
	if err != nil {
		return nil, err
	}
	if err := writeComplete(w, header); err != nil {
		return nil, err
	}
	return &encryptWriter{w: w, aead: aead, header: header, buffer: make([]byte, 0, chunkSize)}, nil
}

func backupCipher(password, header []byte) (cipher.AEAD, error) {
	key := argon2.IDKey(password, header[len(encryptedMagic):len(encryptedMagic)+16], 3, 64*1024, 1, 32)
	block, err := aes.NewCipher(key)
	for i := range key {
		key[i] = 0
	}
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func cryptoFields(header []byte, sequence uint64, record uint32) ([]byte, []byte) {
	nonce := make([]byte, 12)
	copy(nonce, header[len(header)-4:])
	binary.BigEndian.PutUint64(nonce[4:], sequence)
	aad := append([]byte{}, header...)
	aad = binary.BigEndian.AppendUint64(aad, sequence)
	aad = binary.BigEndian.AppendUint32(aad, record)
	return nonce, aad
}
func (w *encryptWriter) record(final bool) error {
	if w.sequence == ^uint64(0) {
		return errors.New("encrypted backup is too large")
	}
	size := uint32(len(w.buffer) + w.aead.Overhead())
	if final {
		size |= 1 << 31
	}
	nonce, aad := cryptoFields(w.header, w.sequence, size)
	sealed := w.aead.Seal(nil, nonce, w.buffer, aad)
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], size)
	if err := writeComplete(w.w, prefix[:]); err != nil {
		return err
	}
	if err := writeComplete(w.w, sealed); err != nil {
		return err
	}
	w.sequence++
	w.buffer = w.buffer[:0]
	return nil
}
func (w *encryptWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("encrypted backup writer is closed")
	}
	used := 0
	for len(p) > 0 {
		n := min(chunkSize-len(w.buffer), len(p))
		w.buffer = append(w.buffer, p[:n]...)
		p = p[n:]
		used += n
		if len(w.buffer) == chunkSize {
			if err := w.record(false); err != nil {
				return used, err
			}
		}
	}
	return used, nil
}
func (w *encryptWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	if len(w.buffer) > 0 {
		if err := w.record(false); err != nil {
			return err
		}
	}
	return w.record(true)
}

type decryptReader struct {
	r        io.Reader
	aead     cipher.AEAD
	header   []byte
	buffer   *bytes.Reader
	sequence uint64
	finished bool
}

func newDecryptReader(r io.Reader, password []byte) (*decryptReader, error) {
	if len(password) < 16 || len(password) > 4096 {
		return nil, errors.New("backup passphrase must contain 16..4096 bytes")
	}
	header := make([]byte, cryptoHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, errors.New("encrypted backup header is truncated")
	}
	if string(header[:len(encryptedMagic)]) != encryptedMagic {
		return nil, errors.New("unknown encrypted backup format")
	}
	aead, err := backupCipher(password, header)
	if err != nil {
		return nil, err
	}
	return &decryptReader{r: r, aead: aead, header: header, buffer: bytes.NewReader(nil)}, nil
}
func (r *decryptReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.buffer.Len() > 0 {
		return r.buffer.Read(p)
	}
	if r.finished {
		return 0, io.EOF
	}
	var prefix [4]byte
	if _, err := io.ReadFull(r.r, prefix[:]); err != nil {
		return 0, errors.New("encrypted backup is truncated before its final record")
	}
	record := binary.BigEndian.Uint32(prefix[:])
	final := record&(1<<31) != 0
	size := record &^ (uint32(1) << 31)
	if size < uint32(r.aead.Overhead()) || size > chunkSize+uint32(r.aead.Overhead()) || final && size != uint32(r.aead.Overhead()) || !final && size == uint32(r.aead.Overhead()) {
		return 0, errors.New("encrypted backup record length is invalid")
	}
	sealed := make([]byte, size)
	if _, err := io.ReadFull(r.r, sealed); err != nil {
		return 0, errors.New("encrypted backup record is truncated")
	}
	nonce, aad := cryptoFields(r.header, r.sequence, record)
	plain, err := r.aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		return 0, errors.New("backup authentication failed: incorrect passphrase or damaged backup")
	}
	r.sequence++
	if final {
		var trailing [1]byte
		n, err := r.r.Read(trailing[:])
		if n != 0 || err != io.EOF {
			return 0, errors.New("data follows encrypted backup final record")
		}
		r.finished = true
		return 0, io.EOF
	}
	r.buffer = bytes.NewReader(plain)
	return r.Read(p)
}

func writeComplete(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err == nil && n != len(p) {
		return io.ErrShortWrite
	}
	return err
}
