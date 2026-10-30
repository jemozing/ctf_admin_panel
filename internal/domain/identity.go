// Package domain defines the versioned contracts shared by the executor and its clients.
// Validation in this package is lexical. The executor must also resolve paths using
// descriptor-relative filesystem operations before accessing untrusted service trees.
package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const SchemaVersion = 1

type ID string

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var componentPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)
var volumePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}$`)

func ParseID(raw string) (ID, error) {
	id := ID(raw)
	return id, id.Validate()
}

func (id ID) Validate() error {
	if !idPattern.MatchString(string(id)) {
		return fmt.Errorf("invalid ID %q: expected 1..64 lowercase ASCII letters, digits, underscores or hyphens", id)
	}
	return nil
}

// Digest is a lowercase SHA-256 digest including its algorithm prefix.
type Digest string

func Hash(data []byte) Digest {
	sum := sha256.Sum256(data)
	return Digest("sha256:" + hex.EncodeToString(sum[:]))
}

func (d Digest) Validate() error {
	if !strings.HasPrefix(string(d), "sha256:") || len(d) != 71 {
		return fmt.Errorf("invalid SHA-256 digest")
	}
	value := string(d)[7:]
	if strings.ToLower(value) != value {
		return fmt.Errorf("digest must use lowercase hexadecimal")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("invalid SHA-256 digest: %w", err)
	}
	return nil
}

func validateText(value, name string, max int) error {
	if value == "" || len(value) > max || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must contain 1..%d bytes without surrounding whitespace", name, max)
	}
	for _, c := range value {
		if unicode.IsControl(c) {
			return fmt.Errorf("%s contains a control character", name)
		}
	}
	return nil
}

// ValidateRelativePath accepts canonical, nonempty POSIX paths below a registered root.
// Backslashes are rejected so paths cannot acquire another meaning in other adapters.
func ValidateRelativePath(value string) error {
	if err := validateText(value, "relative path", 4096); err != nil {
		return err
	}
	if path.IsAbs(value) || path.Clean(value) != value || value == "." || value == ".." || strings.HasPrefix(value, "../") || strings.Contains(value, `\`) {
		return fmt.Errorf("path %q must be a canonical relative POSIX path below its root", value)
	}
	return nil
}

func ValidateAbsolutePath(value string) error {
	if err := validateText(value, "absolute path", 4096); err != nil {
		return err
	}
	if !path.IsAbs(value) || path.Clean(value) != value || value == "/" || strings.Contains(value, `\`) {
		return fmt.Errorf("path %q must be a canonical absolute POSIX path other than /", value)
	}
	return nil
}

// PathsOverlap compares path components, not string prefixes. Inputs must be canonical.
func PathsOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func validateComponent(value string) error {
	if !componentPattern.MatchString(value) {
		return fmt.Errorf("invalid Compose component %q", value)
	}
	return nil
}

// ValidateComponent applies the same lexical boundary used by registration.
// Compose component names are distinct from lowercase internal record IDs.
func ValidateComponent(value string) error { return validateComponent(value) }
