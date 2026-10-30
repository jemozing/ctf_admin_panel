// Command secret_revocation is a fixture-only acceptance helper. It is not
// included in the dashboard/executor images or exposed over their protocol.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/secrets"
)

func main() {
	if len(os.Args) != 4 {
		fail("expected unique synthetic fixture root, secret ID and version")
	}
	root := os.Args[1]
	if filepath.Clean(root) != root || filepath.Dir(root) != "/srv" || !strings.HasPrefix(filepath.Base(root), "ctfm-container-release-") {
		fail("only the container-release smoke's dedicated fixture root is allowed")
	}
	ref := domain.SecretVersionRef{SecretID: domain.ID(os.Args[2]), Version: domain.ID(os.Args[3])}
	if ref.SecretID.Validate() != nil || ref.Version.Validate() != nil {
		fail("invalid fixture secret identity")
	}
	path := filepath.Join(root, "executor", "secrets")
	if info, err := os.Lstat(path); err != nil || !info.IsDir() {
		fail("fixture vault must already exist")
	}
	vault, err := secrets.Open(path)
	if err != nil {
		fail(err.Error())
	}
	defer vault.Close()
	if err := vault.Revoke(ref); err != nil {
		fail(err.Error())
	}
	fmt.Println("synthetic fixture secret version revoked")
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
