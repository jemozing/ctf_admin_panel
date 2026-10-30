//go:build !linux && !darwin

package sourcegit

import (
	"errors"
	"os/exec"
)

func prepareRepository(string) error { return errors.New("isolated Git sources require Unix") }
func configureProcess(*exec.Cmd)     {}
