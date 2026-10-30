//go:build !linux && !darwin

package backup

import "errors"

func publishDirectory(string, string) error {
	return errors.New("safe backup publication requires Linux or macOS")
}
