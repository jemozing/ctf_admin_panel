//go:build !linux && !darwin

package maintenance

import "errors"

var ErrActive = errors.New("maintenance locks require Linux or macOS")

type Lock struct{}

func Acquire(string, bool) (*Lock, error) { return nil, ErrActive }
func (*Lock) Close() error                { return nil }
