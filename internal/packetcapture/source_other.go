//go:build !linux

package packetcapture

func openLiveSource(Interface) (Source, error) { return nil, ErrUnsupportedLivePlatform }
