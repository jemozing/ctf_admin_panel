//go:build !linux

package packetcapture

func enrichInterfaces(in []Interface) []Interface { return in }
