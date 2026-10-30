//go:build linux

package packetcapture

import (
	"encoding/binary"
	"syscall"
)

// Route-netlink GETLINK is read-only and does not require NET_ADMIN. Name/index
// still comes from the same host network namespace; unavailable topology simply
// disables veth alternatives rather than guessing a container peer.
func enrichInterfaces(in []Interface) []Interface {
	data, e := syscall.NetlinkRIB(syscall.RTM_GETLINK, syscall.AF_UNSPEC)
	if e != nil || len(data) > 2<<20 {
		return in
	}
	messages, e := syscall.ParseNetlinkMessage(data)
	if e != nil {
		return in
	}
	for _, m := range messages {
		if m.Header.Type != syscall.RTM_NEWLINK || len(m.Data) < syscall.SizeofIfInfomsg {
			continue
		}
		index := int(int32(binary.NativeEndian.Uint32(m.Data[4:8])))
		attrs, e := syscall.ParseNetlinkRouteAttr(&m)
		if e != nil {
			continue
		}
		master, peer, kind := 0, 0, ""
		for _, a := range attrs {
			switch a.Attr.Type & 0x3fff {
			case 10:
				if len(a.Value) == 4 {
					master = int(binary.NativeEndian.Uint32(a.Value))
				}
			case 5:
				if len(a.Value) == 4 {
					peer = int(binary.NativeEndian.Uint32(a.Value))
				}
			case 18:
				raw := append(make([]byte, syscall.SizeofIfInfomsg), a.Value...)
				nested, e := syscall.ParseNetlinkRouteAttr(&syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: syscall.RTM_NEWLINK}, Data: raw})
				if e != nil {
					continue
				}
				for _, v := range nested {
					if v.Attr.Type&0x3fff == 1 && len(v.Value) > 1 && len(v.Value) < 64 {
						kind = string(v.Value[:len(v.Value)-1])
					}
				}
			}
		}
		for n := range in {
			if in[n].Index == index {
				in[n].MasterIndex = master
				in[n].PeerIndex = peer
				in[n].Kind = kind
			}
		}
	}
	return in
}
