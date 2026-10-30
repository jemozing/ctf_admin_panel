package packetcapture

import (
	"encoding/binary"
	"net/netip"
)

type parsedFrame struct {
	protocol                    string
	source, destination         netip.Addr
	sourcePort, destinationPort int
	flags                       uint8
}

// parseEthernet only parses bounded network/transport headers. Fragment bodies,
// encrypted content and application messages are never interpreted.
func parseEthernet(data []byte) (parsedFrame, bool) {
	var p parsedFrame
	if len(data) < 14 {
		return p, false
	}
	offset := 14
	kind := binary.BigEndian.Uint16(data[12:14])
	for tags := 0; kind == 0x8100 || kind == 0x88a8; tags++ {
		if tags >= 2 || len(data) < offset+4 {
			return p, false
		}
		kind = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
	}
	var next byte
	end := len(data)
	switch kind {
	case 0x0800:
		if len(data) < offset+20 || data[offset]>>4 != 4 {
			return p, false
		}
		ihl := int(data[offset]&15) * 4
		total := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if ihl < 20 || total < ihl || len(data) < offset+ihl {
			return p, false
		}
		if binary.BigEndian.Uint16(data[offset+6:offset+8])&0x3fff != 0 {
			return p, false
		}
		if offset+total < end {
			end = offset + total
		}
		next = data[offset+9]
		p.source = netip.AddrFrom4([4]byte(data[offset+12 : offset+16]))
		p.destination = netip.AddrFrom4([4]byte(data[offset+16 : offset+20]))
		offset += ihl
	case 0x86dd:
		if len(data) < offset+40 || data[offset]>>4 != 6 {
			return p, false
		}
		payload := int(binary.BigEndian.Uint16(data[offset+4 : offset+6]))
		if payload == 0 {
			return p, false
		}
		if offset+40+payload < end {
			end = offset + 40 + payload
		}
		next = data[offset+6]
		p.source = netip.AddrFrom16([16]byte(data[offset+8 : offset+24])).Unmap()
		p.destination = netip.AddrFrom16([16]byte(data[offset+24 : offset+40])).Unmap()
		offset += 40
		start := offset
		for n := 0; next != 6 && next != 17; n++ {
			if n >= 8 || offset-start > 256 || offset+2 > end {
				return p, false
			}
			size := 0
			switch next {
			case 0, 43, 60:
				size = (int(data[offset+1]) + 1) * 8
			case 51:
				size = (int(data[offset+1]) + 2) * 4
			case 44:
				return p, false
			default:
				return p, false
			}
			if size < 8 || offset+size > end || offset+size-start > 256 {
				return p, false
			}
			next = data[offset]
			offset += size
		}
	default:
		return p, false
	}
	if next == 6 {
		if offset+20 > end {
			return p, false
		}
		size := int(data[offset+12]>>4) * 4
		if size < 20 || offset+size > end {
			return p, false
		}
		p.protocol = "tcp"
		p.flags = data[offset+13]
	} else if next == 17 {
		if offset+8 > end || binary.BigEndian.Uint16(data[offset+4:offset+6]) < 8 {
			return p, false
		}
		p.protocol = "udp"
	} else {
		return p, false
	}
	p.sourcePort = int(binary.BigEndian.Uint16(data[offset : offset+2]))
	p.destinationPort = int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
	return p, true
}
