package flows

import (
	"encoding/binary"
	"net/netip"
)

type transportPacket struct {
	protocol                    string
	source, destination         netip.Addr
	sourcePort, destinationPort int
	seq                         uint32
	ack                         uint32
	flags                       uint8
	payload                     []byte
	wirePayload                 int
	headerComplete              bool
	reason                      string
}

// parsePacket parses Ethernet/VLAN/IPv4/IPv6 transport headers. Fragmented IP
// observations are not joined: transport reassembly cannot guess missing IP
// fragments. Packet padding never becomes application data.
func parsePacket(data []byte) (transportPacket, bool) {
	var p transportPacket
	if len(data) < 14 {
		return p, false
	}
	pos := 14
	kind := binary.BigEndian.Uint16(data[12:14])
	for n := 0; kind == 0x8100 || kind == 0x88a8; n++ {
		if n >= 2 || pos+4 > len(data) {
			return p, false
		}
		kind = binary.BigEndian.Uint16(data[pos+2 : pos+4])
		pos += 4
	}
	var next byte
	end := 0
	switch kind {
	case 0x800:
		if pos+20 > len(data) || data[pos]>>4 != 4 {
			return p, false
		}
		ihl := int(data[pos]&15) * 4
		total := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		if ihl < 20 || total < ihl || pos+ihl > len(data) || binary.BigEndian.Uint16(data[pos+6:pos+8])&0x3fff != 0 {
			return p, false
		}
		end = pos + total
		next = data[pos+9]
		p.source = netip.AddrFrom4([4]byte(data[pos+12 : pos+16]))
		p.destination = netip.AddrFrom4([4]byte(data[pos+16 : pos+20]))
		pos += ihl
	case 0x86dd:
		if pos+40 > len(data) || data[pos]>>4 != 6 {
			return p, false
		}
		payload := int(binary.BigEndian.Uint16(data[pos+4 : pos+6]))
		if payload == 0 {
			return p, false
		}
		end = pos + 40 + payload
		next = data[pos+6]
		p.source = netip.AddrFrom16([16]byte(data[pos+8 : pos+24])).Unmap()
		p.destination = netip.AddrFrom16([16]byte(data[pos+24 : pos+40])).Unmap()
		pos += 40
		start := pos
		for n := 0; next != 6 && next != 17; n++ {
			if n >= 8 || pos+2 > len(data) || pos-start > 256 {
				return p, false
			}
			size := 0
			switch next {
			case 0, 43, 60:
				size = (int(data[pos+1]) + 1) * 8
			case 51:
				size = (int(data[pos+1]) + 2) * 4
			default:
				return p, false
			}
			if size < 8 || pos+size > len(data) || pos+size > end || pos+size-start > 256 {
				return p, false
			}
			next = data[pos]
			pos += size
		}
	default:
		return p, false
	}
	if pos+4 > len(data) || pos+4 > end {
		return p, false
	}
	p.sourcePort = int(binary.BigEndian.Uint16(data[pos : pos+2]))
	p.destinationPort = int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
	header := 0
	switch next {
	case 6:
		if pos+20 > len(data) || pos+20 > end {
			return p, false
		}
		header = int(data[pos+12]>>4) * 4
		if header < 20 || pos+header > len(data) || pos+header > end {
			return p, false
		}
		p.protocol = "tcp"
		p.seq = binary.BigEndian.Uint32(data[pos+4 : pos+8])
		p.ack = binary.BigEndian.Uint32(data[pos+8 : pos+12])
		p.flags = data[pos+13]
		p.wirePayload = end - pos - header
	case 17:
		if pos+8 > len(data) || pos+8 > end {
			return p, false
		}
		size := int(binary.BigEndian.Uint16(data[pos+4 : pos+6]))
		if size < 8 || pos+size > end {
			return p, false
		}
		header = 8
		p.protocol = "udp"
		p.wirePayload = size - 8
		end = pos + size
	default:
		return p, false
	}
	p.headerComplete = true
	start := pos + header
	if start < len(data) {
		p.payload = data[start:min(len(data), end)]
	}
	if len(p.payload) < p.wirePayload {
		p.reason = "capture_truncated"
	}
	return p, true
}
