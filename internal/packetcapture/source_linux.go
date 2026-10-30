//go:build linux

package packetcapture

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

type liveSource struct {
	fd     int
	once   sync.Once
	buffer []byte
	fdMu   sync.Mutex
	closed atomic.Bool
}

func networkShort(v uint16) int {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return int(binary.NativeEndian.Uint16(b[:]))
}

func openLiveSource(iface Interface) (Source, error) {
	if !iface.Supported {
		return nil, errors.New("unsupported capture link type")
	}
	protocol := networkShort(unix.ETH_P_ALL)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, protocol)
	if err != nil {
		return nil, ErrUnsupportedLivePlatform
	}
	if err = unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: uint16(protocol), Ifindex: iface.Index}); err != nil {
		unix.Close(fd)
		return nil, errors.New("approved capture interface unavailable")
	}
	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20); err != nil {
		unix.Close(fd)
		return nil, errors.New("bounded packet receive buffer unavailable")
	}
	return &liveSource{fd: fd, buffer: make([]byte, 65535)}, nil
}

func (s *liveSource) Read(ctx context.Context) (Frame, error) {
	buffer := s.buffer
	for {
		if err := ctx.Err(); err != nil {
			return Frame{}, err
		}
		if s.closed.Load() {
			return Frame{}, errors.New("capture socket closed")
		}
		s.fdMu.Lock()
		if s.closed.Load() {
			s.fdMu.Unlock()
			return Frame{}, errors.New("capture socket closed")
		}
		poll := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN}}
		_, err := unix.Poll(poll, 200)
		if err == unix.EINTR {
			s.fdMu.Unlock()
			continue
		}
		if err != nil {
			s.fdMu.Unlock()
			return Frame{}, err
		}
		if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			s.fdMu.Unlock()
			return Frame{}, errors.New("capture socket closed")
		}
		if poll[0].Revents&unix.POLLIN == 0 {
			s.fdMu.Unlock()
			continue
		}
		n, _, _, address, err := unix.Recvmsg(s.fd, buffer, nil, unix.MSG_TRUNC|unix.MSG_DONTWAIT)
		s.fdMu.Unlock()
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		if err != nil {
			return Frame{}, err
		}
		link, ok := address.(*unix.SockaddrLinklayer)
		if !ok || link.Ifindex == 0 {
			return Frame{}, errors.New("capture socket returned unknown link")
		}
		// ARPHRD_ETHER=1 and ARPHRD_LOOPBACK=772 both use Ethernet headers
		// for SOCK_RAW AF_PACKET. Other links would require a different DLT.
		if link.Hatype != 1 && link.Hatype != 772 {
			continue
		}
		return Frame{Data: buffer[:min(n, len(buffer))], WireLength: n, At: time.Now().UTC(), PacketType: link.Pkttype}, nil
	}
}

func (s *liveSource) Close() error {
	var err error
	s.closed.Store(true)
	s.once.Do(func() { s.fdMu.Lock(); defer s.fdMu.Unlock(); err = unix.Close(s.fd) })
	return err
}
