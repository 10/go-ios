package display

import (
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/golog"
)

// ErrUserspaceTunnelUnsupported is OpenReceiver's error for a userspace tunnel,
// whose address lives in the process that started it.
var ErrUserspaceTunnelUnsupported = errors.New("OpenReceiver needs a kernel tunnel: for a userspace tunnel started in this process, pass its Tunnel.ListenUDP socket to NewReceiver")

// Sized to absorb a burst while the reader is between reads. Overflowing it
// makes the device see packet loss and throttle its encoder.
const receiverReadBuffer = 1024 * 1024

// Receiver is the UDP socket the device streams RTP to. Its address and port go
// to StartVideoStream; the caller then uses Read, and WriteTo for RTCP.
type Receiver struct {
	conn net.PacketConn
	ip   string
	port int
}

// OpenReceiver binds a UDP socket on the host's kernel tunnel address, ready to
// be nominated as a stream's receiver. Close it when the stream is stopped.
func OpenReceiver(device ios.DeviceEntry) (*Receiver, error) {
	if device.UserspaceTUN {
		return nil, ErrUserspaceTunnelUnsupported
	}
	hostIP, err := hostTunnelAddress(device)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: hostIP, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("OpenReceiver: failed to bind a UDP socket on %s: %w", hostIP, err)
	}
	if err := conn.SetReadBuffer(receiverReadBuffer); err != nil {
		// Not fatal, so the stream still starts, but at warn: the smaller buffer
		// drops frames under a burst, and the device throttles when it sees that.
		golog.Warn("could not enlarge the RTP receive buffer, keeping the default",
			"module", logModule, "error", err)
	}
	return NewReceiver(conn)
}

// NewReceiver makes a Receiver of a bound UDP socket the device can reach, such
// as a userspace tunnel's Tunnel.ListenUDP. The Receiver owns conn and closes it.
func NewReceiver(conn net.PacketConn) (*Receiver, error) {
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("NewReceiver: unexpected local address type %T", conn.LocalAddr())
	}
	return &Receiver{conn: conn, ip: local.IP.String(), port: local.Port}, nil
}

// IP is the host address the device should send RTP to.
func (r *Receiver) IP() string { return r.ip }

// Port is the UDP port the device should send RTP to.
func (r *Receiver) Port() int { return r.port }

// Read receives one RTP packet and returns its length. One call is one packet,
// so a caller that wants the video keeps the boundaries by reading here rather
// than treating the Receiver as a byte stream.
func (r *Receiver) Read(packet []byte) (int, error) {
	n, _, err := r.conn.ReadFrom(packet)
	if err != nil {
		// A userspace tunnel's socket reports its close as io.EOF.
		if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
			return 0, net.ErrClosed
		}
		return 0, fmt.Errorf("the RTP stream stopped being received: %w", err)
	}
	return n, nil
}

// WriteTo sends one packet from the receiver's port, such as an RTCP receiver
// report to the port the device streams from.
func (r *Receiver) WriteTo(packet []byte, addr net.Addr) (int, error) {
	return r.conn.WriteTo(packet, addr)
}

// Close closes the socket, which is the only thing that unblocks a Read.
func (r *Receiver) Close() error {
	return r.conn.Close()
}

// hostTunnelAddress returns the host's address on the tunnel. Dialing sends
// nothing; it just makes the OS bind the local address the device can reach.
func hostTunnelAddress(device ios.DeviceEntry) (net.IP, error) {
	if device.Address == "" {
		return nil, fmt.Errorf("hostTunnelAddress: device has no tunnel address, start a tunnel first")
	}
	// Port 9 is discard; nothing is ever sent to it.
	conn, err := net.Dial("udp6", net.JoinHostPort(device.Address, "9"))
	if err != nil {
		return nil, fmt.Errorf("hostTunnelAddress: no route to device %s, is the tunnel up? %w", device.Address, err)
	}
	defer conn.Close()

	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("hostTunnelAddress: unexpected local address type %T", conn.LocalAddr())
	}
	return local.IP, nil
}
