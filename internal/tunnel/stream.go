package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"chimera/internal/compiler"
	"chimera/internal/genome"
)

// maxFrameLen is the largest payload carried by one stream frame. 65535
// fits the 2-byte length prefix and the datagram codec already rejects
// larger encrypted frames.
const maxFrameLen = 65535

// maxFirstStreamFrameLen bounds a valid first handshake frame. The
// handshake is padded to at most HandshakeMaxWire bytes before encryption,
// so anything larger is either a protocol error or an active probe.
const maxFirstStreamFrameLen = 4096

// streamPacketConn adapts a reliable byte stream (TCP) to net.PacketConn by
// prefixing every CHIMERA datagram with a 2-byte big-endian length. The
// datagram bytes themselves are untouched, so a TCP session uses exactly
// the same generated handshake and record codecs as UDP.
type streamPacketConn struct {
	conn net.Conn
	rmu  sync.Mutex
	wmu  sync.Mutex
}

func newStreamPacketConn(conn net.Conn) *streamPacketConn {
	return &streamPacketConn{conn: conn}
}

// NewStreamPacketConn wraps any reliable net.Conn with the 2-byte CHIMERA
// stream framing used by TCP, WebSocket, and HTTP transports.
func NewStreamPacketConn(conn net.Conn) net.PacketConn {
	return newStreamPacketConn(conn)
}

func (c *streamPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()

	var hdr [2]byte
	if _, err := io.ReadFull(c.conn, hdr[:]); err != nil {
		return 0, c.conn.RemoteAddr(), err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 {
		return 0, c.conn.RemoteAddr(), errors.New("stream frame length is zero")
	}
	if n > len(p) {
		if _, err := io.CopyN(io.Discard, c.conn, int64(n)); err != nil {
			return 0, c.conn.RemoteAddr(), err
		}
		return 0, c.conn.RemoteAddr(), fmt.Errorf("stream frame %d exceeds buffer %d", n, len(p))
	}
	if _, err := io.ReadFull(c.conn, p[:n]); err != nil {
		return 0, c.conn.RemoteAddr(), err
	}
	return n, c.conn.RemoteAddr(), nil
}

func (c *streamPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if len(p) > maxFrameLen {
		return 0, fmt.Errorf("stream frame too large: %d", len(p))
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()

	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(p)))
	if _, err := c.conn.Write(hdr[:]); err != nil {
		return 0, err
	}
	if _, err := c.conn.Write(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *streamPacketConn) SyscallConn() (syscall.RawConn, error) {
	sc, ok := c.conn.(syscall.Conn)
	if !ok {
		return nil, errors.New("stream conn does not expose a file descriptor")
	}
	return sc.SyscallConn()
}

func (c *streamPacketConn) Close() error { return c.conn.Close() }

func (c *streamPacketConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

func (c *streamPacketConn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

func (c *streamPacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *streamPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// DialStream opens a TCP stream transport. The returned PacketConn carries
// the same generated-protocol datagrams as UDP but with 2-byte framing.
func DialStream(ctx context.Context, address string) (net.PacketConn, net.Addr, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(DefaultKeepaliveInterval)
	}
	spc := newStreamPacketConn(conn)
	return spc, conn.RemoteAddr(), nil
}

// prefedPacketConn replays one datagram already read from the stream, then
// delegates to the underlying PacketConn. It lets ServerHandshakeStream
// inspect the first frame for generation selection and still hand the same
// bytes to runHandshake.
type prefedPacketConn struct {
	net.PacketConn
	mu    sync.Mutex
	first []byte
	addr  net.Addr
}

func (p *prefedPacketConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	p.mu.Lock()
	first := p.first
	if first != nil {
		p.first = nil
		p.mu.Unlock()
		if len(first) > len(buf) {
			return 0, p.addr, fmt.Errorf("prefed frame %d exceeds buffer %d", len(first), len(buf))
		}
		copy(buf, first)
		return len(first), p.addr, nil
	}
	p.mu.Unlock()
	return p.PacketConn.ReadFrom(buf)
}

// selectStreamProtocol mirrors ServerMux.selectHandshake for the
// single-client TCP case. It inspects only the first frame and returns the
// compiled protocol whose cover and handshake step accept it.
func selectStreamProtocol(cps []*compiler.CompiledProtocol, psk []byte, data []byte) (*compiler.CompiledProtocol, uint64, error) {
	if len(cps) == 0 {
		return nil, 0, errors.New("no compiled protocol for stream handshake")
	}
	var primary, serverFirst *compiler.CompiledProtocol
	serverFirstIdx := 0
	for i, cp := range cps {
		h, err := compiler.NewHandshake(cp, genome.DirServer, psk)
		if err != nil {
			continue
		}
		if i == 0 {
			primary = cp
		}
		spec, err := h.CurrentSpec()
		if err != nil {
			continue
		}
		if spec.Direction == genome.DirServer {
			if serverFirst == nil {
				serverFirst = cp
				serverFirstIdx = i
			}
			continue
		}
		inner, err := compiler.UnwrapHandshakeDatagram(cp.Genome, data)
		if err != nil {
			continue
		}
		trimmed, err := compiler.DeclaredFrame(spec, inner)
		if err != nil {
			continue
		}
		if err := h.RecvStep(trimmed); err == nil {
			return cp, uint64(i), nil
		}
	}
	if primary == nil {
		return nil, 0, errors.New("no usable protocol for stream handshake")
	}
	if serverFirst != nil {
		inner, err := compiler.UnwrapHandshakeDatagram(primary.Genome, data)
		if err == nil && compiler.VerifyKnock(psk, inner) {
			return serverFirst, uint64(serverFirstIdx), nil
		}
	}
	return nil, 0, errProbe
}

// ServerHandshakeStream completes a server-side generated handshake over a
// reliable stream and returns an established PacketTunnel together with the
// generation that matched. The caller configures jitter/shaping/keepalive
// before starting packet pumps.
func ServerHandshakeStream(conn net.Conn, cps []*compiler.CompiledProtocol, psk []byte, jitter time.Duration) (*PacketTunnel, uint64, error) {
	spc := newStreamPacketConn(conn)
	if err := conn.SetReadDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return nil, 0, err
	}

	// Read the first stream frame manually so a scanner that sends raw TLS
	// or arbitrary bytes is recognized immediately. A 2-byte length prefix
	// above maxFirstStreamFrameLen cannot belong to a real handshake.
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, 0, err
	}
	frameLen := int(binary.BigEndian.Uint16(hdr[:]))
	if frameLen == 0 || frameLen > maxFirstStreamFrameLen {
		// Capture a few more bytes so policy layers can recognize raw TLS
		// ClientHello prefixes before deciding how to respond.
		probe := append([]byte(nil), hdr[:]...)
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		extra := make([]byte, 62)
		n, _ := conn.Read(extra)
		probe = append(probe, extra[:n]...)
		return nil, 0, &StreamProbeError{First: probe}
	}
	first := make([]byte, frameLen)
	n, err := io.ReadFull(conn, first)
	if err != nil {
		return nil, 0, &StreamProbeError{First: append(append([]byte(nil), hdr[:]...), first[:n]...)}
	}

	cp, generation, err := selectStreamProtocol(cps, psk, first)
	if err != nil {
		if errors.Is(err, errProbe) {
			return nil, 0, &StreamProbeError{First: append([]byte(nil), first...)}
		}
		return nil, 0, err
	}
	h, err := compiler.NewHandshake(cp, genome.DirServer, psk)
	if err != nil {
		return nil, 0, err
	}
	pref := &prefedPacketConn{PacketConn: spc, first: first, addr: conn.RemoteAddr()}
	peer, err := runHandshake(h, pref, nil, false, jitter, handshakeTimeout)
	if err != nil {
		return nil, 0, err
	}
	sess, err := h.FinishPacket()
	if err != nil {
		return nil, 0, err
	}
	return NewPacketTunnel(spc, peer, sess), generation, nil
}
