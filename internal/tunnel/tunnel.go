// Package tunnel implements the CHIMERA UDP transport: datagram handshake
// with retransmission plus encrypted packet forwarding. It deliberately
// ignores malformed datagrams without answering, so active probes receive
// nothing usable.
package tunnel

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"time"

	"chimera/internal/compiler"
)

const (
	handshakeTimeout = 8 * time.Second
	retransmitBase   = 200 * time.Millisecond
	maxRetransmit    = 2 * time.Second
	maxDatagram      = 64 * 1024

	// ControlAssignIP marks a non-IP control payload. IP packets start with
	// a 0x4 or 0x6 version nibble, so 0x01 is unambiguous.
	ControlAssignIP = 0x01
)

// PacketTunnel is an established encrypted packet channel.
type PacketTunnel struct {
	conn net.PacketConn
	peer net.Addr
	sess *compiler.PacketSession
	ctrl chan []byte
	data chan []byte
}

// NewPacketTunnel wraps an established packet session.
func NewPacketTunnel(conn net.PacketConn, peer net.Addr, sess *compiler.PacketSession) *PacketTunnel {
	return &PacketTunnel{
		conn: conn,
		peer: peer,
		sess: sess,
		ctrl: make(chan []byte, 4),
		data: make(chan []byte, 256),
	}
}

// SendPacket encrypts and transmits one IP packet.
func (t *PacketTunnel) SendPacket(packet []byte) error {
	return t.sendPayload(packet)
}

// SendControl encrypts a control payload (e.g. the assigned TUN address).
func (t *PacketTunnel) SendControl(payload []byte) error {
	return t.sendPayload(append([]byte{ControlAssignIP}, payload...))
}

func (t *PacketTunnel) sendPayload(payload []byte) error {
	frame, err := t.sess.Encode(payload)
	if err != nil {
		return err
	}
	if len(frame) > maxDatagram {
		return fmt.Errorf("encrypted frame too large: %d", len(frame))
	}
	_, err = t.conn.WriteTo(frame, t.peer)
	return err
}

// ReceivePacket blocks until a decrypted IP packet is available. Control
// payloads are routed to the control channel instead of being returned.
func (t *PacketTunnel) ReceivePacket() ([]byte, error) {
	select {
	case pkt := <-t.data:
		return pkt, nil
	default:
	}
	buf := make([]byte, maxDatagram)
	for {
		n, addr, err := t.conn.ReadFrom(buf)
		if err != nil {
			return nil, err
		}
		if t.peer != nil && addr.String() != t.peer.String() {
			continue
		}
		msg, err := t.sess.Decode(buf[:n])
		if err != nil {
			continue // silent: invalid probes and duplicates disappear
		}
		pkt := append([]byte(nil), msg.Payload...)
		if len(pkt) > 0 && pkt[0] == ControlAssignIP {
			select {
			case t.ctrl <- pkt[1:]:
			default:
				// No control consumer yet; drop rather than stall the loop.
			}
			continue
		}
		return pkt, nil
	}
}

// WaitControl blocks until the peer sends a control payload. It reads the
// socket itself because callers (Android/iOS) wait for the assigned address
// before starting their packet pumps. Data packets seen while waiting are
// buffered for ReceivePacket.
func (t *PacketTunnel) WaitControl(ctx context.Context) ([]byte, error) {
	for {
		select {
		case pkt := <-t.ctrl:
			return pkt, nil
		case pkt := <-t.data:
			// Drain data read by a concurrent ReceivePacket.
			_ = pkt
			continue
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if err := t.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			return nil, err
		}
		buf := make([]byte, maxDatagram)
		n, addr, err := t.conn.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return nil, err
		}
		if t.peer != nil && addr.String() != t.peer.String() {
			continue
		}
		msg, err := t.sess.Decode(buf[:n])
		if err != nil {
			continue
		}
		pkt := append([]byte(nil), msg.Payload...)
		if len(pkt) > 0 && pkt[0] == ControlAssignIP {
			return pkt[1:], nil
		}
		select {
		case t.data <- pkt:
		default:
			// Buffer full before the platform pump started; drop.
		}
	}
}

// RemoteAddr returns the peer endpoint.
func (t *PacketTunnel) RemoteAddr() net.Addr { return t.peer }

// Close releases the underlying socket.
func (t *PacketTunnel) Close() error {
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

// ClientHandshake runs the generated datagram handshake as a client.
// conn is a bound local UDP socket and peer is the server address.
func ClientHandshake(conn net.PacketConn, peer net.Addr, h *compiler.Handshake) (*compiler.PacketSession, error) {
	if _, err := runHandshake(h, conn, peer, true); err != nil {
		return nil, err
	}
	return h.FinishPacket()
}

// ServerHandshake waits for one client and completes the generated datagram
// handshake. conn must be an already-listening UDP socket.
func ServerHandshake(conn net.PacketConn, h *compiler.Handshake) (net.Addr, *compiler.PacketSession, error) {
	peer, err := runHandshake(h, conn, nil, false)
	if err != nil {
		return nil, nil, err
	}
	sess, err := h.FinishPacket()
	if err != nil {
		return nil, nil, err
	}
	return peer, sess, nil
}

// runHandshake advances the state machine over unreliable datagrams.
//
// Rules:
//   - when it is the local role's turn to send, encode and send one datagram;
//   - when it is the local role's turn to receive, wait silently, dropping
//     every datagram that does not authenticate under the expected step;
//   - while waiting, retransmit the last sent frame with exponential backoff;
//   - a client whose first step is a receive sends one random "knock" so
//     server-first handshake patterns have a peer address to answer.
func runHandshake(h *compiler.Handshake, conn net.PacketConn, peer net.Addr, isClient bool) (net.Addr, error) {
	var last []byte
	sentOnce := false

	for !h.Done() {
		spec, err := h.CurrentSpec()
		if err != nil {
			return nil, err
		}

		if spec.Direction == h.Role() {
			if peer == nil {
				// Server-first pattern: wait for any datagram so we have an
				// address. The client sends one random knock for exactly this
				// purpose; malformed probe data only supplies an address and
				// is never answered with an error.
				if err := conn.SetReadDeadline(time.Now().Add(handshakeTimeout)); err != nil {
					return nil, err
				}
				buf := make([]byte, maxDatagram)
				_, addr, err := conn.ReadFrom(buf)
				if err != nil {
					return nil, err
				}
				peer = addr
			}
			frame, _, err := h.EncodeStep()
			if err != nil {
				return nil, err
			}
			last = append(last[:0], frame...)
			if _, err := conn.WriteTo(frame, peer); err != nil {
				return nil, err
			}
			sentOnce = true
			continue
		}

		// Incoming step. A client in a server-first pattern has nothing to
		// retransmit yet; one random knock gives the server an address.
		if isClient && !sentOnce {
			knock := make([]byte, 32)
			if _, err := rand.Read(knock); err != nil {
				return nil, err
			}
			if _, err := conn.WriteTo(knock, peer); err != nil {
				return nil, err
			}
			sentOnce = true
		}

		wait := retransmitBase
		deadline := time.Now().Add(handshakeTimeout)
		received := false
		for !h.Done() && time.Now().Before(deadline) {
			if err := conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
				return nil, err
			}
			buf := make([]byte, maxDatagram)
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					if last != nil && peer != nil {
						if _, werr := conn.WriteTo(last, peer); werr != nil {
							return nil, werr
						}
					}
					wait *= 2
					if wait > maxRetransmit {
						wait = maxRetransmit
					}
					continue
				}
				return nil, err
			}
			if peer != nil && addr.String() != peer.String() {
				continue
			}
			if err := h.RecvStep(buf[:n]); err != nil {
				continue // silent drop: wrong nonce, wrong step, or a probe
			}
			if peer == nil {
				peer = addr
			}
			received = true
			break
		}
		if !received && !h.Done() {
			return nil, fmt.Errorf("handshake timeout at step %d", h.Progress())
		}
	}

	if peer == nil {
		return nil, errors.New("handshake completed without a peer address")
	}
	return peer, nil
}
