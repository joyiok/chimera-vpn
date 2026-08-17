// Package tunnel implements the CHIMERA UDP transport: datagram handshake
// with retransmission plus encrypted packet forwarding. Malformed
// datagrams are ignored; when a decoy protocol is configured they may
// instead elicit a frame of a different generated species (anti-probe).
package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"chimera/internal/compiler"
)

const (
	handshakeTimeout = 8 * time.Second
	retransmitBase   = 200 * time.Millisecond
	maxRetransmit    = 2 * time.Second
	maxDatagram      = 64 * 1024

	// ControlAssignIP marks a non-IP control payload. IP packets start with
	// a 0x4 or 0x6 version nibble, so 0x01-0x03 are unambiguous.
	ControlAssignIP = 0x01
	// ControlAck reports the sender's contiguous receive position: the
	// first sequence number not yet known to have arrived in order. Loss
	// recovery half 1 of 2 - see ackTracker.
	ControlAck = 0x02
	// ControlSkip asks the peer to move its receive window base forward,
	// declaring every sequence below it dead. Loss recovery half 2 of 2.
	ControlSkip = 0x03
	// ControlKeepalive is a 1-byte no-op payload sent periodically on idle
	// sessions so NAT mappings and firewalls keep the 5-tuple alive.
	ControlKeepalive = 0x04

	// DefaultKeepaliveInterval refreshes NAT mappings well inside the
	// 30s typical UDP timeout; 0 disables keepalives.
	DefaultKeepaliveInterval = 25 * time.Second

	// ackEvery: the receiver piggybacks nothing, so ACKs ride their own
	// frames; 32 data frames between ACKs keeps overhead ~3%.
	ackEvery = 32
	// skipSpan: when the unacknowledged span reaches this fraction of the
	// replay window, the sender asks the peer to skip past the gap rather
	// than let the window wedge. 3/4 leaves headroom for in-flight frames.
	skipSpan = compiler.PacketWindow * 3 / 4
)

// ErrHandshakeTimeout marks a handshake that never completed; clients use
// it to decide whether probing the next generation is worthwhile.
var ErrHandshakeTimeout = errors.New("handshake timeout")

// ackTracker is one direction's loss-recovery state. The owner of a
// tracker is the sender; peerBase is the peer's ACKed contiguous position
// in the owner's send sequence. All methods are safe for concurrent use.
type ackTracker struct {
	mu sync.Mutex
	// peerBase: highest contiguous position the peer has acknowledged.
	peerBase uint64
	// lastLocalBase the peer was told about (our own receive position in
	// the opposite direction - see tunnel note below).
	ackedBase uint64
}

func (a *ackTracker) observeAck(base uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if base > a.peerBase {
		a.peerBase = base
	}
}

func (a *ackTracker) unackedSpan(sent uint64) uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	if sent < a.peerBase {
		return 0
	}
	return sent - a.peerBase
}

// encodeAckPayload builds the encrypted control payload for an ACK of the
// given contiguous base sequence.
func encodeAckPayload(base uint64) []byte {
	p := make([]byte, 9)
	p[0] = ControlAck
	binary.BigEndian.PutUint64(p[1:], base)
	return p
}

// encodeSkipPayload builds the encrypted control payload asking the peer
// to advance its receive base to target.
func encodeSkipPayload(target uint64) []byte {
	p := make([]byte, 9)
	p[0] = ControlSkip
	binary.BigEndian.PutUint64(p[1:], target)
	return p
}

// decodeAckPayload parses an ACK/SKIP control payload produced by the
// encode functions above.
func decodeAckPayload(p []byte) (byte, uint64, error) {
	if len(p) != 9 || (p[0] != ControlAck && p[0] != ControlSkip) {
		return 0, 0, fmt.Errorf("bad ack control payload len %d", len(p))
	}
	return p[0], binary.BigEndian.Uint64(p[1:]), nil
}

// PacketTunnel is an established encrypted packet channel.
type PacketTunnel struct {
	conn net.PacketConn
	peer net.Addr
	sess *compiler.PacketSession
	ctrl chan []byte
	data chan []byte

	// sessMu serializes codec state (encode, decode, window moves): the
	// user goroutine sends while the receive loop decodes concurrently.
	sessMu sync.Mutex

	// ack tracks what the peer has acknowledged of our sends; ackDue counts
	// decoded frames until the next periodic ACK of our receive position.
	ack    ackTracker
	ackDue uint64
	ackMu  sync.Mutex

	// lastRecv is the last authenticated inbound frame (peer liveness).
	// lastSend is the last outbound frame (NAT keepalive pump).
	lastRecv atomic.Int64 // unix nanos
	lastSend atomic.Int64 // unix nanos
	kaCancel context.CancelFunc
	kaDone   chan struct{}

	// jitterMax smears send timing; 0 disables (see applyJitter).
	jitterMax time.Duration

	bytesSent atomic.Uint64
	bytesRecv atomic.Uint64
}

// NewPacketTunnel wraps an established packet session.
func NewPacketTunnel(conn net.PacketConn, peer net.Addr, sess *compiler.PacketSession) *PacketTunnel {
	t := &PacketTunnel{
		conn:   conn,
		peer:   peer,
		sess:   sess,
		ctrl:   make(chan []byte, 4),
		data:   make(chan []byte, 256),
		kaDone: make(chan struct{}),
	}
	now := time.Now().UnixNano()
	t.lastRecv.Store(now)
	t.lastSend.Store(now)
	return t
}

// SetJitter enables uniform send-side timing smear in [0, max].
// max <= 0 disables jitter. Call before packet pumps start.
func (t *PacketTunnel) SetJitter(max time.Duration) {
	if max < 0 {
		max = 0
	}
	t.jitterMax = max
}

// SetShapeBuckets pads encoded datagrams to the next length rung.
// Empty disables shaping. Call before packet pumps start.
func (t *PacketTunnel) SetShapeBuckets(buckets []int) {
	t.sessMu.Lock()
	defer t.sessMu.Unlock()
	if t.sess != nil {
		t.sess.SetShapeBuckets(buckets)
	}
}

// SetKeepalive starts the NAT keepalive pump. interval > 0 sets the idle
// threshold, 0 uses DefaultKeepaliveInterval, negative disables the pump.
// While traffic flows the pump stays silent; after one interval of silence
// it sends ControlKeepalive so NAT mappings and firewalls keep the UDP
// 5-tuple alive. Call before the platform packet pumps start.
func (t *PacketTunnel) SetKeepalive(interval time.Duration) {
	if t.kaCancel != nil {
		t.kaCancel()
		<-t.kaDone
		t.kaCancel = nil
	}
	if interval < 0 {
		return // disabled
	}
	if interval == 0 {
		interval = DefaultKeepaliveInterval
	}
	done := make(chan struct{})
	t.kaDone = done
	ctx, cancel := context.WithCancel(context.Background())
	t.kaCancel = cancel
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if t.quietFor() < interval {
					continue
				}
				_ = t.sendControlRaw([]byte{ControlKeepalive})
			}
		}
	}()
}

func (t *PacketTunnel) touchRecv() { t.lastRecv.Store(time.Now().UnixNano()) }

func (t *PacketTunnel) touchSend() { t.lastSend.Store(time.Now().UnixNano()) }

func (t *PacketTunnel) quietFor() time.Duration {
	r := t.lastRecv.Load()
	s := t.lastSend.Load()
	if s > r {
		r = s
	}
	return time.Since(time.Unix(0, r))
}

// IdleFor is inbound silence: time since the last authenticated frame
// from the peer. Own keepalives and data sends do not reset it, so a
// client watchdog can detect a dead server (Windows GUI and chimerac).
func (t *PacketTunnel) IdleFor() time.Duration {
	return time.Since(time.Unix(0, t.lastRecv.Load()))
}

// Bytes is TUN payload volume (IP packets), not ciphertext or keepalives.
func (t *PacketTunnel) Bytes() (sent, recv uint64) {
	return t.bytesSent.Load(), t.bytesRecv.Load()
}

// SendPacket encrypts and transmits one IP packet.
func (t *PacketTunnel) SendPacket(packet []byte) error {
	if err := t.sendPayload(packet); err != nil {
		return err
	}
	t.bytesSent.Add(uint64(len(packet)))
	return nil
}

// SendControl encrypts a control payload (e.g. the assigned TUN address).
func (t *PacketTunnel) SendControl(payload []byte) error {
	return t.sendPayload(append([]byte{ControlAssignIP}, payload...))
}

func (t *PacketTunnel) sendPayload(payload []byte) error {
	t.sessMu.Lock()
	frame, err := t.sess.Encode(payload)
	t.sessMu.Unlock()
	if err != nil {
		return err
	}
	if err := writeDatagram(t.conn, t.peer, frame, t.jitterMax); err != nil {
		return err
	}
	t.touchSend()
	t.maybeSendLossControl()
	return nil
}

// maybeSendLossControl runs after every send: if the peer has fallen
// skipSpan behind our send position, tell it to skip the gap. ACKs of our
// own receive position are driven by the receive path instead.
func (t *PacketTunnel) maybeSendLossControl() {
	t.sessMu.Lock()
	_, sent := t.sess.AckState()
	if t.ack.unackedSpan(sent) < skipSpan {
		t.sessMu.Unlock()
		return
	}
	frame, err := t.sess.Encode(encodeSkipPayload(sent))
	t.sessMu.Unlock()
	if err != nil {
		return // best effort; the next send retries
	}
	if err := writeDatagram(t.conn, t.peer, frame, t.jitterMax); err != nil {
		return
	}
	// Optimistically advance our view of the peer's position so we do not
	// emit a skip frame for every subsequent send.
	t.ack.observeAck(sent)
}

// sendControlRaw encrypts and transmits one already-encoded control
// payload without recursing into maybeSendLossControl.
func (t *PacketTunnel) sendControlRaw(payload []byte) error {
	t.sessMu.Lock()
	frame, err := t.sess.Encode(payload)
	t.sessMu.Unlock()
	if err != nil {
		return err
	}
	if err := writeDatagram(t.conn, t.peer, frame, t.jitterMax); err != nil {
		return err
	}
	t.touchSend()
	return nil
}

// handleLossControl applies a decoded control payload, returning true when
// the payload was a control frame (data callers continue the loop).
// Caller must hold sessMu.
func (t *PacketTunnel) handleLossControl(pkt []byte) bool {
	if len(pkt) == 0 {
		return false
	}
	switch pkt[0] {
	case ControlAck, ControlSkip:
		if len(pkt) != 9 {
			return true // malformed control: swallow
		}
		kind, v, err := decodeAckPayload(pkt)
		if err != nil {
			return true
		}
		switch kind {
		case ControlAck:
			t.ack.observeAck(v)
		case ControlSkip:
			if err := t.sess.AdvanceBaseTo(v); err != nil {
				// A skip beyond our window or below base is stale/malicious;
				// ignore it silently.
				_ = err
			}
		}
		return true
	case ControlKeepalive:
		return true // NAT probe: refresh only
	default:
		return false
	}
}

// decodeLocked authenticates one datagram and applies control payloads.
// Caller must hold sessMu; the returned payload is nil for control frames.
func (t *PacketTunnel) decodeLocked(buf []byte) (pkt []byte, isCtrl bool, err error) {
	msg, err := t.sess.Decode(buf)
	if err != nil {
		return nil, false, err
	}
	t.touchRecv()
	pkt = append([]byte(nil), msg.Payload...)
	if t.handleLossControl(pkt) {
		return nil, true, nil
	}
	return pkt, false, nil
}

// noteDecoded records one decoded data frame from the peer and returns
// whether a periodic ACK of our contiguous receive position is now due.
func (t *PacketTunnel) noteDecoded() bool {
	t.ackMu.Lock()
	defer t.ackMu.Unlock()
	t.ackDue++
	if t.ackDue < ackEvery {
		return false
	}
	t.ackDue = 0
	return true
}

// ReceivePacket blocks until a decrypted IP packet is available. Control
// payloads are routed to the control channel instead of being returned.
func (t *PacketTunnel) ReceivePacket() ([]byte, error) {
	select {
	case pkt := <-t.data:
		t.bytesRecv.Add(uint64(len(pkt)))
		return pkt, nil
	default:
	}
	// Handshake / WaitControl leave short read deadlines on the socket.
	if err := t.conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
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
		t.sessMu.Lock()
		pkt, isCtrl, err := t.decodeLocked(buf[:n])
		if err != nil {
			t.sessMu.Unlock()
			continue // silent: invalid probes and duplicates disappear
		}
		if isCtrl {
			t.sessMu.Unlock()
			continue
		}
		if len(pkt) > 0 && pkt[0] == ControlAssignIP {
			t.sessMu.Unlock()
			select {
			case t.ctrl <- pkt[1:]:
			default:
				// No control consumer yet; drop rather than stall the loop.
			}
			continue
		}
		due := t.noteDecoded()
		var frame []byte
		var ackErr error
		if due {
			base, _ := t.sess.AckState()
			frame, ackErr = t.sess.Encode(encodeAckPayload(base))
		}
		t.sessMu.Unlock()
		if ackErr == nil && due {
			writeDatagramAsync(t.conn, t.peer, frame, t.jitterMax)
		}
		t.bytesRecv.Add(uint64(len(pkt)))
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
		t.sessMu.Lock()
		pkt, isCtrl, err := t.decodeLocked(buf[:n])
		if err != nil {
			t.sessMu.Unlock()
			continue
		}
		if isCtrl {
			t.sessMu.Unlock()
			continue
		}
		if len(pkt) > 0 && pkt[0] == ControlAssignIP {
			t.sessMu.Unlock()
			return pkt[1:], nil
		}
		due := t.noteDecoded()
		var frame []byte
		var ackErr error
		if due {
			base, _ := t.sess.AckState()
			frame, ackErr = t.sess.Encode(encodeAckPayload(base))
		}
		t.sessMu.Unlock()
		if ackErr == nil && due {
			writeDatagramAsync(t.conn, t.peer, frame, t.jitterMax)
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

// Close releases the underlying socket and stops the keepalive pump.
func (t *PacketTunnel) Close() error {
	if t.kaCancel != nil {
		t.kaCancel()
		<-t.kaDone
		t.kaCancel = nil
	}
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

// ClientHandshake runs the generated datagram handshake as a client.
// conn is a bound local UDP socket and peer is the server address.
func ClientHandshake(conn net.PacketConn, peer net.Addr, h *compiler.Handshake) (*compiler.PacketSession, error) {
	return ClientHandshakeWithJitter(conn, peer, h, 0)
}

// ClientHandshakeWithJitter is ClientHandshake with send-side timing smear.
func ClientHandshakeWithJitter(conn net.PacketConn, peer net.Addr, h *compiler.Handshake, jitter time.Duration) (*compiler.PacketSession, error) {
	if _, err := runHandshake(h, conn, peer, true, jitter); err != nil {
		return nil, err
	}
	return h.FinishPacket()
}

// ServerHandshake waits for one client and completes the generated datagram
// handshake. conn must be an already-listening UDP socket.
func ServerHandshake(conn net.PacketConn, h *compiler.Handshake) (net.Addr, *compiler.PacketSession, error) {
	peer, err := runHandshake(h, conn, nil, false, 0)
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
//   - a client whose first step is a receive sends an authenticated knock so
//     server-first handshake patterns have a peer address to answer.
func runHandshake(h *compiler.Handshake, conn net.PacketConn, peer net.Addr, isClient bool, jitter time.Duration) (net.Addr, error) {
	var last []byte
	sentOnce := false

	for !h.Done() {
		spec, err := h.CurrentSpec()
		if err != nil {
			return nil, err
		}

		if spec.Direction == h.Role() {
			if peer == nil {
				// Server-first: wait for an authenticated knock. Random
				// probes (Alice, IMC 2020) must not elicit the real first
				// frame — that was a confirmation oracle.
				addr, err := waitAuthenticatedKnock(conn, h, handshakeTimeout)
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
			if err := writeDatagram(conn, peer, h.WrapDatagram(frame), jitter); err != nil {
				return nil, err
			}
			sentOnce = true
			continue
		}

		// Incoming step. A client in a server-first pattern has nothing to
		// retransmit yet; an authenticated knock gives the server an address
		// without looking like a fully-encrypted first payload.
		if isClient && !sentOnce {
			knock, err := h.EncodeKnock()
			if err != nil {
				return nil, err
			}
			last = append(last[:0], knock...)
			if err := writeDatagram(conn, peer, h.WrapDatagram(knock), jitter); err != nil {
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
						if werr := writeDatagram(conn, peer, h.WrapDatagram(last), jitter); werr != nil {
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
			inner, uerr := h.UnwrapDatagram(buf[:n])
			if uerr != nil {
				continue
			}
			if err := h.RecvStep(inner); err != nil {
				continue // silent drop: wrong nonce, wrong step, or a probe
			}
			if peer == nil {
				peer = addr
			}
			received = true
			break
		}
		if !received && !h.Done() {
			return nil, fmt.Errorf("step %d: %w", h.Progress(), ErrHandshakeTimeout)
		}
	}

	if peer == nil {
		return nil, errors.New("handshake completed without a peer address")
	}
	_ = conn.SetReadDeadline(time.Time{})
	return peer, nil
}

// waitAuthenticatedKnock reads datagrams until one unwraps to a knock MAC
// under this handshake's PSK. Unauthenticated probes stay unanswered.
func waitAuthenticatedKnock(conn net.PacketConn, h *compiler.Handshake, timeout time.Duration) (net.Addr, error) {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, maxDatagram)
	for {
		remain := time.Until(deadline)
		if remain <= 0 {
			return nil, fmt.Errorf("knock: %w", ErrHandshakeTimeout)
		}
		if err := conn.SetReadDeadline(time.Now().Add(remain)); err != nil {
			return nil, err
		}
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return nil, fmt.Errorf("knock: %w", ErrHandshakeTimeout)
			}
			return nil, err
		}
		inner, err := h.UnwrapDatagram(buf[:n])
		if err != nil {
			continue
		}
		if h.VerifyKnock(inner) {
			return addr, nil
		}
	}
}
