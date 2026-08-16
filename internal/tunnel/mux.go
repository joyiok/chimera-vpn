package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"chimera/internal/compiler"
	"chimera/internal/genome"
)

const (
	maxPendingHandshakes = 1024
	minFirstDatagram     = 16
	newHandshakeMinGap   = time.Second
)

// ServerTunnel is one established packet session on a shared server socket.
// Inbound frames are fed by ServerMux into a per-client queue; outbound
// frames are written directly to the shared socket.
type ServerTunnel struct {
	conn net.PacketConn
	peer net.Addr
	sess *compiler.PacketSession

	recv      chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	onClose   func()

	// sessMu serializes codec state: Accept'd callers send while the mux
	// readLoop decodes concurrently.
	sessMu sync.Mutex

	// ack tracks what the client has acknowledged of our sends; ackDue
	// counts decoded frames until the next periodic ACK (mirror of
	// PacketTunnel's loss recovery).
	ack    ackTracker
	ackDue uint64
	ackMu  sync.Mutex
}

func (t *ServerTunnel) SendPacket(packet []byte) error {
	select {
	case <-t.closed:
		return net.ErrClosed
	default:
	}
	t.sessMu.Lock()
	frame, err := t.sess.Encode(packet)
	if err != nil {
		t.sessMu.Unlock()
		return err
	}
	if len(frame) > maxDatagram {
		t.sessMu.Unlock()
		return fmt.Errorf("encrypted frame too large: %d", len(frame))
	}
	_, err = t.conn.WriteTo(frame, t.peer)
	t.sessMu.Unlock()
	if err != nil {
		return err
	}
	t.maybeSendLossControl()
	return nil
}

// maybeSendLossControl asks the client to skip a gap once the
// unacknowledged span reaches skipSpan (see PacketTunnel for the design).
func (t *ServerTunnel) maybeSendLossControl() {
	t.sessMu.Lock()
	_, sent := t.sess.AckState()
	if t.ack.unackedSpan(sent) < skipSpan {
		t.sessMu.Unlock()
		return
	}
	frame, err := t.sess.Encode(encodeSkipPayload(sent))
	t.sessMu.Unlock()
	if err != nil {
		return
	}
	if len(frame) > maxDatagram {
		return
	}
	if _, err := t.conn.WriteTo(frame, t.peer); err != nil {
		return
	}
	t.ack.observeAck(sent)
}

// handleLossControl applies ACK/SKIP payloads; see PacketTunnel.
// Caller must hold sessMu.
func (t *ServerTunnel) handleLossControl(pkt []byte) bool {
	if len(pkt) != 9 || (pkt[0] != ControlAck && pkt[0] != ControlSkip) {
		return false
	}
	kind, v, err := decodeAckPayload(pkt)
	if err != nil {
		return true
	}
	switch kind {
	case ControlAck:
		t.ack.observeAck(v)
	case ControlSkip:
		_ = t.sess.AdvanceBaseTo(v)
	}
	return true
}

// noteDecoded counts decoded client frames; every ackEvery-th one triggers
// an ACK of the server's contiguous receive position.
func (t *ServerTunnel) noteDecoded() bool {
	t.ackMu.Lock()
	defer t.ackMu.Unlock()
	t.ackDue++
	if t.ackDue < ackEvery {
		return false
	}
	t.ackDue = 0
	return true
}

// ackBaseSnapshot returns the receive base under sessMu, for tests.
func (t *ServerTunnel) ackBaseSnapshot() uint64 {
	t.sessMu.Lock()
	defer t.sessMu.Unlock()
	base, _ := t.sess.AckState()
	return base
}

// SendControl encrypts a control payload (e.g. the assigned TUN address).
func (t *ServerTunnel) SendControl(payload []byte) error {
	return t.SendPacket(append([]byte{ControlAssignIP}, payload...))
}

func (t *ServerTunnel) ReceivePacket() ([]byte, error) {
	select {
	case pkt, ok := <-t.recv:
		if !ok {
			return nil, net.ErrClosed
		}
		return pkt, nil
	case <-t.closed:
		return nil, net.ErrClosed
	}
}

// TryReceive returns one queued packet if available without blocking;
// ok is false when the queue is momentarily empty. Control frames (ACK/
// SKIP) never reach this queue, so callers only ever see data or nil.
func (t *ServerTunnel) TryReceive() ([]byte, error) {
	select {
	case pkt, ok := <-t.recv:
		if !ok {
			return nil, net.ErrClosed
		}
		return pkt, nil
	case <-t.closed:
		return nil, net.ErrClosed
	default:
		return nil, nil
	}
}

func (t *ServerTunnel) feed(packet []byte) bool {
	select {
	case t.recv <- packet:
		return true
	case <-t.closed:
		return false
	default:
		// Queue full: drop rather than backpressure the shared socket loop.
		return false
	}
}

func (t *ServerTunnel) RemoteAddr() net.Addr { return t.peer }

func (t *ServerTunnel) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		if t.onClose != nil {
			t.onClose()
		}
	})
	return nil
}

type pendingHandshake struct {
	mu sync.Mutex

	h        *compiler.Handshake
	last     []byte
	lastSent time.Time
	created  time.Time
	attempts int
	backoff  time.Duration
	addr     net.Addr
}

// ServerMux multiplexes many client handshakes and sessions over one UDP
// socket. Invalid datagrams are ignored silently (anti-probe behaviour).
type ServerMux struct {
	conn net.PacketConn
	cp   *compiler.CompiledProtocol
	psk  []byte

	mu          sync.Mutex
	pending     map[string]*pendingHandshake
	lastCreate  map[string]time.Time
	established map[string]*ServerTunnel
	ready       chan *ServerTunnel
	closed      chan struct{}
	closeOnce   sync.Once
	done        chan struct{}
}

// NewServerMux builds a multiplexer for one generated protocol.
func NewServerMux(conn net.PacketConn, cp *compiler.CompiledProtocol, psk []byte) *ServerMux {
	return &ServerMux{
		conn:        conn,
		cp:          cp,
		psk:         psk,
		pending:     map[string]*pendingHandshake{},
		lastCreate:  map[string]time.Time{},
		established: map[string]*ServerTunnel{},
		ready:       make(chan *ServerTunnel, 32),
		closed:      make(chan struct{}),
		done:        make(chan struct{}),
	}
}

// Run drives the reader and retransmit timer until ctx is cancelled or the
// mux is closed.
func (m *ServerMux) Run(ctx context.Context) {
	defer close(m.done)
	go m.readLoop(ctx)
	go m.timerLoop(ctx)
	<-ctx.Done()
	m.Close()
}

func (m *ServerMux) readLoop(ctx context.Context) {
	buf := make([]byte, maxDatagram)
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.closed:
			return
		default:
		}
		if err := m.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			return
		}
		n, addr, err := m.conn.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		m.handleDatagram(addr, append([]byte(nil), buf[:n]...))
	}
}

func (m *ServerMux) timerLoop(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.closed:
			return
		case <-ticker.C:
			m.retransmit()
		}
	}
}

func (m *ServerMux) handleDatagram(addr net.Addr, data []byte) {
	key := addr.String()

	m.mu.Lock()
	if tun, ok := m.established[key]; ok {
		m.mu.Unlock()
		tun.sessMu.Lock()
		msg, err := tun.sess.Decode(data)
		if err != nil {
			tun.sessMu.Unlock()
			return // silent: duplicate, probe, or wrong session
		}
		pkt := append([]byte(nil), msg.Payload...)
		if tun.handleLossControl(pkt) {
			tun.sessMu.Unlock()
			return
		}
		due := tun.noteDecoded()
		var frame []byte
		var ackErr error
		if due {
			base, _ := tun.sess.AckState()
			frame, ackErr = tun.sess.Encode(encodeAckPayload(base))
		}
		tun.sessMu.Unlock()
		if ackErr == nil && due && len(frame) <= maxDatagram {
			_, _ = tun.conn.WriteTo(frame, tun.peer) // best effort
		}
		tun.feed(pkt)
		return
	}

	p := m.pending[key]
	if p == nil {
		// Anti-probe guard: a new handshake needs a plausible first
		// datagram, a per-address creation rate limit, and a global pending
		// cap so junk traffic cannot exhaust memory.
		now := time.Now()
		if len(data) < minFirstDatagram {
			m.mu.Unlock()
			return
		}
		if last, ok := m.lastCreate[key]; ok && now.Sub(last) < newHandshakeMinGap {
			m.mu.Unlock()
			return
		}
		if len(m.pending) >= maxPendingHandshakes {
			m.mu.Unlock()
			return
		}
		h, err := compiler.NewHandshake(m.cp, genome.DirServer, m.psk)
		if err != nil {
			m.mu.Unlock()
			return
		}
		p = &pendingHandshake{
			h:       h,
			addr:    addr,
			created: now,
			backoff: retransmitBase,
		}
		m.pending[key] = p
		m.lastCreate[key] = now
	}
	m.mu.Unlock()

	m.advance(p, data)
}

// advance feeds one datagram to one pending handshake and sends any outgoing
// steps that become due. It never replies to invalid input.
func (m *ServerMux) advance(p *pendingHandshake, data []byte) {
	p.mu.Lock()
	spec, err := p.h.CurrentSpec()
	if err != nil {
		p.mu.Unlock()
		return // already finished; handled elsewhere
	}

	if spec.Direction == genome.DirServer {
		// Server-first pattern: the datagram is a knock; send our first
		// message(s) now. Do not try to decode the knock.
		m.sendOutgoing(p)
		done := p.h.Done()
		p.mu.Unlock()
		if done {
			m.finishHandshake(p)
		}
		return
	}

	if err := p.h.RecvStep(data); err != nil {
		p.mu.Unlock()
		return // wrong nonce / wrong step / probe: silent
	}
	p.last = nil
	p.attempts = 0
	p.backoff = retransmitBase

	if p.h.Done() {
		p.mu.Unlock()
		m.finishHandshake(p)
		return
	}

	m.sendOutgoing(p)
	done := p.h.Done()
	p.mu.Unlock()
	if done {
		// Some patterns finish with a server-sent message (e.g. c_s).
		m.finishHandshake(p)
	}
}

// sendOutgoing sends all consecutive outgoing steps. Caller holds p.mu.
func (m *ServerMux) sendOutgoing(p *pendingHandshake) {
	for !p.h.Done() {
		spec, err := p.h.CurrentSpec()
		if err != nil {
			return
		}
		if spec.Direction != genome.DirServer {
			return
		}
		frame, _, err := p.h.EncodeStep()
		if err != nil {
			return
		}
		p.last = append(p.last[:0], frame...)
		p.lastSent = time.Now()
		if _, err := m.conn.WriteTo(frame, p.addr); err != nil {
			return
		}
	}
}

func (m *ServerMux) retransmit() {
	now := time.Now()

	m.mu.Lock()
	snapshot := make([]*pendingHandshake, 0, len(m.pending))
	for _, p := range m.pending {
		snapshot = append(snapshot, p)
	}
	m.mu.Unlock()

	for _, p := range snapshot {
		p.mu.Lock()
		if p.h.Done() || now.Sub(p.created) > handshakeTimeout {
			p.mu.Unlock()
			key := p.addr.String()
			m.mu.Lock()
			delete(m.pending, key)
			delete(m.lastCreate, key)
			m.mu.Unlock()
			continue
		}
		if p.last != nil && !p.lastSent.IsZero() && now.Sub(p.lastSent) >= p.backoff {
			if _, err := m.conn.WriteTo(p.last, p.addr); err == nil {
				p.lastSent = now
				p.attempts++
				p.backoff = retransmitBase * time.Duration(1<<min(p.attempts, 4))
			}
		}
		p.mu.Unlock()
	}
}

func (m *ServerMux) finishHandshake(p *pendingHandshake) {
	sess, err := p.h.FinishPacket()
	if err != nil {
		return
	}
	tun := &ServerTunnel{
		conn:   m.conn,
		peer:   p.addr,
		sess:   sess,
		recv:   make(chan []byte, 128),
		closed: make(chan struct{}),
	}
	tun.onClose = func() {
		m.mu.Lock()
		delete(m.established, p.addr.String())
		m.mu.Unlock()
	}

	key := p.addr.String()
	m.mu.Lock()
	delete(m.pending, key)
	delete(m.lastCreate, key)
	if _, exists := m.established[key]; exists {
		m.mu.Unlock()
		return
	}
	m.established[key] = tun
	m.mu.Unlock()

	select {
	case m.ready <- tun:
	case <-m.closed:
		tun.Close()
	}
}

// Accept returns the next completed client session.
func (m *ServerMux) Accept(ctx context.Context) (*ServerTunnel, error) {
	select {
	case tun, ok := <-m.ready:
		if !ok {
			return nil, net.ErrClosed
		}
		return tun, nil
	case <-m.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close shuts the mux and all sessions. Session onClose callbacks acquire
// m.mu, so the established list is copied and released before closing.
func (m *ServerMux) Close() error {
	m.closeOnce.Do(func() {
		close(m.closed)
		m.mu.Lock()
		tuns := make([]*ServerTunnel, 0, len(m.established))
		for _, tun := range m.established {
			tuns = append(tuns, tun)
		}
		m.established = map[string]*ServerTunnel{}
		m.pending = map[string]*pendingHandshake{}
		m.lastCreate = map[string]time.Time{}
		m.mu.Unlock()
		for _, tun := range tuns {
			tun.Close()
		}
	})
	return nil
}

// Done is closed when Run exits.
func (m *ServerMux) Done() <-chan struct{} { return m.done }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
