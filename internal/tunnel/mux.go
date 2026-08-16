package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"chimera/internal/compiler"
	"chimera/internal/genome"
)

const (
	maxPendingHandshakes = 1024
	minFirstDatagram     = 16
	newHandshakeMinGap   = time.Second
)

// tokenBucket is a simple byte-rate limiter for one session. rate is bytes
// per second; capacity bounds bursts. A nil bucket means unlimited.
type tokenBucket struct {
	mu       sync.Mutex
	rate     float64
	capacity float64
	tokens   float64
	last     time.Time
}

func newTokenBucket(bytesPerSec, burst int) *tokenBucket {
	if bytesPerSec <= 0 {
		return nil // unlimited
	}
	cap := float64(burst)
	if cap <= 0 || cap < float64(bytesPerSec) {
		cap = float64(bytesPerSec)
	}
	return &tokenBucket{
		rate:     float64(bytesPerSec),
		capacity: cap,
		tokens:   cap,
		last:     time.Now(),
	}
}

// take spends n bytes; false means the bucket is empty (drop the frame).
func (b *tokenBucket) take(n int) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	b.last = now
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}

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

	// lastActive is touched on every send/decode; the mux timerLoop
	// reaps sessions idle past the configured timeout.
	lastActive atomic.Int64 // unix nanos

	// limiter caps this client's inbound datagram rate (nil = unlimited).
	limiter *tokenBucket
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
	t.touch()
	t.maybeSendLossControl()
	return nil
}

func (t *ServerTunnel) touch() { t.lastActive.Store(time.Now().UnixNano()) }

// idleFor reports how long the session has been quiet.
func (t *ServerTunnel) idleFor() time.Duration {
	return time.Since(time.Unix(0, t.lastActive.Load()))
}

// IdleFor is the exported form of idleFor for operators and tests.
func (t *ServerTunnel) IdleFor() time.Duration { return t.idleFor() }

// sendKeepalive emits a ControlKeepalive frame if the link has been quiet.
func (t *ServerTunnel) sendKeepalive(interval time.Duration) {
	if t.idleFor() < interval {
		return
	}
	t.sessMu.Lock()
	frame, err := t.sess.Encode([]byte{ControlKeepalive})
	t.sessMu.Unlock()
	if err != nil {
		return
	}
	if len(frame) > maxDatagram {
		return
	}
	if _, err := t.conn.WriteTo(frame, t.peer); err == nil {
		t.touch()
	}
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

// handleLossControl applies ACK/SKIP/keepalive payloads; see PacketTunnel.
// Caller must hold sessMu.
func (t *ServerTunnel) handleLossControl(pkt []byte) bool {
	if len(pkt) == 0 {
		return false
	}
	switch pkt[0] {
	case ControlAck, ControlSkip:
		if len(pkt) != 9 {
			return true
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
	case ControlKeepalive:
		return true
	default:
		return false
	}
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
	recvOK   bool // true after at least one authenticated client step
}

// frameLenBuckets bound the datagram-length histogram exposed by Stats;
// the buckets bracket typical VPN-relevant sizes (tiny controls, DNS,
// TCP ACKs, full MTU frames) for later length-shaping analysis.
var frameLenBuckets = []int{128, 512, 1024, 1408, 1500}

// MuxStats is a point-in-time operational snapshot of one multiplexer.
type MuxStats struct {
	Established int      // live sessions
	Pending     int      // handshakes in flight
	FrameLens   []uint64 // authenticated datagrams per bucket + overflow
	Decoys      uint64   // anti-probe decoy replies sent
}

// Stats snapshots session counts and the authenticated-datagram length
// histogram (traffic-shaping groundwork; probes and junk are excluded).
func (m *ServerMux) Stats() MuxStats {
	m.mu.Lock()
	s := MuxStats{
		Established: len(m.established),
		Pending:     len(m.pending),
		FrameLens:   make([]uint64, len(frameLenBuckets)+1),
		Decoys:      m.decoysSent,
	}
	copy(s.FrameLens, m.frameLens[:])
	m.mu.Unlock()
	return s
}

// noteFrameLen records one authenticated datagram under m.mu.
func (m *ServerMux) noteFrameLen(n int) {
	for i, bound := range frameLenBuckets {
		if n < bound {
			m.frameLens[i]++
			return
		}
	}
	m.frameLens[len(frameLenBuckets)]++
}

// ServerMux multiplexes many client handshakes and sessions over one UDP
// socket. Invalid first packets are dropped, or answered with a decoy
// protocol when WithDecoy is set.
type ServerMux struct {
	conn net.PacketConn
	cp   *compiler.CompiledProtocol
	psk  []byte

	// keepalive refreshes idle sessions (NAT mappings); idleTimeout reaps
	// sessions quiet for that long (0 disables reaping). rateLimit caps
	// each session's inbound bytes/sec (0 = unlimited). maxSessions caps
	// established clients (0 = unlimited). decoy, when set, replies to
	// failed first-packet probes with a different generated protocol.
	// Configured via WithKeepalive / WithIdleTimeout / WithRateLimit /
	// WithMaxSessions / WithDecoy before Run.
	keepalive    time.Duration
	idleTimeout  time.Duration
	rateLimit    int
	maxSessions  int
	decoy        *compiler.CompiledProtocol
	shapeBuckets []int

	mu               sync.Mutex
	pending          map[string]*pendingHandshake
	lastCreate       map[string]time.Time
	established      map[string]*ServerTunnel
	frameLens        []uint64
	decoyWindowStart time.Time
	decoyWindowCount int
	decoysSent       uint64
	ready            chan *ServerTunnel
	closed           chan struct{}
	closeOnce        sync.Once
	done             chan struct{}
}

// NewServerMux builds a multiplexer for one generated protocol.
func NewServerMux(conn net.PacketConn, cp *compiler.CompiledProtocol, psk []byte) *ServerMux {
	return &ServerMux{
		conn:        conn,
		cp:          cp,
		psk:         psk,
		keepalive:   DefaultKeepaliveInterval,
		idleTimeout: time.Duration(1 << 62), // reaping off unless configured
		frameLens:   make([]uint64, len(frameLenBuckets)+1),
		pending:     map[string]*pendingHandshake{},
		lastCreate:  map[string]time.Time{},
		established: map[string]*ServerTunnel{},
		ready:       make(chan *ServerTunnel, 32),
		closed:      make(chan struct{}),
		done:        make(chan struct{}),
	}
}

// WithKeepalive sets the server keepalive interval (0 = default,
// negative = disabled).
func (m *ServerMux) WithKeepalive(d time.Duration) *ServerMux {
	if d < 0 {
		d = time.Duration(1 << 62)
	} else if d == 0 {
		d = DefaultKeepaliveInterval
	}
	m.keepalive = d
	return m
}

// WithIdleTimeout sets how long an established session may stay quiet
// before it is reaped (<= 0 disables reaping).
func (m *ServerMux) WithIdleTimeout(d time.Duration) *ServerMux {
	if d <= 0 {
		d = time.Duration(1 << 62)
	}
	m.idleTimeout = d
	return m
}

// WithRateLimit caps each session's inbound datagram bytes per second
// (<= 0 disables limiting). Applies to established sessions only.
func (m *ServerMux) WithRateLimit(bytesPerSec int) *ServerMux {
	m.rateLimit = bytesPerSec
	return m
}

// WithMaxSessions caps the number of established clients. New handshakes
// are dropped silently once the cap is reached (<= 0 = unlimited).
func (m *ServerMux) WithMaxSessions(n int) *ServerMux {
	if n < 0 {
		n = 0
	}
	m.maxSessions = n
	return m
}

// WithDecoy installs a second compiled protocol used only to answer
// invalid first packets. The decoy species must not be a generation the
// real clients will probe (see DecoyGeneration). nil disables decoys.
func (m *ServerMux) WithDecoy(cp *compiler.CompiledProtocol) *ServerMux {
	m.decoy = cp
	return m
}

// WithShapeBuckets pads established-session frames to the next length
// rung. Empty disables shaping (the default until the caller opts in).
func (m *ServerMux) WithShapeBuckets(buckets []int) *ServerMux {
	m.shapeBuckets = append([]int(nil), buckets...)
	return m
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
			m.sweepSessions()
		}
	}
}

// sweepSessions sends keepalives on idle established sessions and closes
// those idle past the configured timeout. Keepalives reset lastActive, so
// a client that has vanished entirely is reaped after idleTimeout while a
// live one stays connected forever.
func (m *ServerMux) sweepSessions() {
	m.mu.Lock()
	tuns := make([]*ServerTunnel, 0, len(m.established))
	for _, tun := range m.established {
		tuns = append(tuns, tun)
	}
	m.mu.Unlock()

	for _, tun := range tuns {
		select {
		case <-tun.closed:
			continue
		default:
		}
		if tun.idleFor() >= m.idleTimeout {
			tun.Close()
			continue
		}
		if m.keepalive > 0 {
			tun.sendKeepalive(m.keepalive)
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
		tun.touch()
		if !tun.limiter.take(len(data)) {
			tun.sessMu.Unlock()
			return // over budget: drop silently (client sees plain loss)
		}
		pkt := append([]byte(nil), msg.Payload...)
		if tun.handleLossControl(pkt) {
			tun.sessMu.Unlock()
			m.mu.Lock()
			m.noteFrameLen(len(data))
			m.mu.Unlock()
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
		m.mu.Lock()
		m.noteFrameLen(len(data))
		m.mu.Unlock()
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
		// cap so junk traffic cannot exhaust memory. A full session table
		// is the same as a closed door: drop, maybe decoy.
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
		if m.maxSessions > 0 && len(m.established) >= m.maxSessions {
			m.lastCreate[key] = now
			m.mu.Unlock()
			m.maybeDecoy(addr, data)
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
// steps that become due. Unauthenticated first packets may get a decoy
// reply; later failures stay silent.
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
		progressed := p.recvOK || p.last != nil
		addr := p.addr
		p.mu.Unlock()
		if !progressed {
			// First datagram did not authenticate: drop the empty
			// pending slot (a real client's retransmission still
			// succeeds on a fresh handshake at seq 0) and optionally
			// answer with the decoy species.
			m.abandonPending(addr)
			m.maybeDecoy(addr, data)
		}
		return // wrong nonce / wrong step / probe: silent otherwise
	}
	p.recvOK = true
	p.last = nil
	p.attempts = 0
	p.backoff = retransmitBase
	p.mu.Unlock()
	m.mu.Lock()
	m.noteFrameLen(len(data))
	m.mu.Unlock()
	p.mu.Lock()

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
		conn:    m.conn,
		peer:    p.addr,
		sess:    sess,
		recv:    make(chan []byte, 128),
		closed:  make(chan struct{}),
		limiter: newTokenBucket(m.rateLimit, m.rateLimit),
	}
	if len(m.shapeBuckets) > 0 {
		tun.sess.SetShapeBuckets(m.shapeBuckets)
	}
	tun.lastActive.Store(time.Now().UnixNano())
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
	if m.maxSessions > 0 && len(m.established) >= m.maxSessions {
		m.mu.Unlock()
		tun.Close()
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

// abandonPending removes a handshake that never authenticated a client
// step. lastCreate is kept so the per-address creation gap still applies.
func (m *ServerMux) abandonPending(addr net.Addr) {
	key := addr.String()
	m.mu.Lock()
	delete(m.pending, key)
	m.mu.Unlock()
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
