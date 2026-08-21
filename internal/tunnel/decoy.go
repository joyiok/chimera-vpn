package tunnel

import (
	"crypto/rand"
	mrand "math/rand/v2"
	"net"
	"time"

	"chimera/internal/compiler"
	"chimera/internal/genome"
)

const (
	// maxDecoyBytes caps a decoy reply so a reflector cannot be built
	// from the feature. Handshake frames of the decoy species that exceed
	// this are simply not sent (silent drop, same as no-decoy).
	maxDecoyBytes = 1200
	// decoyAmpRatio: never answer a probe with more than this many times
	// the probe's own size.
	decoyAmpRatio = 3
	// maxDecoyPerSec is a process-wide ceiling on decoy replies, on top
	// of the per-address newHandshakeMinGap.
	maxDecoyPerSec = 32
)

// DecoyGeneration maps a live generation onto a disjoint decoy species.
// XOR with a large odd constant so sequential client GenerationWindow
// probes never land on the decoy genome.
func DecoyGeneration(generation uint64) uint64 {
	return generation ^ 0xC0DEC0DEC0DEC0DE
}

func allowDecoySize(probeLen, decoyLen int) bool {
	if decoyLen <= 0 || decoyLen > maxDecoyBytes {
		return false
	}
	if decoyLen > decoyAmpRatio*probeLen {
		return false
	}
	return true
}

// maxDecoyBurst caps the frames sent in one decoy exchange.
const maxDecoyBurst = 8

// encodeDecoyFrame emits one structurally valid frame of the decoy
// protocol: the first server-directed handshake message, or the app
// record layout if the decoy species is client-only (should not happen
// with the current generator). Random key_material keeps each reply
// unique so a classifier cannot latch onto a constant blob.
func encodeDecoyFrame(cp *compiler.CompiledProtocol) ([]byte, error) {
	spec, key := decoySpec(cp)
	codec, err := compiler.NewMessageCodec(spec, key)
	if err != nil {
		return nil, err
	}
	inject := map[string][]byte{}
	var km [32]byte
	if _, err := rand.Read(km[:]); err != nil {
		return nil, err
	}
	inject[genome.FieldKey] = km[:]
	frame, _, err := codec.Encode(nil, inject, nil)
	return frame, err
}

func decoySpec(cp *compiler.CompiledProtocol) (genome.MessageSpec, []byte) {
	for _, spec := range cp.Genome.Handshake {
		if spec.Direction == genome.DirServer {
			return spec, cp.Bootstrap.S2C
		}
	}
	return cp.Genome.AppRecord, cp.Bootstrap.S2C
}

func (m *ServerMux) maybeDecoy(addr net.Addr, probe []byte) {
	m.mu.Lock()
	decoy := m.decoy
	burst := m.decoyBurst
	m.mu.Unlock()
	if decoy == nil || addr == nil {
		return
	}
	if burst < 1 {
		burst = 1
	}
	if burst > maxDecoyBurst {
		burst = maxDecoyBurst
	}
	if !m.sendDecoyFrame(addr, probe) {
		return
	}
	// Burst mode: follow-up frames spaced like a busy session's
	// downstream, so an active prober sees a service that converses
	// instead of a single canned reply. Each frame re-encodes with fresh
	// random key material and re-checks the global rate tokens.
	for i := 1; i < burst; i++ {
		delay := time.Duration(30+mrand.IntN(90)) * time.Millisecond
		time.AfterFunc(delay, func() {
			m.sendDecoyFrame(addr, probe)
		})
	}
}

// sendDecoyFrame encodes and sends one decoy reply. Returns false when
// size/amplification/rate guards declined.
func (m *ServerMux) sendDecoyFrame(addr net.Addr, probe []byte) bool {
	m.mu.Lock()
	decoy := m.decoy
	m.mu.Unlock()
	if decoy == nil || addr == nil {
		return false
	}
	frame, err := encodeDecoyFrame(decoy)
	if err != nil {
		return false
	}
	wire := compiler.WrapHandshakeDatagram(decoy.Genome, frame)
	if !allowDecoySize(len(probe), len(wire)) {
		return false
	}
	m.mu.Lock()
	ok := m.takeDecoyTokenLocked()
	m.mu.Unlock()
	if !ok {
		return false
	}
	m.telemetryEvent(TelemetryDecoy, addr)
	writeDatagramAsync(m.conn, addr, wire, m.jitterMax)
	return true
}

// takeDecoyTokenLocked consumes one global decoy slot. Caller holds m.mu.
func (m *ServerMux) takeDecoyTokenLocked() bool {
	now := time.Now()
	if now.Sub(m.decoyWindowStart) >= time.Second {
		m.decoyWindowStart = now
		m.decoyWindowCount = 0
	}
	if m.decoyWindowCount >= maxDecoyPerSec {
		return false
	}
	m.decoyWindowCount++
	m.decoysSent++
	return true
}
