package tunnel

import (
	"crypto/rand"
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
	if m.decoy == nil || addr == nil {
		return
	}
	frame, err := encodeDecoyFrame(m.decoy)
	if err != nil {
		return
	}
	wire := compiler.WrapHandshakeDatagram(m.decoy.Genome, frame)
	if !allowDecoySize(len(probe), len(wire)) {
		return
	}
	m.mu.Lock()
	ok := m.takeDecoyTokenLocked()
	m.mu.Unlock()
	if !ok {
		return
	}
	writeDatagramAsync(m.conn, addr, wire, m.jitterMax)
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
