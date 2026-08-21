package core

import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"time"

	"chimera/internal/compiler"
	"chimera/internal/genome"
	"chimera/internal/tunnel"
)

// The immune system closes the loop between observation and defense: the
// mux reports handshake-plane events (probes, replays, decoys), the
// immune loop aggregates them into a threat level, and the threat level
// drives responses — escalating TCP probe mimicry and accelerating
// generation rotation. Everything de-escalates on its own when the noise
// stops.

const (
	immuneWindow     = 30 * time.Second
	immuneCalmStreak = 2
)

// Threat levels exposed by Server.ThreatLevel.
const (
	ThreatCalm     = 0
	ThreatElevated = 1
	ThreatHigh     = 2
	ThreatAttack   = 3
)

var threatNames = map[int]string{
	ThreatCalm:     "calm",
	ThreatElevated: "elevated",
	ThreatHigh:     "high",
	ThreatAttack:   "attack",
}

// startImmuneLoops launches the scheduled generation rotator (when
// enabled) and the threat monitor. Called from Start with the server
// context.
func (s *Server) startImmuneLoops(ctx context.Context) {
	if s.cfg.GenerationRotation > 0 {
		go s.rotationLoop(ctx)
	}
	go s.immuneLoop(ctx)
}

func (s *Server) rotationLoop(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.GenerationRotation)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.rotateGeneration("scheduled")
		}
	}
}

// rotateGeneration advances the base generation by one, recompiles the
// accepted window, swaps it into every live listener, and pushes the new
// base to connected clients via ControlGeneration.
//
// Old clients stay compatible even without the push: their
// GenerationWindow probing already covers the new base, so the next
// handshake succeeds after at most one extra probe.
func (s *Server) rotateGeneration(reason string) {
	s.mu.Lock()
	if s.rotating {
		s.mu.Unlock()
		return
	}
	s.rotating = true
	outgoing := s.baseGen
	cfg := s.cfg
	cfg.Generation = s.baseGen + 1
	s.mu.Unlock()

	cps, psk, err := compileServerProtocols(cfg)
	if err != nil {
		log.Printf("[immune] rotation compile failed: %v", err)
		s.mu.Lock()
		s.rotating = false
		s.mu.Unlock()
		return
	}
	// Backward compatibility: keep accepting the outgoing base for one
	// more interval so a client that learned generation G just before the
	// rotation can still complete a handshake at G instead of burning a
	// full handshake timeout probing forward.
	if outgoing < cfg.Generation {
		if seed, serr := parseHex32(cfg.SeedHex, "seed"); serr == nil {
			if g, gerr := genome.GenerateWithCipher(seed, outgoing, cfg.Cipher); gerr == nil {
				if cp, cerr := compiler.Compile(g, psk); cerr == nil {
					cps = append(cps, cp)
				}
			}
		}
	}

	s.mu.Lock()
	s.baseGen = cfg.Generation
	muxes := append([]*tunnel.ServerMux(nil), s.muxes...)
	tcpSessions := make([]*tunnel.PacketTunnel, 0, len(s.tcpSessions))
	for t := range s.tcpSessions {
		tcpSessions = append(tcpSessions, t)
	}
	s.mu.Unlock()

	// Never rotate under in-flight handshakes: swapping the window
	// mid-handshake orphans them and the client burns a full timeout.
	// The next tick retries instead.
	pending := 0
	for _, mx := range muxes {
		pending += mx.PendingCount()
	}
	if pending > 0 {
		log.Printf("[immune] rotation deferred: %d handshake(s) in flight", pending)
		s.mu.Lock()
		s.rotating = false
		s.mu.Unlock()
		return
	}

	s.currentCPS.Store(&cps)
	for _, mx := range muxes {
		mx.SetProtocols(cps)
	}

	payload := make([]byte, 9)
	payload[0] = tunnel.ControlGeneration
	binary.BigEndian.PutUint64(payload[1:], cfg.Generation)
	for _, mx := range muxes {
		mx.BroadcastControl(payload)
	}
	for _, t := range tcpSessions {
		_ = t.PushControl(payload)
	}

	log.Printf("[immune] base generation advanced to %d (%s)", cfg.Generation, reason)
	s.mu.Lock()
	s.rotating = false
	s.mu.Unlock()
}

// BaseGeneration returns the server's current base protocol generation
// (advances when rotation is enabled).
func (s *Server) BaseGeneration() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.baseGen
}

// ThreatLevel returns the current immune-system threat level
// (ThreatCalm .. ThreatAttack).
func (s *Server) ThreatLevel() int { return int(s.threat.Load()) }

// ProbeMode returns the TCP probe defense currently in force, which may
// have been escalated from the configured mode by the immune system.
func (s *Server) ProbeMode() tunnel.StreamProbeMode {
	if mode, ok := s.probeMode.Load().(tunnel.StreamProbeMode); ok {
		return mode
	}
	return s.cfg.StreamDecoyMode
}

// onTelemetry aggregates mux handshake-plane events into the immune
// counters. Runs on the mux read loop: atomics only.
func (s *Server) onTelemetry(kind tunnel.TelemetryKind, _ net.Addr) {
	switch kind {
	case tunnel.TelemetryProbe:
		s.teleProbes.Add(1)
	case tunnel.TelemetryReplay:
		s.teleReplays.Add(1)
	case tunnel.TelemetryHandshake:
		s.teleHands.Add(1)
	case tunnel.TelemetryDecoy:
		s.teleDecoys.Add(1)
	}
}

func (s *Server) immuneLoop(ctx context.Context) {
	ticker := time.NewTicker(immuneWindow)
	defer ticker.Stop()
	calm := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		level := s.evaluateThreat()
		prev := int(s.threat.Load())
		switch {
		case level > prev:
			calm = 0
		case level < prev:
			calm++
			if calm >= immuneCalmStreak {
				s.deescalate()
				calm = 0
			}
		default:
			calm = 0
		}
		s.threat.Store(int32(level))
	}
}

// evaluateThreat swaps out one window of telemetry, derives the threat
// level, and applies responses. Split from immuneLoop so tests can drive
// it directly.
func (s *Server) evaluateThreat() int {
	probes := s.teleProbes.Swap(0)
	replays := s.teleReplays.Swap(0)
	handshakes := s.teleHands.Swap(0)
	decoys := s.teleDecoys.Swap(0)

	// Replays are far stronger evidence of targeted analysis than random
	// probes: weight them accordingly.
	score := probes + 10*replays
	level := ThreatCalm
	switch {
	case score >= 200:
		level = ThreatAttack
	case score >= 50:
		level = ThreatHigh
	case score >= 5:
		level = ThreatElevated
	}

	prev := int(s.threat.Load())
	if level > prev {
		log.Printf("[immune] threat level %s (probes=%d replays=%d handshakes=%d decoys=%d)",
			threatNames[level], probes, replays, handshakes, decoys)
		switch level {
		case ThreatElevated:
			s.setProbeMode(tunnel.StreamProbeTLS, "elevated probing")
		case ThreatHigh:
			s.setProbeMode(tunnel.StreamProbeTLS, "high probing")
			if s.cfg.GenerationRotation > 0 {
				s.rotateGeneration("threat response")
			} else {
				log.Printf("[immune] high threat: enable generation_rotation to let the server mutate under fire")
			}
		case ThreatAttack:
			s.setProbeMode(tunnel.StreamProbeClose, "active attack")
			if s.cfg.GenerationRotation > 0 {
				s.rotateGeneration("attack response")
			}
		}
	}
	s.threat.Store(int32(level))
	return level
}

// setProbeMode switches the TCP first-frame defense. Only stream
// transports react; UDP ignores probe modes.
func (s *Server) setProbeMode(mode tunnel.StreamProbeMode, why string) {
	if s.cfg.Transport == "udp" {
		return
	}
	if s.ProbeMode() == mode {
		return
	}
	s.probeMode.Store(mode)
	log.Printf("[immune] TCP probe defense -> %s (%s)", mode, why)
}

func (s *Server) deescalate() {
	log.Printf("[immune] threat subsided; restoring configured defenses")
	s.setProbeMode(s.cfg.StreamDecoyMode, "calm restored")
}

// currentProtocols returns the live protocol window. Stream handlers read
// this per connection so generation rotation takes effect without
// restarting listeners.
func (s *Server) currentProtocols() []*compiler.CompiledProtocol {
	if p := s.currentCPS.Load(); p != nil {
		return *p
	}
	return nil
}
