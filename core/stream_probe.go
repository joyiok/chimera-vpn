package core

import (
	"net"
	"time"

	"chimera/internal/tunnel"
)

// tls12FatalHandshakeFailure is a minimal, standards-compliant TLS 1.2
// fatal alert. A TLS scanner sees a normal "server rejected the handshake"
// response instead of a custom protocol or an abrupt close.
var tls12FatalHandshakeFailure = []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}

func looksLikeTLSClientHello(b []byte) bool {
	return len(b) >= 3 && b[0] == 0x16 && b[1] == 0x03
}

// handleStreamProbe applies the configured TCP decoy behavior to a
// connection whose first stream frame did not authenticate. The connection
// is always closed before this method returns.
func (s *Server) handleStreamProbe(conn net.Conn, first []byte) {
	cfg := s.cfg
	if cfg.StreamDecoyMaxPending > 0 && s.tcpDecoys.Load() >= int64(cfg.StreamDecoyMaxPending) {
		_ = conn.Close()
		return
	}
	s.tcpDecoys.Add(1)
	defer s.tcpDecoys.Add(-1)

	// The immune system may have escalated the configured mode.
	switch s.ProbeMode() {
	case tunnel.StreamProbeClose:
		_ = conn.Close()
		return
	case tunnel.StreamProbeTLS:
		if looksLikeTLSClientHello(first) {
			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, _ = conn.Write(tls12FatalHandshakeFailure)
			_ = conn.Close()
			return
		}
		// Non-TLS garbage: behave like a silent service below.
	}

	// Silent decoy: keep the TCP connection open and discard probe bytes
	// until the configured timeout. The scanner sees an accepted connection
	// that never answers, which is common for NAT/firewall/protocol-agnostic
	// listeners and gives no protocol-specific confirmation.
	timeout := cfg.StreamDecoyTimeout
	if timeout <= 0 {
		timeout = tunnel.DefaultStreamProbeTimeout
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 4096)
	for {
		if _, err := conn.Read(buf); err != nil {
			_ = conn.Close()
			return
		}
	}
}
