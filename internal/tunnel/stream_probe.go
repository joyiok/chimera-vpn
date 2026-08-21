package tunnel

import (
	"errors"
	"fmt"
	"time"
)

// StreamProbeMode controls how a TCP listener reacts to a first stream frame
// that does not authenticate under any accepted generation.
//
//   - "close":  close immediately (legacy behavior, easiest to fingerprint)
//   - "silent": hold the connection open and discard bytes until a timeout,
//     which looks like a service that accepts TCP but does not answer
//   - "tls":    if the first bytes look like a TLS ClientHello, answer with
//     a standard TLS 1.2 fatal handshake alert; otherwise behave like silent
type StreamProbeMode string

const (
	StreamProbeClose  StreamProbeMode = "close"
	StreamProbeSilent StreamProbeMode = "silent"
	StreamProbeTLS    StreamProbeMode = "tls"
)

// DefaultStreamProbeTimeout bounds how long one silent decoy connection may
// stay open. Active scanners usually give up long before this.
const DefaultStreamProbeTimeout = 5 * time.Second

// DefaultStreamProbeMaxPending bounds concurrent unauthenticated TCP
// connections so a probe flood cannot exhaust file descriptors or memory.
const DefaultStreamProbeMaxPending = 256

// StreamProbeError reports that the first frame of a TCP connection looked
// like a probe (or simply did not authenticate). The caller owns the raw
// connection and may apply its configured decoy behavior.
type StreamProbeError struct {
	First []byte
}

func (e *StreamProbeError) Error() string {
	return fmt.Sprintf("stream handshake probe: first frame %d bytes", len(e.First))
}

// IsStreamProbe reports whether err is a first-frame authentication failure
// on a TCP stream (as opposed to an I/O or configuration error).
func IsStreamProbe(err error) bool {
	var probe *StreamProbeError
	return errors.As(err, &probe)
}

// NormalizeStreamProbeMode maps an empty/unset value to the production
// default and rejects unknown modes.
func NormalizeStreamProbeMode(mode StreamProbeMode) (StreamProbeMode, error) {
	if mode == "" {
		return StreamProbeSilent, nil
	}
	switch mode {
	case StreamProbeClose, StreamProbeSilent, StreamProbeTLS:
		return mode, nil
	default:
		return "", fmt.Errorf("unknown stream decoy mode %q (want close, silent, or tls)", mode)
	}
}
