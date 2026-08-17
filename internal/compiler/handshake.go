package compiler

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"

	"chimera/internal/genome"
)

// Handshake drives one endpoint through the generated handshake state
// machine. The two endpoints run concurrently; each Step performs exactly
// one send or receive action.
type Handshake struct {
	role string
	cp   *CompiledProtocol
	psk  []byte

	// codecs are private to this endpoint so AEAD sequence counters never
	// collide between peers.
	codecs []*MessageCodec

	priv   *ecdh.PrivateKey
	remote *ecdh.PublicKey

	transcript hash.Hash
	idx        int
	earlyData  []byte
}

// NewHandshake creates an endpoint with a fresh ephemeral X25519 key and its
// own codec table.
func NewHandshake(cp *CompiledProtocol, role string, psk []byte) (*Handshake, error) {
	if role != genome.DirClient && role != genome.DirServer {
		return nil, fmt.Errorf("role must be client or server, got %q", role)
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	codecs, err := cp.NewHandshakeCodecs()
	if err != nil {
		return nil, err
	}
	return &Handshake{
		role:       role,
		cp:         cp,
		psk:        append([]byte(nil), psk...),
		codecs:     codecs,
		priv:       priv,
		transcript: sha256.New(),
	}, nil
}

// SetEarlyData lets the caller place application bytes into handshake
// messages whose generated layout allows a payload (0-RTT style).
func (h *Handshake) SetEarlyData(b []byte) { h.earlyData = append([]byte(nil), b...) }

// Done reports whether the handshake is complete.
func (h *Handshake) Done() bool { return h.idx >= len(h.codecs) }

// Progress returns the current handshake step index.
func (h *Handshake) Progress() int { return h.idx }

// Role returns the endpoint role.
func (h *Handshake) Role() string { return h.role }

// ProtocolGeneration is the genome generation this handshake was compiled
// from. The server mux uses it to log which species in a generation window
// a client actually matched.
func (h *Handshake) ProtocolGeneration() uint64 {
	if h == nil || h.cp == nil || h.cp.Genome == nil {
		return 0
	}
	return h.cp.Genome.Generation
}

// CurrentSpec returns the layout of the next handshake step.
func (h *Handshake) CurrentSpec() (genome.MessageSpec, error) {
	if h.Done() {
		return genome.MessageSpec{}, fmt.Errorf("handshake already complete")
	}
	return h.cp.Genome.Handshake[h.idx], nil
}

// EncodeStep builds and advances one outgoing handshake frame. The caller
// owns transport: stream mode writes the segments, packet mode sends the
// full frame as one datagram.
func (h *Handshake) EncodeStep() ([]byte, [][]byte, error) {
	if h.Done() {
		return nil, nil, fmt.Errorf("handshake already complete")
	}
	spec := h.cp.Genome.Handshake[h.idx]
	if spec.Direction != h.role {
		return nil, nil, fmt.Errorf("step %d is not an outgoing message for role %s", h.idx, h.role)
	}
	inject := map[string][]byte{}
	if messageHasKey(spec) {
		inject[genome.FieldKey] = h.priv.PublicKey().Bytes()
	}
	var payload []byte
	if spec.HasPayload {
		payload = h.earlyData
	}
	frame, segments, err := h.codecs[h.idx].Encode(payload, inject, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake step %d encode: %w", h.idx, err)
	}
	if _, err := h.transcript.Write(frame); err != nil {
		return nil, nil, err
	}
	h.idx++
	return frame, segments, nil
}

// RecvStep authenticates and advances one incoming handshake frame.
func (h *Handshake) RecvStep(frame []byte) error {
	if h.Done() {
		return fmt.Errorf("handshake already complete")
	}
	spec := h.cp.Genome.Handshake[h.idx]
	if spec.Direction == h.role {
		return fmt.Errorf("step %d is not an incoming message for role %s", h.idx, spec.Direction)
	}
	trimmed, err := DeclaredFrame(spec, frame)
	if err != nil {
		return fmt.Errorf("handshake step %d: %w", h.idx, err)
	}
	msg, err := h.codecs[h.idx].Decode(trimmed)
	if err != nil {
		return fmt.Errorf("handshake step %d decode: %w", h.idx, err)
	}
	if err := h.capturePeerKey(msg); err != nil {
		return fmt.Errorf("handshake step %d: %w", h.idx, err)
	}
	if _, err := h.transcript.Write(trimmed); err != nil {
		return err
	}
	h.idx++
	return nil
}

// Step performs one state-machine action on a reliable byte stream.
func (h *Handshake) Step(rw io.ReadWriter) error {
	spec, err := h.CurrentSpec()
	if err != nil {
		return err
	}
	if spec.Direction == h.role {
		_, segments, err := h.EncodeStep()
		if err != nil {
			return err
		}
		for _, seg := range segments {
			if err := writeFull(rw, seg); err != nil {
				return err
			}
		}
		return nil
	}
	frame, err := ReadFrame(rw, spec)
	if err != nil {
		return fmt.Errorf("handshake step %d read: %w", h.idx, err)
	}
	return h.RecvStep(frame)
}

// Run steps the state machine to completion.
func (h *Handshake) Run(rw io.ReadWriter) error {
	for !h.Done() {
		if err := h.Step(rw); err != nil {
			return err
		}
	}
	return nil
}

// Finish derives the forward-secret session keys. Both endpoints must call
// it only after the handshake completes; they arrive at the same keys
// because the transcript is identical on both sides.
func (h *Handshake) Finish() (*Session, error) {
	c2s, s2c, err := h.sessionKeys()
	if err != nil {
		return nil, err
	}
	return NewSession(h.cp, h.role, c2s, s2c)
}

// FinishPacket is Finish for datagram mode.
func (h *Handshake) FinishPacket() (*PacketSession, error) {
	c2s, s2c, err := h.sessionKeys()
	if err != nil {
		return nil, err
	}
	return NewPacketSession(h.cp, h.role, c2s, s2c)
}

func (h *Handshake) sessionKeys() ([]byte, []byte, error) {
	if !h.Done() {
		return nil, nil, fmt.Errorf("handshake not complete")
	}
	if h.remote == nil {
		return nil, nil, fmt.Errorf("no peer ephemeral key received")
	}
	shared, err := h.priv.ECDH(h.remote)
	if err != nil {
		return nil, nil, err
	}
	transcriptHex := hex.EncodeToString(h.transcript.Sum(nil))
	keyLen, err := KeyLen(h.cp.Genome.AppRecord.Cipher)
	if err != nil {
		return nil, nil, err
	}

	c2s, err := hkdf.Key(sha256.New, shared, h.psk, "chimera-pgc/0/session/c2s\x00"+transcriptHex, keyLen)
	if err != nil {
		return nil, nil, err
	}
	s2c, err := hkdf.Key(sha256.New, shared, h.psk, "chimera-pgc/0/session/s2c\x00"+transcriptHex, keyLen)
	if err != nil {
		return nil, nil, err
	}
	return c2s, s2c, nil
}

func (h *Handshake) capturePeerKey(msg *Message) error {
	kv := msg.Find(genome.FieldKey)
	if kv == nil {
		return nil
	}
	raw := append([]byte(nil), kv.Value...)
	if kv.Spec.Encoding == genome.EncX963 {
		if len(raw) == 33 && raw[0] == 0x04 {
			raw = raw[1:]
		} else if len(raw) != 32 {
			return fmt.Errorf("unexpected X9.63 key size %d", len(raw))
		}
	}
	if len(raw) != 32 {
		return fmt.Errorf("unexpected ephemeral key size %d", len(raw))
	}
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return fmt.Errorf("invalid peer key: %w", err)
	}
	h.remote = pub
	return nil
}

func messageHasKey(spec genome.MessageSpec) bool {
	for _, f := range spec.EncryptedFields {
		if f.Kind == genome.FieldKey {
			return true
		}
	}
	return false
}

// Session carries application records after the generated handshake.
type Session struct {
	spec genome.MessageSpec
	send *MessageCodec
	recv *MessageCodec
}

// NewSession binds app-record codecs to derived session keys.
func NewSession(cp *CompiledProtocol, role string, c2s, s2c []byte) (*Session, error) {
	sendKey, recvKey := c2s, s2c
	if role == genome.DirServer {
		sendKey, recvKey = s2c, c2s
	}
	send, err := NewMessageCodec(cp.Genome.AppRecord, sendKey)
	if err != nil {
		return nil, err
	}
	recv, err := NewMessageCodec(cp.Genome.AppRecord, recvKey)
	if err != nil {
		return nil, err
	}
	return &Session{spec: cp.Genome.AppRecord, send: send, recv: recv}, nil
}

// Send encrypts and writes one application record.
func (s *Session) Send(w io.Writer, payload []byte) error {
	_, segments, err := s.send.Encode(payload, nil, nil)
	if err != nil {
		return err
	}
	for _, seg := range segments {
		if err := writeFull(w, seg); err != nil {
			return err
		}
	}
	return nil
}

// Recv reads and decrypts one application record.
func (s *Session) Recv(r io.Reader) (*Message, error) {
	frame, err := ReadFrame(r, s.spec)
	if err != nil {
		return nil, err
	}
	return s.recv.Decode(frame)
}
