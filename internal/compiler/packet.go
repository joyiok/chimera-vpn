package compiler

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"chimera/internal/genome"
)

const (
	// packetWindow is how far ahead the receiver will try AEAD nonces when
	// frames arrive out of order. The generated VPN carries IP packets, so
	// limited reordering is expected; 8192 frames is ~11 MB at 1400 B.
	packetWindow      = 8192
	packetWindowWords = packetWindow / 64
)

// NewPacketMessageCodec is a MessageCodec configured for datagram mode:
// frames may arrive out of order and duplicates are dropped.
func NewPacketMessageCodec(spec genome.MessageSpec, key []byte) (*MessageCodec, error) {
	c, err := NewMessageCodec(spec, key)
	if err != nil {
		return nil, err
	}
	c.packetMode = true
	c.packetSeen = [packetWindowWords]uint64{}
	return c, nil
}

// EncodePacket encrypts one datagram payload as a single complete frame
// (the generated LengthAlone segmentation is ignored at packet level).
func (c *MessageCodec) EncodePacket(payload []byte, inject map[string][]byte, rnd io.Reader) ([]byte, error) {
	if !c.packetMode {
		return nil, errors.New("message codec is not in packet mode")
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	spec := c.spec
	if !spec.HasPayload && len(payload) != 0 {
		return nil, fmt.Errorf("message %s does not carry payload", spec.Name)
	}

	padLen, err := choosePadding(spec.Padding, rnd)
	if err != nil {
		return nil, err
	}

	var pt []byte
	for _, f := range spec.EncryptedFields {
		b, err := c.encodeEncryptedField(f, padLen, inject, rnd)
		if err != nil {
			return nil, err
		}
		pt = append(pt, b...)
	}
	pt = append(pt, payload...)
	if padLen > 0 {
		pad := make([]byte, padLen)
		if _, err := io.ReadFull(rnd, pad); err != nil {
			return nil, err
		}
		pt = append(pt, pad...)
	}

	ciphertextLen := len(pt) + gcmTagSize
	frameLen := plainFieldsSize(spec) + ciphertextLen
	plainBytes, err := c.encodePlainFields(frameLen, ciphertextLen, rnd)
	if err != nil {
		return nil, err
	}

	nonce := c.nonceAt(c.packetSend)
	ciphertext := c.aead.Seal(nil, nonce, pt, plainBytes)
	c.packetSend++

	frame := make([]byte, 0, frameLen)
	frame = append(frame, plainBytes...)
	frame = append(frame, ciphertext...)
	return frame, nil
}

// DecodePacket authenticates one datagram frame with the receive window.
// Frames that authenticate under an already-seen nonce are treated as
// duplicates and dropped.
func (c *MessageCodec) DecodePacket(frame []byte) (*Message, error) {
	if !c.packetMode {
		return nil, errors.New("message codec is not in packet mode")
	}

	// Structural errors are independent of the candidate nonce; surface the
	// first one only after the window is exhausted so transient auth misses
	// are silent.
	var lastErr error
	for seq := c.packetBase; seq < c.packetBase+packetWindow; seq++ {
		off := seq - c.packetBase
		if c.packetSeen[off/64]&(1<<(off%64)) != 0 {
			continue
		}
		msg, err := c.decodeAt(frame, c.nonceAt(seq))
		if err != nil {
			lastErr = err
			continue
		}
		c.packetSeen[off/64] |= 1 << (off % 64)
		for c.packetSeen[0]&1 != 0 {
			c.shiftPacketWindow()
			c.packetBase++
		}
		return msg, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("%s: packet authenticate outside window: %w", c.spec.Name, lastErr)
	}
	return nil, fmt.Errorf("%s: packet authentication failed", c.spec.Name)
}

func (c *MessageCodec) shiftPacketWindow() {
	for i := 0; i < packetWindowWords-1; i++ {
		c.packetSeen[i] >>= 1
		if c.packetSeen[i+1]&1 != 0 {
			c.packetSeen[i] |= 1 << 63
		}
	}
	c.packetSeen[packetWindowWords-1] >>= 1
}

// PacketSession is the datagram-mode equivalent of Session.
type PacketSession struct {
	spec genome.MessageSpec
	send *MessageCodec
	recv *MessageCodec
}

// NewPacketSession binds packet codecs to session keys for one role.
func NewPacketSession(cp *CompiledProtocol, role string, c2s, s2c []byte) (*PacketSession, error) {
	sendKey, recvKey := c2s, s2c
	if role == genome.DirServer {
		sendKey, recvKey = s2c, c2s
	}
	send, err := NewPacketMessageCodec(cp.Genome.AppRecord, sendKey)
	if err != nil {
		return nil, err
	}
	recv, err := NewPacketMessageCodec(cp.Genome.AppRecord, recvKey)
	if err != nil {
		return nil, err
	}
	return &PacketSession{spec: cp.Genome.AppRecord, send: send, recv: recv}, nil
}

// Encode encrypts one datagram.
func (p *PacketSession) Encode(payload []byte) ([]byte, error) {
	return p.send.EncodePacket(payload, nil, nil)
}

// Decode decrypts one datagram.
func (p *PacketSession) Decode(frame []byte) (*Message, error) {
	return p.recv.DecodePacket(frame)
}

// Spec returns the shared application-record layout.
func (p *PacketSession) Spec() genome.MessageSpec { return p.spec }
