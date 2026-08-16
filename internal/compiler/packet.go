package compiler

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"chimera/internal/genome"
)

const (
	// PacketWindow is how far ahead the receiver will try AEAD nonces when
	// frames arrive out of order. The generated VPN carries IP packets, so
	// limited reordering is expected; 8192 frames is ~11 MB at 1400 B.
	PacketWindow      = 8192
	packetWindowWords = PacketWindow / 64
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

	body, padOff, padWidth, err := c.encodeEncryptedBody(padLen, inject, rnd)
	if err != nil {
		return nil, err
	}

	if idx := padFieldIndex(spec); idx >= 0 && padWidth > 0 && padOff >= 0 && len(c.shapeBuckets) > 0 {
		maxPad := padFieldMax(spec)
		frameLen := plainFieldsSize(spec) + len(body) + len(payload) + padLen + gcmTagSize
		if target := nextShapeSize(frameLen, c.shapeBuckets); target > frameLen {
			extra := target - frameLen
			if padLen+extra <= maxPad {
				padLen += extra
				pf := spec.EncryptedFields[idx]
				enc, err := encodeInt(uint64(padLen), pf.Encoding, pf.Endian)
				if err != nil {
					return nil, err
				}
				if len(enc) != padWidth {
					return nil, fmt.Errorf("pad_length width changed while shaping")
				}
				copy(body[padOff:padOff+padWidth], enc)
			}
		}
	}

	pt := append(body, payload...)
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
	for seq := c.packetBase; seq < c.packetBase+PacketWindow; seq++ {
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

// PacketBase returns the receiver window base: the first sequence number
// that is not yet known to have arrived (in order) or been skipped over.
func (c *MessageCodec) PacketBase() uint64 {
	if !c.packetMode {
		return 0
	}
	return c.packetBase
}

// PacketSent returns how many packet-mode frames this codec has encoded.
func (c *MessageCodec) PacketSent() uint64 {
	if !c.packetMode {
		return 0
	}
	return c.packetSend
}

// AdvanceBaseTo moves the receiver window base forward and clears the
// replay bitmap, declaring every sequence below the new base as dead: a
// frame from below the new base will never again authenticate. This is
// the receiver half of loss recovery - the sender asks for a skip once
// the unacknowledged span grows too large. A target at or below the
// current base, or beyond the window, is rejected.
func (c *MessageCodec) AdvanceBaseTo(target uint64) error {
	if !c.packetMode {
		return errors.New("message codec is not in packet mode")
	}
	if target <= c.packetBase {
		return nil
	}
	if target > c.packetBase+PacketWindow {
		return fmt.Errorf("advance target %d beyond window (base %d)", target, c.packetBase)
	}
	c.packetBase = target
	c.packetSeen = [packetWindowWords]uint64{}
	return nil
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

// AckState exposes what loss recovery needs: the receiver window base and
// the number of frames sent in this direction.
func (p *PacketSession) AckState() (base, sent uint64) {
	return p.recv.PacketBase(), p.send.PacketSent()
}

// PacketBase returns this side's receive window base.
func (p *PacketSession) PacketBase() uint64 { return p.recv.PacketBase() }

// AdvanceBaseTo moves this side's receive window base forward (sender asked
// to skip a lost run of frames). See MessageCodec.AdvanceBaseTo.
func (p *PacketSession) AdvanceBaseTo(target uint64) error {
	return p.recv.AdvanceBaseTo(target)
}

// DefaultShapeBuckets is the production datagram-length ladder. Frames
// already larger than the last rung are left alone so we never force
// UDP fragmentation just to hit a bucket.
var DefaultShapeBuckets = []int{128, 512, 1024, 1452}

// SetShapeBuckets pads encoded frames up to the next rung of buckets.
// An empty slice disables shaping. Only the send codec is affected.
func (p *PacketSession) SetShapeBuckets(buckets []int) {
	p.send.shapeBuckets = append([]int(nil), buckets...)
}

func nextShapeSize(n int, buckets []int) int {
	if n <= 0 || len(buckets) == 0 {
		return n
	}
	for _, b := range buckets {
		if n <= b {
			return b
		}
	}
	return n
}

func padFieldIndex(spec genome.MessageSpec) int {
	for i, f := range spec.EncryptedFields {
		if f.Kind == genome.FieldPadLen {
			return i
		}
	}
	return -1
}

func padFieldMax(spec genome.MessageSpec) int {
	i := padFieldIndex(spec)
	if i < 0 {
		return 0
	}
	n := intWidth(spec.EncryptedFields[i].Encoding)
	if n <= 0 {
		return 0
	}
	if n >= 3 {
		return 1<<20 - 1 // 1 MiB cap; u24/u32 never need more on a UDP path
	}
	return int(1<<(8*n)) - 1
}

func (c *MessageCodec) encodeEncryptedBody(padLen int, inject map[string][]byte, rnd io.Reader) (body []byte, padOff, padWidth int, err error) {
	padOff = -1
	for _, f := range c.spec.EncryptedFields {
		if f.Kind == genome.FieldPadLen {
			padOff = len(body)
		}
		b, err := c.encodeEncryptedField(f, padLen, inject, rnd)
		if err != nil {
			return nil, 0, 0, err
		}
		if f.Kind == genome.FieldPadLen {
			padWidth = len(b)
		}
		body = append(body, b...)
	}
	return body, padOff, padWidth, nil
}
