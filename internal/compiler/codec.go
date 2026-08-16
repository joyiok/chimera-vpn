package compiler

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"

	"chimera/internal/genome"
)

// Frame overhead of AES-GCM in the reference implementation (16-byte tag).
const gcmTagSize = 16

// Message is the decoded view of one protocol frame.
type Message struct {
	Spec      genome.MessageSpec
	Plain     []FieldValue
	Encrypted []FieldValue
	Payload   []byte
}

// FieldValue is one runtime field value from a decoded frame.
type FieldValue struct {
	Spec  genome.FieldSpec
	Value []byte
}

// MessageCodec is a compiled encoder/decoder for exactly one message layout.
// A codec instance must be used for exactly one direction (send or receive)
// so its sequence counter advances correctly.
type MessageCodec struct {
	spec genome.MessageSpec
	key  []byte
	aead cipher.AEAD
	seq  uint64
	seen seenWindow
	// packet-mode state: send counter and an anti-replay receive window.
	packetSend uint64
	packetBase uint64
	packetSeen [packetWindowWords]uint64
	packetMode bool
	// shapeBuckets, when set, pads packet-mode frames up to the next
	// rung so ciphertext lengths take a small number of values.
	shapeBuckets []int
}

// seenWindow is a 64-entry anti-replay bitmap over contiguous sequence
// numbers, used by stream-mode receives (handshake frames): seq numbers
// below base are dead, [base, base+64) are individually remembered.
type seenWindow struct {
	base uint64
	bits uint64
}

// observe records seq and reports whether it is fresh. Duplicates and
// sequences below base are rejected. A jump of 64+ declares the entire
// skipped run dead (a genuine stream never delivers it again, and treating
// it as live would reopen a replay window).
func (w *seenWindow) observe(seq uint64) bool {
	if seq < w.base {
		return false
	}
	off := seq - w.base
	if off >= 64 {
		w.base = seq
		w.bits = 1
		return true
	}
	if w.bits&(1<<off) != 0 {
		return false
	}
	w.bits |= 1 << off
	return true
}

// NewMessageCodec validates a message spec and binds a directional key.
func NewMessageCodec(spec genome.MessageSpec, key []byte) (*MessageCodec, error) {
	if err := validateMessage(spec); err != nil {
		return nil, err
	}
	want, err := KeyLen(spec.Cipher)
	if err != nil {
		return nil, err
	}
	if len(key) != want {
		return nil, fmt.Errorf("cipher %s needs %d-byte key, got %d", spec.Cipher, want, len(key))
	}
	aead, err := newAEAD(spec.Cipher, key)
	if err != nil {
		return nil, fmt.Errorf("cipher %s: %w", spec.Cipher, err)
	}
	c := &MessageCodec{spec: spec, key: key, aead: aead}
	c.seen.base = 0
	return c, nil
}

// newAEAD builds the AEAD primitive named by a cipher identifier. The GCM
// tag size (16) equals the Poly1305 tag size, so framing is identical.
func newAEAD(cipherName string, key []byte) (cipher.AEAD, error) {
	if cipherName == genome.CipherChaCha20P1305 {
		return chacha20poly1305.New(key)
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// Spec exposes the compiled message layout.
func (c *MessageCodec) Spec() genome.MessageSpec { return c.spec }

// Encode produces one frame (and, when the genotype says "length alone",
// three transport segments) carrying payload.
//
// inject may supply runtime values for ValueInjected fields; the handshake
// uses this for key_material. When absent, random bytes of the expected size
// are generated.
func (c *MessageCodec) Encode(payload []byte, inject map[string][]byte, rnd io.Reader) ([]byte, [][]byte, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	spec := c.spec
	if !spec.HasPayload && len(payload) != 0 {
		return nil, nil, fmt.Errorf("message %s does not carry payload", spec.Name)
	}

	padLen, err := choosePadding(spec.Padding, rnd)
	if err != nil {
		return nil, nil, err
	}

	// 1. Build plaintext: encrypted fields, then payload, then padding.
	var pt []byte
	for _, f := range spec.EncryptedFields {
		b, err := c.encodeEncryptedField(f, padLen, inject, rnd)
		if err != nil {
			return nil, nil, err
		}
		pt = append(pt, b...)
	}
	pt = append(pt, payload...)
	if padLen > 0 {
		pad := make([]byte, padLen)
		if _, err := io.ReadFull(rnd, pad); err != nil {
			return nil, nil, err
		}
		pt = append(pt, pad...)
	}

	//  2. Derive framing constants. The length field is authenticated data,
	//     so it must be finalised before encryption.
	ciphertextLen := len(pt) + gcmTagSize
	frameLen := plainFieldsSize(spec) + ciphertextLen

	plainBytes, err := c.encodePlainFields(frameLen, ciphertextLen, rnd)
	if err != nil {
		return nil, nil, err
	}

	// 3. Encrypt with sequence-derived nonce; plain fields are the AAD.
	nonce := c.nonce()
	ciphertext := c.aead.Seal(nil, nonce, pt, plainBytes)
	if len(ciphertext) != ciphertextLen {
		return nil, nil, errors.New("internal: ciphertext length mismatch")
	}

	// Stream mode advances the nonce counter immediately.
	c.seq++

	frame := make([]byte, 0, frameLen)
	frame = append(frame, plainBytes...)
	frame = append(frame, ciphertext...)
	return frame, splitSegments(frame, spec), nil
}

// Decode parses and authenticates one complete frame.
func (c *MessageCodec) decodeAt(frame []byte, nonce []byte) (*Message, error) {
	spec := c.spec
	plainSize := plainFieldsSize(spec)
	if len(frame) < plainSize {
		return nil, fmt.Errorf("%s: frame too short: %d < %d", spec.Name, len(frame), plainSize)
	}

	msg := &Message{Spec: spec, Plain: make([]FieldValue, 0, len(spec.PlainFields))}
	off := 0
	var declaredLength *uint64
	for i, f := range spec.PlainFields {
		n, err := fixedSize(f)
		if err != nil {
			return nil, err
		}
		if off+n > len(frame) {
			return nil, fmt.Errorf("%s: truncated plain field %s", spec.Name, f.Kind)
		}
		v := append([]byte(nil), frame[off:off+n]...)
		msg.Plain = append(msg.Plain, FieldValue{Spec: f, Value: v})
		off += n

		if i == spec.LengthFieldIndex {
			lv, err := decodeInt(v, f.Encoding, f.Endian)
			if err != nil {
				return nil, err
			}
			declaredLength = &lv
		}
	}

	rawPlain := frame[:off]
	ciphertext := frame[off:]

	// Validate the length field only after every plain field (which may
	// follow the length field in the generated order) has been consumed.
	if declaredLength != nil {
		f := spec.PlainFields[spec.LengthFieldIndex]
		switch f.Subject {
		case "ciphertext":
			if int(*declaredLength) != len(ciphertext) {
				return nil, fmt.Errorf("%s: ciphertext length %d != declared %d", spec.Name, len(ciphertext), *declaredLength)
			}
		case "record":
			if int(*declaredLength) != len(frame) {
				return nil, fmt.Errorf("%s: record length %d != declared %d", spec.Name, len(frame), *declaredLength)
			}
		default:
			return nil, fmt.Errorf("%s: unknown length subject %q", spec.Name, f.Subject)
		}
	}

	pt, err := c.aead.Open(nil, nonce, ciphertext, rawPlain)
	if err != nil {
		return nil, fmt.Errorf("%s: authenticate/open: %w", spec.Name, err)
	}

	// Parse encrypted fields in the generated order.
	eo := 0
	for _, f := range spec.EncryptedFields {
		b, n, err := decodeEncryptedField(f, pt[eo:])
		if err != nil {
			return nil, err
		}
		eo += n
		msg.Encrypted = append(msg.Encrypted, FieldValue{Spec: f, Value: b})
	}

	// What remains is payload + padding. pad_length (when present) has
	// already been parsed; cross-check it against the actual tail.
	padLen := 0
	if fv := msg.Find(genome.FieldPadLen); fv != nil {
		padLen = int(fv.Uint())
	}
	if eo+padLen > len(pt) {
		return nil, fmt.Errorf("%s: padding %d exceeds remaining plaintext %d", spec.Name, padLen, len(pt)-eo)
	}
	payloadLen := len(pt) - eo - padLen
	if !spec.HasPayload && payloadLen != 0 {
		return nil, fmt.Errorf("%s: %d unexpected payload bytes", spec.Name, payloadLen)
	}
	msg.Payload = append([]byte(nil), pt[eo:eo+payloadLen]...)
	return msg, nil
}

// Decode strictly decodes frames in order (stream mode). Sequence numbers
// diverging more than 63 from the stream position are rejected (a replayed
// frame from further back cannot be legitimate in this mode).
func (c *MessageCodec) Decode(frame []byte) (*Message, error) {
	for probe := c.seq; probe < c.seq+64; probe++ {
		msg, err := c.decodeAt(frame, c.nonceAt(probe))
		if err != nil {
			continue // wrong position: try the next (reordered / replayed frame)
		}
		if !c.seen.observe(probe) {
			return nil, fmt.Errorf("%s: replayed sequence %d", c.spec.Name, probe)
		}
		for c.seen.bits&1 != 0 && c.seen.base <= c.seq {
			c.seen.bits >>= 1
			c.seen.base++
			c.seq++
		}
		return msg, nil
	}
	return nil, fmt.Errorf("%s: frame does not authenticate within stream window", c.spec.Name)
}

// Find returns the first field of the given kind, or nil.
func (m *Message) Find(kind string) *FieldValue {
	for i := range m.Plain {
		if m.Plain[i].Spec.Kind == kind {
			return &m.Plain[i]
		}
	}
	for i := range m.Encrypted {
		if m.Encrypted[i].Spec.Kind == kind {
			return &m.Encrypted[i]
		}
	}
	return nil
}

// Uint decodes an integer field value (u8/u16/u24/u32).
func (fv *FieldValue) Uint() uint64 {
	v, _ := decodeInt(fv.Value, fv.Spec.Encoding, fv.Spec.Endian)
	return v
}

func (c *MessageCodec) encodeEncryptedField(f genome.FieldSpec, padLen int, inject map[string][]byte, rnd io.Reader) ([]byte, error) {
	switch f.Kind {
	case genome.FieldPadLen:
		return encodeInt(uint64(padLen), f.Encoding, f.Endian)

	case genome.FieldKey:
		raw := inject[f.Kind]
		if raw == nil {
			raw = make([]byte, 32)
			if _, err := io.ReadFull(rnd, raw); err != nil {
				return nil, err
			}
		}
		switch f.Encoding {
		case genome.EncRaw32:
			if len(raw) != 32 {
				return nil, fmt.Errorf("key_material: want 32 bytes, got %d", len(raw))
			}
			return append([]byte(nil), raw...), nil
		case genome.EncX963:
			if len(raw) == 32 {
				return append([]byte{0x04}, raw...), nil
			}
			if len(raw) == 33 {
				return append([]byte(nil), raw...), nil
			}
			return nil, fmt.Errorf("key_material: want 32/33 bytes, got %d", len(raw))
		}
		return nil, fmt.Errorf("key_material: unsupported encoding %q", f.Encoding)

	default:
		switch f.Encoding {
		case genome.EncFixedBytes:
			b := make([]byte, f.Size)
			if _, err := io.ReadFull(rnd, b); err != nil {
				return nil, err
			}
			return b, nil
		case genome.EncPrefixedU8, genome.EncPrefixedU16:
			n := f.MinSize
			if f.MaxSize > f.MinSize {
				x, err := randInt(rnd, f.MaxSize-f.MinSize+1)
				if err != nil {
					return nil, err
				}
				n = f.MinSize + x
			}
			b := make([]byte, n)
			if _, err := io.ReadFull(rnd, b); err != nil {
				return nil, err
			}
			if f.Encoding == genome.EncPrefixedU8 {
				return append([]byte{byte(n)}, b...), nil
			}
			prefix := make([]byte, 2)
			binary.BigEndian.PutUint16(prefix, uint16(n))
			return append(prefix, b...), nil
		default:
			return nil, fmt.Errorf("field %s: unsupported encoding %q", f.Kind, f.Encoding)
		}
	}
}

func decodeEncryptedField(f genome.FieldSpec, buf []byte) (value []byte, size int, err error) {
	switch f.Encoding {
	case genome.EncU8, genome.EncU16, genome.EncU24, genome.EncU32:
		n := intWidth(f.Encoding)
		if len(buf) < n {
			return nil, 0, fmt.Errorf("field %s: truncated", f.Kind)
		}
		return append([]byte(nil), buf[:n]...), n, nil

	case genome.EncFixedBytes, genome.EncRaw32, genome.EncX963:
		if f.Size <= 0 {
			return nil, 0, fmt.Errorf("field %s: invalid fixed size %d", f.Kind, f.Size)
		}
		if len(buf) < f.Size {
			return nil, 0, fmt.Errorf("field %s: need %d bytes, have %d", f.Kind, f.Size, len(buf))
		}
		return append([]byte(nil), buf[:f.Size]...), f.Size, nil

	case genome.EncPrefixedU8:
		if len(buf) < 1 {
			return nil, 0, fmt.Errorf("field %s: truncated prefix", f.Kind)
		}
		n := int(buf[0])
		if len(buf) < 1+n {
			return nil, 0, fmt.Errorf("field %s: prefix=%d exceeds buffer", f.Kind, n)
		}
		return append([]byte(nil), buf[1:1+n]...), 1 + n, nil

	case genome.EncPrefixedU16:
		if len(buf) < 2 {
			return nil, 0, fmt.Errorf("field %s: truncated prefix", f.Kind)
		}
		n := int(binary.BigEndian.Uint16(buf[:2]))
		if len(buf) < 2+n {
			return nil, 0, fmt.Errorf("field %s: prefix=%d exceeds buffer", f.Kind, n)
		}
		return append([]byte(nil), buf[2:2+n]...), 2 + n, nil
	}
	return nil, 0, fmt.Errorf("field %s: unsupported encoding %q", f.Kind, f.Encoding)
}

func (c *MessageCodec) encodePlainFields(frameLen, ciphertextLen int, rnd io.Reader) ([]byte, error) {
	spec := c.spec
	var out []byte
	for i, f := range spec.PlainFields {
		var b []byte
		if i == spec.LengthFieldIndex {
			subject := ciphertextLen
			if f.Subject == "record" {
				subject = frameLen
			}
			v, err := encodeInt(uint64(subject), f.Encoding, f.Endian)
			if err != nil {
				return nil, err
			}
			b = v
		} else {
			switch f.Kind {
			case genome.FieldVersion, genome.FieldType:
				raw, err := hex.DecodeString(f.ValueHex)
				if err != nil {
					return nil, err
				}
				b = raw
			case genome.FieldNonce:
				b = make([]byte, f.Size)
				if _, err := io.ReadFull(rnd, b); err != nil {
					return nil, err
				}
			case genome.FieldReserved:
				if f.ValueSource == genome.ValueRandom {
					b = make([]byte, f.Size)
					if _, err := io.ReadFull(rnd, b); err != nil {
						return nil, err
					}
				} else {
					raw, err := hex.DecodeString(f.ValueHex)
					if err != nil {
						return nil, err
					}
					b = raw
				}
			default:
				return nil, fmt.Errorf("field %s cannot be plaintext", f.Kind)
			}
		}
		n, err := fixedSize(f)
		if err != nil {
			return nil, err
		}
		if len(b) != n {
			return nil, fmt.Errorf("field %s: encoded %d bytes, layout expects %d", f.Kind, len(b), n)
		}
		out = append(out, b...)
	}
	return out, nil
}

// nonce derives a unique 12-byte AEAD nonce from (message index, sequence).
// Different messages in the same direction share a bootstrap key, so the
// message index is essential for nonce uniqueness.
// nonceAt derives the AEAD nonce for an explicit message sequence number.
func (c *MessageCodec) nonceAt(seq uint64) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint32(b[0:4], uint32(c.spec.Index))
	binary.BigEndian.PutUint64(b[4:12], seq)
	return b
}

func (c *MessageCodec) nonce() []byte { return c.nonceAt(c.seq) }

func choosePadding(p genome.PaddingPolicy, rnd io.Reader) (int, error) {
	switch p.Mode {
	case genome.PaddingNone:
		return 0, nil
	case genome.PaddingUniform:
		return randIntRange(rnd, p.Min, p.Max)
	case genome.PaddingBurst:
		x, err := randInt(rnd, 100)
		if err != nil {
			return 0, err
		}
		if x < 20 {
			return randIntRange(rnd, p.Min, p.Max)
		}
		return 0, nil
	default:
		return 0, fmt.Errorf("unknown padding mode %q", p.Mode)
	}
}

// splitSegments implements the generated "write length field alone" choice:
// [fields before length][length][fields after length + ciphertext].
func splitSegments(frame []byte, spec genome.MessageSpec) [][]byte {
	if !spec.LengthAlone || spec.LengthFieldIndex < 0 {
		return [][]byte{frame}
	}
	before := 0
	for i, f := range spec.PlainFields {
		n, _ := fixedSize(f)
		if i == spec.LengthFieldIndex {
			var segs [][]byte
			if before > 0 {
				segs = append(segs, frame[:before])
			}
			segs = append(segs, frame[before:before+n])
			segs = append(segs, frame[before+n:])
			return segs
		}
		before += n
	}
	return [][]byte{frame}
}

// ReadFrame reads one generated-protocol frame from a byte stream. It knows
// the fixed plain field layout and uses the length field to find the frame
// boundary, so it works for both length subjects.
func ReadFrame(r io.Reader, spec genome.MessageSpec) ([]byte, error) {
	frame := make([]byte, 0, 64)
	var declared *uint64
	var lengthBytes []byte
	for i, f := range spec.PlainFields {
		n, err := fixedSize(f)
		if err != nil {
			return nil, err
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		frame = append(frame, b...)

		if i == spec.LengthFieldIndex {
			v, err := decodeInt(b, f.Encoding, f.Endian)
			if err != nil {
				return nil, err
			}
			declared = &v
			lengthBytes = append([]byte(nil), b...)
		}
	}

	if declared == nil {
		return nil, errors.New("message has no length field; stream framing impossible")
	}
	f := spec.PlainFields[spec.LengthFieldIndex]

	// Compute the bytes still needed after the plain field section.
	var rest int
	switch f.Subject {
	case "ciphertext":
		rest = int(*declared)
	case "record":
		rest = int(*declared) - len(frame)
	default:
		return nil, fmt.Errorf("unknown length subject %q", f.Subject)
	}
	if rest < 0 || rest > 1<<26 {
		return nil, fmt.Errorf("implausible frame remainder %d", rest)
	}
	restb := make([]byte, rest)
	if _, err := io.ReadFull(r, restb); err != nil {
		return nil, err
	}
	frame = append(frame, restb...)
	_ = lengthBytes
	return frame, nil
}

// DeclaredFrame returns the prefix of a datagram that the generated length
// field says is the real record. Trailing bytes (handshake printable pad
// used to leave the IMC 2020 160–700 replay-trigger band) are dropped so
// AEAD and the handshake transcript see the same inner frame the sender
// encoded. A truncated datagram is an error; a frame with no extra tail is
// returned unchanged.
func DeclaredFrame(spec genome.MessageSpec, frame []byte) ([]byte, error) {
	off := 0
	var declared *uint64
	var subject string
	for i, f := range spec.PlainFields {
		n, err := fixedSize(f)
		if err != nil {
			return nil, err
		}
		if off+n > len(frame) {
			return nil, fmt.Errorf("%s: truncated plain field %s", spec.Name, f.Kind)
		}
		if i == spec.LengthFieldIndex {
			lv, err := decodeInt(frame[off:off+n], f.Encoding, f.Endian)
			if err != nil {
				return nil, err
			}
			declared = &lv
			subject = f.Subject
		}
		off += n
	}
	if declared == nil {
		return frame, nil
	}
	var n int
	switch subject {
	case "ciphertext":
		n = off + int(*declared)
	case "record":
		n = int(*declared)
	default:
		return nil, fmt.Errorf("%s: unknown length subject %q", spec.Name, subject)
	}
	if n < off || n > len(frame) {
		return nil, fmt.Errorf("%s: declared frame %d out of range (have %d, plain %d)", spec.Name, n, len(frame), off)
	}
	if n == len(frame) {
		return frame, nil
	}
	return frame[:n], nil
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		p = p[n:]
	}
	return nil
}

func plainFieldsSize(spec genome.MessageSpec) int {
	n := 0
	for _, f := range spec.PlainFields {
		s, _ := fixedSize(f)
		n += s
	}
	return n
}

func fixedSize(f genome.FieldSpec) (int, error) {
	switch f.Encoding {
	case genome.EncU8:
		return 1, nil
	case genome.EncU16:
		return 2, nil
	case genome.EncU24:
		return 3, nil
	case genome.EncU32:
		return 4, nil
	case genome.EncFixedBytes, genome.EncRaw32, genome.EncX963:
		if f.Size <= 0 {
			return 0, fmt.Errorf("field %s has invalid fixed size %d", f.Kind, f.Size)
		}
		return f.Size, nil
	default:
		return 0, fmt.Errorf("field %s: encoding %q has no fixed size", f.Kind, f.Encoding)
	}
}

func intWidth(enc string) int {
	switch enc {
	case genome.EncU8:
		return 1
	case genome.EncU16:
		return 2
	case genome.EncU24:
		return 3
	case genome.EncU32:
		return 4
	}
	return 0
}

func encodeInt(v uint64, enc, endian string) ([]byte, error) {
	n := intWidth(enc)
	if n == 0 {
		return nil, fmt.Errorf("not an integer encoding: %q", enc)
	}
	if n < 8 && v > (uint64(1)<<(8*n))-1 {
		return nil, fmt.Errorf("value %d does not fit %s", v, enc)
	}
	b := make([]byte, n)
	var tmp [8]byte
	switch endian {
	case "big":
		binary.BigEndian.PutUint64(tmp[:], v)
		copy(b, tmp[8-n:])
	case "little":
		binary.LittleEndian.PutUint64(tmp[:], v)
		copy(b, tmp[:n])
	default:
		return nil, fmt.Errorf("unknown endianness %q", endian)
	}
	return b, nil
}

func decodeInt(b []byte, enc, endian string) (uint64, error) {
	n := intWidth(enc)
	if n == 0 {
		return 0, fmt.Errorf("not an integer encoding: %q", enc)
	}
	if len(b) < n {
		return 0, fmt.Errorf("integer %s: need %d bytes, have %d", enc, n, len(b))
	}
	var out [8]byte
	if endian == "big" {
		copy(out[8-n:], b[:n])
		return binary.BigEndian.Uint64(out[:]), nil
	}
	if endian == "little" {
		copy(out[:n], b[:n])
		return binary.LittleEndian.Uint64(out[:]), nil
	}
	return 0, fmt.Errorf("unknown endianness %q", endian)
}

func randInt(r io.Reader, n int) (int, error) {
	if n <= 0 {
		return 0, nil
	}
	var b [8]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint64(b[:]) % uint64(n)), nil
}

func randIntRange(r io.Reader, lo, hi int) (int, error) {
	if hi <= lo {
		return lo, nil
	}
	x, err := randInt(r, hi-lo+1)
	if err != nil {
		return 0, err
	}
	return lo + x, nil
}
