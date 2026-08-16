package compiler

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"

	"chimera/internal/genome"
)

// BootstrapKeys are the PSK-derived keys used to encrypt handshake messages
// before ephemeral ECDH completes.
type BootstrapKeys struct {
	C2S []byte
	S2C []byte
}

// CompiledProtocol is an executable form of one ProtocolGenome.
//
// It stores the validated message layout table. Codec instances are NOT
// shared between endpoints: every endpoint needs independent AEAD sequence
// counters, so each one compiles a fresh codec set.
type CompiledProtocol struct {
	Genome    *genome.ProtocolGenome
	Bootstrap BootstrapKeys
	Handshake []genome.MessageSpec
}

// Compile validates a generated genome and binds it to a pre-shared key.
func Compile(g *genome.ProtocolGenome, psk []byte) (*CompiledProtocol, error) {
	if g == nil {
		return nil, fmt.Errorf("nil genome")
	}
	if len(psk) == 0 {
		return nil, fmt.Errorf("empty pre-shared key")
	}
	if g.Schema != genome.GeneratorSchema {
		return nil, fmt.Errorf("unsupported genome schema %q", g.Schema)
	}
	if len(g.Handshake) == 0 {
		return nil, fmt.Errorf("genome has no handshake messages")
	}

	// The generator currently selects one cipher for the whole genome, so
	// the bootstrap keys follow that cipher's key size.
	keyLen, err := KeyLen(g.Handshake[0].Cipher)
	if err != nil {
		return nil, err
	}
	salt := []byte("chimera-pgc/0/bootstrap-salt")
	c2s, err := hkdf.Key(sha256.New, psk, salt, "chimera-pgc/0/bootstrap/c2s", keyLen)
	if err != nil {
		return nil, err
	}
	s2c, err := hkdf.Key(sha256.New, psk, salt, "chimera-pgc/0/bootstrap/s2c", keyLen)
	if err != nil {
		return nil, err
	}

	cp := &CompiledProtocol{
		Genome: g,
		Bootstrap: BootstrapKeys{
			C2S: c2s,
			S2C: s2c,
		},
	}

	// Validate every handshake layout and key binding up front.
	for i, spec := range g.Handshake {
		key := cp.Bootstrap.C2S
		if spec.Direction == genome.DirServer {
			key = cp.Bootstrap.S2C
		}
		if _, err := NewMessageCodec(spec, key); err != nil {
			return nil, fmt.Errorf("handshake message %d (%s): %w", i, spec.Name, err)
		}
		cp.Handshake = append(cp.Handshake, spec)
	}

	// The application-record layout is compiled on demand after session key
	// derivation; validate it now so failures happen at compile time.
	if _, err := validateMessageReturning(g.AppRecord); err != nil {
		return nil, fmt.Errorf("app record: %w", err)
	}
	return cp, nil
}

// NewHandshakeCodecs compiles a fresh codec set for one endpoint.
func (cp *CompiledProtocol) NewHandshakeCodecs() ([]*MessageCodec, error) {
	codecs := make([]*MessageCodec, 0, len(cp.Handshake))
	for i, spec := range cp.Handshake {
		key := cp.Bootstrap.C2S
		if spec.Direction == genome.DirServer {
			key = cp.Bootstrap.S2C
		}
		c, err := NewMessageCodec(spec, key)
		if err != nil {
			return nil, fmt.Errorf("handshake message %d (%s): %w", i, spec.Name, err)
		}
		codecs = append(codecs, c)
	}
	return codecs, nil
}

// validateMessage is the complete static check of one generated message.
func validateMessage(spec genome.MessageSpec) error {
	_, err := validateMessageReturning(spec)
	return err
}

func validateMessageReturning(spec genome.MessageSpec) (genome.MessageSpec, error) {
	// Cipher.
	switch spec.Cipher {
	case genome.CipherAES128GCM, genome.CipherAES192GCM, genome.CipherAES256GCM:
	default:
		return spec, fmt.Errorf("unsupported cipher %q", spec.Cipher)
	}

	// Plain fields must all be fixed-size and parsable by ReadFrame.
	lengthSeen := 0
	for i, f := range spec.PlainFields {
		if f.Placement != genome.PlacePlain {
			return spec, fmt.Errorf("plain field %d (%s) has placement %q", i, f.Kind, f.Placement)
		}
		if _, err := fixedSize(f); err != nil {
			return spec, fmt.Errorf("plain field %d: %w", i, err)
		}
		if f.Kind == genome.FieldLength {
			lengthSeen++
			if spec.LengthFieldIndex != i {
				return spec, fmt.Errorf("length field at index %d but LengthFieldIndex=%d", i, spec.LengthFieldIndex)
			}
			if f.Subject != "ciphertext" && f.Subject != "record" {
				return spec, fmt.Errorf("length field has invalid subject %q", f.Subject)
			}
		}
	}
	if lengthSeen != 1 {
		return spec, fmt.Errorf("schema 0 requires exactly one length field, found %d", lengthSeen)
	}
	if spec.LengthFieldIndex < 0 || spec.LengthFieldIndex >= len(spec.PlainFields) {
		return spec, fmt.Errorf("LengthFieldIndex %d out of range", spec.LengthFieldIndex)
	}

	// Encrypted fields.
	padLenSeen := 0
	for _, f := range spec.EncryptedFields {
		if f.Placement != genome.PlaceEncrypted {
			return spec, fmt.Errorf("encrypted field %s has placement %q", f.Kind, f.Placement)
		}
		switch f.Kind {
		case genome.FieldPadLen:
			padLenSeen++
			if intWidth(f.Encoding) == 0 {
				return spec, fmt.Errorf("pad_length must use an integer encoding, got %q", f.Encoding)
			}
		case genome.FieldKey:
			if f.Encoding != genome.EncRaw32 && f.Encoding != genome.EncX963 {
				return spec, fmt.Errorf("key_material has unsupported encoding %q", f.Encoding)
			}
		case genome.FieldCert, genome.FieldExtra:
			if f.Encoding != genome.EncFixedBytes && f.Encoding != genome.EncPrefixedU8 && f.Encoding != genome.EncPrefixedU16 {
				return spec, fmt.Errorf("field %s has unsupported encoding %q", f.Kind, f.Encoding)
			}
		}
	}

	if spec.Padding.Mode == genome.PaddingNone {
		if padLenSeen != 0 {
			return spec, fmt.Errorf("padding disabled but pad_length field present")
		}
	} else {
		if padLenSeen != 1 {
			return spec, fmt.Errorf("padding %s requires exactly one pad_length field, found %d", spec.Padding.Mode, padLenSeen)
		}
		switch spec.Padding.Mode {
		case genome.PaddingUniform, genome.PaddingBurst:
		default:
			return spec, fmt.Errorf("unknown padding mode %q", spec.Padding.Mode)
		}
		if spec.Padding.Min < 0 || spec.Padding.Max < spec.Padding.Min {
			return spec, fmt.Errorf("invalid padding range [%d,%d]", spec.Padding.Min, spec.Padding.Max)
		}
	}
	return spec, nil
}

// KeyLen returns the AEAD key length required by a cipher identifier.
func KeyLen(cipherName string) (int, error) {
	switch cipherName {
	case genome.CipherAES128GCM:
		return 16, nil
	case genome.CipherAES192GCM:
		return 24, nil
	case genome.CipherAES256GCM:
		return 32, nil
	}
	return 0, fmt.Errorf("unsupported cipher %q", cipherName)
}
