// Package genome defines the "genotype" of a generated protocol.
//
// A ProtocolGenome is the complete, declarative description of one protocol
// species: handshake pattern, per-message field layout, integer encodings,
// padding policy and cipher choice. The compiler package turns it into an
// executable state machine. Nothing here is a wire protocol by itself; the
// compiler produces the wire protocol.
package genome

// Field placements.
const (
	PlacePlain     = "plain"
	PlaceEncrypted = "encrypted"
)

// Field kinds understood by the codec. The names intentionally follow the
// vocabulary of UPGen (type/version/nonce/length/pad-length/reserved/
// extra/certificate/key-material) so generated specs can be compared with the
// paper's design space.
const (
	FieldVersion  = "version"
	FieldType     = "type"
	FieldNonce    = "nonce"
	FieldLength   = "length"
	FieldPadLen   = "pad_length"
	FieldReserved = "reserved"
	FieldExtra    = "extra"
	FieldKey      = "key_material"
	FieldCert     = "certificate"
	FieldPayload  = "payload"
)

// Field encodings.
const (
	EncFixedBytes  = "fixed_bytes"
	EncPrefixedU8  = "prefixed_u8"
	EncPrefixedU16 = "prefixed_u16"
	EncU8          = "u8"
	EncU16         = "u16"
	EncU24         = "u24"
	EncU32         = "u32"
	EncRaw32       = "raw32"
	EncX963        = "x963"
)

// Value sources.
const (
	ValueConstant = "constant"
	ValueRandom   = "random"
	ValueZero     = "zero"
	ValueInjected = "injected"
)

// Padding modes.
const (
	PaddingNone    = "none"
	PaddingUniform = "uniform"
	PaddingBurst   = "burst"
)

// Directions.
const (
	DirClient = "client"
	DirServer = "server"
	DirBoth   = "bidirectional"
)

// Cipher identifiers used in the spec. The current reference implementation
// provides AES-GCM variants and ChaCha20-Poly1305 from the Go standard
// library; ChaCha suits clients without AES hardware acceleration.
const (
	CipherAES128GCM     = "aes-128-gcm"
	CipherAES192GCM     = "aes-192-gcm"
	CipherAES256GCM     = "aes-256-gcm"
	CipherChaCha20P1305 = "chacha20-poly1305"
)

// FieldSpec describes one field in one message.
type FieldSpec struct {
	Kind      string `json:"kind"`
	Placement string `json:"placement"` // plain | encrypted
	Encoding  string `json:"encoding"`

	// Endian applies to integer encodings (u16/u24/u32). Empty means the
	// field is not an integer.
	Endian string `json:"endian,omitempty"`

	// Size is the fixed byte size for fixed_bytes/raw32/x963 fields.
	Size int `json:"size,omitempty"`
	// MinSize/MaxSize bound the runtime content length of prefixed_u8 and
	// prefixed_u16 fields. For fixed-size fields both are zero.
	MinSize int `json:"min_size,omitempty"`
	MaxSize int `json:"max_size,omitempty"`

	// ValueHex is used for constant fields (version/type/reserved-zero).
	ValueHex string `json:"value_hex,omitempty"`

	// ValueSource controls what is written at runtime.
	ValueSource string `json:"value_source,omitempty"`

	// Subject is only set for the length field: "ciphertext" means the
	// encoded integer is len(ciphertext); "record" means it is the total
	// frame length in bytes.
	Subject string `json:"subject,omitempty"`
}

// PaddingPolicy is the per-message padding distribution. Every frame draws a
// fresh length from the policy at runtime; the policy itself is part of the
// fixed genotype.
type PaddingPolicy struct {
	Mode string `json:"mode"`
	Min  int    `json:"min"`
	Max  int    `json:"max"`
}

// MessageSpec is the layout of one message in the protocol state machine.
type MessageSpec struct {
	Index     int    `json:"index"`
	Name      string `json:"name"`
	Direction string `json:"direction"` // client | server
	Purpose   string `json:"purpose"`   // hello | hello+key | key | ack | data

	PlainFields     []FieldSpec `json:"plain_fields"`
	EncryptedFields []FieldSpec `json:"encrypted_fields"`

	// LengthFieldIndex is the index into PlainFields occupied by the length
	// field, or -1 when the message carries no length field.
	LengthFieldIndex int `json:"length_field_index"`

	// LengthAlone, when true, means the length field is emitted as its own
	// transport segment (UPGen calls this "write length field alone").
	LengthAlone bool `json:"length_alone"`

	HasPayload bool          `json:"has_payload"`
	Padding    PaddingPolicy `json:"padding"`

	Cipher string `json:"cipher"`
}

// ProtocolGenome is a complete generated protocol species.
type ProtocolGenome struct {
	Schema       string `json:"schema"`
	Generation   uint64 `json:"generation"`
	SeedMaterial string `json:"seed_material_sha256"`

	HandshakePattern string        `json:"handshake_pattern"`
	Handshake        []MessageSpec `json:"handshake"`
	AppRecord        MessageSpec   `json:"app_record"`

	// EstimatedEntropyBits is the generator's own accounting of the design
	// space consumed for this genotype. It is an approximation (choices are
	// not all independent) but useful for comparing generations.
	EstimatedEntropyBits float64 `json:"estimated_entropy_bits"`

	// ProtocolFingerprint identifies the full generated design. Two seeds or
	// generations should (with overwhelming probability) have different
	// fingerprints.
	ProtocolFingerprint string `json:"protocol_fingerprint"`
}
