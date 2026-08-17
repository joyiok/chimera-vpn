package genome

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"

	"chimera/internal/drbg"
)

// GeneratorSchema identifies the grammar/compiler revision. Bump it whenever
// the generation algorithm changes so old deployed genotypes stay readable.
const GeneratorSchema = "chimera-pgc/0"

type patternStep struct {
	direction string
	purpose   string
	hasKey    bool
}

type patternDef struct {
	name  string
	steps []patternStep
}

// patternTable mirrors the small handshake grammar. Each pattern guarantees
// that both peers contribute an ephemeral key, so the reference handshake can
// always derive forward-secret session keys after the last step.
var patternTable = []patternDef{
	{
		name: "c_s",
		steps: []patternStep{
			{DirClient, "hello+key", true},
			{DirServer, "hello+key", true},
		},
	},
	{
		name: "c_s_c",
		steps: []patternStep{
			{DirClient, "hello", false},
			{DirServer, "hello+key", true},
			{DirClient, "key", true},
		},
	},
	{
		name: "c_s_c_s",
		steps: []patternStep{
			{DirClient, "hello", false},
			{DirServer, "hello+key", true},
			{DirClient, "key", true},
			{DirServer, "ack", false},
		},
	},
	{
		name: "c_c_s",
		steps: []patternStep{
			{DirClient, "hello", false},
			{DirClient, "key", true},
			{DirServer, "hello+key", true},
		},
	},
	{
		name: "s_c",
		steps: []patternStep{
			{DirServer, "hello+key", true},
			{DirClient, "key", true},
		},
	},
	{
		name: "s_c_s",
		steps: []patternStep{
			{DirServer, "hello+key", true},
			{DirClient, "key", true},
			{DirServer, "ack", false},
		},
	},
}

func knownCipher(name string) bool {
	switch name {
	case CipherAES128GCM, CipherAES192GCM, CipherAES256GCM, CipherChaCha20P1305:
		return true
	}
	return false
}

// KnownCipher reports whether name is a cipher the generator accepts as an
// override (see GenerateWithCipher).
func KnownCipher(name string) bool { return knownCipher(name) }

type generator struct {
	r       *drbg.Rand
	entropy float64
}

// Generate deterministically expands (seed, generation) into a complete
// protocol genome. The same inputs always produce the same design, and a
// different generation number is a protocol "mutation".
func Generate(seed []byte, generation uint64) (*ProtocolGenome, error) {
	return generate(seed, generation, "")
}

// GenerateWithCipher is Generate with a forced cipher suite (e.g.
// CipherChaCha20P1305 for clients without AES hardware acceleration).
// The cipher draw is consumed either way, so every other design choice is
// bit-identical to Generate for the same (seed, generation); an empty or
// unknown cipher falls back to the drawn default.
func GenerateWithCipher(seed []byte, generation uint64, cipher string) (*ProtocolGenome, error) {
	return generate(seed, generation, cipher)
}

func generate(seed []byte, generation uint64, forceCipher string) (*ProtocolGenome, error) {
	seedSum := sha256.Sum256(seed)
	seedMat := append([]byte("chimera-pgc-v0/seed\x00"), seedSum[:]...)

	root := drbg.New(seedMat, "chimera-pgc-v0/root")
	r := root.Child(fmt.Sprintf("generation/%d", generation))
	g := &generator{r: r}

	// Protocol-wide cipher choice.
	ciphers := []string{CipherAES128GCM, CipherAES192GCM, CipherAES256GCM}
	cipherWeights := []int{2, 1, 5}
	cipher := ciphers[g.weighted("cipher", cipherWeights)]
	if forceCipher != "" {
		if !knownCipher(forceCipher) {
			return nil, fmt.Errorf("unknown cipher %q", forceCipher)
		}
		cipher = forceCipher
	}

	pat := patternTable[g.weighted("handshake_pattern", []int{3, 3, 3, 1, 1, 1})]

	gm := &ProtocolGenome{
		Schema:           GeneratorSchema,
		Generation:       generation,
		SeedMaterial:     hex.EncodeToString(seedSum[:]),
		HandshakePattern: pat.name,
	}

	for i, step := range pat.steps {
		gm.Handshake = append(gm.Handshake, g.message(i, step.direction, step.purpose, step.hasKey, cipher))
	}

	gm.AppRecord = g.message(len(pat.steps), DirBoth, "data", false, cipher)

	// Fingerprint the complete design. The fingerprint field itself is
	// empty at marshal time and is therefore not part of the digest.
	sum := sha256.Sum256([]byte(mustJSON(gm)))
	gm.ProtocolFingerprint = hex.EncodeToString(sum[:])
	gm.EstimatedEntropyBits = math.Round(g.entropy*10) / 10
	return gm, nil
}

func (g *generator) message(index int, direction, purpose string, hasKey bool, cipher string) MessageSpec {
	isAppRecord := purpose == "data"

	// ---- plaintext field pool ----
	var plain []FieldSpec
	if g.weighted("version_present", []int{9, 1}) == 0 {
		plain = append(plain, g.versionField())
	}
	if g.weighted("type_present", []int{9, 1}) == 0 {
		plain = append(plain, g.typeField())
	}
	if g.weighted("nonce_present", []int{3, 1}) == 0 {
		plain = append(plain, g.nonceField())
	}
	if g.weighted("reserved_present", []int{3, 7}) == 0 {
		plain = append(plain, g.reservedField())
	}
	plain = g.permuteFields(plain)
	plainWithoutLength := 0
	for _, f := range plain {
		n, _ := fieldFixedSize(f)
		plainWithoutLength += n
	}

	// ---- payload decision ----
	hasPayload := false
	switch purpose {
	case "hello":
		hasPayload = g.weighted("payload_hello", []int{10, 90}) == 0
	case "hello+key":
		hasPayload = g.weighted("payload_hello_key", []int{35, 65}) == 0
	case "key":
		hasPayload = g.weighted("payload_key", []int{10, 90}) == 0
	case "ack":
		hasPayload = g.weighted("payload_ack", []int{40, 60}) == 0
	case "data":
		hasPayload = true
	}

	// Padding policy is sampled before the pad_length field so the field
	// width can be chosen to actually fit the maximum padding size.
	padding := g.paddingPolicy()

	// ---- encrypted field pool ----
	var enc []FieldSpec
	if hasKey {
		enc = append(enc, g.keyField())
	}
	if direction == DirServer && g.weighted("certificate_present", []int{55, 45}) == 0 {
		enc = append(enc, g.certField())
	}
	if g.weighted("extra_present", []int{45, 55}) == 0 {
		enc = append(enc, g.extraField())
	}
	if padding.Mode != PaddingNone {
		enc = append(enc, g.padLenField(padding.Max))
	}
	enc = g.permuteFields(enc)

	// ---- length field ----
	//
	// The width must be able to express the largest possible frame for
	// this layout. Handshake layouts are bounded by their generated
	// fields, padding and early-data allowance. Application records are
	// intentionally unbounded, so they never use a u8 length.
	maxCipher := aeadTagSize
	for _, f := range enc {
		maxCipher += maxEncodedFieldSize(f)
	}
	maxCipher += padding.Max
	if hasPayload && !isAppRecord {
		maxCipher += maxHandshakeEarlyData
	}
	minBytes := plainWithoutLength + 4 + maxCipher
	length := g.lengthField(minBytes, isAppRecord)
	lengthPos := g.choose("length_position", len(plain)+1)
	plain = append(plain, FieldSpec{})
	copy(plain[lengthPos+1:], plain[lengthPos:])
	plain[lengthPos] = length

	return MessageSpec{
		Index:            index,
		Name:             fmt.Sprintf("M%d_%s", index, direction),
		Direction:        direction,
		Purpose:          purpose,
		PlainFields:      plain,
		EncryptedFields:  enc,
		LengthFieldIndex: lengthPos,
		LengthAlone:      g.weighted("length_alone", []int{20, 80}) == 0,
		HasPayload:       hasPayload,
		Padding:          padding,
		Cipher:           cipher,
	}
}

func (g *generator) permuteFields(in []FieldSpec) []FieldSpec {
	out := make([]FieldSpec, len(in))
	for i, idx := range g.r.Perm(len(in)) {
		out[i] = in[idx]
	}
	return out
}

func (g *generator) versionField() FieldSpec {
	size := g.weighted("version_size", []int{3, 1}) + 1 // 1 or 2 bytes
	var b []byte
	if size == 1 {
		b = []byte{byte(g.choose("version_value1", 5) + 1)}
	} else {
		major := byte(g.choose("version_major", 4))
		minor := byte(g.choose("version_minor", 16))
		b = []byte{major, minor}
	}
	return FieldSpec{
		Kind:        FieldVersion,
		Placement:   PlacePlain,
		Encoding:    EncFixedBytes,
		Size:        size,
		ValueHex:    hex.EncodeToString(b),
		ValueSource: ValueConstant,
	}
}

func (g *generator) typeField() FieldSpec {
	size := g.weighted("type_size", []int{3, 1}) + 1
	raw := g.r.Bytes(size)
	raw[0] = byte(g.choose("type_lo_nibble", 15) + 1)
	if size == 2 {
		raw[1] = byte(g.choose("type_hi_byte", 255))
	}
	return FieldSpec{
		Kind:        FieldType,
		Placement:   PlacePlain,
		Encoding:    EncFixedBytes,
		Size:        size,
		ValueHex:    hex.EncodeToString(raw),
		ValueSource: ValueConstant,
	}
}

func (g *generator) nonceField() FieldSpec {
	sizes := []int{4, 8, 12, 16, 32}
	weights := []int{2, 3, 4, 3, 1}
	size := sizes[g.weighted("nonce_size", weights)]
	return FieldSpec{
		Kind:        FieldNonce,
		Placement:   PlacePlain,
		Encoding:    EncFixedBytes,
		Size:        size,
		ValueSource: ValueRandom,
	}
}

func (g *generator) reservedField() FieldSpec {
	sizes := []int{1, 2, 4, 8, 16}
	weights := []int{3, 2, 2, 1, 1}
	size := sizes[g.weighted("reserved_size", weights)]
	source := ValueZero
	if g.weighted("reserved_value", []int{7, 3}) == 1 {
		source = ValueRandom
	}
	valueHex := ""
	if source == ValueZero {
		valueHex = hex.EncodeToString(make([]byte, size))
	}
	return FieldSpec{
		Kind:        FieldReserved,
		Placement:   PlacePlain,
		Encoding:    EncFixedBytes,
		Size:        size,
		ValueHex:    valueHex,
		ValueSource: source,
	}
}

func (g *generator) lengthField(minBytes int, isAppRecord bool) FieldSpec {
	type opt struct {
		enc string
		w   int
	}
	var opts []opt
	if isAppRecord {
		opts = []opt{{EncU16, 4}, {EncU24, 3}, {EncU32, 2}}
	} else {
		all := []opt{{EncU8, 1}, {EncU16, 3}, {EncU24, 2}, {EncU32, 2}}
		for _, o := range all {
			if maxIntValue(o.enc) >= int64(minBytes) {
				opts = append(opts, o)
			}
		}
		if len(opts) == 0 {
			opts = []opt{{EncU32, 1}}
		}
	}
	weights := make([]int, len(opts))
	for i := range opts {
		weights[i] = opts[i].w
	}
	enc := opts[g.weighted("length_width", weights)].enc

	subject := "ciphertext"
	if g.weighted("length_subject", []int{4, 1}) == 1 {
		subject = "record"
	}
	endian := "big"
	if g.weighted("length_endian", []int{3, 1}) == 1 {
		endian = "little"
	}
	return FieldSpec{
		Kind:        FieldLength,
		Placement:   PlacePlain,
		Encoding:    enc,
		Endian:      endian,
		Subject:     subject,
		ValueSource: ValueConstant, // value is computed at encode time
	}
}

func (g *generator) keyField() FieldSpec {
	enc := EncRaw32
	if g.weighted("key_encoding", []int{4, 1}) == 1 {
		enc = EncX963
	}
	size := 32
	if enc == EncX963 {
		size = 33
	}
	return FieldSpec{
		Kind:        FieldKey,
		Placement:   PlaceEncrypted,
		Encoding:    enc,
		Size:        size,
		ValueSource: ValueInjected,
	}
}

func (g *generator) certField() FieldSpec {
	if g.weighted("cert_encoding", []int{3, 1}) == 0 {
		size := g.rangeChoice("cert_size", 64, 449) // 64..512
		return FieldSpec{
			Kind:        FieldCert,
			Placement:   PlaceEncrypted,
			Encoding:    EncFixedBytes,
			Size:        size,
			ValueSource: ValueRandom,
		}
	}
	return FieldSpec{
		Kind:        FieldCert,
		Placement:   PlaceEncrypted,
		Encoding:    EncPrefixedU16,
		MinSize:     64,
		MaxSize:     512,
		ValueSource: ValueRandom,
	}
}

func (g *generator) extraField() FieldSpec {
	enc := g.weighted("extra_encoding", []int{4, 3, 1})
	switch enc {
	case 0:
		size := g.rangeChoice("extra_fixed_size", 4, 61) // 4..64
		return FieldSpec{
			Kind:        FieldExtra,
			Placement:   PlaceEncrypted,
			Encoding:    EncFixedBytes,
			Size:        size,
			ValueSource: ValueRandom,
		}
	case 1:
		return FieldSpec{
			Kind:        FieldExtra,
			Placement:   PlaceEncrypted,
			Encoding:    EncPrefixedU8,
			MinSize:     1,
			MaxSize:     64,
			ValueSource: ValueRandom,
		}
	default:
		return FieldSpec{
			Kind:        FieldExtra,
			Placement:   PlaceEncrypted,
			Encoding:    EncPrefixedU16,
			MinSize:     1,
			MaxSize:     512,
			ValueSource: ValueRandom,
		}
	}
}

func (g *generator) padLenField(maxPad int) FieldSpec {
	enc := EncU8
	if maxPad > 255 {
		enc = EncU16
	} else if g.weighted("padlen_width", []int{3, 1}) == 1 {
		enc = EncU16
	}
	endian := "big"
	if g.weighted("padlen_endian", []int{3, 1}) == 1 {
		endian = "little"
	}
	return FieldSpec{
		Kind:        FieldPadLen,
		Placement:   PlaceEncrypted,
		Encoding:    enc,
		Endian:      endian,
		ValueSource: ValueRandom,
	}
}

func (g *generator) paddingPolicy() PaddingPolicy {
	switch g.weighted("padding_mode", []int{1, 5, 2}) {
	case 0:
		return PaddingPolicy{Mode: PaddingNone}
	case 1:
		min := g.rangeChoice("padding_min", 0, 33) // 0..32
		max := min + g.rangeChoice("padding_span", 1, 257)
		return PaddingPolicy{Mode: PaddingUniform, Min: min, Max: max}
	default:
		min := 16 * g.choose("burst_min", 2)
		max := min + g.rangeChoice("burst_span", 64, 449)
		return PaddingPolicy{Mode: PaddingBurst, Min: min, Max: max}
	}
}

// choose logs log2(n) and samples uniformly.
func (g *generator) choose(label string, n int) int {
	if n <= 1 {
		return 0
	}
	g.entropy += math.Log2(float64(n))
	return g.r.Intn(n)
}

// rangeChoice samples uniformly from [lo, hi).
func (g *generator) rangeChoice(label string, lo, hi int) int {
	if hi <= lo {
		return lo
	}
	g.entropy += math.Log2(float64(hi - lo))
	return lo + g.r.Intn(hi-lo)
}

// weighted samples an index and adds the exact entropy of the distribution.
func (g *generator) weighted(label string, weights []int) int {
	total := 0
	for _, w := range weights {
		total += w
	}
	h := 0.0
	for _, w := range weights {
		p := float64(w) / float64(total)
		h -= p * math.Log2(p)
	}
	g.entropy += h
	return g.r.PickWeighted(weights)
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

const (
	aeadTagSize           = 16 // AES-GCM tag in the reference codec
	maxHandshakeEarlyData = 1400
)

func fieldFixedSize(f FieldSpec) (int, bool) {
	switch f.Encoding {
	case EncU8:
		return 1, true
	case EncU16:
		return 2, true
	case EncU24:
		return 3, true
	case EncU32:
		return 4, true
	case EncFixedBytes, EncRaw32, EncX963:
		if f.Size > 0 {
			return f.Size, true
		}
	}
	return 0, false
}

func maxEncodedFieldSize(f FieldSpec) int {
	switch f.Encoding {
	case EncPrefixedU8:
		return 1 + f.MaxSize
	case EncPrefixedU16:
		return 2 + f.MaxSize
	}
	if n, ok := fieldFixedSize(f); ok {
		return n
	}
	return 0
}

func maxIntValue(enc string) int64 {
	switch enc {
	case EncU8:
		return 1<<8 - 1
	case EncU16:
		return 1<<16 - 1
	case EncU24:
		return 1<<24 - 1
	case EncU32:
		return 1<<32 - 1
	}
	return 0
}
