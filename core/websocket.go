package core

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// websocketPath derives the WebSocket endpoint path from seed+generation.
// A random-looking path makes the upgrade endpoint unguessable to scanners;
// all other paths are answered with a generic decoy page by the server.
func websocketPath(seedHex string, generation uint64) string {
	seed, err := parseHex32(seedHex, "seed")
	if err != nil {
		return "/"
	}
	h := sha256.New()
	h.Write([]byte("chimera-pgc/0/websocket-path\x00"))
	h.Write(seed)
	var gen [8]byte
	binary.BigEndian.PutUint64(gen[:], generation)
	h.Write(gen[:])
	sum := h.Sum(nil)
	return "/" + hex.EncodeToString(sum[:8])
}
