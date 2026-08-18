// Package invite encodes and parses Chimera share URLs so a client can be
// configured without typing seed/PSK by hand.
//
// Canonical form:
//
//	chimera://v1/<base64url({"v":1,"a":"host:port","s":"<64 hex>","p":"<64 hex>","g":0,"n":"optional"})>
//
// Also accepted: chimera://connect?addr=&seed=&psk=&generation=&name=,
// a pasted client.json object, or the same URL buried in surrounding text.
// The URL is the secret; callers must not log it.
package invite

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

const schemePrefix = "chimera://v1/"

// Profile is one client endpoint. Hex fields are lowercase 64-char strings.
type Profile struct {
	Addr       string
	SeedHex    string
	PSKHex     string
	Generation uint64
	Name       string
}

type wire struct {
	V    int    `json:"v"`
	Addr string `json:"a"`
	Seed string `json:"s"`
	PSK  string `json:"p"`
	Gen  uint64 `json:"g"`
	Name string `json:"n,omitempty"`
}

// Format returns a chimera://v1/… URL. Name is optional.
func Format(p Profile) (string, error) {
	norm, err := normalize(p)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(wire{
		V:    1,
		Addr: norm.Addr,
		Seed: norm.SeedHex,
		PSK:  norm.PSKHex,
		Gen:  norm.Generation,
		Name: norm.Name,
	})
	if err != nil {
		return "", err
	}
	return schemePrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// Parse accepts an invite URL, query URL, or client.json text.
func Parse(text string) (Profile, error) {
	s := strings.TrimSpace(text)
	if s == "" {
		return Profile{}, fmt.Errorf("empty invite")
	}
	if extracted := extractURL(s); extracted != "" {
		s = extracted
	}
	switch {
	case strings.HasPrefix(s, "{"):
		return parseJSON(s)
	case strings.HasPrefix(s, "chimera://v1/"):
		return parseV1(strings.TrimPrefix(s, "chimera://v1/"))
	case strings.HasPrefix(s, "chimera://connect"):
		return parseConnect(s)
	default:
		return Profile{}, fmt.Errorf("not a chimera invite")
	}
}

func parseV1(payload string) (Profile, error) {
	payload = strings.TrimSpace(payload)
	payload = strings.TrimRight(payload, "/")
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		// Some messengers re-pad; try with padding.
		raw, err = base64.URLEncoding.DecodeString(payload)
		if err != nil {
			return Profile{}, fmt.Errorf("invite payload: %w", err)
		}
	}
	var w wire
	if err := json.Unmarshal(raw, &w); err != nil {
		return Profile{}, fmt.Errorf("invite json: %w", err)
	}
	if w.V != 0 && w.V != 1 {
		return Profile{}, fmt.Errorf("unsupported invite version %d", w.V)
	}
	return normalize(Profile{
		Addr:       w.Addr,
		SeedHex:    w.Seed,
		PSKHex:     w.PSK,
		Generation: w.Gen,
		Name:       w.Name,
	})
}

func parseConnect(rawURL string) (Profile, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return Profile{}, err
	}
	q := u.Query()
	gen := uint64(0)
	if g := first(q, "generation", "g"); g != "" {
		n, err := strconv.ParseUint(g, 10, 64)
		if err != nil {
			return Profile{}, fmt.Errorf("generation: %w", err)
		}
		gen = n
	}
	return normalize(Profile{
		Addr:       first(q, "addr", "server", "serverAddr"),
		SeedHex:    first(q, "seed", "seedHex"),
		PSKHex:     first(q, "psk", "pskHex"),
		Generation: gen,
		Name:       first(q, "name", "n"),
	})
}

func parseJSON(s string) (Profile, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return Profile{}, fmt.Errorf("json: %w", err)
	}
	gen := uint64(0)
	switch v := m["generation"].(type) {
	case float64:
		if v < 0 {
			return Profile{}, fmt.Errorf("generation must be >= 0")
		}
		gen = uint64(v)
	case string:
		if v != "" {
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return Profile{}, fmt.Errorf("generation: %w", err)
			}
			gen = n
		}
	}
	return normalize(Profile{
		Addr:       jsonString(m, "serverAddr", "a", "addr"),
		SeedHex:    jsonString(m, "seedHex", "s", "seed_hex"),
		PSKHex:     jsonString(m, "pskHex", "p", "psk_hex"),
		Generation: gen,
		Name:       jsonString(m, "name", "n"),
	})
}

func normalize(p Profile) (Profile, error) {
	p.Addr = strings.TrimSpace(p.Addr)
	p.Name = strings.TrimSpace(p.Name)
	seed, err := normHex("seed", p.SeedHex)
	if err != nil {
		return Profile{}, err
	}
	psk, err := normHex("psk", p.PSKHex)
	if err != nil {
		return Profile{}, err
	}
	if p.Addr == "" {
		return Profile{}, fmt.Errorf("server address is empty")
	}
	p.SeedHex = seed
	p.PSKHex = psk
	return p, nil
}

func normHex(label, s string) (string, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "0x")
	if len(s) != 64 {
		return "", fmt.Errorf("%s must be 64 hex characters", label)
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", fmt.Errorf("%s: %w", label, err)
	}
	return s, nil
}

func extractURL(s string) string {
	for _, prefix := range []string{"chimera://v1/", "chimera://connect"} {
		i := strings.Index(s, prefix)
		if i < 0 {
			continue
		}
		rest := s[i:]
		if cut := strings.IndexAny(rest, " \t\r\n<>\"'"); cut >= 0 {
			rest = rest[:cut]
		}
		return rest
	}
	return ""
}

func first(q url.Values, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(q.Get(k)); v != "" {
			return v
		}
	}
	return ""
}

func jsonString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		switch v := m[k].(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}
