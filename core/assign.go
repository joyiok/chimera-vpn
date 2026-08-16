package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
)

// addressPool hands out unique IPv4 addresses from a client CIDR.
//
// Layout assumption: host offset 1 is the server's own TUN gateway
// (e.g. 10.99.0.1/24), so allocation starts at host offset 2 and stops
// before the broadcast address.
type addressPool struct {
	mu       sync.Mutex
	ip       uint32
	prefix   int
	count    int // usable addresses (gateway and broadcast excluded)
	bitset   []uint64
	nextHint int
}

func newAddressPool(cidr string) (*addressPool, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse client_cidr: %w", err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, errors.New("client_cidr must be IPv4")
	}
	ones, bits := ipnet.Mask.Size()
	if ones > bits-2 {
		return nil, fmt.Errorf("client_cidr /%d is too small for clients", ones)
	}
	hostBits := bits - ones
	count := (1 << hostBits) - 3 // network, gateway, broadcast
	if count <= 0 {
		return nil, errors.New("client_cidr has no usable addresses")
	}
	return &addressPool{
		ip:     binary.BigEndian.Uint32(ip4) & binary.BigEndian.Uint32(ipnet.Mask),
		prefix: ones,
		count:  count,
		bitset: make([]uint64, (count+63)/64),
	}, nil
}

// Allocate returns the next free client address.
func (p *addressPool) Allocate() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := 0; i < p.count; i++ {
		idx := (p.nextHint + i) % p.count
		if p.bitset[idx/64]&(1<<(idx%64)) == 0 {
			p.bitset[idx/64] |= 1 << (idx % 64)
			p.nextHint = (idx + 1) % p.count
			return p.ipString(idx), nil
		}
	}
	return "", errors.New("client address pool exhausted")
}

// Release returns an allocated address to the pool.
func (p *addressPool) Release(ip string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	idx, ok := p.index(ip)
	if !ok {
		return
	}
	p.bitset[idx/64] &^= 1 << (idx % 64)
	if idx < p.nextHint {
		p.nextHint = idx
	}
}

func (p *addressPool) ipString(idx int) string {
	v := p.ip + uint32(idx+2)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

func (p *addressPool) index(ip string) (int, bool) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0, false
	}
	ip4 := parsed.To4()
	if ip4 == nil {
		return 0, false
	}
	v := binary.BigEndian.Uint32(ip4)
	if v < p.ip+2 || v >= p.ip+uint32(p.count+2) {
		return 0, false
	}
	return int(v - p.ip - 2), true
}
