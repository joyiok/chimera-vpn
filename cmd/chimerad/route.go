package main

import (
	"net"
	"sync"

	"chimera/core"
)

// clientRoute maps a client's tunnel source IP to its server-side Conn.
type clientRoute struct {
	mu     sync.RWMutex
	byIP   map[string]*core.Conn
	byConn map[*core.Conn]string
}

func newClientRoute() *clientRoute {
	return &clientRoute{byIP: map[string]*core.Conn{}, byConn: map[*core.Conn]string{}}
}

func (r *clientRoute) register(conn *core.Conn, ip string) *core.Conn {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.byConn[conn]; ok && old != "" {
		delete(r.byIP, old)
	}
	var displaced *core.Conn
	if other, ok := r.byIP[ip]; ok && other != conn {
		displaced = other
		delete(r.byConn, other)
	}
	r.byConn[conn] = ip
	r.byIP[ip] = conn
	return displaced
}

func (r *clientRoute) lookup(ip string) *core.Conn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byIP[ip]
}

func (r *clientRoute) remove(conn *core.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ip := r.byConn[conn]
	delete(r.byConn, conn)
	if ip != "" {
		delete(r.byIP, ip)
	}
}

// packetIP returns the source or destination IP of a raw IPv4/IPv6 packet.
func packetIP(packet []byte, dst bool) string {
	if len(packet) == 0 {
		return ""
	}
	offset := 12
	if dst {
		offset = 16
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) >= 20 {
			return net.IP(packet[offset : offset+4]).String()
		}
	case 6:
		if len(packet) >= 40 {
			if dst {
				return net.IP(packet[24:40]).String()
			}
			return net.IP(packet[8:24]).String()
		}
	}
	return ""
}
