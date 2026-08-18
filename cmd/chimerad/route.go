package main

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

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

func (r *clientRoute) snapshot() []sessionSnap {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]sessionSnap, 0, len(r.byConn))
	for conn, ip := range r.byConn {
		if conn == nil {
			continue
		}
		remote := ""
		if addr := conn.RemoteAddr(); addr != nil {
			remote = addr.String()
		}
		out = append(out, sessionSnap{
			IP:         ip,
			Remote:     remote,
			Idle:       conn.IdleFor(),
			Generation: conn.Generation(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IP != out[j].IP {
			return out[i].IP < out[j].IP
		}
		return out[i].Remote < out[j].Remote
	})
	return out
}

func formatSessionSnap(s sessionSnap) string {
	ip := s.IP
	if ip == "" {
		ip = "-"
	}
	remote := s.Remote
	if remote == "" {
		remote = "-"
	}
	return fmt.Sprintf("client %s tun=%s gen=%d idle=%s", remote, ip, s.Generation, s.Idle.Truncate(time.Second))
}

type sessionSnap struct {
	IP         string
	Remote     string
	Idle       time.Duration
	Generation uint64
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
