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
	// byHost groups live conns by source host IP (no port) so roaming
	// clients' stale sessions can be reaped eagerly.
	byHost map[string]map[*core.Conn]struct{}
}

func newClientRoute() *clientRoute {
	return &clientRoute{
		byIP:   map[string]*core.Conn{},
		byConn: map[*core.Conn]string{},
		byHost: map[string]map[*core.Conn]struct{}{},
	}
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
		if h := hostIP(other.RemoteAddr()); h != "" {
			delete(r.byHost[h], other)
		}
	}
	r.byConn[conn] = ip
	r.byIP[ip] = conn
	if host := hostIP(conn.RemoteAddr()); host != "" {
		if r.byHost == nil {
			r.byHost = map[string]map[*core.Conn]struct{}{}
		}
		if r.byHost[host] == nil {
			r.byHost[host] = map[*core.Conn]struct{}{}
		}
		r.byHost[host][conn] = struct{}{}
	}
	return displaced
}

// reapRoamed closes sessions from the same host IP (different source port)
// that have been inbound-silent for at least maxIdle. When a client roams
// (NAT rebinding, network switch), the old endpoint's session otherwise
// lingers until the idle reap, holding a pool address and a MaxSessions
// slot; a flapping client can accumulate zombies against both. Sessions
// that are still active (idle < maxIdle) are left alone, so two legit
// clients behind one NAT are safe.
func (r *clientRoute) reapRoamed(host string, keep *core.Conn, maxIdle time.Duration) []*core.Conn {
	r.mu.Lock()
	defer r.mu.Unlock()
	var stale []*core.Conn
	for conn := range r.byHost[host] {
		if conn == nil || conn == keep {
			continue
		}
		if conn.IdleFor() >= maxIdle {
			stale = append(stale, conn)
		}
	}
	for _, conn := range stale {
		delete(r.byHost[host], conn)
		if ip, ok := r.byConn[conn]; ok {
			delete(r.byConn, conn)
			delete(r.byIP, ip)
		}
	}
	return stale
}

func hostIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
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
	if h := hostIP(conn.RemoteAddr()); h != "" {
		delete(r.byHost[h], conn)
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
