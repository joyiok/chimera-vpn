package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"chimera/internal/compiler"
	"chimera/internal/tunnel"
)

const httpPairTimeout = 10 * time.Second

type httpSession struct {
	mu        sync.Mutex
	up        io.ReadCloser
	down      *httpDownStream
	started   bool
	startedCh chan struct{}
	done      chan struct{}
}

type httpDownStream struct {
	w       http.ResponseWriter
	flusher http.Flusher
	mu      sync.Mutex
}

func (d *httpDownStream) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n, err := d.w.Write(p)
	if err == nil && d.flusher != nil {
		d.flusher.Flush()
	}
	return n, err
}

func (s *Server) startHTTPListeners(ctx context.Context, addrs []string, cps []*compiler.CompiledProtocol, psk []byte) error {
	path := websocketPath(s.cfg.SeedHex, s.cfg.Generation)
	var tlsCfg *tls.Config
	if s.cfg.Transport == "https" {
		var err error
		tlsCfg, err = serverTLSConfig(s.cfg)
		if err != nil {
			return err
		}
	}
	serveLns := make([]net.Listener, 0, len(addrs))
	for _, addr := range addrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, l := range s.httpLns {
				_ = l.Close()
			}
			s.cancel()
			return fmt.Errorf("listen http %s: %w", addr, err)
		}
		serveLn := net.Listener(ln)
		if tlsCfg != nil {
			serveLn = tls.NewListener(serveLn, tlsCfg)
		}
		serveLns = append(serveLns, serveLn)
		s.httpLns = append(s.httpLns, ln)
		s.httpSrvs = append(s.httpSrvs, &http.Server{
			Handler:           s.httpHandler(path, cps, psk),
			ReadHeaderTimeout: 5 * time.Second,
		})
	}
	var wg sync.WaitGroup
	for i := range s.httpSrvs {
		wg.Add(1)
		go func(srv *http.Server, serveLn net.Listener) {
			defer wg.Done()
			_ = srv.Serve(serveLn)
		}(s.httpSrvs[i], serveLns[i])
	}
	s.tcpAcceptCh = make(chan streamAccept, max(16, len(addrs)*16))
	s.tcpSessions = make(map[*tunnel.PacketTunnel]struct{})
	s.httpPairs = make(map[string]*httpSession)
	s.httpDone = make(chan struct{})
	go func() {
		wg.Wait()
		close(s.httpDone)
	}()
	go func() {
		<-ctx.Done()
		for _, srv := range s.httpSrvs {
			_ = srv.Close()
		}
	}()
	return nil
}

func (s *Server) httpHandler(path string, cps []*compiler.CompiledProtocol, psk []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		sid := r.URL.Query().Get("sid")
		if len(sid) != 24 {
			http.NotFound(w, r)
			return
		}
		switch r.URL.Query().Get("dir") {
		case "up":
			s.handleHTTPUpload(w, r, sid, cps, psk)
		case "down":
			s.handleHTTPDownload(w, r, sid, cps, psk)
		default:
			http.NotFound(w, r)
		}
	})
}

func (s *Server) sessionForHTTP(sid string) *httpSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.httpPairs[sid]
	if p == nil {
		p = &httpSession{startedCh: make(chan struct{}), done: make(chan struct{})}
		s.httpPairs[sid] = p
	}
	return p
}

func (s *Server) dropHTTPSession(sid string) {
	s.mu.Lock()
	delete(s.httpPairs, sid)
	s.mu.Unlock()
}

func (s *Server) maybeStartHTTPSession(sid string, p *httpSession, ctx context.Context, cps []*compiler.CompiledProtocol, psk []byte) bool {
	p.mu.Lock()
	if p.started || p.up == nil || p.down == nil {
		p.mu.Unlock()
		return p.started
	}
	p.started = true
	up := p.up
	down := p.down
	close(p.startedCh)
	p.mu.Unlock()

	local := httpNamedAddr{value: "http-server"}
	conn := tunnel.NewServerHTTPConn(up, down, local, httpNamedAddr{value: "http-remote"})
	go func() {
		s.handleStreamConn(ctx, conn, cps, psk)
		<-conn.Done()
		// Release the upload/download handler goroutines: they park on
		// p.done once the legs are paired and nothing else closes it.
		close(p.done)
		s.dropHTTPSession(sid)
	}()
	return true
}

func (s *Server) handleHTTPUpload(w http.ResponseWriter, r *http.Request, sid string, cps []*compiler.CompiledProtocol, psk []byte) {
	p := s.sessionForHTTP(sid)
	p.mu.Lock()
	if p.up != nil {
		p.mu.Unlock()
		http.Error(w, "duplicate upload", http.StatusConflict)
		return
	}
	p.up = r.Body
	p.mu.Unlock()

	started := s.maybeStartHTTPSession(sid, p, r.Context(), cps, psk)
	if !started {
		p.mu.Lock()
		startedCh := p.startedCh
		p.mu.Unlock()
		select {
		case <-startedCh:
		case <-time.After(httpPairTimeout):
			s.dropHTTPSession(sid)
			http.Error(w, "pairing timeout", http.StatusGatewayTimeout)
			return
		case <-r.Context().Done():
			s.dropHTTPSession(sid)
			return
		}
	}
	// Deliberately do NOT answer 200 here: net/http clients abort a
	// streaming chunked request body as soon as any response arrives,
	// which would close the upload leg mid-session. Hold the response
	// open until the session ends, then let the handler return.
	select {
	case <-p.done:
	case <-r.Context().Done():
	}
}

func (s *Server) handleHTTPDownload(w http.ResponseWriter, r *http.Request, sid string, cps []*compiler.CompiledProtocol, psk []byte) {
	flusher, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if flusher != nil {
		flusher.Flush()
	}
	down := &httpDownStream{w: w, flusher: flusher}
	p := s.sessionForHTTP(sid)
	p.mu.Lock()
	if p.down != nil {
		p.mu.Unlock()
		return
	}
	p.down = down
	p.mu.Unlock()

	if s.maybeStartHTTPSession(sid, p, r.Context(), cps, psk) {
		select {
		case <-p.done:
		case <-r.Context().Done():
		}
		return
	}
	select {
	case <-p.done:
	case <-time.After(httpPairTimeout):
		s.dropHTTPSession(sid)
	}
}

type httpNamedAddr struct{ value string }

func (a httpNamedAddr) Network() string { return "tcp" }
func (a httpNamedAddr) String() string  { return a.value }

func namedAddrFor(_, _ string) net.Addr              { return httpNamedAddr{value: "http"} }
func hostFromRequest(w http.ResponseWriter) string   { return "" }
func remoteFromRequest(w http.ResponseWriter) string { return "" }
