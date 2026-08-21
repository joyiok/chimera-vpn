package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

type namedAddr struct {
	network string
	value   string
}

func (a namedAddr) Network() string { return a.network }
func (a namedAddr) String() string  { return a.value }

// httpClientConn merges a GET response body (download) with a POST request
// body (upload) into one net.Conn. Read deadlines are enforced with a timer
// and close the whole session on expiry, so a dead peer cannot pin a
// goroutine forever.
type httpClientConn struct {
	reader io.ReadCloser
	writer *io.PipeWriter
	closer []io.Closer
	cancel context.CancelFunc

	rmu sync.Mutex
	wmu sync.Mutex
	rdl time.Time
	wdl time.Time

	closeOnce sync.Once
	local     net.Addr
	remote    net.Addr
}

func (c *httpClientConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	deadline := c.rdl
	c.rmu.Unlock()
	if deadline.IsZero() {
		return c.reader.Read(p)
	}
	type result struct {
		n   int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		n, err := c.reader.Read(p)
		ch <- result{n, err}
	}()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.n, r.err
	case <-timer.C:
		_ = c.Close()
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *httpClientConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	deadline := c.wdl
	c.wmu.Unlock()
	if deadline.IsZero() {
		return c.writer.Write(p)
	}
	type result struct {
		n   int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		n, err := c.writer.Write(p)
		ch <- result{n, err}
	}()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.n, r.err
	case <-timer.C:
		_ = c.Close()
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *httpClientConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.cancel()
		for _, closer := range c.closer {
			_ = closer.Close()
		}
		err = c.reader.Close()
	})
	return err
}

func (c *httpClientConn) LocalAddr() net.Addr  { return c.local }
func (c *httpClientConn) RemoteAddr() net.Addr { return c.remote }
func (c *httpClientConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	c.SetWriteDeadline(t)
	return nil
}
func (c *httpClientConn) SetReadDeadline(t time.Time) error {
	c.rmu.Lock()
	c.rdl = t
	c.rmu.Unlock()
	return nil
}
func (c *httpClientConn) SetWriteDeadline(t time.Time) error {
	c.wmu.Lock()
	c.wdl = t
	c.wmu.Unlock()
	return nil
}

// directProxy disables environment proxy handling: CHIMERA HTTP transport
// must reach its own server directly, never through a local proxy.
func directProxy(*http.Request) (*url.URL, error) { return nil, nil }

// DialHTTPStream opens the two-leg HTTP session:
//
// POST <base>?sid=...&dir=up   (upload, chunked request body)
// GET  <base>?sid=...&dir=down (download, long-lived response body)
//
// base must include scheme (http/https), host, and the seed-derived path.
// tlsConfig applies to https requests.
func DialHTTPStream(ctx context.Context, base string, tlsConfig *tls.Config) (net.Conn, net.Addr, error) {
	pr, pw := io.Pipe()
	sidBytes := make([]byte, 12)
	if _, err := rand.Read(sidBytes); err != nil {
		return nil, nil, err
	}
	sid := hex.EncodeToString(sidBytes)
	baseURL, err := url.Parse(base)
	if err != nil {
		return nil, nil, err
	}
	q := baseURL.Query()
	q.Set("sid", sid)
	q.Set("dir", "up")
	upURL := *baseURL
	upURL.RawQuery = q.Encode()
	q.Set("dir", "down")
	downURL := *baseURL
	downURL.RawQuery = q.Encode()

	client := &http.Client{Transport: &http.Transport{Proxy: directProxy, TLSClientConfig: tlsConfig}}
	ctx, cancel := context.WithCancel(ctx)
	postDone := make(chan error, 1)
	go func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, upURL.String(), pr)
		if err != nil {
			postDone <- err
			return
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err := client.Do(req)
		if err != nil {
			postDone <- err
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			postDone <- errors.New("http upload: " + resp.Status)
			return
		}
		postDone <- nil
		_, _ = io.Copy(io.Discard, resp.Body) // server keeps the POST response open
	}()

	downResp, err := client.Get(downURL.String())
	if err != nil {
		cancel()
		_ = pw.Close()
		return nil, nil, err
	}
	if downResp.StatusCode != http.StatusOK {
		cancel()
		_ = pw.Close()
		_ = downResp.Body.Close()
		return nil, nil, errors.New(downResp.Status)
	}
	// net/http only delivers the POST response once the request body has
	// been fully written, and this body intentionally stays open for the
	// whole session — waiting on postDone here would deadlock. The GET 200
	// above already proves the server accepted the session path; watch
	// postDone in the background and tear the conn down if the upload leg
	// fails (connection reset, refused, context canceled, ...).
	go func() {
		select {
		case err := <-postDone:
			if err != nil {
				cancel()
				_ = pw.Close()
			}
		case <-ctx.Done():
		}
	}()

	host := baseURL.Host
	conn := &httpClientConn{
		reader: downResp.Body,
		writer: pw,
		cancel: cancel,
		local:  namedAddr{network: "tcp", value: "http-client"},
		remote: namedAddr{network: "tcp", value: host},
	}
	return conn, conn.RemoteAddr(), nil
}

// ServerHTTPConn adapts one paired upload body + download writer to net.Conn.
// Close is idempotent and always releases both HTTP legs.
type ServerHTTPConn struct {
	reader io.ReadCloser
	writer io.Writer

	rmu sync.Mutex
	rdl time.Time

	closeOnce sync.Once
	done      chan struct{}
	local     net.Addr
	remote    net.Addr
}

func NewServerHTTPConn(reader io.ReadCloser, writer io.Writer, local, remote net.Addr) *ServerHTTPConn {
	return &ServerHTTPConn{
		reader: reader,
		writer: writer,
		done:   make(chan struct{}),
		local:  local,
		remote: remote,
	}
}

func (c *ServerHTTPConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	deadline := c.rdl
	c.rmu.Unlock()

	type result struct {
		n   int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		n, err := c.reader.Read(p)
		ch <- result{n, err}
	}()

	var timerC <-chan time.Time
	if !deadline.IsZero() {
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		timerC = timer.C
	}
	select {
	case r := <-ch:
		return r.n, r.err
	case <-c.done:
		// Close is finishing in the background; the in-flight read above
		// unblocks once the request body is released. The session is over
		// either way.
		return 0, io.ErrClosedPipe
	case <-timerC:
		go func() { _ = c.reader.Close() }()
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *ServerHTTPConn) Write(p []byte) (int, error) {
	return c.writer.Write(p)
}

func (c *ServerHTTPConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		// net/http request bodies hold their mutex across the blocking
		// network read, so reader.Close deadlocks if a concurrent Read is
		// parked on the socket. Close it in the background; the read
		// unblocks once the client tears down the POST leg.
		go func() { _ = c.reader.Close() }()
	})
	return nil
}

func (c *ServerHTTPConn) LocalAddr() net.Addr  { return c.local }
func (c *ServerHTTPConn) RemoteAddr() net.Addr { return c.remote }
func (c *ServerHTTPConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return nil
}
func (c *ServerHTTPConn) SetReadDeadline(t time.Time) error {
	c.rmu.Lock()
	c.rdl = t
	c.rmu.Unlock()
	return nil
}
func (c *ServerHTTPConn) SetWriteDeadline(t time.Time) error { return nil }

// Done is closed when either side closes the session.
func (c *ServerHTTPConn) Done() <-chan struct{} { return c.done }
