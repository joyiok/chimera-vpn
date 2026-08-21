package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// wsReadBuffer bounds a single binary WebSocket message. CHIMERA stream
// frames are at most 65535 bytes, so this is comfortably above them.
const wsReadBuffer = 128 * 1024

// websocketConn adapts one WebSocket connection to net.Conn. Each binary
// message carries one or more CHIMERA stream frames; text messages from
// browsers are ignored, which keeps the endpoint tolerant of casual probes.
type websocketConn struct {
	ws *websocket.Conn

	rmu    sync.Mutex
	reader io.Reader
	wmu    sync.Mutex
}

func (c *websocketConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for {
		if c.reader == nil {
			messageType, r, err := c.ws.NextReader()
			if err != nil {
				return 0, err
			}
			if messageType != websocket.BinaryMessage {
				// Drain ignored text/control messages and continue.
				_, _ = io.Copy(io.Discard, r)
				continue
			}
			c.reader = r
		}
		n, err := c.reader.Read(p)
		if err != nil && errors.Is(err, io.EOF) {
			c.reader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (c *websocketConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := c.ws.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *websocketConn) Close() error                  { return c.ws.Close() }
func (c *websocketConn) LocalAddr() net.Addr           { return c.ws.LocalAddr() }
func (c *websocketConn) RemoteAddr() net.Addr          { return c.ws.RemoteAddr() }
func (c *websocketConn) SetDeadline(t time.Time) error { return c.ws.UnderlyingConn().SetDeadline(t) }
func (c *websocketConn) SetReadDeadline(t time.Time) error {
	return c.ws.UnderlyingConn().SetReadDeadline(t)
}
func (c *websocketConn) SetWriteDeadline(t time.Time) error {
	return c.ws.UnderlyingConn().SetWriteDeadline(t)
}

// DialWebSocketPacket dials ws://address/path and adapts the WebSocket
// connection into the same length-framed PacketConn used by TCP transport.
func DialWebSocketPacket(ctx context.Context, address, path string) (net.PacketConn, net.Addr, error) {
	return dialWebSocketPacket(ctx, "ws", address, path, nil)
}

// DialWebSocketPacketTLS dials wss://address/path with the supplied TLS
// configuration. A nil config uses crypto/tls defaults and system roots.
func DialWebSocketPacketTLS(ctx context.Context, address, path string, tlsConfig *tls.Config) (net.PacketConn, net.Addr, error) {
	return dialWebSocketPacket(ctx, "wss", address, path, tlsConfig)
}

func dialWebSocketPacket(ctx context.Context, scheme, address, path string, tlsConfig *tls.Config) (net.PacketConn, net.Addr, error) {
	u := url.URL{Scheme: scheme, Host: address, Path: path}
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		TLSClientConfig:  tlsConfig,
	}
	ws, _, err := dialer.DialContext(ctx, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	conn := &websocketConn{ws: ws}
	spc := newStreamPacketConn(conn)
	return spc, ws.RemoteAddr(), nil
}

// UpgradeWebSocket upgrades an inbound HTTP request to a WebSocket and
// returns it as a net.Conn. The caller owns the HTTP server and decoy
// pages; this package only performs the upgrade.
func UpgradeWebSocket(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	upgrader := websocket.Upgrader{
		HandshakeTimeout: 4 * time.Second,
		ReadBufferSize:   wsReadBuffer,
		WriteBufferSize:  wsReadBuffer,
		CheckOrigin: func(*http.Request) bool {
			return true // CHIMERA clients are not browser-origin constrained
		},
	}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, err
	}
	return &websocketConn{ws: ws}, nil
}
