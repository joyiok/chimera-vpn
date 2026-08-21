package core

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
)

// clientTLSConfig builds the wss client TLS configuration. Production
// profiles keep TLSCAFile empty (system roots) and never set
// TLSInsecureSkipVerify.
func clientTLSConfig(cfg Config) (*tls.Config, error) {
	host, _, err := net.SplitHostPort(cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("parse server address %q: %w", cfg.ServerAddr, err)
	}
	tc := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         host,
		InsecureSkipVerify: cfg.TLSInsecureSkipVerify, // #nosec G402 -- opt-in development flag
	}
	if cfg.TLSCAFile != "" {
		pem, err := os.ReadFile(cfg.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("read tls_ca_file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tls_ca_file %s contains no certificates", cfg.TLSCAFile)
		}
		tc.RootCAs = pool
	}
	return tc, nil
}

// serverTLSConfig loads the wss server certificate. Both files are
// mandatory when transport=wss.
func serverTLSConfig(cfg Config) (*tls.Config, error) {
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		return nil, fmt.Errorf("transport wss requires tls_cert_file and tls_key_file")
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load wss certificate: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}, nil
}
