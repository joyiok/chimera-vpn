package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "chimera-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func TestWSSRoundTrip(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t)
	srvCfg := testConfig("127.0.0.1:0", "wss")
	srvCfg.TLSCertFile = certFile
	srvCfg.TLSKeyFile = keyFile
	srv, err := NewServer(srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	cliCfg := testConfig(srv.LocalAddr().String(), "wss")
	cliCfg.TLSInsecureSkipVerify = true
	cli, err := NewClient(cliCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Start(); err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := srv.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SendPacket([]byte("wss-echo")); err != nil {
		t.Fatal(err)
	}
	got, err := cli.ReceivePacket()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "wss-echo" {
		t.Fatalf("got %q", got)
	}
}

func TestWSSRejectsInsecureByDefault(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t)
	srvCfg := testConfig("127.0.0.1:0", "wss")
	srvCfg.TLSCertFile = certFile
	srvCfg.TLSKeyFile = keyFile
	srv, err := NewServer(srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	cli, err := NewClient(testConfig(srv.LocalAddr().String(), "wss"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Start(); err == nil {
		cli.Close()
		t.Fatal("self-signed wss must be rejected when TLSInsecureSkipVerify is false")
	}
}
