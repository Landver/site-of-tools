package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/dnstools"
)

func TestAuditTLSChainLocalServer(t *testing.T) {
	// Generate self-signed cert for mock server
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 128)
				_, _ = c.Read(buf)
			}(conn)
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	rep, err := dnstools.AuditTLSChain(context.Background(), "127.0.0.1", addr.Port)
	if err != nil {
		t.Fatalf("AuditTLSChain: %v", err)
	}

	if len(rep.Certificates) == 0 {
		t.Fatalf("expected at least 1 certificate, got 0")
	}
	if rep.Certificates[0].Subject != "localhost" {
		t.Errorf("subject = %q, want 'localhost'", rep.Certificates[0].Subject)
	}
}

func TestAuditTLSChainEmptyHost(t *testing.T) {
	_, err := dnstools.AuditTLSChain(context.Background(), "", 443)
	if err == nil {
		t.Errorf("expected error for empty host, got nil")
	}
}
