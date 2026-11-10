package dnstools

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Certificate Chain & AIA (Authority Information Access) Chasing.
// Reconstructs incomplete TLS chains where webservers omit intermediate CAs.

type CertChainInfo struct {
	Subject      string   `json:"subject"`
	Issuer       string   `json:"issuer"`
	NotBefore    string   `json:"not_before"`
	NotAfter     string   `json:"not_after"`
	DNSNames     []string `json:"dns_names,omitempty"`
	AIAIssuers   []string `json:"aia_issuers,omitempty"`
	IsRoot       bool     `json:"is_root"`
	ChasedViaAIA bool     `json:"chased_via_aia,omitempty"`
}

type TLSChainReport struct {
	Complete     bool            `json:"complete"`
	ChainLength  int             `json:"chain_length"`
	ChasedCount  int             `json:"chased_count"`
	Certificates []CertChainInfo `json:"certificates"`
	Issues       []string        `json:"issues,omitempty"`
}

// AuditTLSChain dials host:port, inspects presented certificates, and chases AIA caIssuers if incomplete.
func AuditTLSChain(ctx context.Context, host string, port int) (*TLSChainReport, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, errors.New("empty host")
	}
	if port <= 0 {
		port = 443
	}

	dialer := &net.Dialer{Timeout: 3 * time.Second}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	conf := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // we want raw chain inspection even if untrusted
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)
	if err != nil {
		return nil, fmt.Errorf("tls connection failed: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	peerCerts := state.PeerCertificates
	if len(peerCerts) == 0 {
		return nil, errors.New("no peer certificates presented")
	}

	rep := &TLSChainReport{
		Complete: true,
	}

	// Record presented certificates
	for _, cert := range peerCerts {
		isRoot := cert.Subject.String() == cert.Issuer.String()
		rep.Certificates = append(rep.Certificates, CertChainInfo{
			Subject:    cert.Subject.CommonName,
			Issuer:     cert.Issuer.CommonName,
			NotBefore:  cert.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:   cert.NotAfter.UTC().Format(time.RFC3339),
			DNSNames:   cert.DNSNames,
			AIAIssuers: cert.IssuingCertificateURL,
			IsRoot:     isRoot,
		})
	}

	// Verify standard verification
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	intermediates := x509.NewCertPool()
	for i := 1; i < len(peerCerts); i++ {
		intermediates.AddCert(peerCerts[i])
	}

	opts := x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}

	if _, err := peerCerts[0].Verify(opts); err != nil {
		rep.Complete = false
		rep.Issues = append(rep.Issues, fmt.Sprintf("Verification failure: %v", err))

		// If verification failed and leaf has AIA URLs, try chasing intermediate
		if len(peerCerts[0].IssuingCertificateURL) > 0 {
			chasedCert, chaseErr := chaseAIA(ctx, peerCerts[0].IssuingCertificateURL[0])
			if chaseErr == nil && chasedCert != nil {
				rep.ChasedCount++
				rep.Certificates = append(rep.Certificates, CertChainInfo{
					Subject:      chasedCert.Subject.CommonName,
					Issuer:       chasedCert.Issuer.CommonName,
					NotBefore:    chasedCert.NotBefore.UTC().Format(time.RFC3339),
					NotAfter:     chasedCert.NotAfter.UTC().Format(time.RFC3339),
					DNSNames:     chasedCert.DNSNames,
					ChasedViaAIA: true,
				})
				intermediates.AddCert(chasedCert)
				if _, retryErr := peerCerts[0].Verify(opts); retryErr == nil {
					rep.Complete = true
					rep.Issues = append(rep.Issues, "Server omitted intermediate CA; chain repaired via AIA chasing")
				}
			}
		}
	}

	rep.ChainLength = len(rep.Certificates)
	return rep, nil
}

// chaseAIA fetches intermediate DER/PEM certificate from caIssuers URL with strict size & egress caps.
func chaseAIA(ctx context.Context, u string) (*x509.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Timeout: 2 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AIA HTTP status %d", resp.StatusCode)
	}

	// 512 KB max for intermediate certs
	data, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, err
	}

	// Try DER first, then PEM
	if cert, err := x509.ParseCertificate(data); err == nil {
		return cert, nil
	}
	if certs, err := x509.ParseCertificates(data); err == nil && len(certs) > 0 {
		return certs[0], nil
	}
	block, _ := pem.Decode(data)
	if block != nil {
		return x509.ParseCertificate(block.Bytes)
	}
	return nil, errors.New("failed to parse certificate as DER or PEM")
}
