package ciphertools

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// C7 — X.509 certificates, chains and CSRs. SANs come first on purpose: they
// are what browsers match, and a CN-only certificate is the usual "works in
// curl, fails in Chrome" (docs/03-correctness-traps.md). Fingerprints hash the
// DER bytes, never the PEM text. Several certificates are checked as a chain:
// each one against the next, and when the order is wrong, the order that
// would be right.

func init() {
	register(Op{Name: "cert", Path: "/cert", Page: "cert", Fragment: "cipher/cert-result", Run: runCert})
}

// maxCerts bounds one paste. Ordering a chain checks every name-matched pair,
// so the cost grows with the square of the count; a chain is rarely over 5.
const maxCerts = 20

// maxPEMBlocks bounds the blocks of any type, skipped ones included.
const maxPEMBlocks = 100

// renewWithin is when "expires soon" starts.
const renewWithin = 30 * 24 * time.Hour

// SANs are a certificate's or request's subject alternative names.
type SANs struct {
	DNS   []string `json:"dns,omitempty"`
	IP    []string `json:"ip,omitempty"`
	Email []string `json:"email,omitempty"`
	URI   []string `json:"uri,omitempty"`
}

// Count is how many names there are in all.
func (s SANs) Count() int { return len(s.DNS) + len(s.IP) + len(s.Email) + len(s.URI) }

func sansOf(dns []string, ips []net.IP, emails []string, uris []*url.URL) SANs {
	s := SANs{DNS: dns, Email: emails}
	for _, ip := range ips {
		s.IP = append(s.IP, ip.String())
	}
	for _, u := range uris {
		s.URI = append(s.URI, u.String())
	}
	return s
}

// CertView is one decoded certificate.
type CertView struct {
	N          int      `json:"n"` // position among the certificates, from 1
	SANs       SANs     `json:"sans"`
	Subject    string   `json:"subject"`
	Issuer     string   `json:"issuer"`
	NotBefore  string   `json:"not_before"`
	NotAfter   string   `json:"not_after"`
	DaysLeft   int      `json:"days_left"`
	Validity   Validity `json:"validity"` // valid | expired | not-yet-valid
	Serial     string   `json:"serial"`
	SerialDec  string   `json:"serial_decimal"`
	Version    int      `json:"version"`
	SigAlg     string   `json:"signature_algorithm"`
	Key        string   `json:"public_key"`
	KeyUsage   []string `json:"key_usage,omitempty"`
	ExtUsage   []string `json:"ext_key_usage,omitempty"`
	IsCA       bool     `json:"is_ca"`
	Basic      string   `json:"basic_constraints"`
	SKI        string   `json:"subject_key_id,omitempty"`
	AKI        string   `json:"authority_key_id,omitempty"`
	OCSP       []string `json:"ocsp,omitempty"`
	IssuerURL  []string `json:"issuing_certificate_url,omitempty"`
	CRL        []string `json:"crl,omitempty"`
	SHA256     string   `json:"sha256_fingerprint"`
	SHA1       string   `json:"sha1_fingerprint"`
	SPKISHA256 string   `json:"spki_sha256"`
	SelfSigned bool     `json:"self_signed"`

	Warnings []Warning `json:"warnings,omitempty"`

	Title string `json:"-"` // first DNS name, else the CN
}

// CSRView is one decoded certificate signing request.
type CSRView struct {
	N          int    `json:"n"`
	Subject    string `json:"subject"`
	SANs       SANs   `json:"sans"`
	Key        string `json:"public_key"`
	SigAlg     string `json:"signature_algorithm"`
	SigOK      bool   `json:"signature_ok"`
	SigDetail  string `json:"signature_detail"`
	SPKISHA256 string `json:"spki_sha256"`

	Warnings []Warning `json:"warnings,omitempty"`

	Title string `json:"-"`
}

// Link signature states.
const (
	LinkValid      = "valid"
	LinkInvalid    = "invalid"
	LinkInsecure   = "insecure"    // signed with SHA-1 or MD5, which verifiers reject
	LinkNotCA      = "not-ca"      // the right key signed it, but the issuer may not issue
	LinkNotChecked = "not-checked" // the names don't chain, so the signature is moot
	// LinkUnsupported: an algorithm Go's x509 can't check at all (DSA, Ed448),
	// so the signature is neither confirmed nor refuted.
	LinkUnsupported = "unsupported"
)

// CertLink is one adjacent pair: is Issuer the certificate that issued Child?
type CertLink struct {
	Child     int    `json:"child"`
	Issuer    int    `json:"issuer"`
	NameMatch bool   `json:"name_match"`
	Signature string `json:"signature"`
	// Issued: the names chain and the issuer's key made the signature, which
	// is what the order check needs. A verifier also wants Signature "valid".
	Issued bool   `json:"issued"`
	Detail string `json:"detail"`
}

// Chain is the order check over two or more certificates.
type Chain struct {
	Links   []CertLink `json:"links"`
	OrderOK bool       `json:"order_ok"`
	Detail  string     `json:"detail"`
	// Suggested is the right order, leaf first, as positions from 1; set only
	// when the pasted order is wrong and a single chain exists.
	Suggested    []int    `json:"suggested_order,omitempty"`
	SuggestedPEM string   `json:"suggested_pem,omitempty"`
	End          string   `json:"end,omitempty"`
	Notes        []string `json:"notes,omitempty"`

	SuggestedText string `json:"-"`
}

// KeyMatch answers "is this the key for this certificate?".
type KeyMatch struct {
	State   string `json:"state"` // match | no-match | error
	Detail  string `json:"detail"`
	Key     string `json:"key,omitempty"`
	Cert    int    `json:"certificate,omitempty"`
	Request int    `json:"request,omitempty"`
}

// CertResult is everything read from one paste.
type CertResult struct {
	ReadAs   string     `json:"read_as"`
	Certs    []CertView `json:"certificates,omitempty"`
	CSRs     []CSRView  `json:"requests,omitempty"`
	Chain    *Chain     `json:"chain,omitempty"`
	KeyMatch *KeyMatch  `json:"key_match,omitempty"`
	Warnings []Warning  `json:"warnings,omitempty"`
}

func runCert(in Input) (any, error) {
	now, err := in.now()
	if err != nil {
		return nil, err
	}
	data := []byte(in.Get("cert"))
	if f := in.Files["cert_file"]; len(f) > 0 {
		data = f
	}
	return InspectCerts(data, in.Get("key"), now)
}

// InspectCerts reads certificates and requests from PEM, from DER as base64 or
// hex, or from raw DER bytes, and checks key (optional: PEM, JWK or OpenSSH)
// against them. now decides expiry.
func InspectCerts(data []byte, key string, now time.Time) (*CertResult, error) {
	p, err := readCertInput(data)
	if err != nil {
		return nil, err
	}
	r := &CertResult{ReadAs: p.readAs, Warnings: p.notes}
	for i, c := range p.certs {
		r.Certs = append(r.Certs, viewCert(i+1, c, now))
	}
	for i, c := range p.csrs {
		r.CSRs = append(r.CSRs, viewCSR(i+1, c))
	}
	if len(p.certs) > 1 {
		r.Chain = checkChain(p.certs)
	}
	switch {
	case strings.TrimSpace(key) != "":
		r.KeyMatch = matchKey(key, p.certs, p.csrs)
		if len(p.keyPEM) > 0 {
			r.Warnings = append(r.Warnings, Warning{LevelInfo, "The pasted PEM holds a key as well; the key field was used for the match instead."})
		}
	case len(p.keyPEM) > 0:
		r.KeyMatch = matchKey(string(p.keyPEM), p.certs, p.csrs)
		r.KeyMatch.Detail += " (Checked with the key found among the pasted PEM blocks.)"
	}
	return r, nil
}

// certInput is what readCertInput found.
type certInput struct {
	certs  []*x509.Certificate
	csrs   []*x509.CertificateRequest
	keyPEM []byte // key blocks pasted alongside, as in a combined cert+key file
	readAs string
	notes  []Warning
}

func (p *certInput) note(text string) { p.notes = append(p.notes, Warning{LevelInfo, text}) }

func (p *certInput) full() error {
	if n := len(p.certs) + len(p.csrs); n > maxCerts {
		return fmt.Errorf("more than %d certificates and requests; this page reads up to %d at once", maxCerts, maxCerts)
	}
	return nil
}

// keyPEMTypes are PEM blocks that are keys, not certificates.
var keyPEMTypes = map[string]bool{
	"PRIVATE KEY": true, "RSA PRIVATE KEY": true, "EC PRIVATE KEY": true, "ENCRYPTED PRIVATE KEY": true,
	"OPENSSH PRIVATE KEY": true, "PUBLIC KEY": true, "RSA PUBLIC KEY": true, "EC PARAMETERS": true,
}

func readCertInput(data []byte) (*certInput, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("no certificate given: paste PEM, or the DER as base64 or hex")
	}
	p := &certInput{}
	var err error
	if bytes.Contains(data, []byte("-----BEGIN")) {
		err = p.readPEM(data)
	} else {
		err = p.readDER(data)
	}
	if err != nil {
		return nil, err
	}
	if len(p.certs)+len(p.csrs) == 0 {
		if len(p.keyPEM) > 0 {
			return nil, errors.New("that is a key, not a certificate. The Keys page reads keys; here, put it in the key field to check it against a certificate")
		}
		return nil, errors.New("no certificate or certificate request found")
	}
	return p, nil
}

func (p *certInput) readPEM(data []byte) error {
	begin := []byte("-----BEGIN")
	rest, n := data, 0
	for {
		b, after := pem.Decode(rest)
		if b == nil {
			break
		}
		// pem.Decode skips a block it can't read and returns the next good one,
		// so a skipped block shows up as an extra BEGIN in what was consumed.
		consumed := rest[:len(rest)-len(after)]
		if bytes.Count(consumed, begin) > 1 {
			at := len(data) - len(rest) + bytes.Index(consumed, begin)
			return pemBlockError(data, at, n+1)
		}
		n++
		if n > maxPEMBlocks {
			return fmt.Errorf("more than %d PEM blocks; paste fewer at once", maxPEMBlocks)
		}
		if err := p.addPEM(n, b); err != nil {
			return err
		}
		rest = after
	}
	if i := bytes.Index(rest, begin); i >= 0 {
		return pemBlockError(data, len(data)-len(rest)+i, n+1)
	}
	p.readAs = fmt.Sprintf("PEM, %d block%s", n, plural(n))
	return nil
}

// pemBlockError explains why the block starting at offset at didn't decode,
// with offsets counted from the start of the paste.
func pemBlockError(data []byte, at, n int) error {
	s := string(data)
	nl := strings.IndexByte(s[at:], '\n')
	if nl < 0 {
		return fmt.Errorf("PEM block %d (offset %d) has nothing after its BEGIN line", n, at)
	}
	bodyAt := at + nl + 1
	end := strings.Index(s[bodyAt:], "-----END")
	if next := strings.Index(s[bodyAt:], "-----BEGIN"); end < 0 || next >= 0 && next < end {
		return fmt.Errorf("PEM block %d (offset %d) has no -----END line; the paste may have been cut short", n, at)
	}
	if _, _, err := decodeBase64Any(strings.Repeat(" ", bodyAt) + s[bodyAt:bodyAt+end]); err != nil {
		return fmt.Errorf("PEM block %d: %w", n, err)
	}
	return fmt.Errorf("PEM block %d (offset %d) couldn't be read; check that its BEGIN and END lines name the same type", n, at)
}

func (p *certInput) addPEM(n int, b *pem.Block) error {
	switch b.Type {
	case "CERTIFICATE":
		c, err := x509.ParseCertificate(b.Bytes)
		if err == nil {
			err = certKeySize(c.PublicKey)
		}
		if err != nil {
			return fmt.Errorf("PEM block %d (CERTIFICATE): %w", n, derError(err))
		}
		p.certs = append(p.certs, c)
	case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
		c, err := x509.ParseCertificateRequest(b.Bytes)
		if err == nil {
			err = certKeySize(c.PublicKey)
		}
		if err != nil {
			return fmt.Errorf("PEM block %d (%s): %w", n, b.Type, derError(err))
		}
		p.csrs = append(p.csrs, c)
	case "TRUSTED CERTIFICATE":
		return fmt.Errorf("PEM block %d is openssl's TRUSTED CERTIFICATE, which carries trust settings after the certificate; write a plain copy first: openssl x509 -in cert.pem -out plain.pem", n)
	case "PKCS7":
		return fmt.Errorf("PEM block %d is a PKCS#7 bundle; list its certificates first: openssl pkcs7 -print_certs -in bundle.p7b", n)
	default:
		if keyPEMTypes[b.Type] {
			p.keyPEM = append(p.keyPEM, pem.EncodeToMemory(b)...)
			return nil
		}
		p.note(fmt.Sprintf("PEM block %d (%s) isn't a certificate or a request; skipped.", n, b.Type))
	}
	return p.full()
}

func (p *certInput) readDER(data []byte) error {
	var der []byte
	switch {
	case !utf8.Valid(data) || !printable(string(data)):
		der, p.readAs = data, "DER bytes"
	case looksHex(string(data)):
		b, err := decodeHex(string(data))
		if err != nil {
			return fmt.Errorf("hex: %w", err)
		}
		der, p.readAs = b, "DER, as hex"
	default:
		b, variant, err := decodeBase64Any(string(data))
		if err != nil {
			return fmt.Errorf("not PEM, and not DER as base64 or hex: %w", err)
		}
		der, p.readAs = b, "DER, as "+variant
	}
	if len(der) == 0 || der[0] != 0x30 {
		return fmt.Errorf("the input is %d bytes that don't start with 0x30 (an ASN.1 SEQUENCE), so it isn't a DER certificate. Paste PEM (-----BEGIN CERTIFICATE-----), or the DER as base64 or hex", len(der))
	}
	certs, err := x509.ParseCertificates(der)
	if err == nil {
		for i, c := range certs {
			if err := certKeySize(c.PublicKey); err != nil {
				return fmt.Errorf("certificate %d: %w", i+1, err)
			}
		}
		p.certs = certs
		return p.full()
	}
	if csr, cerr := x509.ParseCertificateRequest(der); cerr == nil {
		if err := certKeySize(csr.PublicKey); err != nil {
			return err
		}
		p.csrs = []*x509.CertificateRequest{csr}
		return nil
	}
	return fmt.Errorf("not a DER certificate or request: %w", derError(err))
}

// certKeySize applies the RSA cap (keys.go) to a certificate's key, since its
// signatures, and those it made, are checked with it.
func certKeySize(pub any) error {
	if k, ok := pub.(*rsa.PublicKey); ok {
		return checkRSASize(k)
	}
	return nil
}

// looksHex: only hex digits once whitespace and ':' / '-' separators go.
func looksHex(s string) bool {
	c, _ := stripSpace(s)
	c = strings.NewReplacer(":", "", "-", "").Replace(c)
	return c != "" && allHex(c)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") }

func dn(s string) string {
	if s == "" {
		return "(empty)"
	}
	return s
}

func title(sans SANs, cn, subject string) string {
	switch {
	case len(sans.DNS) > 0:
		return sans.DNS[0]
	case cn != "":
		return cn
	case len(sans.IP) > 0:
		return sans.IP[0]
	case len(sans.Email) > 0:
		return sans.Email[0]
	}
	return dn(subject)
}

func sigAlgName(a x509.SignatureAlgorithm) string {
	if a == x509.UnknownSignatureAlgorithm {
		return "unknown"
	}
	return a.String()
}

// weakSigHash names the broken hash in a signature algorithm, or "".
func weakSigHash(a x509.SignatureAlgorithm) string {
	switch a {
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return "SHA-1"
	case x509.MD5WithRSA:
		return "MD5"
	case x509.MD2WithRSA:
		return "MD2"
	}
	return ""
}

var keyUsageNames = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "Digital Signature"},
	{x509.KeyUsageContentCommitment, "Content Commitment (Non-Repudiation)"},
	{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
	{x509.KeyUsageDataEncipherment, "Data Encipherment"},
	{x509.KeyUsageKeyAgreement, "Key Agreement"},
	{x509.KeyUsageCertSign, "Certificate Sign"},
	{x509.KeyUsageCRLSign, "CRL Sign"},
	{x509.KeyUsageEncipherOnly, "Encipher Only"},
	{x509.KeyUsageDecipherOnly, "Decipher Only"},
}

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "Any",
	x509.ExtKeyUsageServerAuth:                     "TLS Web Server Authentication",
	x509.ExtKeyUsageClientAuth:                     "TLS Web Client Authentication",
	x509.ExtKeyUsageCodeSigning:                    "Code Signing",
	x509.ExtKeyUsageEmailProtection:                "E-mail Protection",
	x509.ExtKeyUsageIPSECEndSystem:                 "IPSec End System",
	x509.ExtKeyUsageIPSECTunnel:                    "IPSec Tunnel",
	x509.ExtKeyUsageIPSECUser:                      "IPSec User",
	x509.ExtKeyUsageTimeStamping:                   "Time Stamping",
	x509.ExtKeyUsageOCSPSigning:                    "OCSP Signing",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "Microsoft Server Gated Crypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "Netscape Server Gated Crypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "Microsoft Commercial Code Signing",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "Microsoft Kernel Code Signing",
}

func basicConstraints(c *x509.Certificate) string {
	switch {
	case !c.BasicConstraintsValid:
		return "absent (so not a CA)"
	case !c.IsCA:
		return "not a CA (end entity)"
	case c.MaxPathLen > 0:
		return fmt.Sprintf("CA, path length up to %d", c.MaxPathLen)
	case c.MaxPathLen == 0 && c.MaxPathLenZero:
		return "CA, path length 0 (may issue only end-entity certificates)"
	}
	return "CA, no path length limit"
}

func serialHex(c *x509.Certificate) string {
	if c.SerialNumber == nil {
		return ""
	}
	b := c.SerialNumber.Bytes()
	if len(b) == 0 {
		b = []byte{0}
	}
	s := fingerprintHex(b)
	if c.SerialNumber.Sign() < 0 {
		s = "-" + s
	}
	return s
}

// selfSigned: issuer and subject are the same name, and the certificate's own
// key made its signature. SHA-1 is allowed here (CheckSignature, not
// CheckSignatureFrom); a signature that can't be checked at all (MD5) counts
// on the names alone.
func selfSigned(c *x509.Certificate) bool {
	if !bytes.Equal(c.RawIssuer, c.RawSubject) {
		return false
	}
	ok, unverifiable := signedBy(c, c)
	return ok || unverifiable
}

// signedBy checks child's signature with parent's key only, ignoring whether
// parent may issue. unverifiable: the algorithm is too broken to check (MD5),
// or one Go doesn't implement (DSA, Ed448); either way no verdict, not "invalid".
func signedBy(child, parent *x509.Certificate) (ok, unverifiable bool) {
	err := parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature)
	if err == nil {
		return true, false
	}
	var ia x509.InsecureAlgorithmError
	return false, errors.As(err, &ia) || errors.Is(err, x509.ErrUnsupportedAlgorithm)
}

func viewCert(n int, c *x509.Certificate, now time.Time) CertView {
	v := CertView{
		N:          n,
		SANs:       sansOf(c.DNSNames, c.IPAddresses, c.EmailAddresses, c.URIs),
		Subject:    dn(c.Subject.String()),
		Issuer:     dn(c.Issuer.String()),
		NotBefore:  stamp(c.NotBefore),
		NotAfter:   stamp(c.NotAfter),
		DaysLeft:   int(math.Floor(c.NotAfter.Sub(now).Hours() / 24)),
		Serial:     serialHex(c),
		Version:    c.Version,
		SigAlg:     sigAlgName(c.SignatureAlgorithm),
		Key:        keyName(c.PublicKey),
		IsCA:       c.IsCA,
		Basic:      basicConstraints(c),
		OCSP:       c.OCSPServer,
		IssuerURL:  c.IssuingCertificateURL,
		CRL:        c.CRLDistributionPoints,
		SelfSigned: selfSigned(c),
	}
	if c.SerialNumber != nil {
		v.SerialDec = c.SerialNumber.String()
	}
	if c.PublicKey == nil {
		v.Key = "unsupported (" + c.PublicKeyAlgorithm.String() + ")"
	}
	v.Title = title(v.SANs, c.Subject.CommonName, v.Subject)
	for _, u := range keyUsageNames {
		if c.KeyUsage&u.bit != 0 {
			v.KeyUsage = append(v.KeyUsage, u.name)
		}
	}
	for _, u := range c.ExtKeyUsage {
		name, ok := extKeyUsageNames[u]
		if !ok {
			name = "unknown (" + strconv.Itoa(int(u)) + ")"
		}
		v.ExtUsage = append(v.ExtUsage, name)
	}
	for _, oid := range c.UnknownExtKeyUsage {
		v.ExtUsage = append(v.ExtUsage, oid.String())
	}
	if len(c.SubjectKeyId) > 0 {
		v.SKI = fingerprintHex(c.SubjectKeyId)
	}
	if len(c.AuthorityKeyId) > 0 {
		v.AKI = fingerprintHex(c.AuthorityKeyId)
	}
	s256, s1 := sha256.Sum256(c.Raw), sha1.Sum(c.Raw)
	v.SHA256, v.SHA1 = fingerprintHex(s256[:]), fingerprintHex(s1[:])
	spki := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	v.SPKISHA256 = fingerprintHex(spki[:])

	switch {
	case now.Before(c.NotBefore):
		v.Validity = Validity{State: "not-yet-valid", Detail: "Not valid yet: starts " + relative(c.NotBefore, now)}
		v.warn(LevelWarn, "Not valid until "+stamp(c.NotBefore)+". Clients reject it until then.")
	case now.After(c.NotAfter):
		v.Validity = Validity{State: "expired", Detail: "Expired " + relative(c.NotAfter, now)}
		v.warn(LevelDanger, "Expired on "+stamp(c.NotAfter)+".")
	default:
		v.Validity = Validity{State: "valid", Detail: "Valid, expires " + relative(c.NotAfter, now)}
		if left := c.NotAfter.Sub(now); left < renewWithin {
			v.warn(LevelWarn, fmt.Sprintf("Expires in %s, on %s. Renew it.", humanDuration(left), stamp(c.NotAfter)))
		}
	}
	if h := weakSigHash(c.SignatureAlgorithm); h != "" {
		if v.SelfSigned {
			v.warn(LevelInfo, fmt.Sprintf("Self-signed with %s. Harmless on a root, since nobody checks a root's own signature.", h))
		} else {
			v.warn(LevelDanger, fmt.Sprintf("Signed with %s, which browsers and Go no longer accept: signatures over %s can be forged.", h, h))
		}
	}
	v.Warnings = append(v.Warnings, rsaSizeWarning(c.PublicKey)...)
	if !c.IsCA && v.SANs.Count() == 0 {
		v.warn(LevelWarn, "No subject alternative names. Browsers match host names against SANs only and ignore the CN (Chrome since version 58), so this certificate fails in them.")
	}
	return v
}

func (v *CertView) warn(level, text string) { v.Warnings = append(v.Warnings, Warning{level, text}) }

func rsaSizeWarning(pub any) []Warning {
	if k, ok := pub.(*rsa.PublicKey); ok && k.N.BitLen() < 2048 {
		return []Warning{{LevelWarn, fmt.Sprintf("RSA %d-bit key: below 2048 bits, the minimum certificate authorities and browsers accept.", k.N.BitLen())}}
	}
	return nil
}

func viewCSR(n int, c *x509.CertificateRequest) CSRView {
	v := CSRView{
		N:       n,
		Subject: dn(c.Subject.String()),
		SANs:    sansOf(c.DNSNames, c.IPAddresses, c.EmailAddresses, c.URIs),
		Key:     keyName(c.PublicKey),
		SigAlg:  sigAlgName(c.SignatureAlgorithm),
	}
	v.Title = title(v.SANs, c.Subject.CommonName, v.Subject)
	spki := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	v.SPKISHA256 = fingerprintHex(spki[:])
	if err := c.CheckSignature(); err != nil {
		v.SigDetail = "The request's signature does NOT verify with the key it carries (" + err.Error() + "). A CA will refuse it."
		v.Warnings = append(v.Warnings, Warning{LevelDanger, v.SigDetail})
	} else {
		v.SigOK = true
		v.SigDetail = "Signed by the key it carries, which proves whoever made it holds the private key."
	}
	if h := weakSigHash(c.SignatureAlgorithm); h != "" {
		v.Warnings = append(v.Warnings, Warning{LevelWarn, fmt.Sprintf("Signed with %s; many CAs refuse such requests.", h)})
	}
	v.Warnings = append(v.Warnings, rsaSizeWarning(c.PublicKey)...)
	if v.SANs.Count() == 0 {
		v.Warnings = append(v.Warnings, Warning{LevelWarn, "No subject alternative names requested. Browsers match host names against SANs only, so check that your CA adds them."})
	}
	return v
}

// checkLink: was child issued by parent?
func checkLink(certs []*x509.Certificate, child, parent int) CertLink {
	c, p := certs[child], certs[parent]
	l := CertLink{Child: child + 1, Issuer: parent + 1, NameMatch: bytes.Equal(c.RawIssuer, p.RawSubject)}
	if !l.NameMatch {
		l.Signature = LinkNotChecked
		l.Detail = fmt.Sprintf("Certificate %d's issuer is %s, but certificate %d's subject is %s.",
			l.Child, dn(c.Issuer.String()), l.Issuer, dn(p.Subject.String()))
		return l
	}
	ok, unverifiable := signedBy(c, p)
	l.Issued = ok || unverifiable
	err := c.CheckSignatureFrom(p)
	var ia x509.InsecureAlgorithmError
	var cv x509.ConstraintViolationError
	switch {
	case err == nil:
		l.Signature = LinkValid
		l.Detail = fmt.Sprintf("Certificate %d is issued and signed by certificate %d.", l.Child, l.Issuer)
	case unverifiable && weakSigHash(c.SignatureAlgorithm) == "":
		l.Signature = LinkUnsupported
		l.Detail = fmt.Sprintf("The names chain, but certificate %d is signed with %s, which Go (and so this page) can't check; browsers reject it too.", l.Child, sigAlgName(c.SignatureAlgorithm))
	case unverifiable:
		l.Signature = LinkInsecure
		l.Detail = fmt.Sprintf("The names chain, but certificate %d is signed with %s, which can't be checked safely.", l.Child, sigAlgName(c.SignatureAlgorithm))
	case !ok:
		l.Signature = LinkInvalid
		l.Detail = fmt.Sprintf("The names chain, but certificate %d's signature does NOT verify with certificate %d's key: another key with the same name, or a damaged certificate.", l.Child, l.Issuer)
	case errors.As(err, &ia):
		l.Signature = LinkInsecure
		l.Detail = fmt.Sprintf("Certificate %d is signed by certificate %d, but with %s, which Go and browsers reject.", l.Child, l.Issuer, weakSigHash(c.SignatureAlgorithm))
	case errors.As(err, &cv):
		l.Signature = LinkNotCA
		l.Detail = fmt.Sprintf("Certificate %d's key made the signature, but it isn't allowed to issue certificates (not a CA, or no Certificate Sign usage), so verifiers reject the link.", l.Issuer)
	default:
		l.Signature = LinkInvalid
		l.Detail = fmt.Sprintf("Certificate %d's key made the signature, but the link fails: %v.", l.Issuer, err)
	}
	return l
}

func checkChain(certs []*x509.Certificate) *Chain {
	n := len(certs)
	ch := &Chain{OrderOK: true}
	for i := 0; i+1 < n; i++ {
		l := checkLink(certs, i, i+1)
		ch.Links = append(ch.Links, l)
		if !l.Issued {
			ch.OrderOK = false
		}
	}

	// Copies are left out of the ordering.
	dup := make([]bool, n)
	seen := map[string]int{}
	unique := 0
	for i, c := range certs {
		if j, ok := seen[string(c.Raw)]; ok {
			dup[i] = true
			ch.Notes = append(ch.Notes, fmt.Sprintf("Certificate %d is a copy of certificate %d.", i+1, j+1))
			ch.OrderOK = false
			continue
		}
		seen[string(c.Raw)] = i
		unique++
	}

	// Who issued whom, among the unique certificates.
	issuer := make([]int, n)
	isParent := make([]bool, n)
	for i := range certs {
		issuer[i] = -1
		if dup[i] {
			continue
		}
		for j := range certs {
			if i == j || dup[j] || !bytes.Equal(certs[i].RawIssuer, certs[j].RawSubject) {
				continue
			}
			if ok, unverifiable := signedBy(certs[i], certs[j]); ok || unverifiable {
				issuer[i], isParent[j] = j, true
				break
			}
		}
	}
	var leaves []int
	for i := range certs {
		if !dup[i] && !isParent[i] {
			leaves = append(leaves, i)
		}
	}
	var order []int
	if len(leaves) == 1 {
		visited := map[int]bool{}
		for at := leaves[0]; at >= 0 && !visited[at]; at = issuer[at] {
			visited[at] = true
			order = append(order, at)
		}
	}

	last := -1
	switch {
	case ch.OrderOK:
		ch.Detail = "In order: each certificate is issued and signed by the one after it."
		last = n - 1
	case len(order) == unique:
		last = order[len(order)-1]
		var pemOut bytes.Buffer
		for _, i := range order {
			ch.Suggested = append(ch.Suggested, i+1)
			pem.Encode(&pemOut, &pem.Block{Type: "CERTIFICATE", Bytes: certs[i].Raw})
		}
		ch.SuggestedText = joinInts(ch.Suggested)
		ch.SuggestedPEM = pemOut.String()
		ch.Detail = "Out of order. Leaf first, then each issuer, is: " + ch.SuggestedText + "."
	case len(leaves) > 1:
		ch.Detail = fmt.Sprintf("These don't form one chain: certificates %s each issue none of the others, and a chain has one such certificate, the leaf.", joinInts(plus1(leaves)))
	case len(leaves) == 0:
		ch.Detail = "These don't form one chain: every certificate issues another one here, which makes a loop (cross-signed certificates?)."
	default:
		ch.Detail = fmt.Sprintf("These don't form one chain: following the issuers from the leaf, certificate %d, reaches only %s.", leaves[0]+1, joinInts(plus1(order)))
	}
	for _, l := range ch.Links {
		if l.Issued && l.Signature != LinkValid {
			ch.Detail += " A link in it fails verification, below."
			break
		}
	}
	if last >= 0 {
		c := certs[last]
		if selfSigned(c) {
			ch.End = fmt.Sprintf("Ends at a self-signed root, certificate %d. Servers usually leave the root out, since clients already have it.", last+1)
		} else {
			ch.End = fmt.Sprintf("Ends at certificate %d, issued by %s, which isn't included. Clients need that issuer already, normally a root in their trust store.", last+1, dn(c.Issuer.String()))
		}
	}
	return ch
}

func plus1(xs []int) []int {
	out := make([]int, len(xs))
	for i, x := range xs {
		out[i] = x + 1
	}
	return out
}

func joinInts(xs []int) string {
	s := make([]string, len(xs))
	for i, x := range xs {
		s[i] = strconv.Itoa(x)
	}
	return strings.Join(s, ", ")
}

// matchKey checks whether any key in input is the key of any certificate or
// request: the same public key, whichever half was pasted.
func matchKey(input string, certs []*x509.Certificate, csrs []*x509.CertificateRequest) *KeyMatch {
	if !looksLikeKeyMaterial(input) {
		return &KeyMatch{State: "error", Detail: "The key field reads as neither PEM, a JWK nor an OpenSSH public key."}
	}
	keys, err := ParseKeys(input)
	if err != nil {
		return &KeyMatch{State: "error", Detail: "Couldn't read the key: " + err.Error()}
	}
	var asym []Key
	for _, k := range keys {
		if k.Kind != KindSecret {
			asym = append(asym, k)
		}
	}
	if len(asym) == 0 {
		return &KeyMatch{State: "error", Detail: "That is a shared secret, which has no public key. A certificate holds a public key, so only a private or public key can match it."}
	}
	for _, k := range asym {
		half := "public key"
		if k.Private != nil {
			half = "private key"
		}
		for i, c := range certs {
			if samePublicKey(k.Public, c.PublicKey) {
				return &KeyMatch{State: "match", Key: k.Describe(), Cert: i + 1, Detail: fmt.Sprintf(
					"The %s belongs to certificate %d (%s): they hold the same public key.", half, i+1, title(sansOf(c.DNSNames, c.IPAddresses, c.EmailAddresses, c.URIs), c.Subject.CommonName, c.Subject.String()))}
			}
		}
		for i, c := range csrs {
			if samePublicKey(k.Public, c.PublicKey) {
				return &KeyMatch{State: "match", Key: k.Describe(), Request: i + 1, Detail: fmt.Sprintf(
					"The %s belongs to request %d: they hold the same public key.", half, i+1)}
			}
		}
	}
	m := &KeyMatch{State: "no-match", Key: asym[0].Describe()}
	what := "The key belongs to none of the certificates or requests here."
	if len(asym) > 1 {
		what = fmt.Sprintf("None of the %d keys belongs to any certificate or request here.", len(asym))
	}
	m.Detail = "No match. " + what
	if sum, err := spkiSHA256(asym[0].Public); err == nil {
		m.Detail += " Its SPKI SHA-256 is " + fingerprintHex(sum)
		if len(certs) > 0 {
			other := sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
			m.Detail += "; certificate 1's is " + fingerprintHex(other[:])
		}
		m.Detail += "."
	}
	return m
}
