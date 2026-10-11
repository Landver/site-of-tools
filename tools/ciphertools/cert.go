package ciphertools

import (
	"bytes"
	"cmp"
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
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

func init() {
	register(Op{Name: "cert", Path: "/cert", Page: "cert", Fragment: "cipher/cert-result", Run: runCert,
		Fields: []Field{
			{Name: "cert", Kind: KindString, Required: true,
				Description: "Certificates and signing requests to decode, as PEM (several are checked as a chain), or DER as base64 or hex; may be left out when cert_file is uploaded."},
			{Name: "cert_file", Kind: KindFile, Description: "A PEM or DER file to read instead of cert."},
			{Name: "key", Kind: KindString,
				Description: "A public or private key (PEM, JWK or an OpenSSH line) to match against the certificates and requests, naming the one it belongs to."},
			nowField,
		}})
}

// maxCerts bounds one paste: ordering a chain checks every name-matched pair.
const maxCerts = 20

const maxPEMBlocks = 100 // of any type, skipped ones included

const renewWithin = 30 * 24 * time.Hour // when "expires soon" starts

type SANs struct {
	DNS   []string `json:"dns,omitempty"`
	IP    []string `json:"ip,omitempty"`
	Email []string `json:"email,omitempty"`
	URI   []string `json:"uri,omitempty"`
}

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

// CertView is one decoded certificate; SANs lead because browsers ignore the CN (docs/03-correctness-traps.md).
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

	Warnings Warnings `json:"warnings,omitempty"`

	Title string `json:"-"`
}

type CSRView struct {
	N               int    `json:"n"`
	Subject         string `json:"subject"`
	SANs            SANs   `json:"sans"`
	Key             string `json:"public_key"`
	SigAlg          string `json:"signature_algorithm"`
	SigOK           bool   `json:"signature_ok"`
	SigDetail       string `json:"signature_detail"`
	SigUnverifiable bool   `json:"signature_unverifiable,omitempty"` // MD5, DSA, Ed448: no verdict either way
	SPKISHA256      string `json:"spki_sha256"`

	Warnings Warnings `json:"warnings,omitempty"`

	Title string `json:"-"`
}

// CertLink.Signature values.
const (
	LinkValid       = "valid"
	LinkInvalid     = "invalid"
	LinkInsecure    = "insecure"    // SHA-1 or MD5, which verifiers reject
	LinkNotCA       = "not-ca"      // the right key signed it, but the issuer may not issue
	LinkNotChecked  = "not-checked" // the names don't chain, so the signature is moot
	LinkUnsupported = "unsupported" // DSA or Ed448, which Go can't check: no verdict
)

// CertLink is one adjacent pair: is Issuer the certificate that issued Child?
type CertLink struct {
	Child     int    `json:"child"`
	Issuer    int    `json:"issuer"`
	NameMatch bool   `json:"name_match"`
	Signature string `json:"signature"`
	Issued    bool   `json:"issued"` // what ordering needs; a verifier also wants Signature "valid"
	Detail    string `json:"detail"`
}

// Chain is the order check over two or more certificates.
type Chain struct {
	Links        []CertLink `json:"links"`
	OrderOK      bool       `json:"order_ok"`
	Detail       string     `json:"detail"`
	Suggested    []int      `json:"suggested_order,omitempty"` // leaf first, from 1; only for one chain out of order
	SuggestedPEM string     `json:"suggested_pem,omitempty"`
	End          string     `json:"end,omitempty"`
	Notes        []string   `json:"notes,omitempty"`
}

type KeyMatch struct {
	State   string `json:"state"` // match | no-match | error
	Detail  string `json:"detail"`
	Key     string `json:"key,omitempty"`
	Cert    int    `json:"certificate,omitempty"`
	Request int    `json:"request,omitempty"`
}

type CertResult struct {
	ReadAs   string     `json:"read_as"`
	Certs    []CertView `json:"certificates,omitempty"`
	CSRs     []CSRView  `json:"requests,omitempty"`
	Chain    *Chain     `json:"chain,omitempty"`
	KeyMatch *KeyMatch  `json:"key_match,omitempty"`
	Warnings Warnings   `json:"warnings,omitempty"`
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

// InspectCerts reads certificates and requests from PEM or DER (raw, base64 or hex) and matches key against them.
func InspectCerts(data []byte, key string, now time.Time) (*CertResult, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("no certificate given: paste PEM, or the DER as base64 or hex")
	}
	p := &certInput{}
	read := p.readDER
	if bytes.Contains(data, []byte("-----BEGIN")) {
		read = p.readPEM
	}
	if err := read(data); err != nil {
		return nil, err
	}
	if len(p.certs)+len(p.csrs) == 0 {
		if len(p.keyPEM) > 0 {
			return nil, errors.New("that is a key, not a certificate. The Keys page reads keys; here, put it in the key field to check it against a certificate")
		}
		return nil, errors.New("no certificate or certificate request found")
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
		r.KeyMatch = matchKey(key, p, r.Certs)
		if len(p.keyPEM) > 0 {
			r.Warnings.add(LevelInfo, "The pasted PEM holds a key as well; the key field was used for the match instead.")
		}
	case len(p.keyPEM) > 0:
		r.KeyMatch = matchKey(string(p.keyPEM), p, r.Certs)
		r.KeyMatch.Detail += " (Checked with the key found among the pasted PEM blocks.)"
	}
	return r, nil
}

type certInput struct {
	certs  []*x509.Certificate
	csrs   []*x509.CertificateRequest
	keyPEM []byte // key blocks pasted alongside, as in a combined cert+key file
	readAs string
	notes  Warnings
}

func (p *certInput) full() error {
	if len(p.certs)+len(p.csrs) > maxCerts {
		return fmt.Errorf("more than %d certificates and requests; this page reads up to %d at once", maxCerts, maxCerts)
	}
	return nil
}

func (p *certInput) readPEM(data []byte) error {
	begin := []byte("-----BEGIN")
	rest, n := data, 0
	for b, after := pem.Decode(rest); b != nil; b, after = pem.Decode(rest) {
		// pem.Decode skips a block it can't read, which leaves an extra BEGIN in what it consumed.
		consumed := rest[:len(rest)-len(after)]
		if bytes.Count(consumed, begin) > 1 {
			return pemBlockError(data, len(data)-len(rest)+bytes.Index(consumed, begin), n+1)
		}
		if n++; n > maxPEMBlocks {
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

// pemBlockError explains why block n, starting at offset at of the paste, didn't decode.
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
	var err error
	switch b.Type {
	case "CERTIFICATE":
		var c *x509.Certificate
		if c, err = x509.ParseCertificate(b.Bytes); err == nil {
			p.certs, err = append(p.certs, c), checkRSASize(c.PublicKey)
		}
	case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
		var c *x509.CertificateRequest
		if c, err = x509.ParseCertificateRequest(b.Bytes); err == nil {
			p.csrs, err = append(p.csrs, c), checkRSASize(c.PublicKey)
		}
	case "TRUSTED CERTIFICATE":
		return fmt.Errorf("PEM block %d is openssl's TRUSTED CERTIFICATE, which carries trust settings after the certificate; write a plain copy first: openssl x509 -in cert.pem -out plain.pem", n)
	case "PKCS7":
		return fmt.Errorf("PEM block %d is a PKCS#7 bundle; list its certificates first: openssl pkcs7 -print_certs -in bundle.p7b", n)
	case "EC PARAMETERS": // pemKinds sends it to /keys, but it only names a curve
		return nil
	default:
		if pemKinds[b.Type].page == "/keys" {
			p.keyPEM = append(p.keyPEM, pem.EncodeToMemory(b)...)
			return nil
		}
		p.notes.add(LevelInfo, fmt.Sprintf("PEM block %d (%s) isn't a certificate or a request; skipped.", n, b.Type))
	}
	if err != nil {
		return fmt.Errorf("PEM block %d (%s): %w", n, b.Type, derError(err))
	}
	return p.full()
}

func (p *certInput) readDER(data []byte) error {
	der, s := data, string(data)
	p.readAs = "DER bytes"
	if utf8.Valid(data) && printable(s) {
		enc, fail := EncBase64, "not PEM, and not DER as base64 or hex"
		if allHex(strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "").Replace(s)) {
			enc, fail = EncHex, "hex"
		}
		b, how, err := decodeInput(s, enc)
		if err != nil {
			return fmt.Errorf("%s: %w", fail, err)
		}
		der, p.readAs = b, "DER, as "+how
	}
	if len(der) == 0 || der[0] != 0x30 {
		return fmt.Errorf("the input is %d bytes that don't start with 0x30 (an ASN.1 SEQUENCE), so it isn't a DER certificate. Paste PEM (-----BEGIN CERTIFICATE-----), or the DER as base64 or hex", len(der))
	}
	certs, err := x509.ParseCertificates(der)
	if err == nil {
		for i, c := range certs {
			if err := checkRSASize(c.PublicKey); err != nil {
				return fmt.Errorf("certificate %d: %w", i+1, err)
			}
		}
		p.certs = certs
		return p.full()
	}
	csr, cerr := x509.ParseCertificateRequest(der)
	if cerr != nil {
		return fmt.Errorf("not a DER certificate or request: %w", derError(err))
	}
	p.csrs = append(p.csrs, csr)
	return checkRSASize(csr.PublicKey)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func dn(s string) string { return cmp.Or(s, "(empty)") }

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

var weakSigHash = map[x509.SignatureAlgorithm]string{
	x509.SHA1WithRSA: "SHA-1", x509.DSAWithSHA1: "SHA-1", x509.ECDSAWithSHA1: "SHA-1",
	x509.MD5WithRSA: "MD5", x509.MD2WithRSA: "MD2",
}

// keyUsageNames[i] names x509.KeyUsage 1<<i, which is RFC 5280's bit i.
var keyUsageNames = []string{"Digital Signature", "Content Commitment (Non-Repudiation)", "Key Encipherment",
	"Data Encipherment", "Key Agreement", "Certificate Sign", "CRL Sign", "Encipher Only", "Decipher Only"}

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny: "Any", x509.ExtKeyUsageServerAuth: "TLS Web Server Authentication",
	x509.ExtKeyUsageClientAuth: "TLS Web Client Authentication", x509.ExtKeyUsageCodeSigning: "Code Signing",
	x509.ExtKeyUsageEmailProtection: "E-mail Protection", x509.ExtKeyUsageIPSECEndSystem: "IPSec End System",
	x509.ExtKeyUsageIPSECTunnel: "IPSec Tunnel", x509.ExtKeyUsageIPSECUser: "IPSec User",
	x509.ExtKeyUsageTimeStamping: "Time Stamping", x509.ExtKeyUsageOCSPSigning: "OCSP Signing",
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

func certSPKI(der []byte) string { sum := sha256.Sum256(der); return fingerprintHex(sum[:]) }

// certUncheckable: too broken to check (MD5) or not in Go (DSA, Ed448), so no verdict, not "invalid".
func certUncheckable(err error) bool {
	return errors.As(err, new(x509.InsecureAlgorithmError)) || errors.Is(err, x509.ErrUnsupportedAlgorithm)
}

// signedBy checks only the signature, SHA-1 allowed, not whether parent may issue.
func signedBy(child, parent *x509.Certificate) (ok, unverifiable bool) {
	err := parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature)
	return err == nil, certUncheckable(err)
}

// certIssued: the names chain and parent's key made child's signature, or it can't be checked.
func certIssued(child, parent *x509.Certificate) bool {
	if !bytes.Equal(child.RawIssuer, parent.RawSubject) {
		return false
	}
	ok, unverifiable := signedBy(child, parent)
	return ok || unverifiable
}

func viewCert(n int, c *x509.Certificate, now time.Time) CertView {
	s256, s1 := sha256.Sum256(c.Raw), sha1.Sum(c.Raw)
	v := CertView{
		N:          n,
		SANs:       sansOf(c.DNSNames, c.IPAddresses, c.EmailAddresses, c.URIs),
		Subject:    dn(c.Subject.String()),
		Issuer:     dn(c.Issuer.String()),
		NotBefore:  stamp(c.NotBefore),
		NotAfter:   stamp(c.NotAfter),
		DaysLeft:   int(math.Floor(c.NotAfter.Sub(now).Hours() / 24)),
		Serial:     cmp.Or(fingerprintHex(c.SerialNumber.Bytes()), "00"), // Bytes of 0 is empty
		SerialDec:  c.SerialNumber.String(),
		Version:    c.Version,
		SigAlg:     sigAlgName(c.SignatureAlgorithm),
		Key:        keyName(c.PublicKey),
		IsCA:       c.IsCA,
		Basic:      basicConstraints(c),
		SKI:        fingerprintHex(c.SubjectKeyId),
		AKI:        fingerprintHex(c.AuthorityKeyId),
		OCSP:       c.OCSPServer,
		IssuerURL:  c.IssuingCertificateURL,
		CRL:        c.CRLDistributionPoints,
		SHA256:     fingerprintHex(s256[:]),
		SHA1:       fingerprintHex(s1[:]),
		SPKISHA256: certSPKI(c.RawSubjectPublicKeyInfo),
		SelfSigned: certIssued(c, c),
	}
	if c.SerialNumber.Sign() < 0 {
		v.Serial = "-" + v.Serial
	}
	if c.PublicKey == nil {
		v.Key = "unsupported (" + c.PublicKeyAlgorithm.String() + ")"
	}
	v.Title = title(v.SANs, c.Subject.CommonName, v.Subject)
	for i, name := range keyUsageNames {
		if c.KeyUsage&(1<<i) != 0 {
			v.KeyUsage = append(v.KeyUsage, name)
		}
	}
	for _, u := range c.ExtKeyUsage {
		v.ExtUsage = append(v.ExtUsage, cmp.Or(extKeyUsageNames[u], fmt.Sprintf("unknown (%d)", u)))
	}
	for _, oid := range c.UnknownExtKeyUsage {
		v.ExtUsage = append(v.ExtUsage, oid.String())
	}

	switch {
	case now.Before(c.NotBefore):
		v.Validity = Validity{State: "not-yet-valid", Detail: "Not valid yet: starts " + relative(c.NotBefore, now)}
		v.Warnings.add(LevelWarn, "Not valid until "+stamp(c.NotBefore)+". Clients reject it until then.")
	case now.After(c.NotAfter):
		v.Validity = Validity{State: "expired", Detail: "Expired " + relative(c.NotAfter, now)}
		v.Warnings.add(LevelDanger, "Expired on "+stamp(c.NotAfter)+".")
	default:
		v.Validity = Validity{State: "valid", Detail: "Valid, expires " + relative(c.NotAfter, now)}
		if left := c.NotAfter.Sub(now); left < renewWithin {
			v.Warnings.add(LevelWarn, fmt.Sprintf("Expires in %s, on %s. Renew it.", humanDuration(left), stamp(c.NotAfter)))
		}
	}
	if h := weakSigHash[c.SignatureAlgorithm]; h != "" {
		if v.SelfSigned {
			v.Warnings.add(LevelInfo, fmt.Sprintf("Self-signed with %s. Harmless on a root, since nobody checks a root's own signature.", h))
		} else {
			v.Warnings.add(LevelDanger, fmt.Sprintf("Signed with %s, which browsers and Go no longer accept: signatures over %s can be forged.", h, h))
		}
	}
	rsaSizeWarning(&v.Warnings, c.PublicKey)
	if !c.IsCA && v.SANs.Count() == 0 {
		v.Warnings.add(LevelWarn, "No subject alternative names. Browsers match host names against SANs only and ignore the CN (Chrome since version 58), so this certificate fails in them.")
	}
	return v
}

func rsaSizeWarning(w *Warnings, pub any) {
	if k, ok := pub.(*rsa.PublicKey); ok && k.N.BitLen() < 2048 {
		w.add(LevelWarn, fmt.Sprintf("RSA %d-bit key: below 2048 bits, the minimum certificate authorities and browsers accept.", k.N.BitLen()))
	}
}

func viewCSR(n int, c *x509.CertificateRequest) CSRView {
	v := CSRView{
		N:          n,
		Subject:    dn(c.Subject.String()),
		SANs:       sansOf(c.DNSNames, c.IPAddresses, c.EmailAddresses, c.URIs),
		Key:        keyName(c.PublicKey),
		SigAlg:     sigAlgName(c.SignatureAlgorithm),
		SPKISHA256: certSPKI(c.RawSubjectPublicKeyInfo),
	}
	v.Title = title(v.SANs, c.Subject.CommonName, v.Subject)
	switch err := c.CheckSignature(); {
	case certUncheckable(err):
		v.SigUnverifiable = true
		v.SigDetail = "Signed with " + v.SigAlg + ", which this tool can't check, so there is no verdict on the signature. Many CAs refuse such requests."
		v.Warnings.add(LevelWarn, v.SigDetail)
	case err != nil:
		v.SigDetail = "The request's signature does NOT verify with the key it carries (" + err.Error() + "). A CA will refuse it."
		v.Warnings.add(LevelDanger, v.SigDetail)
	default:
		v.SigOK = true
		v.SigDetail = "Signed by the key it carries, which proves whoever made it holds the private key."
	}
	if h := weakSigHash[c.SignatureAlgorithm]; h != "" {
		v.Warnings.add(LevelWarn, fmt.Sprintf("Signed with %s; many CAs refuse such requests.", h))
	}
	rsaSizeWarning(&v.Warnings, c.PublicKey)
	if v.SANs.Count() == 0 {
		v.Warnings.add(LevelWarn, "No subject alternative names requested. Browsers match host names against SANs only, so check that your CA adds them.")
	}
	return v
}

func checkLink(certs []*x509.Certificate, child, parent int) CertLink {
	c, p := certs[child], certs[parent]
	l := CertLink{Child: child + 1, Issuer: parent + 1, NameMatch: bytes.Equal(c.RawIssuer, p.RawSubject)}
	if !l.NameMatch {
		l.Signature, l.Detail = LinkNotChecked, fmt.Sprintf("Certificate %d's issuer is %s, but certificate %d's subject is %s.",
			l.Child, dn(c.Issuer.String()), l.Issuer, dn(p.Subject.String()))
		return l
	}
	ok, unverifiable := signedBy(c, p)
	l.Issued = ok || unverifiable
	alg := sigAlgName(c.SignatureAlgorithm)
	switch err := c.CheckSignatureFrom(p); {
	case err == nil:
		l.Signature, l.Detail = LinkValid, fmt.Sprintf("Certificate %d is issued and signed by certificate %d.", l.Child, l.Issuer)
	case unverifiable && weakSigHash[c.SignatureAlgorithm] == "":
		l.Signature, l.Detail = LinkUnsupported, fmt.Sprintf("The names chain, but certificate %d is signed with %s, which Go (and so this page) can't check; browsers reject it too.", l.Child, alg)
	case unverifiable:
		l.Signature, l.Detail = LinkInsecure, fmt.Sprintf("The names chain, but certificate %d is signed with %s, which can't be checked safely.", l.Child, alg)
	case !ok:
		l.Signature, l.Detail = LinkInvalid, fmt.Sprintf("The names chain, but certificate %d's signature does NOT verify with certificate %d's key: another key with the same name, or a damaged certificate.", l.Child, l.Issuer)
	case errors.As(err, new(x509.InsecureAlgorithmError)):
		l.Signature, l.Detail = LinkInsecure, fmt.Sprintf("Certificate %d is signed by certificate %d, but with %s, which Go and browsers reject.", l.Child, l.Issuer, weakSigHash[c.SignatureAlgorithm])
	case errors.As(err, new(x509.ConstraintViolationError)):
		l.Signature, l.Detail = LinkNotCA, fmt.Sprintf("Certificate %d's key made the signature, but it isn't allowed to issue certificates (not a CA, or no Certificate Sign usage), so verifiers reject the link.", l.Issuer)
	default:
		l.Signature, l.Detail = LinkInvalid, fmt.Sprintf("Certificate %d's key made the signature, but the link fails: %v.", l.Issuer, err)
	}
	return l
}

func checkChain(certs []*x509.Certificate) *Chain {
	n := len(certs)
	ch := &Chain{OrderOK: true}
	failing := false
	for i := range n - 1 {
		l := checkLink(certs, i, i+1)
		ch.Links = append(ch.Links, l)
		ch.OrderOK = ch.OrderOK && l.Issued
		failing = failing || l.Issued && l.Signature != LinkValid
	}

	// Copies are left out of the ordering.
	dup := make([]bool, n)
	seen := map[string]int{}
	for i, c := range certs {
		if j, ok := seen[string(c.Raw)]; ok {
			dup[i], ch.OrderOK = true, false
			ch.Notes = append(ch.Notes, fmt.Sprintf("Certificate %d is a copy of certificate %d.", i+1, j+1))
			continue
		}
		seen[string(c.Raw)] = i
	}
	issuer := slices.Repeat([]int{-1}, n)
	for i := range certs {
		for j := range certs {
			if i != j && !dup[i] && !dup[j] && certIssued(certs[i], certs[j]) {
				issuer[i] = j
				break
			}
		}
	}
	var leaves, order []int
	for i := range certs {
		if !dup[i] && !slices.Contains(issuer, i) {
			leaves = append(leaves, i)
		}
	}
	if len(leaves) == 1 {
		for at := leaves[0]; at >= 0 && !slices.Contains(order, at); at = issuer[at] {
			order = append(order, at)
		}
	}

	last := -1
	switch {
	case ch.OrderOK:
		ch.Detail = "In order: each certificate is issued and signed by the one after it."
		last = n - 1
	case len(order) == len(seen):
		last = order[len(order)-1]
		for _, i := range order {
			ch.Suggested = append(ch.Suggested, i+1)
			ch.SuggestedPEM += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certs[i].Raw}))
		}
		ch.Detail = "Out of order. Leaf first, then each issuer, is: " + certPositions(order) + "."
	case len(leaves) > 1:
		ch.Detail = fmt.Sprintf("These don't form one chain: certificates %s each issue none of the others, and a chain has one such certificate, the leaf.", certPositions(leaves))
	case len(leaves) == 0:
		ch.Detail = "These don't form one chain: every certificate issues another one here, which makes a loop (cross-signed certificates?)."
	default:
		ch.Detail = fmt.Sprintf("These don't form one chain: following the issuers from the leaf, certificate %d, reaches only %s.", leaves[0]+1, certPositions(order))
	}
	if failing {
		ch.Detail += " A link in it fails verification, below."
	}
	if last >= 0 {
		if c := certs[last]; certIssued(c, c) {
			ch.End = fmt.Sprintf("Ends at a self-signed root, certificate %d. Servers usually leave the root out, since clients already have it.", last+1)
		} else {
			ch.End = fmt.Sprintf("Ends at certificate %d, issued by %s, which isn't included. Clients need that issuer already, normally a root in their trust store.", last+1, dn(c.Issuer.String()))
		}
	}
	return ch
}

// certPositions writes 0-based indexes as the 1-based positions people see.
func certPositions(idx []int) string {
	s := make([]string, len(idx))
	for i, x := range idx {
		s[i] = strconv.Itoa(x + 1)
	}
	return strings.Join(s, ", ")
}

// matchKey: does any pasted key, either half, hold the public key of a certificate or request?
func matchKey(input string, p *certInput, views []CertView) *KeyMatch {
	if !looksLikeKeyMaterial(input) {
		return &KeyMatch{State: "error", Detail: "The key field reads as neither PEM, a JWK nor an OpenSSH public key."}
	}
	keys, err := ParseKeys(input)
	if err != nil {
		return &KeyMatch{State: "error", Detail: "Couldn't read the key: " + err.Error()}
	}
	keys = slices.DeleteFunc(keys, func(k Key) bool { return k.Kind == KindSecret })
	if len(keys) == 0 {
		return &KeyMatch{State: "error", Detail: "That is a shared secret, which has no public key. A certificate holds a public key, so only a private or public key can match it."}
	}
	for _, k := range keys {
		for i, c := range p.certs {
			if samePublicKey(k.Public, c.PublicKey) {
				return &KeyMatch{State: "match", Key: k.Describe(), Cert: i + 1, Detail: fmt.Sprintf(
					"The %s belongs to certificate %d (%s): they hold the same public key.", k.half(), i+1, views[i].Title)}
			}
		}
		for i, c := range p.csrs {
			if samePublicKey(k.Public, c.PublicKey) {
				return &KeyMatch{State: "match", Key: k.Describe(), Request: i + 1, Detail: fmt.Sprintf(
					"The %s belongs to request %d: they hold the same public key.", k.half(), i+1)}
			}
		}
	}
	m := &KeyMatch{State: "no-match", Key: keys[0].Describe(), Detail: "No match. The key belongs to none of the certificates or requests here."}
	if len(keys) > 1 {
		m.Detail = fmt.Sprintf("No match. None of the %d keys belongs to any certificate or request here.", len(keys))
	}
	if der, err := x509.MarshalPKIXPublicKey(keys[0].Public); err == nil {
		m.Detail += " Its SPKI SHA-256 is " + certSPKI(der)
		if len(views) > 0 {
			m.Detail += "; certificate 1's is " + views[0].SPKISHA256
		}
		m.Detail += "."
	}
	return m
}
