package tests

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

// Certificates are built here with x509.CreateCertificate, so every expected
// value is known rather than copied from a live site that will expire.

var pkiNow = time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

type testPKI struct {
	rootKey, interKey, leafKey *ecdsa.PrivateKey
	root, inter, leaf          []byte // DER
	rootCert, interCert        *x509.Certificate
}

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustCert(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) ([]byte, *x509.Certificate) {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return der, c
}

func caTemplate(serial int64, cn string, pathLen int) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn, Organization: []string{"Cipher Tools Test"}},
		NotBefore: pkiNow.AddDate(-1, 0, 0), NotAfter: pkiNow.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen: pathLen, MaxPathLenZero: pathLen == 0,
	}
}

func leafTemplate() *x509.Certificate {
	u, _ := url.Parse("spiffe://example.com/web")
	return &x509.Certificate{
		SerialNumber: big.NewInt(0x0102ff), Subject: pkix.Name{CommonName: "example.com"},
		DNSNames: []string{"example.com", "www.example.com"}, IPAddresses: []net.IP{net.ParseIP("192.0.2.1")},
		EmailAddresses: []string{"admin@example.com"}, URIs: []*url.URL{u},
		NotBefore: pkiNow.AddDate(0, 0, -1), NotAfter: pkiNow.AddDate(0, 0, 90),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		OCSPServer:            []string{"http://ocsp.example.com"}, IssuingCertificateURL: []string{"http://ca.example.com/inter.der"},
		CRLDistributionPoints: []string{"http://crl.example.com/inter.crl"},
	}
}

func newPKI(t *testing.T) *testPKI {
	t.Helper()
	p := &testPKI{rootKey: ecKey(t), interKey: ecKey(t), leafKey: ecKey(t)}
	rootT := caTemplate(1, "Test Root CA", 1)
	p.root, p.rootCert = mustCert(t, rootT, rootT, &p.rootKey.PublicKey, p.rootKey)
	p.inter, p.interCert = mustCert(t, caTemplate(2, "Test Intermediate CA", 0), p.rootCert, &p.interKey.PublicKey, p.rootKey)
	p.leaf, _ = mustCert(t, leafTemplate(), p.interCert, &p.leafKey.PublicKey, p.interKey)
	return p
}

func pemOf(ders ...[]byte) string {
	var b strings.Builder
	for _, d := range ders {
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d}))
	}
	return b.String()
}

func certOf(t *testing.T, fields url.Values, files map[string][]byte) *ciphertools.CertResult {
	t.Helper()
	if fields.Get("now") == "" {
		fields.Set("now", strconv.FormatInt(pkiNow.Unix(), 10))
	}
	res, err := runOp(t, "cert", fields, files)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return res.(*ciphertools.CertResult)
}

func certErr(t *testing.T, cert string) error {
	t.Helper()
	_, err := runOp(t, "cert", url.Values{"cert": {cert}}, nil)
	if err == nil {
		t.Fatalf("%q: no error", cert)
	}
	return err
}

func fp(sum []byte) string { return strings.ToUpper(colonHex(sum)) }

func TestCertFields(t *testing.T) {
	p := newPKI(t)
	r := certOf(t, url.Values{"cert": {pemOf(p.leaf)}}, nil)
	if len(r.Certs) != 1 || r.Chain != nil || r.ReadAs != "PEM, 1 block" {
		t.Fatalf("%+v", r)
	}
	c := r.Certs[0]
	s256, s1 := sha256.Sum256(p.leaf), sha1.Sum(p.leaf)
	for name, got := range map[string][2]string{
		"title":     {c.Title, "example.com"},
		"dns":       {strings.Join(c.SANs.DNS, ","), "example.com,www.example.com"},
		"ip":        {strings.Join(c.SANs.IP, ","), "192.0.2.1"},
		"email":     {strings.Join(c.SANs.Email, ","), "admin@example.com"},
		"uri":       {strings.Join(c.SANs.URI, ","), "spiffe://example.com/web"},
		"subject":   {c.Subject, "CN=example.com"},
		"issuer":    {c.Issuer, "CN=Test Intermediate CA,O=Cipher Tools Test"},
		"serial":    {c.Serial, "01:02:FF"},
		"serialDec": {c.SerialDec, "66303"},
		"sigalg":    {c.SigAlg, "ECDSA-SHA256"},
		"key":       {c.Key, "ECDSA P-256"},
		"usage":     {strings.Join(c.KeyUsage, ","), "Digital Signature"},
		"eku":       {strings.Join(c.ExtUsage, ","), "TLS Web Server Authentication"},
		"basic":     {c.Basic, "not a CA (end entity)"},
		"ocsp":      {strings.Join(c.OCSP, ","), "http://ocsp.example.com"},
		"aia":       {strings.Join(c.IssuerURL, ","), "http://ca.example.com/inter.der"},
		"crl":       {strings.Join(c.CRL, ","), "http://crl.example.com/inter.crl"},
		"notAfter":  {c.NotAfter, "2026-04-15 12:00:00 UTC"},
		"validity":  {c.Validity.State, "valid"},
		// Fingerprints are over the DER, never the PEM text.
		"sha256": {c.SHA256, fp(s256[:])},
		"sha1":   {c.SHA1, fp(s1[:])},
	} {
		if got[0] != got[1] {
			t.Errorf("%s = %q, want %q", name, got[0], got[1])
		}
	}
	if c.DaysLeft != 90 || c.IsCA || c.SelfSigned || c.Version != 3 || len(c.Warnings) != 0 {
		t.Errorf("days %d ca %v self %v v%d warnings %v", c.DaysLeft, c.IsCA, c.SelfSigned, c.Version, c.Warnings)
	}
	spki := sha256.Sum256(mustParse(t, p.leaf).RawSubjectPublicKeyInfo)
	if c.SPKISHA256 != fp(spki[:]) || c.AKI != fp(p.interCert.SubjectKeyId) || c.AKI == "" {
		t.Errorf("SPKI %s AKI %s", c.SPKISHA256, c.AKI)
	}

	r = certOf(t, url.Values{"cert": {pemOf(p.root, p.inter)}}, nil)
	root, inter := r.Certs[0], r.Certs[1]
	if !root.SelfSigned || !root.IsCA || root.Basic != "CA, path length up to 1" || root.SKI == "" {
		t.Errorf("root: %+v", root)
	}
	if inter.SelfSigned || inter.Basic != "CA, path length 0 (may issue only end-entity certificates)" ||
		!slices.Contains(inter.KeyUsage, "Certificate Sign") {
		t.Errorf("intermediate: %+v", inter)
	}
	// A CA certificate with no SANs is normal; only a leaf gets the warning.
	if len(root.Warnings) != 0 {
		t.Errorf("root warnings %v", root.Warnings)
	}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCertChainOrder(t *testing.T) {
	p := newPKI(t)
	ok := certOf(t, url.Values{"cert": {pemOf(p.leaf, p.inter, p.root)}}, nil).Chain
	if !ok.OrderOK || len(ok.Links) != 2 || ok.Suggested != nil || !strings.Contains(ok.End, "self-signed root, certificate 3") {
		t.Fatalf("in order: %+v", ok)
	}
	for _, l := range ok.Links {
		if !l.NameMatch || !l.Issued || l.Signature != ciphertools.LinkValid {
			t.Errorf("link %+v", l)
		}
	}

	for name, c := range map[string]struct {
		ders [][]byte
		want []int
	}{
		"reversed": {[][]byte{p.root, p.inter, p.leaf}, []int{3, 2, 1}},
		"shuffled": {[][]byte{p.inter, p.leaf, p.root}, []int{2, 1, 3}},
		"no root":  {[][]byte{p.inter, p.leaf}, []int{2, 1}},
	} {
		ch := certOf(t, url.Values{"cert": {pemOf(c.ders...)}}, nil).Chain
		if ch.OrderOK || !slices.Equal(ch.Suggested, c.want) || !strings.Contains(ch.Detail, "Out of order") {
			t.Errorf("%s: %+v", name, ch)
			continue
		}
		// The suggested PEM is the same certificates, leaf first.
		fixed := certOf(t, url.Values{"cert": {ch.SuggestedPEM}}, nil)
		if !fixed.Chain.OrderOK || fixed.Certs[0].Title != "example.com" {
			t.Errorf("%s: suggested PEM isn't in order: %+v", name, fixed.Chain)
		}
	}
	if ch := certOf(t, url.Values{"cert": {pemOf(p.leaf, p.inter)}}, nil).Chain; !ch.OrderOK || !strings.Contains(ch.End, "isn't included") {
		t.Errorf("leaf + intermediate: %+v", ch)
	}

	// An unrelated self-signed certificate: two leaves, no single chain.
	otherKey := ecKey(t)
	otherT := caTemplate(9, "Other Root", 0)
	other, _ := mustCert(t, otherT, otherT, &otherKey.PublicKey, otherKey)
	ch := certOf(t, url.Values{"cert": {pemOf(p.leaf, other)}}, nil).Chain
	if ch.OrderOK || ch.Suggested != nil || !strings.Contains(ch.Detail, "don't form one chain") || ch.Links[0].NameMatch {
		t.Errorf("unrelated: %+v", ch)
	}

	// Same name, different key: the names chain but the signature doesn't.
	impostor, _ := mustCert(t, caTemplate(2, "Test Intermediate CA", 0), p.rootCert, &otherKey.PublicKey, p.rootKey)
	ch = certOf(t, url.Values{"cert": {pemOf(p.leaf, impostor)}}, nil).Chain
	if ch.OrderOK || !ch.Links[0].NameMatch || ch.Links[0].Signature != ciphertools.LinkInvalid {
		t.Errorf("impostor: %+v", ch.Links)
	}

	// Signed by the right key, but the issuer is no CA.
	leafCert := mustParse(t, p.leaf)
	underLeaf := leafTemplate()
	underLeaf.Subject.CommonName, underLeaf.SerialNumber = "sub.example.com", big.NewInt(77)
	sub, _ := mustCert(t, underLeaf, leafCert, &otherKey.PublicKey, p.leafKey)
	ch = certOf(t, url.Values{"cert": {pemOf(sub, p.leaf)}}, nil).Chain
	if !ch.OrderOK || ch.Links[0].Signature != ciphertools.LinkNotCA || !strings.Contains(ch.Detail, "fails verification") {
		t.Errorf("non-CA issuer: %+v", ch)
	}

	// A copy is named and left out of the order.
	ch = certOf(t, url.Values{"cert": {pemOf(p.inter, p.leaf, p.inter)}}, nil).Chain
	if ch.OrderOK || !slices.Equal(ch.Suggested, []int{2, 1}) || len(ch.Notes) != 1 {
		t.Errorf("duplicate: %+v", ch)
	}
}

func TestCertDERInput(t *testing.T) {
	p := newPKI(t)
	want := sha256.Sum256(p.leaf)
	wrapped := base64.StdEncoding.EncodeToString(p.leaf)
	for i := 64; i < len(wrapped); i += 65 {
		wrapped = wrapped[:i] + "\n" + wrapped[i:]
	}
	for name, c := range map[string]struct {
		fields url.Values
		files  map[string][]byte
		readAs string
	}{
		"base64":       {url.Values{"cert": {wrapped}}, nil, "DER, as base64 (standard"}, // padded or not: ECDSA signatures vary in length
		"base64url":    {url.Values{"cert": {base64.RawURLEncoding.EncodeToString(p.leaf)}}, nil, "DER, as "},
		"hex":          {url.Values{"cert": {hex.EncodeToString(p.leaf)}}, nil, "DER, as hex"},
		"colon hex":    {url.Values{"cert": {colonHex(p.leaf)}}, nil, "DER, as hex"},
		"DER file":     {url.Values{"cert": {"ignored while a file is picked"}}, map[string][]byte{"cert_file": p.leaf}, "DER bytes"},
		"PEM file":     {url.Values{}, map[string][]byte{"cert_file": []byte(pemOf(p.leaf))}, "PEM, 1 block"},
		"text before":  {url.Values{"cert": {"subject=CN = example.com\n" + pemOf(p.leaf)}}, nil, "PEM, 1 block"},
		"concatenated": {url.Values{"cert": {base64.StdEncoding.EncodeToString(append(slices.Clone(p.leaf), p.inter...))}}, nil, "DER, as base64"},
	} {
		r := certOf(t, c.fields, c.files)
		if !strings.HasPrefix(r.ReadAs, c.readAs) || r.Certs[0].SHA256 != fp(want[:]) {
			t.Errorf("%s: read as %q, sha256 %s", name, r.ReadAs, r.Certs[0].SHA256)
		}
		if name == "concatenated" && (len(r.Certs) != 2 || !r.Chain.OrderOK) {
			t.Errorf("concatenated DER: %d certs", len(r.Certs))
		}
	}
}

func TestCertCSR(t *testing.T) {
	k := ecKey(t)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "api.example.com", Organization: []string{"Example"}}, DNSNames: []string{"api.example.com"},
	}, k)
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"} {
		r := certOf(t, url.Values{"cert": {string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: csrDER}))}}, nil)
		if len(r.CSRs) != 1 || len(r.Certs) != 0 {
			t.Fatalf("%s: %+v", typ, r)
		}
		c := r.CSRs[0]
		if !c.SigOK || c.Title != "api.example.com" || c.Key != "ECDSA P-256" || c.SigAlg != "ECDSA-SHA256" ||
			!slices.Equal(c.SANs.DNS, []string{"api.example.com"}) || c.Subject != "CN=api.example.com,O=Example" || len(c.Warnings) != 0 {
			t.Errorf("%s: %+v", typ, c)
		}
	}
	// DER as base64 works for a request too.
	if r := certOf(t, url.Values{"cert": {base64.StdEncoding.EncodeToString(csrDER)}}, nil); len(r.CSRs) != 1 || !r.CSRs[0].SigOK {
		t.Errorf("base64 CSR: %+v", r)
	}
	// A damaged signature: the DER still parses, the signature doesn't verify.
	bad := slices.Clone(csrDER)
	bad[len(bad)-1] ^= 0x01
	if c := certOf(t, url.Values{"cert": {base64.StdEncoding.EncodeToString(bad)}}, nil).CSRs[0]; c.SigOK || !noted(c.Warnings, "does NOT verify") {
		t.Errorf("damaged CSR: %+v", c)
	}
	noSAN, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "legacy.example.com"}}, k)
	if c := certOf(t, url.Values{"cert": {base64.StdEncoding.EncodeToString(noSAN)}}, nil).CSRs[0]; !noted(c.Warnings, "No subject alternative names") {
		t.Errorf("CN-only CSR: %v", c.Warnings)
	}
	// The key matches its own request.
	pub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	m := certOf(t, url.Values{"cert": {base64.StdEncoding.EncodeToString(csrDER)},
		"key": {string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))}}, nil).KeyMatch
	if m.State != "match" || m.Request != 1 {
		t.Errorf("CSR key match: %+v", m)
	}
}

func TestCertKeyMatch(t *testing.T) {
	p := newPKI(t)
	chain := pemOf(p.leaf, p.inter)
	pubDER, _ := x509.MarshalPKIXPublicKey(&p.leafKey.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	jwk, _ := ciphertools.PublicJWK(&p.leafKey.PublicKey)
	jwkJSON, _ := json.Marshal(jwk)
	sshPub, _ := ssh.NewPublicKey(&p.leafKey.PublicKey)

	for name, c := range map[string]struct{ key, state string }{
		"private PKCS#8":  {pkcs8PEM(t, p.leafKey), "match"},
		"public SPKI":     {pubPEM, "match"},
		"public JWK":      {string(jwkJSON), "match"},
		"OpenSSH line":    {string(ssh.MarshalAuthorizedKey(sshPub)), "match"},
		"another key":     {pkcs8PEM(t, ecKey(t)), "no-match"},
		"not a key":       {"hello", "error"},
		"broken PEM":      {"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----", "error"},
		"a shared secret": {rfcHSKey, "error"},
	} {
		m := certOf(t, url.Values{"cert": {chain}, "key": {c.key}}, nil).KeyMatch
		if m == nil || m.State != c.state {
			t.Errorf("%s: %+v", name, m)
			continue
		}
		if c.state == "match" && m.Cert != 1 {
			t.Errorf("%s: matched certificate %d, want 1", name, m.Cert)
		}
		if c.state == "no-match" && !strings.Contains(m.Detail, "SPKI SHA-256") {
			t.Errorf("%s: %s", name, m.Detail)
		}
	}
	// The intermediate's key matches certificate 2.
	if m := certOf(t, url.Values{"cert": {chain}, "key": {pkcs8PEM(t, p.interKey)}}, nil).KeyMatch; m.State != "match" || m.Cert != 2 {
		t.Errorf("intermediate key: %+v", m)
	}
	// A combined file (certificate + key) is matched with its own key.
	r := certOf(t, url.Values{"cert": {pemOf(p.leaf) + pkcs8PEM(t, p.leafKey)}}, nil)
	if r.KeyMatch == nil || r.KeyMatch.State != "match" || !strings.Contains(r.KeyMatch.Detail, "pasted PEM") {
		t.Errorf("combined PEM: %+v", r.KeyMatch)
	}
	if m := certOf(t, url.Values{"cert": {chain}}, nil).KeyMatch; m != nil {
		t.Errorf("no key, but KeyMatch %+v", m)
	}
}

func TestCertExpiryStates(t *testing.T) {
	p := newPKI(t)
	leaf := pemOf(p.leaf) // valid pkiNow-1d .. pkiNow+90d
	at := func(d time.Duration) ciphertools.CertView {
		return certOf(t, url.Values{"cert": {leaf}, "now": {strconv.FormatInt(pkiNow.Add(d).Unix(), 10)}}, nil).Certs[0]
	}
	day := 24 * time.Hour
	for name, c := range map[string]struct {
		d           time.Duration
		state, warn string
		days        int
	}{
		"fresh":         {0, "valid", "", 90},
		"within 30":     {70 * day, "valid", "Expires in 20 days", 20},
		"expired":       {95 * day, "expired", "Expired on 2026-04-15", -5},
		"not yet valid": {-2 * day, "not-yet-valid", "Not valid until", 92},
	} {
		v := at(c.d)
		if v.Validity.State != c.state || v.DaysLeft != c.days {
			t.Errorf("%s: state %s days %d (%s)", name, v.Validity.State, v.DaysLeft, v.Validity.Detail)
		}
		if c.warn == "" && len(v.Warnings) != 0 || c.warn != "" && !noted(v.Warnings, c.warn) {
			t.Errorf("%s: warnings %v, want %q", name, v.Warnings, c.warn)
		}
	}
	if v := at(95 * day); v.Warnings[0].Level != ciphertools.LevelDanger {
		t.Errorf("expired should be danger: %v", v.Warnings)
	}
}

func TestCertWarnings(t *testing.T) {
	// RSA 1024, SHA-1, and no SANs, each on its own.
	rsaSmall, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	rootT := caTemplate(1, "Old Root", 1)
	rootT.SignatureAlgorithm = x509.SHA1WithRSA
	_, root := mustCert(t, rootT, rootT, &rsaSmall.PublicKey, rsaSmall)
	leafT := leafTemplate()
	leafT.SignatureAlgorithm = x509.SHA1WithRSA
	leafT.DNSNames, leafT.IPAddresses, leafT.EmailAddresses, leafT.URIs = nil, nil, nil, nil
	leafDER, _ := mustCert(t, leafT, root, &ecKey(t).PublicKey, rsaSmall)

	r := certOf(t, url.Values{"cert": {pemOf(leafDER, root.Raw)}}, nil)
	leaf, rootView := r.Certs[0], r.Certs[1]
	for _, want := range []string{"Signed with SHA-1", "No subject alternative names"} {
		if !noted(leaf.Warnings, want) {
			t.Errorf("leaf lacks %q: %v", want, leaf.Warnings)
		}
	}
	if !noted(rootView.Warnings, "below 2048") || !noted(rootView.Warnings, "Harmless on a root") || !rootView.SelfSigned {
		t.Errorf("root: self-signed %v, %v", rootView.SelfSigned, rootView.Warnings)
	}
	// The link verifies with the key, but SHA-1 is refused by verifiers.
	if l := r.Chain.Links[0]; !r.Chain.OrderOK || !l.Issued || l.Signature != ciphertools.LinkInsecure {
		t.Errorf("SHA-1 link: %+v", l)
	}
}

// A DSA root and the P-256 leaf it signed, made with openssl (Go can't make
// DSA certificates); `openssl verify -CAfile root leaf` accepts the pair.
const (
	dsaLeafPEM = `-----BEGIN CERTIFICATE-----
MIIBGzCB2aADAgECAgECMAsGCWCGSAFlAwQDAjATMREwDwYDVQQDDAhEU0EgUm9v
dDAeFw0yNjA5MjgxMzQ1MjVaFw00NTExMjcxMzQ1MjVaMBYxFDASBgNVBAMMC2Rz
YS5leGFtcGxlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEywQKHsNKIgZSKWmd
WmNN2/hCxsLRVZsBu4nJqkCVU6q6ZwssgVq3rvGFHnen8ITUPQm1+cVw6TLJQXb2
GWZoJaMaMBgwFgYDVR0RBA8wDYILZHNhLmV4YW1wbGUwCwYJYIZIAWUDBAMCAzAA
MC0CFGHSmGaxl82oGla/O5xJZ+g9cd7RAhUAtlt9G7pAOcoHF1uxg8v5PTnU2QE=
-----END CERTIFICATE-----
`
	dsaRootPEM = `-----BEGIN CERTIFICATE-----
MIICiTCCAkagAwIBAgIJAMmLKIPGf6KNMAsGCWCGSAFlAwQDAjATMREwDwYDVQQD
DAhEU0EgUm9vdDAeFw0yNjA5MjgxMzQ1MjVaFw00NjA5MjMxMzQ1MjVaMBMxETAP
BgNVBAMMCERTQSBSb290MIIBtjCCASsGByqGSM44BAEwggEeAoGBAMfmqoaZxKR0
S+BobehCC/CDbjQ6snYDreZrZ756lsRUxNhKRiyv5T+FOJLQcfH8QT0Imc3hnMz+
JuVsU4uN+etpnvHmU+K0YTHNQ3MLmZupFs0WUAERfcDB56Nx4Ech3MOQmSPsiM2Z
l3c7KkUay4wW8BGqxjjJZ3aVgkupo5r/AhUA8yz/fEsy8cW2NVaTdX9a+hTqsbMC
gYAFXcQkslasK0QfKHpYLV6booSPSi1IIKWl4FAEykxZNovSUl6ccLIBdPyvzbWy
rkoxlR+YYDYkY5LITkg03t3LWcwnBDYhR5blHr7UuCHqMg02rNGki1l3rw42mGmm
sDWwG9qcwpy/6nmBy+S6RpXiKMlDFYaai00qqwF9GW1njwOBhAACgYAFy+QzGOzF
BBIGTefjP67fZL74UDc19kRZAY9oCuYcn6EtDbvxdgtgU+mBg0MnmxpLy40uGmss
o+jQIJWGiwlSf6nS25dorPBSy6XGQ4+FZ6t712CsfQhtP78E95DYdaWOo5poG3XC
cgRqYP29sFv5DvzIej1OnWaAItxwnv0CAqMjMCEwDwYDVR0TAQH/BAUwAwEB/zAO
BgNVHQ8BAf8EBAMCAgQwCwYJYIZIAWUDBAMCAzAAMC0CFQCIS1lUUz1ZVzTlESz2
R89E59Tj6wIUIMoQ/mvgOsfYIcbg5zb7i2s9aD0=
-----END CERTIFICATE-----
`
)

// Go's x509 can't check a DSA signature at all. That is "can't say", not "does
// NOT verify": the chain still orders by name, and the link names the reason.
func TestCertUnsupportedSignatureIsNotInvalid(t *testing.T) {
	now := strconv.FormatInt(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Unix(), 10)
	r := certOf(t, url.Values{"cert": {dsaLeafPEM + dsaRootPEM}, "now": {now}}, nil)
	l := r.Chain.Links[0]
	if l.Signature != ciphertools.LinkUnsupported || !l.Issued || !strings.Contains(l.Detail, "can't check") {
		t.Errorf("DSA link: %+v", l)
	}
	if !r.Chain.OrderOK || !r.Certs[1].SelfSigned || !strings.Contains(r.Chain.End, "self-signed root") {
		t.Errorf("DSA chain: %+v, root self-signed %v", r.Chain, r.Certs[1].SelfSigned)
	}
}

func TestCertInputErrors(t *testing.T) {
	p := newPKI(t)
	good := pemOf(p.leaf)
	body := strings.Split(pemOf(p.inter), "\n")
	body[3] = body[3][:10] + "!" + body[3][11:]
	broken := strings.Join(body, "\n")
	offset := len(good) + len(strings.Join(body[:3], "\n")) + 1 + 10

	for in, want := range map[string]string{
		"":                   "no certificate given",
		good + broken:        "'!' at offset " + strconv.Itoa(offset),
		good + broken + good: "PEM block 2:",
		good + "-----BEGIN CERTIFICATE-----\nMIIB":           "PEM block 2 (offset " + strconv.Itoa(len(good)) + ") has no -----END line",
		"-----BEGIN PKCS7-----\nMIIB\n-----END PKCS7-----\n": "openssl pkcs7 -print_certs",
		pkcs8PEM(t, p.leafKey):                               "that is a key",
		"hello world":                                        "0x30",
		"MII!":                                               "offset 3",
		"30820":                                              "odd number of digits",
	} {
		if err := certErr(t, in); !strings.Contains(err.Error(), want) {
			t.Errorf("%.40q: %v, want %q", in, err, want)
		}
	}
	many := strings.Repeat(good, 21)
	if err := certErr(t, many); !strings.Contains(err.Error(), "up to 20") {
		t.Errorf("21 certificates: %v", err)
	}
	if err := certErr(t, good+strings.Repeat("-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n", 100)); !strings.Contains(err.Error(), "more than 100 PEM blocks") {
		t.Errorf("101 blocks: %v", err)
	}
	// A block that isn't a certificate is skipped with a note, not an error.
	r := certOf(t, url.Values{"cert": {good + "-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n"}}, nil)
	if len(r.Certs) != 1 || !noted(r.Warnings, "X509 CRL") {
		t.Errorf("CRL block: %+v", r.Warnings)
	}
}

func TestRenderCert(t *testing.T) {
	p := newPKI(t)
	html := render(t, "cert", url.Values{"cert": {pemOf(p.root, p.inter, p.leaf)}, "now": {strconv.FormatInt(pkiNow.Unix(), 10)}})
	for _, want := range []string{"Wrong order", "3, 2, 1", "www.example.com", "01:02:FF", "Copy"} {
		if !strings.Contains(html, want) {
			t.Errorf("fragment lacks %q", want)
		}
	}
	// SANs before the subject, in every certificate.
	leaf := html[strings.LastIndex(html, "Certificate 3"):]
	if i, j := strings.Index(leaf, "Subject alternative names"), strings.Index(leaf, "<dt>Subject</dt>"); i < 0 || j < 0 || i > j {
		t.Errorf("SANs at %d, subject at %d", i, j)
	}
}

func TestCertPageAndAPI(t *testing.T) {
	p := newPKI(t)
	e := newCipherApp(t)
	page := do(t, e, http.MethodGet, "/cert", "", "", asBrowser).Body.String()
	for _, want := range []string{"openssl x509 -in cert.pem -noout -text", "openssl req -in csr.pem -noout -text", `enctype="multipart/form-data"`} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	body := url.Values{"cert": {pemOf(p.leaf)}, "now": {strconv.FormatInt(pkiNow.Unix(), 10)}}.Encode()
	rec := do(t, e, http.MethodPost, "/cert", body, form, asAPI)
	var got struct {
		Certificates []struct {
			SANs     struct{ DNS []string }
			DaysLeft int `json:"days_left"`
		}
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got.Certificates) != 1 || got.Certificates[0].DaysLeft != 90 ||
		len(got.Certificates[0].SANs.DNS) != 2 {
		t.Fatalf("API: %d %s", rec.Code, rec.Body)
	}
	rec = do(t, e, http.MethodPost, "/cert", body, form, asBrowser)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<!DOCTYPE html>") || !strings.Contains(rec.Body.String(), "www.example.com") {
		t.Fatalf("no-JS: %d", rec.Code)
	}
}

// A CSR signed with an algorithm Go can't check (DSA here, made by openssl) is
// no verdict, the same rule the chain view follows. "Signature invalid" would
// tell the visitor their request is broken when it isn't.
const dsaCSR = `-----BEGIN CERTIFICATE REQUEST-----
MIICGzCCAdcCAQAwFjEUMBIGA1UEAwwLZHNhLmV4YW1wbGUwggG2MIIBKwYHKoZI
zjgEATCCAR4CgYEAxPns90673Q19X82l1cVvZWEAmmBvcKZtsjLhkzw+PjWbJsmF
Z2Lj2wTqdo8J2G/Qrpxb2p+WN6t3rhw91rPM12CW312NqPaBO7d1Nq1+LBovBI9X
ifW7lIRDi7Kc5y6zusxcJDI7bmQvHHJZOdbP9f5/NroN3OVQCKzvhVjEFp8CFQDA
yjg9jSUzuMg4aZetzwmn5mvUUwKBgHxV7UFaq2dH/pC1UJxoh9KerBvjcqh5UTQ3
YfCTgywvYrW2tc9lEofNOEh8sqsK6L621fHzx3VChtQPGxp5O66R0N2VXofqgkoQ
OnBG3Ozg48ZX4CSRjxxyH38LxgwIaJP2yqGNZXgigqjH9d0oQ+4QtS15n0zewTUI
HNHm4a+BA4GEAAKBgBdWU9pnHSyFXUiPbh1+ZhZm0cFRZ8aL2r7tq0tc/sQPNMRV
C+ZG9OZY0CgPoplgrEWIy0NTe/+eWDcUduM/4uZTjvnc6PZ4YbTncTkoxhhwxSZE
LGlp3KQAFn9vzlw/+jjJbba550KwANUBo/1RR53ZTDiOk9nHXs/j+jutGdogoAAw
CwYJYIZIAWUDBAMCAzEAMC4CFQCML/8Bp6o4J5Y1SBkcLoWz3s8CZAIVAKK5opJg
gueeXq/u6Fg1TWIyBGUp
-----END CERTIFICATE REQUEST-----
`

func TestCSRUnsupportedSignatureIsNoVerdict(t *testing.T) {
	res, err := runOp(t, "cert", url.Values{"cert": {dsaCSR}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := res.(*ciphertools.CertResult).CSRs[0]
	if c.SigOK || !c.SigUnverifiable || strings.Contains(c.SigDetail, "does NOT verify") {
		t.Fatalf("ok %v unverifiable %v: %s", c.SigOK, c.SigUnverifiable, c.SigDetail)
	}
}
