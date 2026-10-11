package tests

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

// runOp drives an op the way both the handler and the wasm engine do.
func runOp(t *testing.T, name string, fields url.Values, files map[string][]byte) (any, error) {
	t.Helper()
	op, ok := ciphertools.Lookup(name)
	if !ok {
		t.Fatalf("no op %q", name)
	}
	return ciphertools.Run(op, ciphertools.Input{Fields: fields, Files: files})
}

func opOf[T any](t *testing.T, op string, fields url.Values, files map[string][]byte) *T {
	t.Helper()
	res, err := runOp(t, op, fields, files)
	if err != nil {
		t.Fatalf("%s %.80q: %v", op, fields, err)
	}
	return res.(*T)
}

func runner[T any](op string) func(*testing.T, url.Values) *T {
	return func(t *testing.T, fields url.Values) *T {
		t.Helper()
		return opOf[T](t, op, fields, nil)
	}
}

// wantErr fails unless op refuses fields with an error containing want; "" takes any error.
func wantErr(t *testing.T, op string, fields url.Values, want string) {
	t.Helper()
	if _, err := runOp(t, op, fields, nil); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("%s %.80q: err = %v, want %q", op, fields, err, want)
	}
}

// holds fails the test for each of wants missing from s; what names s in the message.
func holds(t *testing.T, what, s string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(s, want) {
			t.Errorf("%s lacks %q", what, want)
		}
	}
}

// noted: some warning's text contains sub (hasLevel also pins the level).
func noted(ws []ciphertools.Warning, sub string) bool {
	for _, w := range ws {
		if strings.Contains(w.Text, sub) {
			return true
		}
	}
	return false
}

func hasLevel(ws []ciphertools.Warning, level, sub string) bool {
	for _, w := range ws {
		if w.Level == level && strings.Contains(w.Text, sub) {
			return true
		}
	}
	return false
}

func pemBlock(typ string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

func spkiPEM(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pemBlock("PUBLIC KEY", der)
}

func pkcs8PEM(t *testing.T, k crypto.Signer) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pemBlock("PRIVATE KEY", der)
}

func colonHex(b []byte) string { return strings.ReplaceAll(fmt.Sprintf("% x", b), " ", ":") }

func fp(sum []byte) string { return strings.ToUpper(colonHex(sum)) }

func b64u(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
