package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCheckCARejectsExpired(t *testing.T) {
	dir := t.TempDir()
	expired := filepath.Join(dir, "old.pem")
	current := filepath.Join(dir, "now.pem")
	writeCert(t, expired, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	writeCert(t, current, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err := CheckCA(expired, time.Now()); err == nil {
		t.Fatal("expired certificate accepted")
	}
	if err := CheckCA(current, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := CheckCA("", time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPClientDoesNotSetProcessEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	writeCert(t, path, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	before := os.Getenv("SSL_CERT_FILE")
	_ = HTTPClient(Config{CAFile: path})
	if os.Getenv("SSL_CERT_FILE") != before {
		t.Fatal("HTTP client changed SSL_CERT_FILE")
	}
}

func writeCert(t *testing.T, path string, notBefore, notAfter time.Time) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: notBefore, NotAfter: notAfter,
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}
