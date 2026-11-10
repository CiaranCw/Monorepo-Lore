package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"time"
)

// CheckCA reads a PEM certificate and rejects one that is expired or not yet valid.
// An empty path means the caller is not pinning a CA.
func CheckCA(path string, now time.Time) error {
	if path == "" {
		return nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return errors.New("ca file is unreadable")
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return errors.New("ca file is not a certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("ca file is not a certificate")
	}
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return errors.New("ca certificate is not currently valid")
	}
	return nil
}

// HTTPClient trusts cfg.CAFile when it is set. It does not change the process environment.
func HTTPClient(cfg Config) *http.Client {
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("redirect refused")
	}}
	if cfg.CAFile == "" {
		return client
	}
	body, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return client
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(body) {
		return client
	}
	client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	return client
}
