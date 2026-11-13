package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lore-monorepo/internal/client"
	"lore-monorepo/internal/loreexec"
)

func TestConnectCommandAndFollowupWithoutConfigFlag(t *testing.T) {
	cfgRoot := t.TempDir()
	t.Setenv("AppData", cfgRoot)
	t.Setenv("XDG_CONFIG_HOME", cfgRoot)

	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	pair, _ := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)}),
	)

	tok := fakeToken("42")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health/live":
			_, _ = w.Write([]byte(`{"status":"live"}`))
		case "/api/v1/client/info":
			_ = json.NewEncoder(w).Encode(client.ClientInfo{
				AuthURL: "https://127.0.0.1:57049",
				CAPEM:   string(caPEM),
			})
		case "/api/v1/auth/login":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"identity_token": tok,
				"lore_token":     tok,
				"token_type":     "Bearer",
				"username":       "alice",
			})
		case "/api/v1/projects":
			if r.Header.Get("Authorization") != "Bearer "+tok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"projects":[{"Name":"Kubee"}]}`))
		case "/api/v1/me/modules":
			if r.Header.Get("Authorization") != "Bearer "+tok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"modules":[{"ProjectName":"Kubee","Name":"Pandora","MountPath":"Pandora","RepositoryURL":"grpcs://127.0.0.1:57047/repo1","Permission":"write"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	restoreExecutor(t)
	newExecutor = func(string) loreexec.Executor { return helperExecutor() }

	// Reject --password arg.
	if code := run([]string{"connect", "--manager", srv.URL, "--username", "alice", "--password", "secret"}); code == 0 {
		t.Fatal("expected --password flag to be rejected")
	}

	stdin = strings.NewReader("correct-horse\n")
	var out, errBuf bytes.Buffer
	stdout, stderr = &out, &errBuf
	code := run([]string{
		"connect", "--manager", srv.URL, "--username", "alice",
		"--password-stdin", "--lore-binary", os.Args[0], "--json",
	})
	if code != 0 {
		t.Fatalf("connect failed code=%d stderr=%s", code, errBuf.String())
	}
	if strings.Contains(out.String(), "correct-horse") || strings.Contains(errBuf.String(), "correct-horse") ||
		strings.Contains(out.String(), tok) || strings.Contains(errBuf.String(), tok) {
		t.Fatal("connect output leaked secret")
	}
	var connRes client.ConnectResult
	if err := json.Unmarshal(out.Bytes(), &connRes); err != nil {
		t.Fatalf("invalid connect json: %v\n%s", err, out.String())
	}
	if connRes.ModulesCount != 1 || connRes.AuthURL != "https://127.0.0.1:57049" {
		t.Fatalf("unexpected connect result: %+v", connRes)
	}

	// Follow-up commands work WITHOUT --config!
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"project", "list"}); code != 0 || !strings.Contains(out.String(), "Kubee") {
		t.Fatalf("project list failed code=%d out=%s err=%s", code, out.String(), errBuf.String())
	}

	out.Reset()
	errBuf.Reset()
	if code := run([]string{"project", "use", "Kubee"}); code != 0 || !strings.Contains(out.String(), "Kubee") {
		t.Fatalf("project use failed code=%d out=%s err=%s", code, out.String(), errBuf.String())
	}

	out.Reset()
	errBuf.Reset()
	if code := run([]string{"module", "list"}); code != 0 || !strings.Contains(out.String(), "Pandora") {
		t.Fatalf("module list failed code=%d out=%s err=%s", code, out.String(), errBuf.String())
	}

	// Manual --config remains isolated and continues to work.
	manualDir := t.TempDir()
	manualCfg := filepath.Join(manualDir, "manual.toml")
	if err := client.Save(client.Config{Path: manualCfg, ManagerURL: srv.URL, CAFile: connRes.CAFile, AuthStore: "fallback", AuthPath: filepath.Join(manualDir, "auth"), Project: "Kubee"}); err != nil {
		t.Fatal(err)
	}
	if err := client.SaveSession(client.Config{Path: manualCfg, AuthPath: filepath.Join(manualDir, "auth")}, []byte(tok)); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"module", "list", "--config", manualCfg}); code != 0 || !strings.Contains(out.String(), "Pandora") {
		t.Fatalf("manual --config module list failed code=%d out=%s err=%s", code, out.String(), errBuf.String())
	}
}
