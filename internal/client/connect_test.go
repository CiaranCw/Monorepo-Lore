package client

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lore-monorepo/internal/loreexec"
)

type testCA struct {
	caCert  *x509.Certificate
	caPEM   []byte
	caKey   *rsa.PrivateKey
	tlsCert tls.Certificate
	leaf    *x509.Certificate
}

type testChainCA struct {
	rootCert  *x509.Certificate
	rootPEM   []byte
	rootKey   *rsa.PrivateKey
	interCert *x509.Certificate
	interPEM  []byte
	interKey  *rsa.PrivateKey
	leafCert  *x509.Certificate
	leafPEM   []byte
	tlsCert   tls.Certificate // [Leaf, Intermediate]
	leafOnly  tls.Certificate // [Leaf] only
}

func makeTestCA(t *testing.T, cn string, ipSANs []net.IP, dnsSANs []string, notBefore, notAfter time.Time) testCA {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn + "-CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ipSANs,
		DNSNames:     dnsSANs,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})
	pair, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{
		caCert:  caCert,
		caPEM:   caPEM,
		caKey:   caKey,
		tlsCert: pair,
		leaf:    leafCert,
	}
}

func makeTestChainCA(t *testing.T, cn string, ipSANs []net.IP, dnsSANs []string, notBefore, notAfter time.Time) testChainCA {
	t.Helper()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn + "-Root-CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	interKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	interTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: cn + "-Intermediate-CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTpl, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	interCert, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatal(err)
	}
	interPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER})

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ipSANs,
		DNSNames:     dnsSANs,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, interCert, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})

	chainPEM := append([]byte(nil), leafPEM...)
	chainPEM = append(chainPEM, interPEM...)
	fullPair, err := tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leafOnlyPair, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return testChainCA{
		rootCert:  rootCert,
		rootPEM:   rootPEM,
		rootKey:   rootKey,
		interCert: interCert,
		interPEM:  interPEM,
		interKey:  interKey,
		leafCert:  leafCert,
		leafPEM:   leafPEM,
		tlsCert:   fullPair,
		leafOnly:  leafOnlyPair,
	}
}

func setTempUserConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AppData", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	return dir
}

func startTLSManagerMock(t *testing.T, cert tls.Certificate, caPEM []byte, authURL string, exposeClientInfo bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health/live":
			_, _ = w.Write([]byte(`{"status":"live"}`))
		case "/api/v1/client/info":
			if !exposeClientInfo {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(ClientInfo{
				ManagerVersion: "test",
				AuthURL:        authURL,
				RemoteBaseURL:  "grpcs://127.0.0.1:57047",
				CAPEM:          string(caPEM),
			})
		case "/api/v1/auth/login":
			var body struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			sub := "10"
			if body.Username == "bob" {
				sub = "11"
			}
			tok := fakeIdentity(sub)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"identity_token": tok,
				"lore_token":     tok,
				"token_type":     "Bearer",
				"username":       body.Username,
			})
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"projects":[{"Name":"Kubee"},{"Name":"Sandbox"}]}`))
		case "/api/v1/me/modules":
			_, _ = w.Write([]byte(`{"modules":[{"ProjectName":"Kubee","Name":"Pandora","MountPath":"Pandora","RepositoryURL":"grpcs://127.0.0.1:57047/repo1","Permission":"write"},{"ProjectName":"Kubee","Name":"rogue","MountPath":"rogue","RepositoryURL":"grpcs://127.0.0.1:57047/repo2","Permission":"write"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestConnectZeroConfigHTTPSWithTOFUAndInfo(t *testing.T) {
	cfgRoot := setTempUserConfigDir(t)
	cwdDecoyDir := t.TempDir()
	decoyPath := filepath.Join(cwdDecoyDir, "client.toml")
	if err := os.WriteFile(decoyPath, []byte("manager_url = \"http://127.0.0.1:1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prevWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(cwdDecoyDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prevWD) })

	ca := makeTestCA(t, "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, []string{"localhost"}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	srv := startTLSManagerMock(t, ca.tlsCert, ca.caPEM, "https://127.0.0.1:57049", true)

	exec := testLore(t)
	res, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "alice",
		Password:   []byte("secret-pw"),
		Project:    "Kubee",
	}, exec)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	if !res.TOFUTrusted {
		t.Fatalf("expected TOFUTrusted=true on first connect")
	}
	if res.CASHA256 != CertSHA256Hex(ca.caCert) {
		t.Fatalf("unexpected CA SHA256 %s vs %s", res.CASHA256, CertSHA256Hex(ca.caCert))
	}
	if res.AuthURL != "https://127.0.0.1:57049" || res.Project != "Kubee" || res.ModulesCount != 2 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if !strings.HasPrefix(res.ConfigPath, filepath.Join(cfgRoot, "lore-mono", "profiles")) {
		t.Fatalf("config not stored in user config dir: %s", res.ConfigPath)
	}
	decoyBytes, _ := os.ReadFile(decoyPath)
	if !strings.Contains(string(decoyBytes), "127.0.0.1:1") {
		t.Fatalf("decoy CWD config was modified")
	}

	active, err := ActiveConfigPath()
	if err != nil || active != res.ConfigPath {
		t.Fatalf("ActiveConfigPath=%q err=%v want %q", active, err, res.ConfigPath)
	}
	loaded, err := Load(active)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AuthURL != "https://127.0.0.1:57049" || loaded.Project != "Kubee" || loaded.CAFile != res.CAFile || loaded.TrustMode != "pinned" {
		t.Fatalf("unexpected saved config: %+v", loaded)
	}
	pinBody, err := os.ReadFile(PinPathForCA(res.CAFile))
	if err != nil || !strings.HasPrefix(string(pinBody), "v2:") {
		t.Fatalf("expected v2 pin file, got %q err=%v", string(pinBody), err)
	}
	if _, err := os.Stat(filepath.Join(res.AuthPath, "lore-mono-session.tok")); err != nil {
		t.Fatalf("missing persistent session: %v", err)
	}
	cfgRaw, _ := os.ReadFile(res.ConfigPath)
	if strings.Contains(string(cfgRaw), "secret-pw") || strings.Contains(string(cfgRaw), "eyJ") {
		t.Fatalf("secret leaked into client.toml")
	}
}

func TestConnectTwoUsersIsolated(t *testing.T) {
	setTempUserConfigDir(t)
	ca := makeTestCA(t, "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	srv := startTLSManagerMock(t, ca.tlsCert, ca.caPEM, "https://127.0.0.1:57049", true)
	exec := testLore(t)

	resA, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "alice",
		Password:   []byte("pwA"),
		Project:    "Kubee",
	}, exec)
	if err != nil {
		t.Fatal(err)
	}
	resB, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "bob",
		Password:   []byte("pwB"),
		Project:    "Sandbox",
	}, exec)
	if err != nil {
		t.Fatal(err)
	}
	if resA.ProfileDir == resB.ProfileDir || resA.ConfigPath == resB.ConfigPath || resA.AuthPath == resB.AuthPath {
		t.Fatalf("profiles collided: A=%+v B=%+v", resA, resB)
	}
	cfgA, err := Load(resA.ConfigPath)
	if err != nil || cfgA.Project != "Kubee" {
		t.Fatalf("alice config overwritten: %+v err=%v", cfgA, err)
	}
	cfgB, err := Load(resB.ConfigPath)
	if err != nil || cfgB.Project != "Sandbox" {
		t.Fatalf("bob config unexpected: %+v err=%v", cfgB, err)
	}
	tokA, err := LoadSession(cfgA)
	if err != nil || len(tokA) == 0 {
		t.Fatal(err)
	}
	tokB, err := LoadSession(cfgB)
	if err != nil || len(tokB) == 0 {
		t.Fatal(err)
	}
	if string(tokA) == string(tokB) {
		t.Fatalf("alice and bob share the same session token")
	}
}

func TestConnectRejectsAppendedCAAndTamperedOrDeletedPin(t *testing.T) {
	setTempUserConfigDir(t)
	caA := makeTestCA(t, "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	caB := makeTestCA(t, "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	srv := startTLSManagerMock(t, caA.tlsCert, caA.caPEM, "", true)
	exec := testLore(t)

	res, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "alice",
		Password:   []byte("pw"),
	}, exec)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Append CA_B after CA_A while CA_A remains first -> MUST reject expanded trust set in both HTTPClient and Connect!
	appended := append(append([]byte(nil), caA.caPEM...), caB.caPEM...)
	if err := os.WriteFile(res.CAFile, appended, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := HTTPClient(cfg).Get(srv.URL + "/health/live"); err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("expected fingerprint mismatch when CA_B appended to CA_A, got %v", err)
	}
	if _, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "alice",
		Password:   []byte("pw"),
	}, exec); err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("expected Connect to reject expanded CA_A+CA_B bundle, got %v", err)
	}
	// Restore CA_A -> works again.
	if err := os.WriteFile(res.CAFile, caA.caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	resp, err := HTTPClient(cfg).Get(srv.URL + "/health/live")
	if err != nil {
		t.Fatalf("expected restored CA_A to succeed, got %v", err)
	}
	resp.Body.Close()

	// 2. Tamper pin -> reject.
	pinPath := PinPathForCA(res.CAFile)
	origPin, err := os.ReadFile(pinPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinPath, []byte("v2:0000000000000000000000000000000000000000000000000000000000000000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := HTTPClient(cfg).Get(srv.URL + "/health/live"); err == nil {
		t.Fatal("expected tampered pin to be rejected")
	}

	// 3. Corrupt pin format -> reject.
	if err := os.WriteFile(pinPath, []byte("not-a-pin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := HTTPClient(cfg).Get(srv.URL + "/health/live"); err == nil {
		t.Fatal("expected corrupted pin to be rejected")
	}

	// 4. Delete pin from auto profile -> reject fail-closed (never fall back!).
	if err := os.Remove(pinPath); err != nil {
		t.Fatal(err)
	}
	if _, err := HTTPClient(cfg).Get(srv.URL + "/health/live"); err == nil || !strings.Contains(err.Error(), "pin") {
		t.Fatalf("expected auto profile with deleted pin to fail closed, got %v", err)
	}
	_ = os.WriteFile(pinPath, origPin, 0o600)
}

func TestLegacyPinCompatibilityAndMultiCertRejection(t *testing.T) {
	setTempUserConfigDir(t)
	caA := makeTestCA(t, "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	caB := makeTestCA(t, "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	srv := startTLSManagerMock(t, caA.tlsCert, caA.caPEM, "", true)

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	pinPath := filepath.Join(dir, "ca.pin")
	cfgPath := filepath.Join(dir, "client.toml")

	// Legacy B2.13 v1 pin (bare hex of CA_A) + single CA_A -> compatible!
	if err := os.WriteFile(caPath, caA.caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinPath, []byte(CertSHA256Hex(caA.caCert)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Path: cfgPath, ManagerURL: srv.URL, CAFile: caPath, TrustMode: "pinned"}
	resp, err := HTTPClient(cfg).Get(srv.URL + "/health/live")
	if err != nil {
		t.Fatalf("single-cert legacy v1 pin should remain compatible: %v", err)
	}
	resp.Body.Close()

	// Historical multi-cert bundle [CA_A, CA_B] with legacy v1 pin -> MUST NOT expand trust to CA_B!
	bundle := append(append([]byte(nil), caA.caPEM...), caB.caPEM...)
	if err := os.WriteFile(caPath, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := HTTPClient(cfg).Get(srv.URL + "/health/live"); err == nil || !strings.Contains(err.Error(), "legacy ca pin") {
		t.Fatalf("expected legacy v1 pin to reject multi-cert bundle, got %v", err)
	}

	// Explicit --retrust-ca with --ca-file migrates safely to v2 pin covering the full bundle.
	bundlePath := filepath.Join(dir, "bundle.pem")
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	exec := testLore(t)
	res, err := Connect(context.Background(), ConnectOptions{
		ManagerURL:         srv.URL,
		Username:           "alice",
		Password:           []byte("pw"),
		ExplicitCAFile:     bundlePath,
		RetrustCA:          true,
		ExplicitConfigPath: cfgPath,
	}, exec)
	if err != nil {
		t.Fatalf("explicit --retrust-ca failed: %v", err)
	}
	if res.CASHA256 != CertSetSHA256Hex([]*x509.Certificate{caA.caCert, caB.caCert}) {
		t.Fatalf("unexpected v2 multi-cert digest: %s", res.CASHA256)
	}
	// Order-independent check: [CA_B, CA_A] yields identical set digest.
	reversed := append(append([]byte(nil), caB.caPEM...), caA.caPEM...)
	if _, revDigest, err := ParseCAPEMBundle(reversed); err != nil || revDigest != res.CASHA256 {
		t.Fatalf("expected order-independent set digest, got %s vs %s err=%v", revDigest, res.CASHA256, err)
	}
}

func TestConnectRootIntermediateLeafChainValidation(t *testing.T) {
	setTempUserConfigDir(t)
	now := time.Now()
	chain := makeTestChainCA(t, "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, []string{"localhost"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	wrongRoot := makeTestChainCA(t, "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, []string{"localhost"}, now.Add(-time.Hour), now.Add(24*time.Hour))

	// 1. Valid Root -> Intermediate -> Leaf (server sends [Leaf, Intermediate]; Manager provides Root).
	srv := startTLSManagerMock(t, chain.tlsCert, chain.rootPEM, "", true)
	exec := testLore(t)
	res, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "alice",
		Password:   []byte("pw"),
	}, exec)
	if err != nil {
		t.Fatalf("Root -> Intermediate -> Leaf connect failed: %v", err)
	}
	if res.CASHA256 != CertSHA256Hex(chain.rootCert) {
		t.Fatalf("expected Root CA digest %s, got %s", CertSHA256Hex(chain.rootCert), res.CASHA256)
	}

	// 2. Explicit --ca-file with Root only against server sending [Leaf, Intermediate].
	rootPath := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(rootPath, chain.rootPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Connect(context.Background(), ConnectOptions{
		ManagerURL:     srv.URL,
		Username:       "bob",
		Password:       []byte("pw"),
		ExplicitCAFile: rootPath,
	}, exec); err != nil {
		t.Fatalf("explicit Root CA with Intermediate chain failed: %v", err)
	}

	// 3. Untrusted / missing intermediate (server sends [Leaf] only, --ca-file has Root only) -> MUST reject.
	setTempUserConfigDir(t)
	srvNoInter := startTLSManagerMock(t, chain.leafOnly, chain.rootPEM, "", true)
	if _, err := Connect(context.Background(), ConnectOptions{
		ManagerURL:     srvNoInter.URL,
		Username:       "alice",
		Password:       []byte("pw"),
		ExplicitCAFile: rootPath,
	}, exec); err == nil {
		t.Fatal("expected missing/untrusted intermediate to be rejected")
	}

	// 4. Wrong Root CA against [Leaf, Intermediate] -> MUST reject.
	setTempUserConfigDir(t)
	wrongRootPath := filepath.Join(t.TempDir(), "wrong-root.pem")
	if err := os.WriteFile(wrongRootPath, wrongRoot.rootPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Connect(context.Background(), ConnectOptions{
		ManagerURL:     srv.URL,
		Username:       "alice",
		Password:       []byte("pw"),
		ExplicitCAFile: wrongRootPath,
	}, exec); err == nil {
		t.Fatal("expected wrong Root CA to be rejected")
	}

	// 5. Server sends [Leaf, WrongIntermediate] where leaf is actually signed by WrongIntermediate -> Root must reject.
	setTempUserConfigDir(t)
	srvBadChain := startTLSManagerMock(t, wrongRoot.tlsCert, chain.rootPEM, "", true)
	if _, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srvBadChain.URL,
		Username:   "alice",
		Password:   []byte("pw"),
	}, exec); err == nil {
		t.Fatal("expected untrusted intermediate chain to be rejected during TOFU")
	}
}

func TestConnectRejectsFingerprintChangeAndTamperedCA(t *testing.T) {
	setTempUserConfigDir(t)
	ca1 := makeTestCA(t, "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	ca2 := makeTestCA(t, "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	var currentCA atomic.Value
	currentCA.Store(ca1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := currentCA.Load().(testCA)
		switch r.URL.Path {
		case "/health/live":
			_, _ = w.Write([]byte(`{"status":"live"}`))
		case "/api/v1/client/info":
			_ = json.NewEncoder(w).Encode(ClientInfo{CAPEM: string(cur.caPEM)})
		case "/api/v1/auth/login":
			tok := fakeIdentity("10")
			_ = json.NewEncoder(w).Encode(map[string]any{"identity_token": tok, "lore_token": tok, "token_type": "Bearer", "username": "alice"})
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"projects":[{"Name":"Kubee"}]}`))
		case "/api/v1/me/modules":
			_, _ = w.Write([]byte(`{"modules":[{"ProjectName":"Kubee","Name":"Pandora","MountPath":"Pandora","RepositoryURL":"grpcs://127.0.0.1:57047/repo1","Permission":"write"}]}`))
		}
	}))
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			cur := currentCA.Load().(testCA)
			return &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{cur.tlsCert},
			}, nil
		},
	}
	srv.StartTLS()
	defer srv.Close()

	exec := testLore(t)
	res, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "alice",
		Password:   []byte("pw"),
	}, exec)
	if err != nil {
		t.Fatal(err)
	}

	// Swap server cert to CA2 -> both same user and a second user must reject fingerprint change.
	currentCA.Store(ca2)
	if _, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "alice",
		Password:   []byte("pw"),
	}, exec); err == nil {
		t.Fatal("expected rotated CA / MITM to be rejected for existing user")
	}
	if _, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "bob",
		Password:   []byte("pw"),
	}, exec); err == nil {
		t.Fatal("expected rotated CA / MITM to be rejected by host pin for second user")
	}

	// Tamper ca.pem on disk -> HTTPClient must refuse requests.
	if err := os.WriteFile(res.CAFile, ca2.caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := HTTPClient(cfg).Get(srv.URL + "/health/live"); err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("expected fingerprint mismatch on tampered ca.pem, got %v", err)
	}
}

func TestConnectRejectsExpiredNotYetValidAndWrongHostnameCert(t *testing.T) {
	setTempUserConfigDir(t)
	exec := testLore(t)

	expiredCA := makeTestCA(t, "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	srvExpired := startTLSManagerMock(t, expiredCA.tlsCert, expiredCA.caPEM, "", true)
	if _, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srvExpired.URL,
		Username:   "alice",
		Password:   []byte("pw"),
	}, exec); err == nil {
		t.Fatal("expected expired TLS cert to be rejected during TOFU")
	}

	futureCA := makeTestCA(t, "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour))
	srvFuture := startTLSManagerMock(t, futureCA.tlsCert, futureCA.caPEM, "", true)
	if _, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srvFuture.URL,
		Username:   "alice",
		Password:   []byte("pw"),
	}, exec); err == nil {
		t.Fatal("expected not-yet-valid TLS cert to be rejected during TOFU")
	}

	wrongHostCA := makeTestCA(t, "evil.invalid", nil, []string{"evil.invalid"}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	srvWrongHost := startTLSManagerMock(t, wrongHostCA.tlsCert, wrongHostCA.caPEM, "", true)
	if _, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srvWrongHost.URL,
		Username:   "alice",
		Password:   []byte("pw"),
	}, exec); err == nil {
		t.Fatal("expected wrong hostname TLS cert to be rejected during TOFU")
	}
}

func TestConnectLegacyLeafOnlyRollbackAndExplicitCARecovery(t *testing.T) {
	cfgRoot := setTempUserConfigDir(t)
	ca := makeTestCA(t, "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	// Simulate legacy B2.11.1 server: sends Leaf only, no /api/v1/client/info.
	srv := startTLSManagerMock(t, ca.tlsCert, nil, "", false)

	// Simulate Lore CLI rejecting leaf-only ca.pem while accepting ca.caPEM.
	exec := testLore(t)
	exec.Config.Env["LORE_MONO_FAIL_LOGIN"] = "1"

	normURL, err := NormalizeManagerURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	baseDir := filepath.Join(cfgRoot, "lore-mono")
	profDir := ProfileDir(baseDir, normURL, "alice")
	hostPin := HostPinPath(baseDir, normURL)
	hostCA := HostCAPath(baseDir, normURL)

	// First connect: fails in Lore login -> MUST roll back ALL temporary trust/profile state!
	if _, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "alice",
		Password:   []byte("pw"),
	}, exec); err == nil {
		t.Fatal("expected leaf-only connect failure when Lore rejects leaf cert")
	}
	for _, p := range []string{
		filepath.Join(profDir, "client.toml"),
		filepath.Join(profDir, "ca.pem"),
		filepath.Join(profDir, "ca.pin"),
		hostPin,
		hostCA,
	} {
		if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
			t.Fatalf("failed leaf-only connect left stale artifact: %s", p)
		}
	}

	// Second connect: user explicitly supplies the real CA via --ca-file -> MUST succeed cleanly!
	exec.Config.Env["LORE_MONO_FAIL_LOGIN"] = "0"
	caFile := filepath.Join(t.TempDir(), "real-ca.pem")
	if err := os.WriteFile(caFile, ca.caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Connect(context.Background(), ConnectOptions{
		ManagerURL:     srv.URL,
		Username:       "alice",
		Password:       []byte("pw"),
		ExplicitCAFile: caFile,
	}, exec)
	if err != nil {
		t.Fatalf("explicit --ca-file recovery failed: %v", err)
	}
	if res.CASHA256 != CertSHA256Hex(ca.caCert) {
		t.Fatalf("expected recovered pin to match real CA, got %s", res.CASHA256)
	}

	// Ensure a subsequent failed attempt (e.g. Lore failure or wrong password) does NOT wipe existing valid profile/pins!
	exec.Config.Env["LORE_MONO_FAIL_LOGIN"] = "1"
	if _, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "alice",
		Password:   []byte("pw"),
	}, exec); err == nil {
		t.Fatal("expected failure on simulated login error")
	}
	if _, err := os.Stat(res.ConfigPath); err != nil {
		t.Fatalf("pre-existing valid config deleted on later failure: %v", err)
	}
	if _, err := os.Stat(PinPathForCA(res.CAFile)); err != nil {
		t.Fatalf("pre-existing valid pin deleted on later failure: %v", err)
	}
	if _, err := os.Stat(hostPin); err != nil {
		t.Fatalf("pre-existing valid host pin deleted on later failure: %v", err)
	}
}

func TestHTTPClientFailClosedAndManualCompat(t *testing.T) {
	cfgRoot := setTempUserConfigDir(t)
	ca := makeTestCA(t, "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	srv := startTLSManagerMock(t, ca.tlsCert, ca.caPEM, "", true)

	// 1. Missing CA file -> fail closed, never fall back to system roots!
	missingCfg := Config{ManagerURL: srv.URL, CAFile: filepath.Join(t.TempDir(), "missing.pem")}
	if _, err := HTTPClient(missingCfg).Get(srv.URL + "/health/live"); err == nil || !IsTrustError(err) {
		t.Fatalf("expected fail-closed trustError for missing CA file, got %v", err)
	}

	// 2. Corrupted CA file -> fail closed.
	badCAPath := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(badCAPath, []byte("not-a-pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := HTTPClient(Config{ManagerURL: srv.URL, CAFile: badCAPath}).Get(srv.URL + "/health/live"); err == nil || !IsTrustError(err) {
		t.Fatalf("expected fail-closed trustError for bad CA file, got %v", err)
	}

	// 3. Auto profile under profiles/ without ca.pin -> fail closed even if ca.pem is readable!
	profDir := filepath.Join(cfgRoot, "lore-mono", "profiles", "test-prof")
	if err := os.MkdirAll(profDir, 0o700); err != nil {
		t.Fatal(err)
	}
	profCA := filepath.Join(profDir, "ca.pem")
	if err := os.WriteFile(profCA, ca.caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	autoCfg := Config{Path: filepath.Join(profDir, "client.toml"), ManagerURL: srv.URL, CAFile: profCA}
	if _, err := HTTPClient(autoCfg).Get(srv.URL + "/health/live"); err == nil || !IsTrustError(err) {
		t.Fatalf("expected fail-closed when auto profile lacks ca.pin, got %v", err)
	}

	// 4. Manual --config outside profiles/ with valid ca.pem and NO ca.pin -> compatible!
	manualDir := t.TempDir()
	manualCA := filepath.Join(manualDir, "ca.pem")
	if err := os.WriteFile(manualCA, ca.caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	manualCfg := Config{Path: filepath.Join(manualDir, "client.toml"), ManagerURL: srv.URL, CAFile: manualCA}
	resp, err := HTTPClient(manualCfg).Get(srv.URL + "/health/live")
	if err != nil {
		t.Fatalf("manual config with valid ca_file should succeed: %v", err)
	}
	resp.Body.Close()
}

func TestIsUnknownAuthorityErrorStrictClassification(t *testing.T) {
	if !isUnknownAuthorityError(x509.UnknownAuthorityError{}) {
		t.Fatal("expected x509.UnknownAuthorityError to be classified as unknown authority")
	}
	if !isUnknownAuthorityError(fmt.Errorf("tls handshake: %w", x509.UnknownAuthorityError{})) {
		t.Fatal("expected wrapped x509.UnknownAuthorityError to be classified as unknown authority")
	}
	nonTOFU := []error{
		x509.HostnameError{Host: "example.com"},
		x509.CertificateInvalidError{Reason: x509.Expired},
		x509.CertificateInvalidError{Reason: x509.NotAuthorizedToSign},
		errors.New("remote server sent unknown authority string in non-x509 error"),
		errors.New("tls: certificate is not trusted"),
		errors.New("connection refused"),
	}
	for _, err := range nonTOFU {
		if isUnknownAuthorityError(err) {
			t.Fatalf("non-UnknownAuthorityError %T (%v) was wrongly allowed into TOFU", err, err)
		}
	}
}

func TestConnectRetrustCAToSystemRootRemovesStaleCAAndSupportsSecondConnect(t *testing.T) {
	cfgRoot := setTempUserConfigDir(t)
	internalCA := makeTestCA(t, "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, []string{"localhost"}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	sysCA := makeTestCA(t, "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, []string{"localhost"}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	otherCA := makeTestCA(t, "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, []string{"localhost"}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	var curTLS atomic.Value
	var curCAPEM atomic.Value
	curTLS.Store(internalCA.tlsCert)
	curCAPEM.Store(string(internalCA.caPEM))

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health/live":
			_, _ = w.Write([]byte(`{"status":"live"}`))
		case "/api/v1/client/info":
			_ = json.NewEncoder(w).Encode(ClientInfo{
				ManagerVersion: "test",
				CAPEM:          curCAPEM.Load().(string),
			})
		case "/api/v1/auth/login":
			tok := fakeIdentity("10")
			_ = json.NewEncoder(w).Encode(map[string]any{"identity_token": tok, "lore_token": tok, "token_type": "Bearer", "username": "alice"})
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"projects":[{"Name":"Kubee"}]}`))
		case "/api/v1/me/modules":
			_, _ = w.Write([]byte(`{"modules":[{"ProjectName":"Kubee","Name":"Pandora","MountPath":"Pandora","RepositoryURL":"grpcs://127.0.0.1:57047/repo1","Permission":"write"}]}`))
		}
	}))
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			cert := curTLS.Load().(tls.Certificate)
			return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}, nil
		},
	}
	srv.StartTLS()
	defer srv.Close()

	// Separate profile on a different Manager to verify it is never affected.
	srvOther := startTLSManagerMock(t, otherCA.tlsCert, otherCA.caPEM, "", true)

	exec := testLore(t)
	resInit, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "alice",
		Password:   []byte("pw"),
	}, exec)
	if err != nil {
		t.Fatal(err)
	}
	resOther, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srvOther.URL,
		Username:   "bob",
		Password:   []byte("pw"),
	}, exec)
	if err != nil {
		t.Fatal(err)
	}

	normURL, _ := NormalizeManagerURL(srv.URL)
	hostCA := HostCAPath(filepath.Join(cfgRoot, "lore-mono"), normURL)
	if _, err := os.Stat(resInit.CAFile); err != nil {
		t.Fatalf("expected initial profile ca.pem: %v", err)
	}
	if _, err := os.Stat(hostCA); err != nil {
		t.Fatalf("expected initial host CA cache: %v", err)
	}

	// Simulate srv rotating to a cert trusted by system roots, with NO ca_pem in /api/v1/client/info.
	sysPool := x509.NewCertPool()
	sysPool.AddCert(sysCA.caCert)
	prevRoots := testSystemRootCAs
	testSystemRootCAs = sysPool
	t.Cleanup(func() { testSystemRootCAs = prevRoots })
	curTLS.Store(sysCA.tlsCert)
	curCAPEM.Store("")

	// Failed --retrust-ca (e.g., unknown project) MUST roll back deletion of old ca.pem and host CA cache!
	if _, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "alice",
		Password:   []byte("pw"),
		Project:    "NoSuchProject",
		RetrustCA:  true,
	}, exec); err == nil {
		t.Fatal("expected failure on missing project")
	}
	if gotCA, err := os.ReadFile(resInit.CAFile); err != nil || string(gotCA) != string(internalCA.caPEM) {
		t.Fatalf("failed --retrust-ca did not restore old profile ca.pem: err=%v", err)
	}
	if gotHostCA, err := os.ReadFile(hostCA); err != nil || string(gotHostCA) != string(internalCA.caPEM) {
		t.Fatalf("failed --retrust-ca did not restore old host CA cache: err=%v", err)
	}

	// Successful --retrust-ca transitions cleanly to system-root pinning and removes stale ca.pem / hostCA.
	resRetrust, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "alice",
		Password:   []byte("pw"),
		RetrustCA:  true,
	}, exec)
	if err != nil {
		t.Fatalf("--retrust-ca to system root failed: %v", err)
	}
	if resRetrust.CAFile != "" {
		t.Fatalf("expected empty CAFile after retrust to system roots without ca_pem, got %q", resRetrust.CAFile)
	}
	if resRetrust.CASHA256 != CertSHA256Hex(sysCA.caCert) {
		t.Fatalf("expected system root pin %s, got %s", CertSHA256Hex(sysCA.caCert), resRetrust.CASHA256)
	}
	if _, err := os.Stat(resInit.CAFile); !os.IsNotExist(err) {
		t.Fatalf("stale profile ca.pem still exists after --retrust-ca: err=%v", err)
	}
	if _, err := os.Stat(hostCA); !os.IsNotExist(err) {
		t.Fatalf("stale host CA cache still exists after --retrust-ca: err=%v", err)
	}

	// Second Connect WITHOUT --retrust-ca MUST succeed!
	resSecond, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "alice",
		Password:   []byte("pw"),
	}, exec)
	if err != nil {
		t.Fatalf("second Connect after system-root retrust failed: %v", err)
	}
	if resSecond.CASHA256 != CertSHA256Hex(sysCA.caCert) {
		t.Fatalf("unexpected pin on second connect: %s", resSecond.CASHA256)
	}
	cfg, err := Load(resSecond.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := HTTPClient(cfg).Get(srv.URL + "/health/live")
	if err != nil {
		t.Fatalf("HTTPClient failed after system-root retrust: %v", err)
	}
	resp.Body.Close()

	// Other profile on srvOther remains completely untouched.
	if gotOther, err := os.ReadFile(resOther.CAFile); err != nil || string(gotOther) != string(otherCA.caPEM) {
		t.Fatalf("other profile ca.pem was affected: err=%v", err)
	}
}

func TestConnectSnapshotAndRollbackErrorHandling(t *testing.T) {
	cfgRoot := setTempUserConfigDir(t)
	ca := makeTestCA(t, "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	srv := startTLSManagerMock(t, ca.tlsCert, ca.caPEM, "", true)
	exec := testLore(t)

	// 1. Non-NotExist error during snapshotFiles must abort Connect immediately.
	normURL, _ := NormalizeManagerURL(srv.URL)
	baseDir := filepath.Join(cfgRoot, "lore-mono")
	profDir := ProfileDir(baseDir, normURL, "alice")
	caAsDir := filepath.Join(profDir, "ca.pem")
	if err := os.MkdirAll(caAsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "alice",
		Password:   []byte("pw"),
	}, exec); err == nil || !strings.Contains(err.Error(), "snapshot") {
		t.Fatalf("expected snapshot error when ca.pem is a directory, got %v", err)
	}
	_ = os.RemoveAll(profDir)

	// 2. Rollback write failure on existing profile must NOT silently return only the normal error.
	res, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "alice",
		Password:   []byte("pw"),
	}, exec)
	if err != nil {
		t.Fatal(err)
	}
	prevWrite := rollbackWriteFile
	rollbackWriteFile = func(path string, body []byte) error {
		if path == res.ConfigPath || path == PinPathForCA(res.CAFile) {
			return errors.New("injected disk write failure")
		}
		return prevWrite(path, body)
	}
	_, err = Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "alice",
		Password:   []byte("pw"),
		Project:    "NoSuchProject",
	}, exec)
	rollbackWriteFile = prevWrite
	if err == nil || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("expected rollback failed error to be surfaced, got %v", err)
	}

	// 3. Rollback remove failure on fresh profile must surface rollback error.
	prevRemove := rollbackRemove
	rollbackRemove = func(path string) error {
		if strings.HasSuffix(path, "ca.pem") {
			return errors.New("injected remove failure")
		}
		return prevRemove(path)
	}
	_, err = Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "bob",
		Password:   []byte("pw"),
		Project:    "NoSuchProject",
	}, exec)
	rollbackRemove = prevRemove
	if err == nil || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("expected rollback remove failure to be surfaced, got %v", err)
	}
}

func TestConnectCleansUpNewAuthCredentialsOnDiscoveryFailureAndPreservesExisting(t *testing.T) {
	cfgRoot := setTempUserConfigDir(t)
	ca := makeTestCA(t, "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	var loginCount int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health/live":
			_, _ = w.Write([]byte(`{"status":"live"}`))
		case "/api/v1/client/info":
			_ = json.NewEncoder(w).Encode(ClientInfo{CAPEM: string(ca.caPEM)})
		case "/api/v1/auth/login":
			n := atomic.AddInt32(&loginCount, 1)
			tok := fakeIdentity(fmt.Sprintf("%d", 10+n))
			_ = json.NewEncoder(w).Encode(map[string]any{"identity_token": tok, "lore_token": tok, "token_type": "Bearer", "username": "alice"})
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"projects":[{"Name":"Kubee"}]}`))
		case "/api/v1/me/modules":
			_, _ = w.Write([]byte(`{"modules":[{"ProjectName":"Kubee","Name":"Pandora","MountPath":"Pandora","RepositoryURL":"grpcs://127.0.0.1:57047/repo1","Permission":"write"}]}`))
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.tlsCert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	exec := testLore(t)
	normURL, _ := NormalizeManagerURL(srv.URL)
	baseDir := filepath.Join(cfgRoot, "lore-mono")
	profDir := ProfileDir(baseDir, normURL, "alice")
	authDir := filepath.Join(profDir, "auth")

	// Case A: Fresh profile/auth dir where Login succeeds, then project discovery fails -> must remove session, Lore creds, auth dir, and profile dir!
	if _, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "alice",
		Password:   []byte("pw"),
		Project:    "MissingProject",
	}, exec); err == nil {
		t.Fatal("expected error for missing project")
	}
	for _, p := range []string{
		filepath.Join(authDir, "lore-mono-session.tok"),
		filepath.Join(authDir, "identity"),
		authDir,
		profDir,
		HostPinPath(baseDir, normURL),
		HostCAPath(baseDir, normURL),
	} {
		if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
			t.Fatalf("failed Connect left credential/dir artifact %s", p)
		}
	}

	// Case B: Pre-existing valid profile & auth dir (plus unrelated user file) -> later failed Connect restores previous creds & preserves user file!
	res, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "alice",
		Password:   []byte("pw"),
		Project:    "Kubee",
	}, exec)
	if err != nil {
		t.Fatal(err)
	}
	origSess, err := os.ReadFile(filepath.Join(res.AuthPath, "lore-mono-session.tok"))
	if err != nil {
		t.Fatal(err)
	}
	origIdent, err := os.ReadFile(filepath.Join(res.AuthPath, "identity"))
	if err != nil {
		t.Fatal(err)
	}
	userFile := filepath.Join(res.AuthPath, "user-keep.txt")
	if err := os.WriteFile(userFile, []byte("keep-me"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "alice",
		Password:   []byte("pw"),
		Project:    "MissingProject",
	}, exec); err == nil {
		t.Fatal("expected error on second connect with missing project")
	}
	gotSess, err := os.ReadFile(filepath.Join(res.AuthPath, "lore-mono-session.tok"))
	if err != nil || string(gotSess) != string(origSess) {
		t.Fatalf("pre-existing session token was not preserved: got=%q want=%q err=%v", gotSess, origSess, err)
	}
	gotIdent, err := os.ReadFile(filepath.Join(res.AuthPath, "identity"))
	if err != nil || string(gotIdent) != string(origIdent) {
		t.Fatalf("pre-existing identity was not preserved: got=%q want=%q err=%v", gotIdent, origIdent, err)
	}
	gotUser, err := os.ReadFile(userFile)
	if err != nil || string(gotUser) != "keep-me" {
		t.Fatalf("pre-existing user file was modified or deleted: got=%q err=%v", gotUser, err)
	}
}

func TestLockHelperProcess(t *testing.T) {
	if os.Getenv("LORE_MONO_LOCK_HELPER") != "1" {
		return
	}
	lockPath := os.Getenv("LORE_MONO_LOCK_PATH")
	unlock, err := acquireConnectLock(context.Background(), lockPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lock failed: %v\n", err)
		os.Exit(2)
	}
	fmt.Println("LOCKED")
	if os.Getenv("LORE_MONO_LOCK_CRASH") == "1" {
		// Exit without calling unlock() to verify OS kernel releases file lock on crash.
		os.Exit(0)
	}
	// Hold lock until killed by parent.
	time.Sleep(30 * time.Second)
	_ = unlock()
}

func TestConnectHelperProcess(t *testing.T) {
	if os.Getenv("LORE_MONO_CONNECT_HELPER") != "1" {
		return
	}
	managerURL := os.Getenv("LORE_MONO_MANAGER_URL")
	username := os.Getenv("LORE_MONO_USERNAME")
	project := os.Getenv("LORE_MONO_PROJECT")
	execRunner := loreexec.Executor{Config: loreexec.Config{
		Binary:      os.Args[0],
		LeadingArgs: []string{"-test.run=^TestHelperProcess$", "--"},
		Env:         map[string]string{"LORE_MONO_HELPER": "1"},
		Timeout:     5 * time.Second,
	}}
	_, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: managerURL,
		Username:   username,
		Password:   []byte("pw"),
		Project:    project,
	}, execRunner)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func TestAcquireConnectLockCrossProcessAndCrashRecovery(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "locks", "manager.lock")

	// 1. Subprocess holds OS file lock -> parent cannot acquire until released/killed.
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockHelperProcess$")
	cmd.Env = append(os.Environ(), "LORE_MONO_LOCK_HELPER=1", "LORE_MONO_LOCK_PATH="+lockPath)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})

	buf := make([]byte, 32)
	n, err := stdoutPipe.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "LOCKED") {
		t.Fatalf("helper failed to acquire lock: n=%d out=%q err=%v", n, string(buf[:n]), err)
	}

	shortCtx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	if _, err := acquireConnectLock(shortCtx, lockPath); err == nil {
		t.Fatal("expected acquireConnectLock to block while another process holds the lock")
	}

	// 2. Kill child process without unlocking -> kernel releases lock -> parent acquires immediately!
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()

	unlock, err := acquireConnectLock(context.Background(), lockPath)
	if err != nil {
		t.Fatalf("failed to recover lock after process crash: %v", err)
	}
	if err := unlock(); err != nil {
		t.Fatalf("unlock failed: %v", err)
	}
}

func TestConnectConcurrentTwoUsersAndSameUserFailureSafety(t *testing.T) {
	cfgRoot := setTempUserConfigDir(t)
	ca := makeTestCA(t, "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	var activeInProjects int32
	var maxConcurrent int32
	var loginSeq int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health/live":
			_, _ = w.Write([]byte(`{"status":"live"}`))
		case "/api/v1/client/info":
			_ = json.NewEncoder(w).Encode(ClientInfo{CAPEM: string(ca.caPEM)})
		case "/api/v1/auth/login":
			var body struct {
				Username string `json:"username"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			n := atomic.AddInt32(&loginSeq, 1)
			tok := fakeIdentity(fmt.Sprintf("%s-%d", body.Username, n))
			_ = json.NewEncoder(w).Encode(map[string]any{
				"identity_token": tok,
				"lore_token":     tok,
				"token_type":     "Bearer",
				"username":       body.Username,
			})
		case "/api/v1/projects":
			cur := atomic.AddInt32(&activeInProjects, 1)
			for {
				prev := atomic.LoadInt32(&maxConcurrent)
				if cur <= prev || atomic.CompareAndSwapInt32(&maxConcurrent, prev, cur) {
					break
				}
			}
			time.Sleep(60 * time.Millisecond)
			atomic.AddInt32(&activeInProjects, -1)
			_, _ = w.Write([]byte(`{"projects":[{"Name":"Kubee"},{"Name":"Sandbox"}]}`))
		case "/api/v1/me/modules":
			_, _ = w.Write([]byte(`{"modules":[{"ProjectName":"Kubee","Name":"Pandora","MountPath":"Pandora","RepositoryURL":"grpcs://127.0.0.1:57047/repo1","Permission":"write"}]}`))
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.tlsCert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	execRunner := testLore(t)

	// 1. Two users connect concurrently to the same Manager -> serialized by Manager lock, both succeed, host pin consistent.
	var wg sync.WaitGroup
	var resA, resB ConnectResult
	var errA, errB error
	wg.Add(2)
	go func() {
		defer wg.Done()
		resA, errA = Connect(context.Background(), ConnectOptions{
			ManagerURL: srv.URL,
			Username:   "alice",
			Password:   []byte("pw"),
			Project:    "Kubee",
		}, execRunner)
	}()
	go func() {
		defer wg.Done()
		resB, errB = Connect(context.Background(), ConnectOptions{
			ManagerURL: srv.URL,
			Username:   "bob",
			Password:   []byte("pw"),
			Project:    "Sandbox",
		}, execRunner)
	}()
	wg.Wait()
	if errA != nil || errB != nil {
		t.Fatalf("concurrent two-user connect failed: errA=%v errB=%v", errA, errB)
	}
	if resA.ProfileDir == resB.ProfileDir || resA.AuthPath == resB.AuthPath || resA.CASHA256 != resB.CASHA256 {
		t.Fatalf("concurrent two-user connect isolation/pin mismatch: A=%+v B=%+v", resA, resB)
	}
	if atomic.LoadInt32(&maxConcurrent) > 1 {
		t.Fatalf("expected Manager lock to serialize concurrent Connects, maxConcurrent=%d", maxConcurrent)
	}

	normURL, _ := NormalizeManagerURL(srv.URL)
	baseDir := filepath.Join(cfgRoot, "lore-mono")
	hostPin := HostPinPath(baseDir, normURL)
	if _, err := os.Stat(hostPin); err != nil {
		t.Fatalf("missing shared host pin: %v", err)
	}

	// 2. Same user in two terminals simultaneously: one succeeds, one fails at project discovery.
	// Neither order may delete/corrupt the succeeding Connect's auth credentials, profile pin, or host pin.
	for i := 0; i < 2; i++ {
		var okRes ConnectResult
		var okErr, failErr error
		wg.Add(2)
		if i == 0 {
			go func() {
				defer wg.Done()
				okRes, okErr = Connect(context.Background(), ConnectOptions{
					ManagerURL: srv.URL,
					Username:   "carol",
					Password:   []byte("pw"),
					Project:    "Kubee",
				}, execRunner)
			}()
			go func() {
				defer wg.Done()
				time.Sleep(15 * time.Millisecond)
				_, failErr = Connect(context.Background(), ConnectOptions{
					ManagerURL: srv.URL,
					Username:   "carol",
					Password:   []byte("pw"),
					Project:    "MissingProject",
				}, execRunner)
			}()
		} else {
			// Reverse staggered start so failing Connect is likely first and succeeding Connect second.
			go func() {
				defer wg.Done()
				_, failErr = Connect(context.Background(), ConnectOptions{
					ManagerURL: srv.URL,
					Username:   "dave",
					Password:   []byte("pw"),
					Project:    "MissingProject",
				}, execRunner)
			}()
			go func() {
				defer wg.Done()
				time.Sleep(15 * time.Millisecond)
				okRes, okErr = Connect(context.Background(), ConnectOptions{
					ManagerURL: srv.URL,
					Username:   "dave",
					Password:   []byte("pw"),
					Project:    "Kubee",
				}, execRunner)
			}()
		}
		wg.Wait()
		if okErr != nil {
			t.Fatalf("round %d succeeding Connect failed: %v", i, okErr)
		}
		if failErr == nil {
			t.Fatalf("round %d failing Connect unexpectedly succeeded", i)
		}
		if _, err := os.Stat(filepath.Join(okRes.AuthPath, "lore-mono-session.tok")); err != nil {
			t.Fatalf("round %d auth session missing: %v", i, err)
		}
		if _, err := os.Stat(filepath.Join(okRes.AuthPath, "identity")); err != nil {
			t.Fatalf("round %d lore identity missing: %v", i, err)
		}
		if _, err := os.Stat(PinPathForCA(okRes.CAFile)); err != nil {
			t.Fatalf("round %d profile pin missing: %v", i, err)
		}
		if _, err := os.Stat(hostPin); err != nil {
			t.Fatalf("round %d host pin missing: %v", i, err)
		}
	}

	// 3. Cross-process concurrent Connect: child process fails at project discovery while parent succeeds.
	cmd := exec.Command(os.Args[0], "-test.run=^TestConnectHelperProcess$")
	cmd.Env = append(os.Environ(),
		"LORE_MONO_CONNECT_HELPER=1",
		"LORE_MONO_MANAGER_URL="+srv.URL,
		"LORE_MONO_USERNAME=alice",
		"LORE_MONO_PROJECT=MissingProject",
	)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	parentRes, parentErr := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "alice",
		Password:   []byte("pw"),
		Project:    "Kubee",
	}, execRunner)
	childErr := cmd.Wait()
	if parentErr != nil {
		t.Fatalf("parent Connect failed during cross-process race: %v", parentErr)
	}
	if childErr == nil {
		t.Fatal("child failing Connect unexpectedly exited 0")
	}
	if _, err := os.Stat(filepath.Join(parentRes.AuthPath, "lore-mono-session.tok")); err != nil {
		t.Fatalf("cross-process failure deleted parent session: %v", err)
	}
	if _, err := os.Stat(PinPathForCA(parentRes.CAFile)); err != nil {
		t.Fatalf("cross-process failure deleted profile pin: %v", err)
	}
	if _, err := os.Stat(hostPin); err != nil {
		t.Fatalf("cross-process failure deleted host pin: %v", err)
	}

	// 4. After locks are released, re-connecting works cleanly.
	if _, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "alice",
		Password:   []byte("pw"),
		Project:    "Kubee",
	}, execRunner); err != nil {
		t.Fatalf("reconnect after concurrent tests failed: %v", err)
	}
}

func TestConnectNestedAuthDirSnapshotAndRollback(t *testing.T) {
	cfgRoot := setTempUserConfigDir(t)
	ca := makeTestCA(t, "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	srv := startTLSManagerMock(t, ca.tlsCert, ca.caPEM, "", true)

	normURL, _ := NormalizeManagerURL(srv.URL)
	baseDir := filepath.Join(cfgRoot, "lore-mono")
	profDir := ProfileDir(baseDir, normURL, "alice")
	authDir := filepath.Join(profDir, "auth")

	// Pre-existing nested user directory + file inside auth/.
	existingSub := filepath.Join(authDir, "nested", "keep")
	if err := os.MkdirAll(existingSub, 0o700); err != nil {
		t.Fatal(err)
	}
	existingFile := filepath.Join(existingSub, "user.dat")
	if err := os.WriteFile(existingFile, []byte("keep-nested"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Custom executor that writes both a flat credential and a nested subdir/file during login.
	nestedExec := loreexec.Executor{Config: loreexec.Config{
		Binary:      os.Args[0],
		LeadingArgs: []string{"-test.run=^TestHelperProcess$", "--"},
		Env:         map[string]string{"LORE_MONO_HELPER": "1"},
		Timeout:     5 * time.Second,
	}}
	// Also simulate a new nested directory appearing in auth/ before Connect fails at project discovery.
	newSub := filepath.Join(authDir, "new-sub")
	if err := os.MkdirAll(newSub, 0o700); err != nil {
		t.Fatal(err)
	}
	// First connect succeeds and records only existingSub; then create newSub during a failing Connect.
	if _, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "alice",
		Password:   []byte("pw"),
		Project:    "Kubee",
	}, nestedExec); err != nil {
		t.Fatal(err)
	}
	// Remove newSub before testing rollback with injected nested file inside a failing Connect.
	_ = os.RemoveAll(newSub)

	// Run failing Connect where pre-existing auth/ has existingFile, and manually ensure restoreAuthDir removes newly created nested subdirs/files.
	snap, err := snapshotAuthDir(authDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(authDir, "ephemeral", "deep"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(authDir, "ephemeral", "deep", "cred.tok"), []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restoreAuthDir(snap); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(authDir, "ephemeral")); !os.IsNotExist(err) {
		t.Fatalf("expected newly created nested auth subdir to be removed on rollback")
	}
	got, err := os.ReadFile(existingFile)
	if err != nil || string(got) != "keep-nested" {
		t.Fatalf("expected pre-existing nested file to be preserved: got=%q err=%v", got, err)
	}

	// Verify symlink inside authDir fails closed instead of silently skipping.
	linkPath := filepath.Join(authDir, "sym")
	if symErr := os.Symlink(existingFile, linkPath); symErr == nil {
		if _, err := snapshotAuthDir(authDir); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("expected symlink in auth dir to fail closed, got %v", err)
		}
		_ = os.Remove(linkPath)
	}
}
