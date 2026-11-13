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
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
