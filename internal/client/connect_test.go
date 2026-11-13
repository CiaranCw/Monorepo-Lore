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
	// Put a decoy client.toml in CWD to prove Connect never searches or reuses CWD configs.
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
	if loaded.AuthURL != "https://127.0.0.1:57049" || loaded.Project != "Kubee" || loaded.CAFile != res.CAFile {
		t.Fatalf("unexpected saved config: %+v", loaded)
	}
	if _, err := os.Stat(PinPathForCA(res.CAFile)); err != nil {
		t.Fatalf("missing ca.pin: %v", err)
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

func TestConnectRejectsExpiredAndWrongHostnameCert(t *testing.T) {
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

func TestConnectLegacyServerWithoutClientInfo(t *testing.T) {
	setTempUserConfigDir(t)
	ca := makeTestCA(t, "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	srv := startTLSManagerMock(t, ca.tlsCert, nil, "", false)

	exec := testLore(t)
	res, err := Connect(context.Background(), ConnectOptions{
		ManagerURL: srv.URL,
		Username:   "alice",
		Password:   []byte("pw"),
	}, exec)
	if err != nil {
		t.Fatalf("legacy connect failed: %v", err)
	}
	if !res.TOFUTrusted || res.CASHA256 != CertSHA256Hex(ca.leaf) {
		t.Fatalf("expected leaf TOFU pin on legacy server, got %+v", res)
	}
}
