package manager

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"lore-monorepo/internal/client"
	"lore-monorepo/internal/config"
	"lore-monorepo/internal/logging"
)

func fakeLore(t *testing.T) string {
	t.Helper()
	name := "lore"
	if runtime.GOOS == "windows" {
		name = "lore.exe"
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("not a real binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func testApp(t *testing.T, binary string) *App {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Config{
		Listen:          "127.0.0.1:0",
		ShutdownTimeout: 2 * time.Second,
		DatabasePath:    filepath.Join(dir, "manager.db"),
		LoreBinary:      binary,
		CommandTimeout:  time.Second,
		LogLevel:        "info",
		LogFormat:       "json",
		Auth: config.Auth{
			Issuer:      "http://127.0.0.1:52010",
			Audience:    []string{"lore-host.internal"},
			GRPCListen:  "127.0.0.1:52010",
			IdentityTTL: 12 * time.Hour,
			AccessTTL:   5 * time.Minute,
			PrivateKey:  filepath.Join(dir, "keys", "identity-active.pem"),
			PublicKey:   filepath.Join(dir, "keys", "identity-active.pub.pem"),
			JWKS:        filepath.Join(dir, "keys", "jwks.json"),
		},
	}
	app, err := New(cfg, logging.New(io.Discard, logging.Info, "manager"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if app.DB != nil {
			app.DB.Close()
		}
	})
	return app
}

func TestLiveReadyVersion(t *testing.T) {
	app := testApp(t, fakeLore(t))
	srv := httptestServer(t, app)
	body := getJSON(t, srv+"/health/live")
	if body["status"] != "live" {
		t.Fatalf("%v", body)
	}
	ready := getJSON(t, srv+"/health/ready")
	if ready["status"] != "ready" {
		t.Fatalf("%v", ready)
	}
	ver := getJSON(t, srv+"/version")
	if ver["manager"] != Version || ver["commit"] != Commit {
		t.Fatalf("%v", ver)
	}
	res, err := http.Get(srv + "/api/v1/projects")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated projects %d", res.StatusCode)
	}
	if res.Header.Get("X-Request-ID") == "" {
		t.Fatal("missing request id")
	}
}

func TestReadyFailsWithoutDatabaseOrBinary(t *testing.T) {
	app := testApp(t, filepath.Join(t.TempDir(), "missing-lore"))
	srv := httptestServer(t, app)
	res, err := http.Get(srv + "/health/ready")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d", res.StatusCode)
	}
	app.DB.Close()
	closed := app.DB
	app.DB = closed
	res, err = http.Get(srv + "/health/ready")
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("closed database ready %d", res.StatusCode)
	}
	res.Body.Close()
	res, err = http.Get(srv + "/health/live")
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("live should stay up: %v %v", err, res)
	}
	res.Body.Close()
}

func TestShutdownWaitsForRequest(t *testing.T) {
	app := testApp(t, fakeLore(t))
	started := make(chan struct{})
	release := make(chan struct{})
	app.Gate = func() {
		select {
		case <-started:
		default:
			close(started)
		}
		<-release
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- app.Serve(ctx, ln) }()
	resCh := make(chan int, 1)
	go func() {
		res, err := http.Get("http://" + ln.Addr().String() + "/health/live")
		if err != nil {
			resCh <- 0
			return
		}
		res.Body.Close()
		resCh <- res.StatusCode
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("request did not enter")
	}
	cancel()
	close(release)
	select {
	case code := <-resCh:
		if code != http.StatusOK {
			t.Fatalf("in-flight status %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight request was dropped")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve did not return")
	}
}

func TestTokenServiceLoadsWithoutAffectingHealth(t *testing.T) {
	var buf bytes.Buffer
	dir := t.TempDir()
	cfg := config.Config{
		Listen:          "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		DatabasePath:    filepath.Join(dir, "manager.db"),
		LoreBinary:      fakeLore(t),
		CommandTimeout:  time.Second,
		LogLevel:        "info",
		LogFormat:       "json",
		Auth: config.Auth{
			Issuer:      "http://127.0.0.1:52010",
			Audience:    []string{"lore-host.internal"},
			GRPCListen:  "127.0.0.1:52010",
			IdentityTTL: 12 * time.Hour,
			AccessTTL:   5 * time.Minute,
			PrivateKey:  filepath.Join(dir, "keys", "identity-active.pem"),
			PublicKey:   filepath.Join(dir, "keys", "identity-active.pub.pem"),
			JWKS:        filepath.Join(dir, "keys", "jwks.json"),
		},
	}
	app, err := New(cfg, logging.New(&buf, logging.Info, "manager"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.DB.Close() })
	if app.Tokens == nil || app.Tokens.ActiveKID() == "" {
		t.Fatal("token service was not loaded")
	}
	identity, err := app.Tokens.IssueIdentity("7", "alice", 2)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := app.Tokens.VerifyIdentity(identity)
	if err != nil || claims.AuthVersion != 2 || claims.PreferredUsername != "alice" {
		t.Fatalf("identity verify %v %+v", err, claims)
	}
	if _, err := app.Tokens.VerifyAccess(identity); err == nil {
		t.Fatal("identity token was accepted as access")
	}
	if bytes.Contains(buf.Bytes(), []byte("PRIVATE KEY")) || bytes.Contains(buf.Bytes(), []byte(identity)) {
		t.Fatal("startup log contains key material or a token")
	}
	again, err := New(cfg, logging.New(io.Discard, logging.Info, "manager"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { again.DB.Close() })
	if again.Tokens.ActiveKID() != app.Tokens.ActiveKID() {
		t.Fatal("restart generated a new signing key")
	}
	body := getJSON(t, httptestServer(t, app)+"/health/live")
	if body["status"] != "live" {
		t.Fatalf("%v", body)
	}
}

func TestClientInfoEndpoint(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	// Write a certificate PEM alongside an unrelated private key block to verify private keys are never leaked.
	if err := os.WriteFile(caPath, []byte("-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	app := testApp(t, fakeLore(t))
	app.Config.Client.AuthURL = "https://auth.example.internal:57049"
	app.Config.Import.RemoteBaseURL = "grpcs://gw.example.internal:57047"
	app.Config.Client.CAFile = caPath
	srv := httptestServer(t, app)

	// Private-key-only file yields empty ca_pem/ca_sha256.
	info := getJSON(t, srv+"/api/v1/client/info")
	if info["auth_url"] != "https://auth.example.internal:57049" || info["remote_base_url"] != "grpcs://gw.example.internal:57047" {
		t.Fatalf("unexpected client info: %v", info)
	}
	if info["ca_pem"] != "" || info["ca_sha256"] != "" {
		t.Fatalf("non-cert block leaked: %v", info)
	}

	// Two-cert bundle produces the exact same canonical set digest as client.ParseCAPEMBundle.
	bundlePEM := append(testCertPEM(t, "RootA"), testCertPEM(t, "RootB")...)
	if err := os.WriteFile(caPath, bundlePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	wantPEM, wantSHA, err := client.ParseCAPEMBundle(bundlePEM)
	if err != nil {
		t.Fatal(err)
	}
	info2 := getJSON(t, srv+"/api/v1/client/info")
	if info2["ca_pem"] != wantPEM || info2["ca_sha256"] != wantSHA {
		t.Fatalf("manager ca_sha256 mismatch: got (%v, %v) want (%v, %v)", info2["ca_sha256"], info2["ca_pem"], wantSHA, wantPEM)
	}
}

func testCertPEM(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func httptestServer(t *testing.T, app *App) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: app.Handler()}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return "http://" + ln.Addr().String()
}

func getJSON(t *testing.T, url string) map[string]any {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(res.Body)
	var body map[string]any
	if err := json.Unmarshal(buf.Bytes(), &body); err != nil {
		t.Fatalf("%s: %v", buf.String(), err)
	}
	if res.StatusCode != http.StatusOK && urlHas(url, "/health/live", "/version", "/health/ready") {
		t.Fatalf("%s status %d body %s", url, res.StatusCode, buf.String())
	}
	return body
}

func urlHas(url string, parts ...string) bool {
	for _, p := range parts {
		if len(url) >= len(p) && url[len(url)-len(p):] == p {
			return true
		}
	}
	return false
}
