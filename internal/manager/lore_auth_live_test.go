package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"lore-monorepo/internal/client"
	"lore-monorepo/internal/config"
	"lore-monorepo/internal/logging"
	"lore-monorepo/internal/loreexec"
	"lore-monorepo/internal/project"
	"lore-monorepo/internal/user"
)

// TestLoreAuthBridgeLive starts an isolated Lore server and the in-process
// Manager. It is skipped unless LORE_BIN and LORE_SERVER are set.
func TestLoreAuthBridgeLive(t *testing.T) {
	loreBin := os.Getenv("LORE_BIN")
	serverBin := os.Getenv("LORE_SERVER")
	if loreBin == "" || serverBin == "" {
		t.Skip("LORE_BIN and LORE_SERVER are required")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Fatal("openssl is required for the isolated server certificate")
	}
	root := t.TempDir()
	reportDir := ""
	if report := os.Getenv("B23_REPORT"); report != "" {
		reportDir = report
		if err := os.MkdirAll(report, 0o755); err != nil {
			t.Fatal(err)
		}
		root = filepath.Join(report, "run")
		_ = os.RemoveAll(root)
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cert, key := labCert(t, root)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app := startAuthManager(t, ctx, root)
	if _, err := user.Create(context.Background(), app.DB, "test", "alice", "correct-horse", "user"); err != nil {
		t.Fatal(err)
	}
	srv := startLoreServer(t, serverBin, root, cert, key)
	defer srv.Process.Kill()
	waitPort(t, "127.0.0.1:53337")
	time.Sleep(8 * time.Second)
	authDir := filepath.Join(root, "auth")
	if err := os.MkdirAll(authDir, 0o700); err != nil {
		t.Fatal(err)
	}
	execLore := loreexec.Executor{Config: loreexec.Config{
		Binary:  loreBin,
		Timeout: time.Minute,
		Env: map[string]string{
			"LORE_AUTH_STORE": "fallback",
			"LORE_AUTH_PATH":  authDir,
			"SSL_CERT_FILE":   cert,
		},
	}}
	if err := client.Login(context.Background(), client.Config{
		ManagerURL: "http://127.0.0.1:53300",
		LoreBinary: loreBin,
		AuthURL:    "http://127.0.0.1:53310",
		AuthStore:  "fallback",
		AuthPath:   authDir,
	}, "alice", []byte("correct-horse"), execLore); err != nil {
		t.Fatal(err)
	}
	repoA := createRemoteRepo(t, execLore, filepath.Join(root, "seed-a"))
	repoB := createRemoteRepo(t, execLore, filepath.Join(root, "seed-b"))
	registerGrant(t, app, repoA, repoB)
	before := app.Bridge.Exchanges()
	clone := runLore(t, execLore, filepath.Join(root, "work-a"), "clone", "grpcs://127.0.0.1:53337/"+repoA, ".")
	if clone.ExitCode != 0 {
		t.Fatalf("authorized clone failed exit=%d", clone.ExitCode)
	}
	if app.Bridge.Exchanges() <= before {
		t.Fatal("clone did not call token exchange")
	}
	denied := runLore(t, execLore, root, "clone", "grpcs://127.0.0.1:53337/"+repoB, "work-b")
	if denied.ExitCode == 0 {
		t.Fatal("unauthorized clone succeeded")
	}
	writeFile(t, filepath.Join(root, "work-a", "note.txt"))
	if push := pushFile(t, execLore, filepath.Join(root, "work-a")); push.ExitCode != 0 {
		t.Fatalf("push failed exit=%d", push.ExitCode)
	}
	cached := runLore(t, execLore, filepath.Join(root, "work-a"), "status")
	if err := user.SetStatus(context.Background(), app.DB, "test", "alice", "disabled"); err != nil {
		t.Fatal(err)
	}
	_ = runLore(t, execLore, filepath.Join(root, "work-a"), "auth", "logout", "--resource", repoA)
	if again := runLore(t, execLore, root, "clone", "grpcs://127.0.0.1:53337/"+repoA, "work-a2"); again.ExitCode == 0 {
		t.Fatal("disabled user exchanged a new access token")
	}
	if err := user.SetPassword(context.Background(), app.DB, "test", "alice", "new-password-1"); err != nil {
		t.Fatal(err)
	}
	if old := runLore(t, execLore, root, "clone", "grpcs://127.0.0.1:53337/"+repoA, "work-a3"); old.ExitCode == 0 {
		t.Fatal("old identity was accepted after password change")
	}
	if err := user.SetStatus(context.Background(), app.DB, "test", "alice", "active"); err != nil {
		t.Fatal(err)
	}
	cancel()
	waitPortGone(t, "127.0.0.1:53310")
	waitPortGone(t, "127.0.0.1:53300")
	_ = cached
	stopped := runLore(t, execLore, filepath.Join(root, "work-a"), "status")
	recovered := false
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	app2 := startAuthManager(t, ctx2, root)
	if err := client.Login(context.Background(), client.Config{
		ManagerURL: "http://127.0.0.1:53300", LoreBinary: loreBin, AuthURL: "http://127.0.0.1:53310",
		AuthStore: "fallback", AuthPath: authDir,
	}, "alice", []byte("new-password-1"), execLore); err != nil {
		t.Fatal(err)
	}
	if back := runLore(t, execLore, filepath.Join(root, "work-a"), "status"); back.ExitCode == 0 {
		recovered = true
	}
	writeReport(firstNonEmpty(reportDir, root), map[string]any{
		"clone_exit": clone.ExitCode, "denied_exit": denied.ExitCode,
		"exchanges": app.Bridge.Exchanges(), "stopped_status_exit": stopped.ExitCode,
		"relogin_status_ok": recovered, "repo_a": repoA, "repo_b": repoB,
	})
	if !recovered {
		t.Fatal("status after re-login failed")
	}
	_ = app2
}

func startAuthManager(t *testing.T, ctx context.Context, root string) *App {
	t.Helper()
	cfg := config.Config{
		Listen: "127.0.0.1:53300", ShutdownTimeout: 5 * time.Second,
		DatabasePath: filepath.Join(root, "manager.db"), LoreBinary: os.Getenv("LORE_BIN"),
		CommandTimeout: time.Minute, LogLevel: "info", LogFormat: "json",
		Auth: config.Auth{
			Issuer: "http://127.0.0.1:53310", Audience: []string{"127.0.0.1"},
			GRPCListen: "127.0.0.1:53310", IdentityTTL: 12 * time.Hour, AccessTTL: 5 * time.Minute,
			PrivateKey: filepath.Join(root, "keys", "identity-active.pem"),
			PublicKey:  filepath.Join(root, "keys", "identity-active.pub.pem"),
			JWKS:       filepath.Join(root, "keys", "jwks.json"),
		},
	}
	app, err := New(cfg, logging.New(io.Discard, logging.Info, "manager"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = app.Serve(ctx, ln) }()
	waitPort(t, "127.0.0.1:53310")
	return app
}

func startLoreServer(t *testing.T, bin, root, cert, key string) *exec.Cmd {
	t.Helper()
	dir := filepath.Join(root, "server-config")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(root, "store")
	if err := os.MkdirAll(store, 0o755); err != nil {
		t.Fatal(err)
	}
	jwks := filepath.Join(root, "keys", "jwks.json")
	body := fmt.Sprintf(`# isolated B2.3 server
[environment.endpoint]
auth_url = "http://127.0.0.1:53310"
[server.auth]
jwt_issuer = "http://127.0.0.1:53310"
jwt_audience = ["127.0.0.1"]
[server.auth.jwk]
endpoint = "file://%s"
[server.quic]
host = "127.0.0.1"
port = 53337
[server.quic.certificate]
cert_file = "%s"
pkey_file = "%s"
[server.grpc]
host = "127.0.0.1"
port = 53337
verify_client_certs = false
[server.grpc.certificate]
cert_file = "%s"
pkey_file = "%s"
[server.http]
host = "127.0.0.1"
port = 53339
[immutable_store.local]
path = "%s"
[mutable_store.local]
path = "%s"
[topology]
provider = "none"
`, filepath.ToSlash(jwks), cert, key, cert, key, store, store)
	if err := os.WriteFile(filepath.Join(dir, "local.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("stdbuf", "-oL", "-eL", bin, "--config", dir)
	cmd.Env = append(os.Environ(), "RUST_LOG=info")
	logf, err := os.Create(filepath.Join(root, "loreserver.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = logf
	cmd.Stderr = logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = cmd.Wait() }()
	return cmd
}

func labCert(t *testing.T, root string) (string, string) {
	t.Helper()
	cert := os.Getenv("LORE_TLS_CERT")
	key := os.Getenv("LORE_TLS_KEY")
	if cert != "" && key != "" {
		return cert, key
	}
	return writeCert(t, root)
}

func writeCert(t *testing.T, root string) (string, string) {
	t.Helper()
	dir := filepath.Join(root, "certs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cert := filepath.Join(dir, "server.pem")
	key := filepath.Join(dir, "server.key")
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", cert,
		"-days", "2", "-nodes", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl: %v %s", err, out)
	}
	return cert, key
}

func createRemoteRepo(t *testing.T, ex loreexec.Executor, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	res := runLore(t, ex, dir, "--debug", "--non-interactive", "--json", "repository", "create", "grpcs://127.0.0.1:53337/"+filepath.Base(dir))
	if res.ExitCode != 0 {
		_ = os.WriteFile(filepath.Join(dir, "create-fail.txt"), []byte(redactText(res.Stdout+"\n"+res.Stderr)), 0o644)
		t.Fatalf("repository create exit=%d", res.ExitCode)
	}
	id := findRepoID(res.Stdout)
	if id == "" {
		t.Fatal("repository create did not report an id")
	}
	return id
}

func registerGrant(t *testing.T, app *App, allowed, denied string) {
	t.Helper()
	ctx := context.Background()
	account, err := user.GetByID(ctx, app.DB, 1)
	if err != nil {
		t.Fatal(err)
	}
	parent := "00112233445566778899aabbccddeeff"
	p, err := project.CreateProject(ctx, app.DB, "test", project.Project{
		Name: "Alpha", ParentRepositoryID: parent, ParentRepositoryURL: "grpcs://127.0.0.1:53337/" + parent, CreatedBy: account.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := project.CreateModule(ctx, app.DB, "test", project.Module{
		ProjectID: p.ID, Name: "Engine", RepositoryID: allowed, RepositoryURL: "grpcs://127.0.0.1:53337/" + allowed, MountPath: "Engine",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := project.CreateModule(ctx, app.DB, "test", project.Module{
		ProjectID: p.ID, Name: "Client", RepositoryID: denied, RepositoryURL: "grpcs://127.0.0.1:53337/" + denied, MountPath: "Client",
	}); err != nil {
		t.Fatal(err)
	}
	if err := project.GrantModule(ctx, app.DB, "test", account.ID, engine.ID); err != nil {
		t.Fatal(err)
	}
}

func pushFile(t *testing.T, ex loreexec.Executor, dir string) loreexec.CommandResult {
	t.Helper()
	writeFile(t, filepath.Join(dir, "note.txt"))
	if res := runLore(t, ex, dir, "stage", "note.txt"); res.ExitCode != 0 {
		return res
	}
	if res := runLore(t, ex, dir, "commit", "-m", "note"); res.ExitCode != 0 {
		return res
	}
	return runLore(t, ex, dir, "push")
}

func runLore(t *testing.T, ex loreexec.Executor, dir string, args ...string) loreexec.CommandResult {
	t.Helper()
	res, err := ex.Run(context.Background(), loreexec.Request{Argv: args, Dir: dir})
	if err != nil {
		t.Fatalf("lore %s: %v", args[0], err)
	}
	return res
}

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func writeReport(dir string, body map[string]any) {
	raw, _ := json.MarshalIndent(body, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "report.json"), raw, 0o644)
}

var repoIDPattern = regexp.MustCompile(`[0-9a-f]{32}`)

func redactText(s string) string {
	var b strings.Builder
	for _, field := range strings.Fields(s) {
		if strings.HasPrefix(field, "eyJ") {
			b.WriteString("<redacted-jwt> ")
			continue
		}
		b.WriteString(field)
		b.WriteByte(' ')
	}
	out := b.String()
	if len(out) > 2000 {
		out = out[:2000]
	}
	return out
}

func findRepoID(text string) string {
	ids := repoIDPattern.FindAllString(text, -1)
	if len(ids) == 0 {
		return ""
	}
	return ids[len(ids)-1]
}

func waitPort(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("port %s did not open", addr)
}

func waitPortGone(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			return
		}
		conn.Close()
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("port %s stayed open", addr)
}
