package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lore-monorepo/internal/loreexec"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("LORE_MONO_HELPER") != "1" {
		return
	}
	args := helperArgs(os.Args)
	if len(args) == 0 {
		os.Exit(2)
	}
	switch args[0] {
	case "login":
		if os.Getenv("LORE_MONO_FAIL_LOGIN") == "1" || !isLoreIdentityLogin(args) {
			os.Exit(9)
		}
		tok := flagValue(args, "--token")
		sub := jwtSubject(tok)
		if sub == "" {
			os.Exit(9)
		}
		dir := os.Getenv("LORE_AUTH_PATH")
		if dir == "" {
			os.Exit(9)
		}
		if err := os.WriteFile(filepath.Join(dir, "identity"), []byte(sub), 0o600); err != nil {
			os.Exit(9)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "token_value")); statErr == nil {
			_ = os.WriteFile(filepath.Join(dir, "token_value"), []byte(tok), 0o600)
		}
	case "auth":
		dir := os.Getenv("LORE_AUTH_PATH")
		if len(args) > 1 && hasArg(args, "--with-token") {
			if tokBytes, rErr := os.ReadFile(filepath.Join(dir, "token_value")); rErr == nil {
				os.Stdout.WriteString("Token: " + string(tokBytes) + "\n")
				os.Exit(0)
			}
		}
		body, err := os.ReadFile(filepath.Join(dir, "identity"))
		if err != nil {
			os.Exit(9)
		}
		os.Stdout.WriteString("identity " + string(body) + "\n")
	case "fail":
		os.Exit(9)
	default:
		os.Exit(2)
	}
	os.Exit(0)
}

func TestCheckManagerURL(t *testing.T) {
	if err := CheckManagerURL("http://127.0.0.1:52000"); err != nil {
		t.Fatal(err)
	}
	if err := CheckManagerURL("https://lore.example"); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"http://lore.example", "http://alice:secret@127.0.0.1:52000", "ftp://127.0.0.1"} {
		if err := CheckManagerURL(raw); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestConfigRejectsSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.toml")
	body := "manager_url = \"http://127.0.0.1:52000\"\npassword = \"secret\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("config with a password key was accepted")
	}
	cfg := Config{Path: path, ManagerURL: "http://127.0.0.1:52000", LoreBinary: "lore"}
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(saved), "secret") || strings.Contains(string(saved), "eyJ") {
		t.Fatal("saved config contains a secret")
	}
}

func TestLoginUsesLoreStore(t *testing.T) {
	dir := t.TempDir()
	token := fakeIdentity("7")
	var seenPassword string
	url := serveLogin(t, func(user, password string) (int, string) {
		seenPassword = password
		if user != "alice" || password != "correct-horse" {
			return 401, `{"error":"invalid username or password"}`
		}
		return 200, `{"identity_token":"` + token + `","token_type":"Bearer","expires_in":43200,"username":"alice"}`
	})
	exec := testLore(t)
	cfg := Config{
		ManagerURL: url,
		AuthStore:  "fallback",
		AuthPath:   dir,
		AuthURL:    "http://127.0.0.1:52010",
	}
	err := Login(context.Background(), cfg, "alice", []byte("correct-horse"), exec)
	if err != nil {
		t.Fatal(err)
	}
	if seenPassword != "correct-horse" {
		t.Fatal("password was not sent in the request body")
	}
	stored, err := os.ReadFile(filepath.Join(dir, "identity"))
	if err != nil || string(stored) != "7" {
		t.Fatalf("store %q %v", stored, err)
	}
	if strings.Contains(string(stored), token) {
		t.Fatal("store contains the raw token")
	}
	cfg.ManagerURL = "http://127.0.0.1:1"
	if err := Login(context.Background(), cfg, "alice", []byte("correct-horse"), exec); err == nil || err.Error() != "manager unavailable" {
		t.Fatalf("down manager: %v", err)
	}
}

func TestLoginFailureDoesNotClaimSuccess(t *testing.T) {
	token := fakeIdentity("7")
	url := serveLogin(t, func(string, string) (int, string) {
		return 200, `{"identity_token":"` + token + `","token_type":"Bearer","expires_in":1,"username":"alice"}`
	})
	exec := testLore(t)
	exec.Config.Env["LORE_MONO_FAIL_LOGIN"] = "1"
	err := Login(context.Background(), Config{ManagerURL: url, AuthPath: t.TempDir()}, "alice", []byte("correct-horse"), exec)
	if err == nil || !strings.Contains(err.Error(), "lore login failed") {
		t.Fatalf("store failure reported success: %v", err)
	}
}

func testLore(t *testing.T) loreexec.Executor {
	t.Helper()
	return loreexec.Executor{Config: loreexec.Config{
		Binary:      os.Args[0],
		LeadingArgs: []string{"-test.run=^TestHelperProcess$", "--"},
		Env:         map[string]string{"LORE_MONO_HELPER": "1"},
		Timeout:     5 * time.Second,
	}}
}

func helperArgs(argv []string) []string {
	for i, arg := range argv {
		if arg == "--" && i+1 < len(argv) {
			return argv[i+1:]
		}
	}
	return nil
}

func isLoreIdentityLogin(args []string) bool {
	return len(args) > 0 && args[0] == "login" && flagValue(args, "--token-type") == "lore" && flagValue(args, "--token") != ""
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func flagValue(args []string, name string) string {
	for i, arg := range args {
		if arg == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func jwtSubject(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return ""
	}
	return claims.Sub
}

func serveLogin(t *testing.T, handle func(user, password string) (int, string)) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/login" || r.Method != http.MethodPost || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		code, body := handle(req.Username, req.Password)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestSilentLoreCredentialRefreshFromPersistentSession(t *testing.T) {
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	_ = os.MkdirAll(authDir, 0o700)
	persistentTok := fakeIdentity("7")
	// Expired exp-bearing token simulates 12h+ elapsed in Lore credential store.
	expiredLore := fakeJWTWithExp("7", time.Now().Add(-time.Hour).Unix())
	freshLore := fakeJWTWithExp("7", time.Now().Add(12*time.Hour).Unix())
	_ = os.WriteFile(filepath.Join(authDir, "token_value"), []byte(expiredLore), 0o600)

	refreshCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/lore-token":
			refreshCalls++
			if r.Header.Get("Authorization") != "Bearer "+persistentTok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(w, `{"lore_token":"`+freshLore+`","expires_in":43200,"username":"alice"}`)
		case "/api/v1/me/modules":
			_, _ = io.WriteString(w, `{"modules":[{"RepositoryURL":"grpc://127.0.0.1:53547/engine"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := Config{ManagerURL: srv.URL, AuthStore: "fallback", AuthPath: authDir, LoreBinary: "lore"}
	if err := SaveSession(cfg, []byte(persistentTok)); err != nil {
		t.Fatal(err)
	}
	ex := loreexec.Executor{Config: loreexec.Config{
		Binary:      os.Args[0],
		LeadingArgs: []string{"-test.run=^TestHelperProcess$", "--"},
		Env:         map[string]string{"LORE_MONO_HELPER": "1"},
		Timeout:     5 * time.Second,
	}}
	if err := os.WriteFile(filepath.Join(authDir, "token_value"), []byte(expiredLore), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureLoreCredential(context.Background(), cfg, ex); err != nil {
		t.Fatalf("EnsureLoreCredential with expired lore token: %v", err)
	}
	if refreshCalls != 1 {
		t.Fatalf("expected 1 silent refresh call when expired, got %d", refreshCalls)
	}
	// When stored Lore token is still valid, no extra refresh HTTP request is made.
	if err := os.WriteFile(filepath.Join(authDir, "token_value"), []byte(freshLore), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureLoreCredential(context.Background(), cfg, ex); err != nil {
		t.Fatalf("EnsureLoreCredential with fresh lore token: %v", err)
	}
	if refreshCalls != 1 {
		t.Fatalf("expected no refresh when lore token still valid, got %d", refreshCalls)
	}
	_ = os.Remove(filepath.Join(authDir, "token_value"))
	if err := os.Remove(filepath.Join(authDir, "identity")); err != nil {
		t.Fatal(err)
	}
	if err := EnsureLoreCredential(context.Background(), cfg, ex); err != nil {
		t.Fatalf("EnsureLoreCredential when lore token missing: %v", err)
	}
	if refreshCalls != 2 {
		t.Fatalf("expected second refresh when lore token missing, got %d", refreshCalls)
	}
}

func fakeIdentity(sub string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + sub + `"}`))
	return header + "." + payload + ".sig"
}

func fakeJWTWithExp(sub string, exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"sub":%q,"exp":%d}`, sub, exp)))
	return header + "." + payload + ".sig"
}
