package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
		sub := jwtSubject(flagValue(args, "--token"))
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
	case "auth":
		body, err := os.ReadFile(filepath.Join(os.Getenv("LORE_AUTH_PATH"), "identity"))
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

func fakeIdentity(sub string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + sub + `"}`))
	return header + "." + payload + ".sig"
}
