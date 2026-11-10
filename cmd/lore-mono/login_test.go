package main

import (
	"bytes"
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
		token := flagValue(args, "--token")
		if flagValue(args, "--token-type") != "lore" || token == "" {
			os.Exit(9)
		}
		sub := jwtSubject(token)
		if sub == "" {
			os.Exit(9)
		}
		dir := os.Getenv("LORE_AUTH_PATH")
		if err := os.MkdirAll(dir, 0o700); err != nil {
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
	default:
		os.Exit(2)
	}
	os.Exit(0)
}

func TestPasswordIsNotAnArgument(t *testing.T) {
	if _, err := parseLogin([]string{"--password", "secret"}); err == nil {
		t.Fatal("password argument accepted")
	}
	if _, err := parseLogin([]string{"--password=secret"}); err == nil {
		t.Fatal("password argument accepted")
	}
}

func TestLoginCommandStoresCredential(t *testing.T) {
	token := fakeToken("7")
	url := serveFixedLogin(t, token)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "client.toml")
	authPath := filepath.Join(dir, "auth")
	restoreExecutor(t)
	newExecutor = func(string) loreexec.Executor { return helperExecutor() }
	stdin = strings.NewReader("correct-horse\n")
	var out, errBuf bytes.Buffer
	stdout = &out
	stderr = &errBuf
	code := run([]string{
		"login", "--password-stdin", "--username", "alice", "--manager", url,
		"--config", cfgPath, "--auth-path", authPath, "--auth-store", "fallback",
		"--lore-binary", os.Args[0],
	})
	if code != 0 {
		t.Fatalf("exit %d stderr %s", code, errBuf.String())
	}
	if strings.Contains(out.String(), token) || strings.Contains(errBuf.String(), token) || strings.Contains(errBuf.String(), "correct-horse") {
		t.Fatal("command output contains a secret")
	}
	saved, err := os.ReadFile(cfgPath)
	if err != nil || strings.Contains(string(saved), "correct-horse") || strings.Contains(string(saved), "eyJ") {
		t.Fatalf("config leaked a secret: %s", saved)
	}
	stored, err := os.ReadFile(filepath.Join(authPath, "identity"))
	if err != nil || string(stored) != "7" {
		t.Fatalf("credential store %q %v", stored, err)
	}
}

func TestHiddenPasswordReaderIsUsed(t *testing.T) {
	called := false
	previous := readPassword
	readPassword = func() ([]byte, error) {
		called = true
		return []byte("correct-horse"), nil
	}
	t.Cleanup(func() { readPassword = previous })
	restoreExecutor(t)
	newExecutor = func(string) loreexec.Executor { return helperExecutor() }
	url := serveFixedLogin(t, fakeToken("4"))
	dir := t.TempDir()
	stdin = strings.NewReader("")
	var errBuf bytes.Buffer
	stderr = &errBuf
	stdout = &bytes.Buffer{}
	code := run([]string{"login", "--username", "alice", "--manager", url, "--auth-path", dir, "--lore-binary", os.Args[0]})
	if code != 0 || !called {
		t.Fatalf("code %d called %t stderr %s", code, called, errBuf.String())
	}
	if strings.Contains(errBuf.String(), "correct-horse") {
		t.Fatal("password was echoed")
	}
}

func restoreExecutor(t *testing.T) {
	t.Helper()
	previous := newExecutor
	t.Cleanup(func() { newExecutor = previous })
}

func helperExecutor() loreexec.Executor {
	return loreexec.Executor{Config: loreexec.Config{
		Binary:      os.Args[0],
		LeadingArgs: []string{"-test.run=^TestHelperProcess$", "--"},
		Env:         map[string]string{"LORE_MONO_HELPER": "1"},
		Timeout:     5 * time.Second,
	}}
}

func serveFixedLogin(t *testing.T, token string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Password != "correct-horse" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"invalid username or password"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"identity_token":"`+token+`","token_type":"Bearer","expires_in":43200,"username":"alice"}`)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func fakeToken(sub string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + sub + `"}`))
	return header + "." + payload + ".sig"
}

func helperArgs(argv []string) []string {
	for i, arg := range argv {
		if arg == "--" && i+1 < len(argv) {
			return argv[i+1:]
		}
	}
	return nil
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
