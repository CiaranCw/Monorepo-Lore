// Package client is the lore-mono side of Manager login.
//
// It sends the password only in a JSON body to a loopback HTTP or HTTPS
// Manager, then asks the Lore CLI to store the returned identity token.
// Passwords and tokens are not written to the client config file.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/BurntSushi/toml"

	"lore-monorepo/internal/loreexec"
)

// Config is the non-secret client file.
type Config struct {
	Path       string
	ManagerURL string
	LoreBinary string
	AuthURL    string
	RemoteURL  string
	AuthStore  string
	AuthPath   string
	Project    string
	CAFile     string
}

type fileConfig struct {
	ManagerURL string `toml:"manager_url"`
	LoreBinary string `toml:"lore_binary"`
	AuthURL    string `toml:"auth_url"`
	RemoteURL  string `toml:"remote_url"`
	AuthStore  string `toml:"auth_store"`
	AuthPath   string `toml:"auth_path"`
	Project    string `toml:"project"`
	CAFile     string `toml:"ca_file"`
}

// Load reads a client config. Unknown keys are rejected so a password or
// token cannot hide in the file under another name.
func Load(path string) (Config, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var raw fileConfig
	meta, err := toml.Decode(string(body), &raw)
	if err != nil {
		return Config{}, fmt.Errorf("client config: %w", err)
	}
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		return Config{}, fmt.Errorf("client config: unknown keys: %s", undecoded)
	}
	cfg := Config{
		Path:       path,
		ManagerURL: strings.TrimSpace(raw.ManagerURL),
		LoreBinary: strings.TrimSpace(raw.LoreBinary),
		AuthURL:    strings.TrimSpace(raw.AuthURL),
		RemoteURL:  strings.TrimSpace(raw.RemoteURL),
		AuthStore:  strings.TrimSpace(raw.AuthStore),
		AuthPath:   strings.TrimSpace(raw.AuthPath),
		Project:    strings.TrimSpace(raw.Project),
		CAFile:     strings.TrimSpace(raw.CAFile),
	}
	if cfg.LoreBinary == "" {
		cfg.LoreBinary = "lore"
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks the non-secret fields.
func (c Config) Validate() error {
	if c.ManagerURL != "" {
		if err := CheckManagerURL(c.ManagerURL); err != nil {
			return err
		}
	}
	switch c.AuthStore {
	case "", "fallback":
	default:
		return errors.New("client config: auth_store must be empty or fallback")
	}
	return nil
}

// CheckManagerURL allows HTTPS, or HTTP only when the host is loopback.
// Credentials in the URL are rejected.
func CheckManagerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("manager url must be http:// or https://")
	}
	if u.User != nil {
		return errors.New("manager url must not contain a username or password")
	}
	if u.Scheme == "http" && !loopback(u.Hostname()) {
		return errors.New("plain http is only allowed for a loopback manager")
	}
	return nil
}

func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Save writes the non-secret fields. It refuses to be pointed at a body that
// already failed validation.
func Save(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if cfg.Path == "" {
		return errors.New("client config path is empty")
	}
	raw := fileConfig{
		ManagerURL: cfg.ManagerURL,
		LoreBinary: cfg.LoreBinary,
		AuthURL:    cfg.AuthURL,
		RemoteURL:  cfg.RemoteURL,
		AuthStore:  cfg.AuthStore,
		AuthPath:   cfg.AuthPath,
		Project:    cfg.Project,
		CAFile:     cfg.CAFile,
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(raw); err != nil {
		return err
	}
	return writeFile(cfg.Path, buf.Bytes())
}

// Login exchanges a password for an identity token and stores it with Lore.
// password is wiped by the caller. A Lore failure is not reported as success.
func Login(ctx context.Context, cfg Config, username string, password []byte, exec loreexec.Executor) error {
	if err := CheckManagerURL(cfg.ManagerURL); err != nil {
		return err
	}
	token, subject, name, err := fetchIdentity(ctx, cfg, username, password)
	if err != nil {
		return err
	}
	defer wipe(token)
	if err := storeIdentity(ctx, cfg, exec, token); err != nil {
		return err
	}
	if err := confirmIdentity(ctx, cfg, exec, subject, name); err != nil {
		return err
	}
	return nil
}

type loginResponse struct {
	IdentityToken string `json:"identity_token"`
	TokenType     string `json:"token_type"`
	Username      string `json:"username"`
	Error         string `json:"error"`
}

func fetchIdentity(ctx context.Context, cfg Config, username string, password []byte) ([]byte, string, string, error) {
	payload, err := json.Marshal(struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{Username: username, Password: string(password)})
	if err != nil {
		return nil, "", "", errors.New("login failed")
	}
	defer wipe(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(cfg.ManagerURL, "/")+"/api/v1/auth/login", bytes.NewReader(payload))
	if err != nil {
		return nil, "", "", errors.New("login failed")
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := HTTPClient(cfg).Do(req)
	if err != nil {
		return nil, "", "", errors.New("manager unavailable")
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, "", "", errors.New("login failed")
	}
	defer wipe(body)
	var parsed loginResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, "", "", errors.New("login failed")
	}
	if res.StatusCode == http.StatusUnauthorized {
		return nil, "", "", errors.New("invalid username or password")
	}
	if res.StatusCode == http.StatusForbidden {
		return nil, "", "", errors.New("account disabled")
	}
	if res.StatusCode != http.StatusOK || parsed.IdentityToken == "" || parsed.TokenType != "Bearer" {
		return nil, "", "", errors.New("login failed")
	}
	subject, err := subjectOf(parsed.IdentityToken)
	if err != nil {
		return nil, "", "", errors.New("login failed")
	}
	return []byte(parsed.IdentityToken), subject, parsed.Username, nil
}

func storeIdentity(ctx context.Context, cfg Config, exec loreexec.Executor, token []byte) error {
	argv := []string{"login", "--token-type", "lore", "--token", string(token)}
	if cfg.AuthURL != "" {
		argv = append(argv, "--auth-url", cfg.AuthURL)
	}
	if cfg.RemoteURL != "" {
		argv = append(argv, cfg.RemoteURL)
	}
	res, err := exec.Run(ctx, loreexec.Request{Argv: argv, Env: loreEnv(cfg)})
	if err != nil || !res.ProcessSucceeded() {
		return fmt.Errorf("lore login failed exit=%d detail=%s", res.ExitCode, publicText(res.Stderr+" "+res.Stdout))
	}
	return nil
}

func confirmIdentity(ctx context.Context, cfg Config, exec loreexec.Executor, subject, username string) error {
	res, err := exec.Run(ctx, loreexec.Request{Argv: []string{"auth", "list"}, Env: loreEnv(cfg)})
	if err != nil || !res.ProcessSucceeded() {
		return fmt.Errorf("credential list failed exit=%d", res.ExitCode)
	}
	if strings.Contains(res.Stdout, "eyJ") {
		return errors.New("credential store update failed")
	}
	if subject != "" && strings.Contains(res.Stdout, subject) {
		return nil
	}
	if username != "" && strings.Contains(res.Stdout, username) {
		return nil
	}
	return errors.New("credential store update failed")
}

func loreEnv(cfg Config) map[string]string {
	env := map[string]string{}
	if cfg.AuthStore != "" {
		env["LORE_AUTH_STORE"] = cfg.AuthStore
	}
	if cfg.AuthPath != "" {
		env["LORE_AUTH_PATH"] = cfg.AuthPath
	}
	if len(env) == 0 {
		return nil
	}
	return env
}

func subjectOf(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", errors.New("token")
	}
	raw, err := decodeSegment(parts[1])
	if err != nil {
		return "", err
	}
	var claims struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil || claims.Subject == "" {
		return "", errors.New("token")
	}
	return claims.Subject, nil
}

func publicText(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	for _, part := range strings.Fields(s) {
		if strings.Count(part, ".") >= 2 && strings.HasPrefix(part, "eyJ") {
			s = strings.ReplaceAll(s, part, "<redacted-jwt>")
		}
	}
	if len(s) > 240 {
		s = s[:240]
	}
	return strings.TrimSpace(s)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
