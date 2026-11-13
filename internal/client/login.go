// Package client is the lore-mono side of Manager login.
//
// It sends the password only in a JSON body to a loopback HTTP or HTTPS
// Manager, then asks the Lore CLI to store the returned identity token.
// Passwords and tokens are not written to the client config file.
package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	TrustMode  string
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
	TrustMode  string `toml:"trust_mode,omitempty"`
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
		TrustMode:  strings.TrimSpace(raw.TrustMode),
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
	switch c.TrustMode {
	case "", "pinned":
	default:
		return errors.New("client config: trust_mode must be empty or pinned")
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
		TrustMode:  cfg.TrustMode,
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(raw); err != nil {
		return err
	}
	return writeFile(cfg.Path, buf.Bytes())
}

// Login exchanges a password for a persistent Manager identity token (no exp)
// and a Lore-compatible exp-bearing identity token stored with the Lore CLI.
// password is wiped by the caller. A Lore failure is not reported as success.
func Login(ctx context.Context, cfg Config, username string, password []byte, exec loreexec.Executor) error {
	if err := CheckManagerURL(cfg.ManagerURL); err != nil {
		return err
	}
	persistent, loreTok, subject, name, err := fetchIdentity(ctx, cfg, username, password)
	if err != nil {
		return err
	}
	defer wipe(persistent)
	defer wipe(loreTok)
	if err := SaveSession(cfg, persistent); err != nil {
		return err
	}
	remote := cfg.RemoteURL
	if strings.TrimSpace(remote) == "" {
		if found, findErr := firstRepositoryURL(ctx, cfg, persistent); findErr == nil {
			remote = found
		}
	}
	if err := storeIdentity(ctx, cfg, exec, loreTok, remote); err != nil {
		_ = DeleteSession(cfg)
		return err
	}
	if err := confirmIdentity(ctx, cfg, exec, subject, name); err != nil {
		_ = DeleteSession(cfg)
		return err
	}
	return nil
}

type loginResponse struct {
	IdentityToken string `json:"identity_token"`
	LoreToken     string `json:"lore_token"`
	TokenType     string `json:"token_type"`
	Username      string `json:"username"`
	Error         string `json:"error"`
}

func fetchIdentity(ctx context.Context, cfg Config, username string, password []byte) ([]byte, []byte, string, string, error) {
	payload, err := json.Marshal(struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{Username: username, Password: string(password)})
	if err != nil {
		return nil, nil, "", "", errors.New("login failed")
	}
	defer wipe(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(cfg.ManagerURL, "/")+"/api/v1/auth/login", bytes.NewReader(payload))
	if err != nil {
		return nil, nil, "", "", errors.New("login failed")
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := HTTPClient(cfg).Do(req)
	if err != nil {
		if IsTrustError(err) {
			return nil, nil, "", "", err
		}
		return nil, nil, "", "", errors.New("manager unavailable")
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, nil, "", "", errors.New("login failed")
	}
	defer wipe(body)
	var parsed loginResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, nil, "", "", errors.New("login failed")
	}
	if res.StatusCode == http.StatusUnauthorized {
		return nil, nil, "", "", errors.New("invalid username or password")
	}
	if res.StatusCode == http.StatusForbidden {
		return nil, nil, "", "", errors.New("account disabled")
	}
	if res.StatusCode != http.StatusOK || parsed.IdentityToken == "" || parsed.TokenType != "Bearer" {
		return nil, nil, "", "", errors.New("login failed")
	}
	subject, err := subjectOf(parsed.IdentityToken)
	if err != nil {
		return nil, nil, "", "", errors.New("login failed")
	}
	loreTok := parsed.LoreToken
	if loreTok == "" {
		loreTok = parsed.IdentityToken
	}
	return []byte(parsed.IdentityToken), []byte(loreTok), subject, parsed.Username, nil
}

func storeIdentity(ctx context.Context, cfg Config, exec loreexec.Executor, token []byte, remote string) error {
	return storeIdentityWith(ctx, cfg, func(c context.Context, req loreexec.Request) (loreexec.CommandResult, error) {
		return exec.Run(c, req)
	}, token, remote)
}

func storeIdentityWith(ctx context.Context, cfg Config, run func(context.Context, loreexec.Request) (loreexec.CommandResult, error), token []byte, remote string) error {
	argv := []string{"login", "--token-type", "lore", "--token", string(token)}
	if cfg.AuthURL != "" {
		argv = append(argv, "--auth-url", cfg.AuthURL)
	}
	if strings.TrimSpace(remote) != "" {
		argv = append(argv, remote)
	}
	res, err := run(ctx, loreexec.Request{Argv: argv, Env: loreEnv(cfg)})
	if err != nil || !res.ProcessSucceeded() {
		return fmt.Errorf("lore login failed exit=%d detail=%s", res.ExitCode, publicText(res.Stderr+" "+res.Stdout))
	}
	return nil
}

func confirmIdentity(ctx context.Context, cfg Config, exec loreexec.Executor, subject, username string) error {
	return confirmIdentityWith(ctx, cfg, func(c context.Context, req loreexec.Request) (loreexec.CommandResult, error) {
		return exec.Run(c, req)
	}, subject, username)
}

func confirmIdentityWith(ctx context.Context, cfg Config, run func(context.Context, loreexec.Request) (loreexec.CommandResult, error), subject, username string) error {
	res, err := run(ctx, loreexec.Request{Argv: []string{"auth", "list"}, Env: loreEnv(cfg)})
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
	if cfg.CAFile != "" {
		env["SSL_CERT_FILE"] = cfg.CAFile
	}
	if len(env) == 0 {
		return nil
	}
	return env
}

func firstRepositoryURL(ctx context.Context, cfg Config, token []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(cfg.ManagerURL, "/")+"/api/v1/me/modules", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+string(token))
	res, err := HTTPClient(cfg).Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil || res.StatusCode != http.StatusOK {
		return "", errors.New("module list failed")
	}
	var parsed struct {
		Modules []struct {
			RepositoryURL string
		}
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", err
	}
	for _, m := range parsed.Modules {
		if strings.TrimSpace(m.RepositoryURL) != "" {
			return m.RepositoryURL, nil
		}
	}
	return "", errors.New("no repository")
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

// SessionPath returns the private file where lore-mono persists the long-lived
// Manager session token (without exp). It stays out of client.toml and out of git.
func SessionPath(cfg Config) (string, error) {
	if strings.TrimSpace(cfg.AuthPath) != "" {
		return filepath.Join(cfg.AuthPath, "lore-mono-session.tok"), nil
	}
	if strings.TrimSpace(cfg.Path) != "" {
		return filepath.Join(filepath.Dir(cfg.Path), ".lore-mono-session.tok"), nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(strings.TrimRight(cfg.ManagerURL, "/")))
	return filepath.Join(base, "lore-mono", "session-"+hex.EncodeToString(sum[:8])+".tok"), nil
}

// SaveSession writes the persistent Manager session token with 0600 permissions.
func SaveSession(cfg Config, token []byte) error {
	if len(bytes.TrimSpace(token)) == 0 {
		return nil
	}
	path, err := SessionPath(cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFile(path, bytes.TrimSpace(token))
}

// LoadSession reads the persistent Manager session token if present.
func LoadSession(cfg Config) ([]byte, error) {
	path, err := SessionPath(cfg)
	if err != nil {
		return nil, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, errors.New("empty session")
	}
	return trimmed, nil
}

// DeleteSession removes the stored persistent Manager session token.
func DeleteSession(cfg Config) error {
	path, err := SessionPath(cfg)
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// EnsureLoreCredential checks whether the Lore credential store already holds a
// non-expired identity token; if missing or near expiry, it silently refreshes
// one from Manager using the persistent session token without prompting.
func EnsureLoreCredential(ctx context.Context, cfg Config, exec loreexec.Executor) error {
	return EnsureLoreCredentialWith(ctx, cfg, func(c context.Context, req loreexec.Request) (loreexec.CommandResult, error) {
		return exec.Run(c, req)
	})
}

// EnsureLoreCredentialWith runs Lore credential inspection/storage through a custom runner.
func EnsureLoreCredentialWith(ctx context.Context, cfg Config, run func(context.Context, loreexec.Request) (loreexec.CommandResult, error)) error {
	sessionTok, err := LoadSession(cfg)
	if err != nil {
		return nil // fall back to whatever Lore credential store already holds
	}
	defer wipe(sessionTok)

	res, runErr := run(ctx, loreexec.Request{Argv: []string{"auth", "list", "--with-token"}, Env: loreEnv(cfg)})
	if runErr == nil && res.ExitCode == 0 {
		if loreTok := extractListedToken(res.Stdout); loreTok != "" {
			if !jwtExpiresSoon(loreTok, 2*time.Minute) {
				return nil
			}
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(cfg.ManagerURL, "/")+"/api/v1/auth/lore-token", nil)
	if err != nil {
		return errors.New("session refresh failed")
	}
	req.Header.Set("Authorization", "Bearer "+string(sessionTok))
	resp, err := HTTPClient(cfg).Do(req)
	if err != nil {
		if IsTrustError(err) {
			return err
		}
		return errors.New("manager unavailable")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return errors.New("session refresh failed")
	}
	defer wipe(body)
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return errors.New("session expired or revoked; please run lore-mono login")
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New("session refresh failed")
	}
	var parsed struct {
		LoreToken string `json:"lore_token"`
		Username  string `json:"username"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.LoreToken == "" {
		return errors.New("session refresh failed")
	}
	subject, err := subjectOf(parsed.LoreToken)
	if err != nil {
		return errors.New("session refresh failed")
	}
	remote := cfg.RemoteURL
	if strings.TrimSpace(remote) == "" {
		if found, findErr := firstRepositoryURL(ctx, cfg, sessionTok); findErr == nil {
			remote = found
		}
	}
	if err := storeIdentityWith(ctx, cfg, run, []byte(parsed.LoreToken), remote); err != nil {
		return err
	}
	return confirmIdentityWith(ctx, cfg, run, subject, parsed.Username)
}

func extractListedToken(stdout string) string {
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Token:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Token:"))
		}
	}
	return ""
}

func jwtExpiresSoon(raw string, margin time.Duration) bool {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return true
	}
	dec, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return true
	}
	var claims struct {
		Exp *int64 `json:"exp"`
	}
	if err := json.Unmarshal(dec, &claims); err != nil || claims.Exp == nil || *claims.Exp <= 0 {
		return true
	}
	return !time.Now().UTC().Add(margin).Before(time.Unix(*claims.Exp, 0))
}
