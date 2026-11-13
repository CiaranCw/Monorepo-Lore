package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"lore-monorepo/internal/loreexec"
)

// ConnectOptions configures zero-config client onboarding for one Manager and user.
type ConnectOptions struct {
	ManagerURL         string
	Username           string
	Password           []byte
	Project            string
	ExplicitCAFile     string
	ExplicitAuthURL    string
	LoreBinary         string
	ExplicitConfigPath string
	ExplicitAuthPath   string
	AuthStore          string
}

// ConnectResult summarizes the initialized profile without exposing any secrets.
type ConnectResult struct {
	ConfigPath   string   `json:"config_path"`
	ProfileDir   string   `json:"profile_dir"`
	AuthPath     string   `json:"auth_path"`
	CAFile       string   `json:"ca_file,omitempty"`
	CASHA256     string   `json:"ca_sha256,omitempty"`
	TOFUTrusted  bool     `json:"tofu_trusted"`
	ManagerURL   string   `json:"manager_url"`
	AuthURL      string   `json:"auth_url,omitempty"`
	Username     string   `json:"username"`
	Project      string   `json:"project,omitempty"`
	Projects     []string `json:"projects"`
	ModulesCount int      `json:"modules_count"`
}

// UserConfigBaseDir returns the standard per-user configuration directory for lore-mono.
func UserConfigBaseDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "lore-mono"), nil
}

// NormalizeManagerURL validates ManagerURL and returns a canonical form for profile keying.
func NormalizeManagerURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if err := CheckManagerURL(raw); err != nil {
		return "", err
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/"), nil
}

// ProfileDir returns an isolated profile directory keyed by Manager URL and username.
func ProfileDir(baseDir, managerURL, username string) string {
	u, _ := url.Parse(managerURL)
	hostPart := "manager"
	if u != nil && u.Hostname() != "" {
		hostPart = sanitizeSlug(u.Hostname())
	}
	userPart := sanitizeSlug(username)
	if userPart == "" {
		userPart = "user"
	}
	sum := sha256.Sum256([]byte(managerURL + "\x00" + username))
	slug := fmt.Sprintf("%s-%s-%s", hostPart, userPart, hex.EncodeToString(sum[:6]))
	return filepath.Join(baseDir, "profiles", slug)
}

// HostPinPath returns the per-Manager TLS pin file under the user config directory.
func HostPinPath(baseDir, managerURL string) string {
	sum := sha256.Sum256([]byte(managerURL))
	return filepath.Join(baseDir, "pins", hex.EncodeToString(sum[:8])+".pin")
}

// HostCAPath returns the cached public CA certificate path for a pinned Manager URL.
func HostCAPath(baseDir, managerURL string) string {
	sum := sha256.Sum256([]byte(managerURL))
	return filepath.Join(baseDir, "pins", hex.EncodeToString(sum[:8])+".pem")
}

// ActiveConfigPath returns the config path recorded by the latest `lore-mono connect`,
// or empty string if none is set or the file no longer exists.
func ActiveConfigPath() (string, error) {
	baseDir, err := UserConfigBaseDir()
	if err != nil {
		return "", nil
	}
	pointer := filepath.Join(baseDir, "current-profile")
	body, err := os.ReadFile(pointer)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	target := strings.TrimSpace(string(body))
	if target == "" {
		return "", nil
	}
	if _, err := os.Stat(target); err != nil {
		return "", nil
	}
	return target, nil
}

// SetActiveConfigPath stores the active auto-connected profile config path.
func SetActiveConfigPath(configPath string) error {
	baseDir, err := UserConfigBaseDir()
	if err != nil {
		return err
	}
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(baseDir, "current-profile"), []byte(abs+"\n"))
}

// ResolveLoreBinary finds the lore CLI executable without modifying user shell config.
func ResolveLoreBinary(explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return strings.TrimSpace(explicit)
	}
	if found, err := exec.LookPath("lore"); err == nil && found != "" {
		return "lore"
	}
	if runtime.GOOS == "windows" {
		candidate := `C:\Program Files\lore\lore.exe`
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	} else {
		for _, candidate := range []string{"/usr/local/bin/lore", "/data/lore/bin/lore"} {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate
			}
		}
	}
	return "lore"
}

// Connect bootstraps TLS trust (with TOFU + SHA-256 fingerprint pinning for internal CAs),
// creates an isolated client profile in the standard user config directory, logs in using
// persistent Manager session + Lore credentials, and discovers accessible projects/modules.
func Connect(ctx context.Context, opts ConnectOptions, execRunner loreexec.Executor) (ConnectResult, error) {
	managerURL, err := NormalizeManagerURL(opts.ManagerURL)
	if err != nil {
		return ConnectResult{}, err
	}
	username := strings.TrimSpace(opts.Username)
	if username == "" {
		return ConnectResult{}, errors.New("username is required")
	}

	var baseDir, profileDir, configPath, authPath, caSavePath, profilePinPath, hostPinPath, hostCAPath string
	if strings.TrimSpace(opts.ExplicitConfigPath) != "" {
		absCfg, absErr := filepath.Abs(opts.ExplicitConfigPath)
		if absErr != nil {
			return ConnectResult{}, absErr
		}
		configPath = absCfg
		profileDir = filepath.Dir(absCfg)
		authPath = strings.TrimSpace(opts.ExplicitAuthPath)
		if authPath == "" {
			authPath = filepath.Join(profileDir, "auth")
		}
		caSavePath = filepath.Join(profileDir, "ca.pem")
		profilePinPath = PinPathForCA(caSavePath)
	} else {
		baseDir, err = UserConfigBaseDir()
		if err != nil {
			return ConnectResult{}, err
		}
		profileDir = ProfileDir(baseDir, managerURL, username)
		configPath = filepath.Join(profileDir, "client.toml")
		authPath = strings.TrimSpace(opts.ExplicitAuthPath)
		if authPath == "" {
			authPath = filepath.Join(profileDir, "auth")
		}
		caSavePath = filepath.Join(profileDir, "ca.pem")
		profilePinPath = PinPathForCA(caSavePath)
		hostPinPath = HostPinPath(baseDir, managerURL)
		hostCAPath = HostCAPath(baseDir, managerURL)
	}

	if err := os.MkdirAll(authPath, 0o700); err != nil {
		return ConnectResult{}, err
	}

	// Preserve project/auth_url only from this exact isolated profile if reconnecting.
	var prevCfg Config
	if loaded, loadErr := Load(configPath); loadErr == nil {
		prevCfg = loaded
	}

	boot, err := bootstrapTLSAndInfo(ctx, managerURL, opts.ExplicitCAFile, caSavePath, profilePinPath, hostPinPath, hostCAPath)
	if err != nil {
		return ConnectResult{}, err
	}

	authStore := strings.TrimSpace(opts.AuthStore)
	if authStore == "" {
		authStore = "fallback"
	}
	authURL := strings.TrimSpace(opts.ExplicitAuthURL)
	if authURL == "" {
		authURL = strings.TrimSpace(boot.Info.AuthURL)
	}
	if authURL == "" {
		authURL = strings.TrimSpace(prevCfg.AuthURL)
	}
	loreBinary := ResolveLoreBinary(opts.LoreBinary)

	cfg := Config{
		Path:       configPath,
		ManagerURL: managerURL,
		LoreBinary: loreBinary,
		AuthURL:    authURL,
		AuthStore:  authStore,
		AuthPath:   authPath,
		Project:    prevCfg.Project,
		CAFile:     boot.CAFile,
	}
	if err := Save(cfg); err != nil {
		return ConnectResult{}, err
	}
	if execRunner.Config.Binary == "" {
		execRunner.Config.Binary = loreBinary
	}

	if err := Login(ctx, cfg, username, opts.Password, execRunner); err != nil {
		if boot.TOFULeafOnly {
			return ConnectResult{}, fmt.Errorf("%w (server sent only a non-CA leaf cert without /api/v1/client/info ca_pem; pass --ca-file <ca.pem> if Lore rejects it)", err)
		}
		return ConnectResult{}, err
	}

	// If auth_url was not published by Manager, capture the URL Lore discovered via Gateway.
	if cfg.AuthURL == "" {
		if discovered := discoverLoreAuthURL(ctx, cfg, execRunner); discovered != "" {
			cfg.AuthURL = discovered
			_ = Save(cfg)
		}
	}

	sessionTok, err := LoadSession(cfg)
	if err != nil {
		return ConnectResult{}, errors.New("session unavailable after login")
	}
	defer wipe(sessionTok)

	projects, err := fetchProjectNames(ctx, cfg, sessionTok)
	if err != nil {
		return ConnectResult{}, err
	}
	targetProject := strings.TrimSpace(opts.Project)
	if targetProject != "" {
		if !containsString(projects, targetProject) {
			return ConnectResult{}, fmt.Errorf("project %q is not accessible", targetProject)
		}
		cfg.Project = targetProject
		if err := Save(cfg); err != nil {
			return ConnectResult{}, err
		}
	} else if cfg.Project != "" && !containsString(projects, cfg.Project) {
		cfg.Project = ""
		_ = Save(cfg)
	}

	modulesCount, err := countAuthorizedModules(ctx, cfg, sessionTok, cfg.Project)
	if err != nil {
		return ConnectResult{}, err
	}

	if strings.TrimSpace(opts.ExplicitConfigPath) == "" {
		if err := SetActiveConfigPath(cfg.Path); err != nil {
			return ConnectResult{}, err
		}
	}

	return ConnectResult{
		ConfigPath:   cfg.Path,
		ProfileDir:   profileDir,
		AuthPath:     cfg.AuthPath,
		CAFile:       cfg.CAFile,
		CASHA256:     boot.CASHA256,
		TOFUTrusted:  boot.TOFUTrusted,
		ManagerURL:   cfg.ManagerURL,
		AuthURL:      cfg.AuthURL,
		Username:     username,
		Project:      cfg.Project,
		Projects:     projects,
		ModulesCount: modulesCount,
	}, nil
}

func discoverLoreAuthURL(ctx context.Context, cfg Config, execRunner loreexec.Executor) string {
	res, err := execRunner.Run(ctx, loreexec.Request{Argv: []string{"auth", "list"}, Env: loreEnv(cfg)})
	if err != nil || !res.ProcessSucceeded() {
		return ""
	}
	for _, line := range strings.Split(res.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Auth URL:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Auth URL:"))
		}
	}
	return ""
}

func fetchProjectNames(ctx context.Context, cfg Config, token []byte) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(cfg.ManagerURL, "/")+"/api/v1/projects", nil)
	if err != nil {
		return nil, errors.New("project list failed")
	}
	req.Header.Set("Authorization", "Bearer "+string(token))
	res, err := HTTPClient(cfg).Do(req)
	if err != nil {
		return nil, errors.New("project list failed")
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil || res.StatusCode != http.StatusOK {
		return nil, errors.New("project list failed")
	}
	var parsed struct {
		Projects []struct {
			Name string
		}
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, errors.New("project list failed")
	}
	out := make([]string, 0, len(parsed.Projects))
	for _, p := range parsed.Projects {
		if p.Name != "" {
			out = append(out, p.Name)
		}
	}
	return out, nil
}

func countAuthorizedModules(ctx context.Context, cfg Config, token []byte, projectFilter string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(cfg.ManagerURL, "/")+"/api/v1/me/modules", nil)
	if err != nil {
		return 0, errors.New("module list failed")
	}
	req.Header.Set("Authorization", "Bearer "+string(token))
	res, err := HTTPClient(cfg).Do(req)
	if err != nil {
		return 0, errors.New("module list failed")
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil || res.StatusCode != http.StatusOK {
		return 0, errors.New("module list failed")
	}
	var parsed struct {
		Modules []struct {
			ProjectName string
		}
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return 0, errors.New("module list failed")
	}
	count := 0
	for _, m := range parsed.Modules {
		if projectFilter != "" && m.ProjectName != projectFilter {
			continue
		}
		count++
	}
	return count, nil
}

func containsString(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}

func sanitizeSlug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteByte('-')
		}
		if b.Len() >= 24 {
			break
		}
	}
	return strings.Trim(b.String(), "-")
}
