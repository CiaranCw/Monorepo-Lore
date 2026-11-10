// Package config loads the Manager TOML file.
//
// Relative paths are resolved against the directory that contains the config
// file, not the process working directory. The file stores key paths, never
// key bytes, JWTs, or passwords. LORE_AUTH_STORE is left empty unless the
// file sets auth_store = "fallback".
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

const (
	DefaultListen          = "127.0.0.1:52000"
	DefaultShutdownTimeout = 15 * time.Second
	DefaultCommandTimeout  = 120 * time.Second
	DefaultDatabasePath    = "data/manager.db"
	DefaultLogLevel        = "info"
	DefaultLogFormat       = "json"
	DefaultGRPCListen      = "127.0.0.1:52010"
	DefaultIdentityTTL     = 12 * time.Hour
	DefaultAccessTTL       = 5 * time.Minute
	DefaultPrivateKey      = "data/keys/identity-active.pem"
	DefaultPublicKey       = "data/keys/identity-active.pub.pem"
	DefaultJWKS            = "data/keys/jwks.json"
)

// Config is the validated Manager configuration.
type Config struct {
	Path            string
	Listen          string
	ShutdownTimeout time.Duration
	DatabasePath    string
	LoreBinary      string
	CommandTimeout  time.Duration
	AuthStore       string
	AuthPath        string
	LogLevel        string
	LogFormat       string
	Auth            Auth
	Publish         Publish
}

// Publish is the server-side snapshot publisher. Empty Workspace leaves it unmounted.
// The auth path belongs to the publisher service account and is never returned to users.
type Publish struct {
	ParentURL string
	Workspace string
	AuthStore string
	AuthPath  string
	CAFile    string
}

// Auth is the Token Service configuration. Paths are files, not key material.
// GRPCListen is reserved for a future AuthBridge and is not bound in B2.1.
type Auth struct {
	Issuer      string
	Audience    []string
	GRPCListen  string
	IdentityTTL time.Duration
	AccessTTL   time.Duration
	PrivateKey  string
	PublicKey   string
	JWKS        string
}

type fileConfig struct {
	Manager struct {
		Listen          string `toml:"listen"`
		ShutdownTimeout string `toml:"shutdown_timeout"`
	} `toml:"manager"`
	Database struct {
		Path string `toml:"path"`
	} `toml:"database"`
	Lore struct {
		Binary         string `toml:"binary"`
		CommandTimeout string `toml:"command_timeout"`
		AuthStore      string `toml:"auth_store"`
		AuthPath       string `toml:"auth_path"`
	} `toml:"lore"`
	Logging struct {
		Level  string `toml:"level"`
		Format string `toml:"format"`
	} `toml:"logging"`
	Auth struct {
		Issuer      string   `toml:"issuer"`
		Audience    []string `toml:"audience"`
		GRPCListen  string   `toml:"grpc_listen"`
		IdentityTTL string   `toml:"identity_ttl"`
		AccessTTL   string   `toml:"access_ttl"`
		PrivateKey  string   `toml:"private_key"`
		PublicKey   string   `toml:"public_key"`
		JWKS        string   `toml:"jwks"`
	} `toml:"auth"`
	Publish struct {
		ParentURL string `toml:"parent_url"`
		Workspace string `toml:"workspace"`
		AuthStore string `toml:"auth_store"`
		AuthPath  string `toml:"auth_path"`
		CAFile    string `toml:"ca_file"`
	} `toml:"publish"`
}

// Load reads path and validates it. Missing files and malformed TOML are errors.
func Load(path string) (Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Config{}, fmt.Errorf("config path: %w", err)
	}
	body, err := os.ReadFile(abs)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var raw fileConfig
	meta, err := toml.Decode(string(body), &raw)
	if err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		return Config{}, fmt.Errorf("unknown config keys: %s", undecoded)
	}
	cfg := Config{
		Path:         abs,
		Listen:       raw.Manager.Listen,
		DatabasePath: raw.Database.Path,
		LoreBinary:   raw.Lore.Binary,
		AuthStore:    raw.Lore.AuthStore,
		AuthPath:     raw.Lore.AuthPath,
		LogLevel:     raw.Logging.Level,
		LogFormat:    raw.Logging.Format,
		Auth: Auth{
			Issuer:     strings.TrimSpace(raw.Auth.Issuer),
			Audience:   raw.Auth.Audience,
			GRPCListen: raw.Auth.GRPCListen,
			PrivateKey: raw.Auth.PrivateKey,
			PublicKey:  raw.Auth.PublicKey,
			JWKS:       raw.Auth.JWKS,
		},
		Publish: Publish{
			ParentURL: strings.TrimSpace(raw.Publish.ParentURL),
			Workspace: strings.TrimSpace(raw.Publish.Workspace),
			AuthStore: strings.TrimSpace(raw.Publish.AuthStore),
			AuthPath:  strings.TrimSpace(raw.Publish.AuthPath),
			CAFile:    strings.TrimSpace(raw.Publish.CAFile),
		},
	}
	if cfg.Listen == "" {
		cfg.Listen = DefaultListen
	}
	if cfg.DatabasePath == "" {
		cfg.DatabasePath = DefaultDatabasePath
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = DefaultLogLevel
	}
	if cfg.LogFormat == "" {
		cfg.LogFormat = DefaultLogFormat
	}
	if cfg.Auth.GRPCListen == "" {
		cfg.Auth.GRPCListen = DefaultGRPCListen
	}
	if cfg.Auth.PrivateKey == "" {
		cfg.Auth.PrivateKey = DefaultPrivateKey
	}
	if cfg.Auth.PublicKey == "" {
		cfg.Auth.PublicKey = DefaultPublicKey
	}
	if cfg.Auth.JWKS == "" {
		cfg.Auth.JWKS = DefaultJWKS
	}
	cfg.ShutdownTimeout, err = parseDuration(raw.Manager.ShutdownTimeout, DefaultShutdownTimeout, "manager.shutdown_timeout")
	if err != nil {
		return Config{}, err
	}
	cfg.CommandTimeout, err = parseDuration(raw.Lore.CommandTimeout, DefaultCommandTimeout, "lore.command_timeout")
	if err != nil {
		return Config{}, err
	}
	cfg.Auth.IdentityTTL, err = parseDuration(raw.Auth.IdentityTTL, DefaultIdentityTTL, "auth.identity_ttl")
	if err != nil {
		return Config{}, err
	}
	cfg.Auth.AccessTTL, err = parseDuration(raw.Auth.AccessTTL, DefaultAccessTTL, "auth.access_ttl")
	if err != nil {
		return Config{}, err
	}
	base := filepath.Dir(abs)
	cfg.DatabasePath = resolve(base, cfg.DatabasePath)
	cfg.LoreBinary = resolve(base, cfg.LoreBinary)
	if cfg.AuthPath != "" {
		cfg.AuthPath = resolve(base, cfg.AuthPath)
	}
	if cfg.Publish.Workspace != "" {
		cfg.Publish.Workspace = resolve(base, cfg.Publish.Workspace)
	}
	if cfg.Publish.AuthPath != "" {
		cfg.Publish.AuthPath = resolve(base, cfg.Publish.AuthPath)
	}
	if cfg.Publish.CAFile != "" {
		cfg.Publish.CAFile = resolve(base, cfg.Publish.CAFile)
	}
	cfg.Auth.PrivateKey = resolve(base, cfg.Auth.PrivateKey)
	cfg.Auth.PublicKey = resolve(base, cfg.Auth.PublicKey)
	cfg.Auth.JWKS = resolve(base, cfg.Auth.JWKS)
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks fields without reading the database or starting Lore.
func (c Config) Validate() error {
	if err := validateListen(c.Listen); err != nil {
		return err
	}
	if c.ShutdownTimeout <= 0 {
		return fmt.Errorf("manager.shutdown_timeout must be positive")
	}
	if c.CommandTimeout <= 0 {
		return fmt.Errorf("lore.command_timeout must be positive")
	}
	if strings.TrimSpace(c.DatabasePath) == "" {
		return fmt.Errorf("database.path is required")
	}
	if strings.TrimSpace(c.LoreBinary) == "" {
		return fmt.Errorf("lore.binary is required")
	}
	switch c.AuthStore {
	case "", "fallback":
	default:
		return fmt.Errorf("lore.auth_store must be empty or \"fallback\"")
	}
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("logging.level must be debug, info, warn, or error")
	}
	if c.LogFormat != "json" {
		return fmt.Errorf("logging.format must be json")
	}
	return c.Auth.validate(c.Listen)
}

func parseDuration(raw string, fallback time.Duration, name string) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}
	return d, nil
}

func resolve(base, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}

func (a Auth) validate(httpListen string) error {
	if a.Issuer == "" || strings.ContainsAny(a.Issuer, " \t\r\n") {
		return fmt.Errorf("auth.issuer is required")
	}
	if len(a.Audience) == 0 {
		return fmt.Errorf("auth.audience is required")
	}
	for _, aud := range a.Audience {
		if strings.TrimSpace(aud) == "" || strings.ContainsAny(aud, " \t\r\n") || strings.Contains(aud, "*") {
			return fmt.Errorf("auth.audience entries must be non-empty hosts")
		}
	}
	if err := validateListenAddr(a.GRPCListen, "auth.grpc_listen"); err != nil {
		return err
	}
	if a.GRPCListen == httpListen {
		return fmt.Errorf("auth.grpc_listen must differ from manager.listen")
	}
	if a.IdentityTTL <= 0 || a.AccessTTL <= 0 {
		return fmt.Errorf("auth token lifetimes must be positive")
	}
	if a.PrivateKey == "" || a.PublicKey == "" || a.JWKS == "" {
		return fmt.Errorf("auth key paths are required")
	}
	if a.PrivateKey == a.PublicKey || a.PrivateKey == a.JWKS || a.PublicKey == a.JWKS {
		return fmt.Errorf("auth private key, public key, and jwks must be different files")
	}
	return nil
}

func validateListen(addr string) error {
	return validateListenAddr(addr, "manager.listen")
}

func validateListenAddr(addr, name string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return fmt.Errorf("%s must be host:port", name)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return fmt.Errorf("%s must name a specific address, not every interface", name)
	}
	return nil
}
