package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "manager.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const valid = `
[manager]
listen = "127.0.0.1:52000"
shutdown_timeout = "15s"

[database]
path = "data/manager.db"

[lore]
binary = "bin/lore"
command_timeout = "2m"

[logging]
level = "debug"
format = "json"

[auth]
issuer = "http://127.0.0.1:52010"
audience = ["lore-host.internal"]
`

func TestLoadValidResolvesRelativePaths(t *testing.T) {
	path := writeConfig(t, valid)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(cfg.Path)
	if cfg.DatabasePath != filepath.Join(dir, "data", "manager.db") {
		t.Fatalf("database path %s", cfg.DatabasePath)
	}
	if cfg.LoreBinary != filepath.Join(dir, "bin", "lore") {
		t.Fatalf("binary %s", cfg.LoreBinary)
	}
	if cfg.ShutdownTimeout != 15*time.Second || cfg.CommandTimeout != 2*time.Minute {
		t.Fatalf("timeouts %s %s", cfg.ShutdownTimeout, cfg.CommandTimeout)
	}
	if cfg.Auth.IdentityTTL != DefaultIdentityTTL || cfg.Auth.AccessTTL != DefaultAccessTTL {
		t.Fatalf("auth ttl %+v", cfg.Auth)
	}
	if cfg.Auth.PrivateKey != filepath.Join(dir, "data", "keys", "identity-active.pem") {
		t.Fatalf("private key path %s", cfg.Auth.PrivateKey)
	}
	if cfg.Auth.GRPCListen != DefaultGRPCListen {
		t.Fatalf("grpc %s", cfg.Auth.GRPCListen)
	}
	if cfg.AuthStore != "" {
		t.Fatalf("auth store defaulted to %q", cfg.AuthStore)
	}
}

func TestDefaults(t *testing.T) {
	path := writeConfig(t, "[lore]\nbinary = \"lore\"\n[auth]\nissuer = \"http://127.0.0.1:52010\"\naudience = [\"lore-host.internal\"]\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != DefaultListen || cfg.LogLevel != "info" || cfg.LogFormat != "json" {
		t.Fatalf("%+v", cfg)
	}
	if cfg.ShutdownTimeout != DefaultShutdownTimeout || cfg.CommandTimeout != DefaultCommandTimeout {
		t.Fatalf("defaults %+v", cfg)
	}
}

func TestMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.toml")); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestMalformed(t *testing.T) {
	path := writeConfig(t, "[lore\nbinary = \n")
	if _, err := Load(path); err == nil {
		t.Fatal("malformed toml accepted")
	}
}

func TestInvalidListenAndTimeout(t *testing.T) {
	cases := []string{
		"[lore]\nbinary = \"lore\"\n[manager]\nlisten = \"bad\"\n",
		"[lore]\nbinary = \"lore\"\n[manager]\nlisten = \"0.0.0.0:52000\"\n",
		"[lore]\nbinary = \"lore\"\n[manager]\nshutdown_timeout = \"0s\"\n",
		"[lore]\nbinary = \"lore\"\n[manager]\nshutdown_timeout = \"nope\"\n",
		"[lore]\nbinary = \"lore\"\n[lore]\nauth_store = \"keyring\"\n[auth]\nissuer = \"http://127.0.0.1:52010\"\naudience = [\"lore-host.internal\"]\n",
		"unknown = true\n[lore]\nbinary = \"lore\"\n[auth]\nissuer = \"http://127.0.0.1:52010\"\naudience = [\"lore-host.internal\"]\n",
		"[lore]\nbinary = \"lore\"\n",
		"[lore]\nbinary = \"lore\"\n[auth]\nissuer = \"http://127.0.0.1:52010\"\naudience = []\n",
		"[lore]\nbinary = \"lore\"\n[auth]\nissuer = \"http://127.0.0.1:52010\"\naudience = [\"*\"]\n",
		"[lore]\nbinary = \"lore\"\n[manager]\nlisten = \"127.0.0.1:52010\"\n[auth]\nissuer = \"http://127.0.0.1:52010\"\naudience = [\"lore-host.internal\"]\ngrpc_listen = \"127.0.0.1:52010\"\n",
		"[lore]\nbinary = \"lore\"\n[auth]\nissuer = \"http://127.0.0.1:52010\"\naudience = [\"lore-host.internal\"]\nidentity_ttl = \"0s\"\n",
	}
	for _, body := range cases {
		path := writeConfig(t, body)
		if _, err := Load(path); err == nil {
			t.Fatalf("accepted %q", body)
		}
	}
}

func TestAuthStoreFallbackAllowed(t *testing.T) {
	path := writeConfig(t, "[lore]\nbinary = \"lore\"\nauth_store = \"fallback\"\nauth_path = \"data/auth\"\n[auth]\nissuer = \"http://127.0.0.1:52010\"\naudience = [\"lore-host.internal\"]\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthStore != "fallback" || !strings.HasSuffix(cfg.AuthPath, filepath.Join("data", "auth")) {
		t.Fatalf("%+v", cfg)
	}
}
