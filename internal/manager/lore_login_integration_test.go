package manager

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"lore-monorepo/internal/client"
	"lore-monorepo/internal/config"
	"lore-monorepo/internal/logging"
	"lore-monorepo/internal/loreexec"
	"lore-monorepo/internal/user"
)

// TestRealLoreCredentialStore runs only when LORE_BIN points at the Lore 0.10.1
// wrapper. The child gets its own auth directory and LORE_AUTH_STORE=fallback.
// It does not open a Lore server and does not use the operator credential store.
func TestRealLoreCredentialStore(t *testing.T) {
	bin := os.Getenv("LORE_BIN")
	if bin == "" {
		t.Skip("LORE_BIN is not set")
	}
	dir := t.TempDir()
	app, err := New(config.Config{
		Listen:          "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		DatabasePath:    filepath.Join(dir, "manager.db"),
		LoreBinary:      bin,
		CommandTimeout:  time.Second,
		LogLevel:        "info",
		LogFormat:       "json",
		Auth: config.Auth{
			Issuer:      "http://127.0.0.1:52010",
			Audience:    []string{"127.0.0.1"},
			GRPCListen:  "127.0.0.1:52011",
			IdentityTTL: 12 * time.Hour,
			AccessTTL:   5 * time.Minute,
			PrivateKey:  filepath.Join(dir, "keys", "identity-active.pem"),
			PublicKey:   filepath.Join(dir, "keys", "identity-active.pub.pem"),
			JWKS:        filepath.Join(dir, "keys", "jwks.json"),
		},
	}, logging.New(io.Discard, logging.Info, "manager"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.DB.Close() })
	if _, err := user.Create(context.Background(), app.DB, "test", "alice", "correct-horse", "user"); err != nil {
		t.Fatal(err)
	}
	url := httptestServer(t, app)
	cfg := client.Config{
		ManagerURL: url,
		LoreBinary: bin,
		AuthURL:    "http://127.0.0.1:52010",
		AuthStore:  "fallback",
		AuthPath:   t.TempDir(),
	}
	exec := loreexec.Executor{Config: loreexec.Config{Binary: bin, Timeout: time.Minute}}
	if err := client.Login(context.Background(), cfg, "alice", []byte("correct-horse"), exec); err != nil {
		t.Fatal(err)
	}
}
