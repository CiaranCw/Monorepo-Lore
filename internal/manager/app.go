// Package manager wires configuration, SQLite, the Lore adapter, and HTTP.
package manager

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"lore-monorepo/internal/authbridge"
	"lore-monorepo/internal/config"
	"lore-monorepo/internal/database"
	"lore-monorepo/internal/gitimport"
	"lore-monorepo/internal/logging"
	"lore-monorepo/internal/loreadapter"
	"lore-monorepo/internal/loreexec"
	"lore-monorepo/internal/project"
	"lore-monorepo/internal/publish"
	"lore-monorepo/internal/token"

	"google.golang.org/grpc"

	"lore-monorepo/gen/epic_urc"
	"lore-monorepo/gen/ucs_auth"
)

// Version and Commit are overridden with -ldflags when a release build has them.
var (
	Version = "0.0.0-dev"
	Commit  = "unknown"
)

// UserStore and ProjectStore share one database connection.
// Business methods stay in internal/user and internal/project.
type UserStore struct{ DB *sql.DB }
type ProjectStore struct{ DB *sql.DB }

// App is one Manager process.
type App struct {
	Config        config.Config
	Log           *logging.Logger
	DB            *sql.DB
	Users         *UserStore
	Projects      *ProjectStore
	Exec          loreexec.Executor
	Lore          *loreadapter.Client
	Tokens        *token.Service
	Bridge        *authbridge.Service
	PublishDriver publish.Driver
	PublishLore   *loreadapter.Client
	PublishRoot   string
	Importer      *gitimport.Importer
	HTTP          *http.Server
	grpcSrv       *grpc.Server

	// snapshotPreparer is test-only dependency injection. Production always
	// prepares server-owned parent/module workspaces through prepareSnapshot.
	snapshotPreparer func(context.Context, *project.Project) (string, map[string]string, error)

	// Gate, if set, runs at the start of every HTTP request. Tests use it
	// to hold a request across shutdown. Production leaves it nil.
	Gate func()
}

// New opens SQLite, runs migrations, and builds the Lore adapter.
// The HTTP server is not started.
func New(cfg config.Config, log *logging.Logger) (*App, error) {
	if log == nil {
		return nil, errors.New("manager: logger is nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	tokens, err := token.Open(token.Options{
		Issuer:      cfg.Auth.Issuer,
		Audience:    cfg.Auth.Audience,
		IdentityTTL: cfg.Auth.IdentityTTL,
		AccessTTL:   cfg.Auth.AccessTTL,
		PrivateKey:  cfg.Auth.PrivateKey,
		PublicKey:   cfg.Auth.PublicKey,
		JWKS:        cfg.Auth.JWKS,
	})
	if err != nil {
		return nil, err
	}
	log.Info("token service ready", map[string]any{
		"active_kid":  tokens.ActiveKID(),
		"grpc_listen": cfg.Auth.GRPCListen,
	})
	if err := os.MkdirAll(filepath.Dir(cfg.DatabasePath), 0o755); err != nil {
		return nil, fmt.Errorf("database directory: %w", err)
	}
	db, err := database.Open(cfg.DatabasePath)
	if err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	env := map[string]string{}
	if cfg.AuthStore != "" {
		env["LORE_AUTH_STORE"] = cfg.AuthStore
	}
	if cfg.AuthPath != "" {
		env["LORE_AUTH_PATH"] = cfg.AuthPath
	}
	var envOrNil map[string]string
	if len(env) > 0 {
		envOrNil = env
	}
	exec := loreexec.Executor{Config: loreexec.Config{
		Binary:  cfg.LoreBinary,
		Timeout: cfg.CommandTimeout,
		Env:     envOrNil,
	}}
	if err := gitimport.RecoverInterruptedJobs(context.Background(), db); err != nil {
		db.Close()
		return nil, fmt.Errorf("recover import jobs: %w", err)
	}
	loreClient := &loreadapter.Client{Exec: exec, Env: envOrNil}
	importWorkspace := cfg.Import.Workspace
	if importWorkspace == "" {
		importWorkspace = filepath.Join(filepath.Dir(cfg.DatabasePath), "imports")
	}
	gitBin := cfg.Import.GitBinary
	if gitBin == "" {
		gitBin = "git"
	}
	app := &App{
		Config:   cfg,
		Log:      log,
		DB:       db,
		Users:    &UserStore{DB: db},
		Projects: &ProjectStore{DB: db},
		Exec:     exec,
		Lore:     loreClient,
		Tokens:   tokens,
		Importer: &gitimport.Importer{
			DB:                   db,
			Lore:                 loreClient,
			GitBinary:            gitBin,
			WorkspaceRoot:        importWorkspace,
			RemoteBaseURL:        cfg.Import.RemoteBaseURL,
			RestrictLocalSources: true,
			AllowedLocalDirs:     append([]string(nil), cfg.Import.AllowedLocalDirs...),
			RestrictSSHKeyPaths:  true,
			AllowedSSHKeyDirs:    append([]string(nil), cfg.Import.AllowedSSHDirs...),
		},
	}
	app.Bridge = authbridge.New(
		authbridge.UserDirectory{Get: app.userByID},
		tokens,
		tokens,
		authbridge.NewStoreResolver(db),
	)
	app.HTTP = &http.Server{
		Addr:              cfg.Listen,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return app, nil
}

// Run listens until ctx is cancelled, then drains HTTP and closes the database.
func (a *App) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", a.Config.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	return a.Serve(ctx, ln)
}

// Serve accepts on ln. Shutdown waits for active handlers, then closes SQLite.
func (a *App) Serve(ctx context.Context, ln net.Listener) error {
	grpcLn, err := net.Listen("tcp", a.Config.Auth.GRPCListen)
	if err != nil {
		return fmt.Errorf("auth grpc listen: %w", err)
	}
	a.grpcSrv = grpc.NewServer()
	epic_urc.RegisterUrcAuthApiServer(a.grpcSrv, a.Bridge)
	ucs_auth.RegisterRebacApiServer(a.grpcSrv, a.Bridge)
	a.Log.Info("manager listening", map[string]any{
		"http": ln.Addr().String(),
		"grpc": grpcLn.Addr().String(),
	})
	errCh := make(chan error, 2)
	go func() {
		err := a.grpcSrv.Serve(grpcLn)
		if errors.Is(err, grpc.ErrServerStopped) {
			err = nil
		}
		errCh <- err
	}()
	go func() {
		err := a.HTTP.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()
	select {
	case <-ctx.Done():
	case err := <-errCh:
		a.stopServers()
		a.closeDB()
		return err
	}
	a.stopServers()
	a.closeDB()
	a.Log.Info("manager stopped", nil)
	return nil
}

func (a *App) stopServers() {
	shutCtx, cancel := context.WithTimeout(context.Background(), a.Config.ShutdownTimeout)
	defer cancel()
	stopped := make(chan struct{})
	if a.grpcSrv != nil {
		go func() {
			a.grpcSrv.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-shutCtx.Done():
			a.grpcSrv.Stop()
		}
	}
	if a.HTTP != nil {
		_ = a.HTTP.Shutdown(shutCtx)
	}
}

func (a *App) closeDB() {
	if a.DB == nil {
		return
	}
	if err := a.DB.Close(); err != nil {
		a.Log.Error("close database", map[string]any{"err": err.Error()})
	}
	a.DB = nil
}

// NotifyContext cancels when the process receives Ctrl+C or SIGTERM.
func NotifyContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-ch:
			cancel()
		case <-ctx.Done():
		}
		signal.Stop(ch)
	}()
	return ctx, cancel
}
