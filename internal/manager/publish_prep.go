package manager

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"lore-monorepo/internal/history"
	"lore-monorepo/internal/loreadapter"
	"lore-monorepo/internal/loreexec"
	"lore-monorepo/internal/project"
	"lore-monorepo/internal/user"
)

// prepareSnapshot clones the parent and each active module into the server
// workspace. The publisher service identity is the only Lore credential used.
// Modules imported in offline managed mode (`lore://local/...`) resolve directly
// to their managed Lore repository directory, and newly pushed revisions are
// indexed into module_commits automatically.
func (a *App) prepareSnapshot(ctx context.Context, p *project.Project) (string, map[string]string, error) {
	if a.PublishLore == nil || a.PublishRoot == "" {
		return "", nil, fmt.Errorf("publisher unavailable")
	}
	root := filepath.Join(a.PublishRoot, strconv.FormatInt(p.ID, 10))
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", nil, err
	}
	parent := filepath.Join(root, "parent")
	if err := os.RemoveAll(parent); err != nil {
		return "", nil, err
	}
	if err := a.cloneInto(ctx, p.ParentRepositoryURL, parent); err != nil {
		_ = os.WriteFile(filepath.Join(root, "prep-error.txt"), []byte("parent: "+err.Error()), 0o644)
		return "", nil, err
	}
	mods, err := project.ListModules(ctx, a.DB, p.ID, false)
	if err != nil {
		return "", nil, err
	}
	dirs := map[string]string{}
	if err := os.MkdirAll(filepath.Join(root, "modules"), 0o755); err != nil {
		return "", nil, err
	}
	for _, m := range mods {
		if strings.HasPrefix(m.RepositoryURL, "lore://local/") {
			if localDir, ok := a.managedLocalRepoDir(ctx, m.ID); ok {
				dirs[m.Name] = localDir
				_, _ = history.SyncModuleFromLore(ctx, a.DB, a.PublishLore, m.ID, localDir)
				continue
			}
		}
		dir := filepath.Join(root, "modules", m.Name)
		if err := os.RemoveAll(dir); err != nil {
			return "", nil, err
		}
		if err := a.cloneInto(ctx, m.RepositoryURL, dir); err != nil {
			_ = os.WriteFile(filepath.Join(root, "prep-error.txt"), []byte(m.Name+": "+err.Error()), 0o644)
			return "", nil, err
		}
		dirs[m.Name] = dir
		_, _ = history.SyncModuleFromLore(ctx, a.DB, a.PublishLore, m.ID, dir)
	}
	return parent, dirs, nil
}

func (a *App) managedLocalRepoDir(ctx context.Context, moduleID int64) (string, bool) {
	var workDir string
	err := a.DB.QueryRowContext(ctx, `
		SELECT lore_work_path FROM import_job_items
		WHERE module_id=? AND lore_work_path <> ''
		ORDER BY item_id DESC LIMIT 1
	`, moduleID).Scan(&workDir)
	if err != nil || workDir == "" {
		return "", false
	}
	if st, statErr := os.Stat(filepath.Join(workDir, ".lore")); statErr == nil && st.IsDir() {
		return workDir, true
	}
	return "", false
}

func (a *App) syncModuleHistoryOnServer(ctx context.Context, m *project.Module, explicitDir string) (history.SyncStats, error) {
	loreClient := a.PublishLore
	if loreClient == nil {
		loreClient = a.Lore
	}
	if loreClient == nil {
		return history.SyncStats{}, fmt.Errorf("lore client unavailable")
	}

	if explicitDir != "" {
		return history.SyncModuleFromLore(ctx, a.DB, loreClient, m.ID, explicitDir)
	}

	if strings.HasPrefix(m.RepositoryURL, "lore://local/") {
		if localDir, ok := a.managedLocalRepoDir(ctx, m.ID); ok {
			return history.SyncModuleFromLore(ctx, a.DB, loreClient, m.ID, localDir)
		}
		return history.SyncStats{}, fmt.Errorf("local module repository workspace not found")
	}

	syncClient, cleanup, err := a.serviceSyncClient(ctx, loreClient, m.RepositoryURL)
	if err != nil {
		return history.SyncStats{}, err
	}
	defer cleanup()

	if localDir, ok := a.managedLocalRepoDir(ctx, m.ID); ok {
		argv := []string{"--non-interactive"}
		if syncClient.Identity != "" {
			argv = append(argv, "--identity", syncClient.Identity)
		}
		argv = append(argv, "sync", "--repository", localDir)
		res, err := syncClient.Exec.Run(ctx, loreexec.Request{
			Argv: argv,
			Dir:  localDir,
			Env:  syncClient.Env,
		})
		if err != nil || res.ExitCode != 0 {
			return history.SyncStats{}, fmt.Errorf("remote lore sync failed for module %s", m.Name)
		}
		return history.SyncModuleFromLore(ctx, a.DB, syncClient, m.ID, localDir)
	}

	cacheBase := filepath.Join(filepath.Dir(a.Config.DatabasePath), "history-cache")
	if a.PublishRoot != "" {
		cacheBase = filepath.Join(a.PublishRoot, "history-cache")
	}
	dest := filepath.Join(cacheBase, strconv.FormatInt(m.ID, 10), "repo")
	if err := a.cloneIntoWithClient(ctx, syncClient, m.RepositoryURL, dest); err != nil {
		return history.SyncStats{}, err
	}
	return history.SyncModuleFromLore(ctx, a.DB, syncClient, m.ID, dest)
}

func (a *App) serviceSyncClient(ctx context.Context, base *loreadapter.Client, repoURL string) (*loreadapter.Client, func(), error) {
	if a.DB == nil || a.Tokens == nil {
		return nil, func() {}, fmt.Errorf("service authentication unavailable")
	}
	account, err := a.resolveServiceAccount(ctx, base)
	if err != nil {
		return nil, func() {}, err
	}
	if account.Kind != "service" {
		return nil, func() {}, fmt.Errorf("account %s is not a service account", account.Username)
	}
	if account.Status != "active" {
		return nil, func() {}, fmt.Errorf("service account %s is disabled", account.Username)
	}

	tok, err := a.Tokens.IssueIdentity(strconv.FormatInt(account.ID, 10), account.Username, account.AuthVersion)
	if err != nil {
		return nil, func() {}, fmt.Errorf("issue service identity token: %w", err)
	}
	defer func() { tok = "" }()

	tmpAuth, err := os.MkdirTemp("", "lore-svc-auth-*")
	if err != nil {
		return nil, func() {}, fmt.Errorf("create service auth dir: %w", err)
	}
	cleanup := func() {
		_ = os.RemoveAll(tmpAuth)
	}

	syncEnv := make(map[string]string, len(base.Env)+2)
	for k, v := range base.Env {
		syncEnv[k] = v
	}
	syncEnv["LORE_AUTH_STORE"] = "fallback"
	syncEnv["LORE_AUTH_PATH"] = tmpAuth

	var syncExec loreadapter.Runner = base.Exec
	if ex, ok := base.Exec.(loreexec.Executor); ok {
		cfg := ex.Config
		cfg.Env = syncEnv
		syncExec = loreexec.Executor{Config: cfg}
	}

	argv := []string{"login", "--token-type", "lore", "--token", tok}
	if authListen := strings.TrimSpace(a.Config.Auth.GRPCListen); authListen != "" && !strings.HasPrefix(a.Config.Auth.Issuer, "https://") {
		argv = append(argv, "--auth-url", "http://"+authListen)
	}
	argv = append(argv, repoURL)
	loginRes, err := syncExec.Run(ctx, loreexec.Request{
		Argv: argv,
		Dir:  tmpAuth,
		Env:  syncEnv,
	})
	if err != nil || loginRes.ExitCode != 0 {
		cleanup()
		return nil, func() {}, fmt.Errorf("service account lore login failed: exit=%d %v", loginRes.ExitCode, err)
	}

	return &loreadapter.Client{
		Exec:     syncExec,
		Env:      syncEnv,
		Identity: strconv.FormatInt(account.ID, 10),
	}, cleanup, nil
}

func (a *App) resolveServiceAccount(ctx context.Context, base *loreadapter.Client) (*user.User, error) {
	if name := strings.TrimSpace(a.Config.Publish.ServiceUser); name != "" {
		account, _, err := user.Get(ctx, a.DB, name)
		if err != nil {
			return nil, fmt.Errorf("service account %s unavailable: %w", name, err)
		}
		return account, nil
	}
	if base != nil && base.Env["LORE_AUTH_PATH"] != "" && base.Exec != nil {
		if res, err := base.Exec.Run(ctx, loreexec.Request{
			Argv: []string{"--non-interactive", "auth", "list"},
			Env:  base.Env,
		}); err == nil && res.ExitCode == 0 {
			name, id := parseLoreAuthUser(res.Stdout)
			if id > 0 {
				account, gErr := user.GetByID(ctx, a.DB, id)
				if gErr != nil {
					return nil, fmt.Errorf("service account %d unavailable: %w", id, gErr)
				}
				return account, nil
			}
			if name != "" {
				account, _, gErr := user.Get(ctx, a.DB, name)
				if gErr != nil {
					return nil, fmt.Errorf("service account %s unavailable: %w", name, gErr)
				}
				return account, nil
			}
		}
	}
	var account user.User
	err := a.DB.QueryRowContext(ctx, `
		SELECT user_id, username, kind, status, auth_version
		FROM users
		WHERE kind='service'
		ORDER BY CASE WHEN username LIKE '%publisher%' THEN 0 ELSE 1 END, user_id DESC
		LIMIT 1
	`).Scan(&account.ID, &account.Username, &account.Kind, &account.Status, &account.AuthVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("no service account configured")
	}
	if err != nil {
		return nil, err
	}
	return &account, nil
}

func parseLoreAuthUser(stdout string) (string, int64) {
	for _, rawLine := range strings.Split(stdout, "\n") {
		line := strings.TrimSpace(rawLine)
		if !strings.HasPrefix(line, "User:") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "User:"))
		if idx := strings.LastIndex(rest, "("); idx > 0 && strings.HasSuffix(rest, ")") {
			name := strings.TrimSpace(rest[:idx])
			idStr := strings.TrimSuffix(strings.TrimSpace(rest[idx+1:]), ")")
			if id, err := strconv.ParseInt(idStr, 10, 64); err == nil && id > 0 {
				return name, id
			}
			return name, 0
		}
		if rest != "" {
			return rest, 0
		}
	}
	return "", 0
}

func (a *App) cloneInto(ctx context.Context, repoURL, dest string) error {
	return a.cloneIntoWithClient(ctx, a.PublishLore, repoURL, dest)
}

func (a *App) cloneIntoWithClient(ctx context.Context, client *loreadapter.Client, repoURL, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	_ = os.RemoveAll(dest)
	argv := []string{"--non-interactive"}
	if client.Identity != "" {
		argv = append(argv, "--identity", client.Identity)
	}
	argv = append(argv, "clone", repoURL, dest)
	res, err := client.Exec.Run(ctx, loreexec.Request{
		Argv: argv,
		Dir:  filepath.Dir(dest),
		Env:  client.Env,
	})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("clone exit %d", res.ExitCode)
	}
	return nil
}
