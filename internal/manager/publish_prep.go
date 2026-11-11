package manager

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"lore-monorepo/internal/history"
	"lore-monorepo/internal/loreadapter"
	"lore-monorepo/internal/loreexec"
	"lore-monorepo/internal/project"
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

	if localDir, ok := a.managedLocalRepoDir(ctx, m.ID); ok {
		// If backed by a remote Lore URL, refresh branches/revisions first and fail explicitly if remote sync fails!
		if !strings.HasPrefix(m.RepositoryURL, "lore://local/") {
			res, err := loreClient.Exec.Run(ctx, loreexec.Request{
				Argv: []string{"--non-interactive", "sync", "--repository", localDir},
				Dir:  localDir,
				Env:  loreClient.Env,
			})
			if err != nil || res.ExitCode != 0 {
				return history.SyncStats{}, fmt.Errorf("remote lore sync failed for module %s", m.Name)
			}
		}
		return history.SyncModuleFromLore(ctx, a.DB, loreClient, m.ID, localDir)
	}

	if strings.HasPrefix(m.RepositoryURL, "lore://local/") {
		return history.SyncStats{}, fmt.Errorf("local module repository workspace not found")
	}

	cacheBase := filepath.Join(filepath.Dir(a.Config.DatabasePath), "history-cache")
	if a.PublishRoot != "" {
		cacheBase = filepath.Join(a.PublishRoot, "history-cache")
	}
	dest := filepath.Join(cacheBase, strconv.FormatInt(m.ID, 10), "repo")
	if err := a.cloneIntoWithClient(ctx, loreClient, m.RepositoryURL, dest); err != nil {
		return history.SyncStats{}, err
	}
	return history.SyncModuleFromLore(ctx, a.DB, loreClient, m.ID, dest)
}

func (a *App) cloneInto(ctx context.Context, repoURL, dest string) error {
	return a.cloneIntoWithClient(ctx, a.PublishLore, repoURL, dest)
}

func (a *App) cloneIntoWithClient(ctx context.Context, client *loreadapter.Client, repoURL, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	_ = os.RemoveAll(dest)
	res, err := client.Exec.Run(ctx, loreexec.Request{
		Argv: []string{"--non-interactive", "clone", repoURL, dest},
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
