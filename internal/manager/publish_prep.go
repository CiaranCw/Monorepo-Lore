package manager

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"lore-monorepo/internal/loreexec"
	"lore-monorepo/internal/project"
	"lore-monorepo/internal/publish"
)

// prepareSnapshot clones the parent and each active module into the server
// workspace. The publisher service identity is the only Lore credential used.
func (a *App) prepareSnapshot(ctx context.Context, p *project.Project) (string, map[string]string, error) {
	if a.PublishLore == nil || a.PublishRoot == "" {
		return "", nil, fmt.Errorf("publisher unavailable")
	}
	if drv, ok := a.PublishDriver.(*publish.LoreDriver); ok {
		drv.ParentURL = p.ParentRepositoryURL
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
		dir := filepath.Join(root, "modules", m.Name)
		if err := os.RemoveAll(dir); err != nil {
			return "", nil, err
		}
		if err := a.cloneInto(ctx, m.RepositoryURL, dir); err != nil {
			_ = os.WriteFile(filepath.Join(root, "prep-error.txt"), []byte(m.Name+": "+err.Error()), 0o644)
			return "", nil, err
		}
		dirs[m.Name] = dir
	}
	return parent, dirs, nil
}

func (a *App) cloneInto(ctx context.Context, repoURL, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	_ = os.RemoveAll(dest)
	res, err := a.PublishLore.Exec.Run(ctx, loreexec.Request{
		Argv: []string{"--non-interactive", "clone", repoURL, dest},
		Dir:  filepath.Dir(dest),
		Env:  a.PublishLore.Env,
	})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("clone exit %d", res.ExitCode)
	}
	return nil
}
