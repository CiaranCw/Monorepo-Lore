package publish

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"lore-monorepo/internal/loreadapter"
	"lore-monorepo/internal/loreexec"
)

// LoreDriver publishes through the real Lore 0.10.1 CLI.
type LoreDriver struct {
	Client    *loreadapter.Client
	ParentURL string
}

func (d LoreDriver) Revisions(ctx context.Context, dir string) (string, string, error) {
	st, err := d.Client.Status(ctx, dir)
	if err != nil {
		return "", "", err
	}
	return st.Revision, st.RevisionRemote, nil
}

func (d LoreDriver) Links(ctx context.Context, dir string) (map[string]string, error) {
	links, err := d.Client.Links(ctx, dir)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, link := range links {
		out[link.LinkPath] = link.Revision
	}
	return out, nil
}

func (d LoreDriver) EnsureLink(ctx context.Context, dir, mount, repoURL, revision string) error {
	links, err := d.Client.Links(ctx, dir)
	if err != nil {
		return err
	}
	for _, link := range links {
		if link.LinkPath == mount {
			if link.Revision == revision {
				return nil
			}
			if err := d.Client.RemoveLink(ctx, dir, mount); err != nil {
				return err
			}
			break
		}
	}
	return d.Client.AddLink(ctx, dir, mount, repoURL, "/", revision, true)
}

func (d LoreDriver) RemoveLink(ctx context.Context, dir, mount string) error {
	return d.Client.RemoveLink(ctx, dir, mount)
}

func (d LoreDriver) Commit(ctx context.Context, dir, message string) error {
	err := d.Client.Commit(ctx, dir, message)
	if errors.Is(err, loreadapter.ErrNothingStaged) {
		return ErrNoChange
	}
	return err
}

func (d LoreDriver) Push(ctx context.Context, dir string) error {
	return d.Client.Push(ctx, dir)
}

var historyRev = regexp.MustCompile(`[0-9a-f]{64}`)

// FindOperation scans revision history for the operation id in the commit message,
// then clones that parent revision and reads its links.
func (d LoreDriver) FindOperation(ctx context.Context, dir string, operationID int64) (bool, string, map[string]string, error) {
	if d.Client == nil || d.Client.Exec == nil || d.ParentURL == "" {
		return false, "", nil, fmt.Errorf("publish: lore history is not configured")
	}
	res, err := d.Client.Exec.Run(ctx, loreexec.Request{
		Argv: []string{"--non-interactive", "revision", "history", "20", "--repository", dir},
		Dir:  dir,
		Env:  d.Client.Env,
	})
	if err != nil {
		return false, "", nil, err
	}
	text := res.Stdout + "\n" + res.Stderr
	needle := "op=" + strconv.FormatInt(operationID, 10)
	if !strings.Contains(text, needle) {
		return false, "", nil, nil
	}
	idx := strings.Index(text, needle)
	window := text[max(0, idx-400):idx]
	revs := historyRev.FindAllString(window, -1)
	if len(revs) == 0 {
		revs = historyRev.FindAllString(text, -1)
	}
	if len(revs) == 0 {
		return false, "", nil, fmt.Errorf("publish: operation %d has no revision in history", operationID)
	}
	rev := revs[len(revs)-1]
	parent, err := os.MkdirTemp(filepath.Dir(dir), "pin-check-")
	if err != nil {
		return false, "", nil, err
	}
	defer os.RemoveAll(parent)
	tmp := filepath.Join(parent, "repo")
	if err := d.Client.Clone(ctx, loreadapter.CloneOptions{URL: d.ParentURL, Path: tmp, Revision: rev}); err != nil {
		return true, rev, nil, err
	}
	pins, err := d.Links(ctx, tmp)
	if err != nil {
		return true, rev, nil, err
	}
	return true, rev, pins, nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
