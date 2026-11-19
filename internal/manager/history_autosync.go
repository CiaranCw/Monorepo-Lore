package manager

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"lore-monorepo/internal/loreadapter"
	"lore-monorepo/internal/project"
)

const zeroRev64 = "0000000000000000000000000000000000000000000000000000000000000000"

// SyncSweepResult summarizes one incremental repository history sync sweep.
type SyncSweepResult struct {
	Checked         int   `json:"checked"`
	Changed         int   `json:"changed"`
	Synced          int   `json:"synced"`
	CommitsUpserted int   `json:"commits_upserted"`
	Failed          int   `json:"failed"`
	DurationMS      int64 `json:"duration_ms"`
}

type historySyncCoordinator struct {
	mu      sync.Mutex
	running bool
	pending bool
	done    chan struct{}
}

func (a *App) historySyncCoord() *historySyncCoordinator {
	a.historySyncOnce.Do(func() {
		a.historySync = &historySyncCoordinator{}
	})
	return a.historySync
}

type syncCandidate struct {
	module           project.Module
	localDir         string
	bootstrapMainRev string
	dbRefs           map[string]string
}

// SyncChangedModules checks active modules against Lore remote branch tips and
// incrementally indexes only modules whose branches changed (or have never been indexed).
// Concurrent callers coalesce cleanly while guaranteeing at least one fresh pass for
// pushes arriving during an in-flight sweep.
func (a *App) SyncChangedModules(ctx context.Context, projectID int64, includeUnmanaged bool) (SyncSweepResult, error) {
	coord := a.historySyncCoord()

	for {
		coord.mu.Lock()
		if !coord.running {
			coord.running = true
			coord.pending = false
			coord.done = make(chan struct{})
			coord.mu.Unlock()
			break
		}
		coord.pending = true
		waitCh := coord.done
		coord.mu.Unlock()

		select {
		case <-waitCh:
			// Run or coalesce into the next pass so a trigger arriving mid-sweep is never dropped.
		case <-ctx.Done():
			return SyncSweepResult{}, ctx.Err()
		}
	}

	var (
		res SyncSweepResult
		err error
	)
	for {
		res, err = a.runSyncSweep(ctx, projectID, includeUnmanaged)

		coord.mu.Lock()
		again := coord.pending && ctx.Err() == nil
		coord.pending = false
		if !again {
			coord.running = false
			close(coord.done)
			coord.mu.Unlock()
			return res, err
		}
		coord.mu.Unlock()
	}
}

func (a *App) runSyncSweep(ctx context.Context, projectID int64, includeUnmanaged bool) (SyncSweepResult, error) {
	start := time.Now()
	var out SyncSweepResult

	if a.DB == nil {
		return out, fmt.Errorf("database unavailable")
	}
	loreClient := a.PublishLore
	if loreClient == nil {
		loreClient = a.Lore
	}
	if loreClient == nil {
		return out, fmt.Errorf("lore client unavailable")
	}

	candidates, err := a.loadSyncCandidates(ctx, projectID)
	if err != nil {
		return out, err
	}
	out.Checked = len(candidates)
	if len(candidates) == 0 {
		out.DurationMS = time.Since(start).Milliseconds()
		return out, nil
	}

	var firstRemoteURL string
	for _, c := range candidates {
		if strings.TrimSpace(c.module.RepositoryURL) != "" && !strings.HasPrefix(c.module.RepositoryURL, "lore://local/") {
			firstRemoteURL = c.module.RepositoryURL
			break
		}
	}

	var (
		syncClient *loreadapter.Client
		cleanup    = func() {}
	)
	if firstRemoteURL != "" {
		sc, cl, scErr := a.serviceSyncClient(ctx, loreClient, firstRemoteURL)
		if scErr != nil {
			return out, scErr
		}
		syncClient = sc
		cleanup = cl
	} else {
		syncClient = loreClient
	}
	defer cleanup()

	workers := a.Config.History.Concurrency
	if workers <= 0 {
		workers = 4
	}
	if workers > len(candidates) {
		workers = len(candidates)
	}

	jobs := make(chan syncCandidate, len(candidates))
	for _, c := range candidates {
		jobs <- c
	}
	close(jobs)

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cand := range jobs {
				if ctx.Err() != nil {
					return
				}
				changed, upserted, syncErr := a.syncCandidateIfNeeded(ctx, cand, syncClient, includeUnmanaged)
				mu.Lock()
				if changed {
					out.Changed++
				}
				if syncErr != nil {
					out.Failed++
					if a.Log != nil {
						a.Log.Warn("auto history sync module failed", map[string]any{
							"module_id": cand.module.ID,
							"module":    cand.module.Name,
							"err":       syncErr.Error(),
						})
					}
				} else if changed {
					out.Synced++
					out.CommitsUpserted += upserted
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	out.DurationMS = time.Since(start).Milliseconds()
	if (out.Changed > 0 || out.Failed > 0) && a.Log != nil {
		a.Log.Info("history sync sweep", map[string]any{
			"checked":          out.Checked,
			"changed":          out.Changed,
			"synced":           out.Synced,
			"commits_upserted": out.CommitsUpserted,
			"failed":           out.Failed,
			"duration_ms":      out.DurationMS,
		})
	}
	return out, nil
}

func (a *App) syncCandidateIfNeeded(ctx context.Context, cand syncCandidate, syncClient *loreadapter.Client, includeUnmanaged bool) (bool, int, error) {
	if strings.HasPrefix(cand.module.RepositoryURL, "lore://local/") {
		if cand.localDir == "" {
			return false, 0, nil
		}
		if len(cand.dbRefs) > 0 && !includeUnmanaged {
			return false, 0, nil
		}
		stats, err := a.syncModuleHistoryWithClient(ctx, &cand.module, syncClient)
		return true, stats.CommitsUpserted, err
	}

	if cand.localDir != "" {
		remoteBranches, err := syncClient.ListBranchesAt(ctx, cand.localDir, true)
		if err != nil {
			return true, 0, fmt.Errorf("list remote branches: %w", err)
		}
		if !remoteBranchesDiffer(remoteBranches, cand.dbRefs, cand.bootstrapMainRev) {
			return false, 0, nil
		}
		stats, err := a.syncModuleHistoryWithClient(ctx, &cand.module, syncClient)
		return true, stats.CommitsUpserted, err
	}

	if !includeUnmanaged {
		return false, 0, nil
	}
	stats, err := a.syncModuleHistoryWithClient(ctx, &cand.module, syncClient)
	return true, stats.CommitsUpserted, err
}

func remoteBranchesDiffer(remoteBranches []loreadapter.Branch, dbRefs map[string]string, bootstrapMainRev string) bool {
	remoteMap := make(map[string]string, len(remoteBranches))
	for _, b := range remoteBranches {
		if b.Archived || b.Name == "" || strings.HasPrefix(b.Name, "lore-link-") {
			continue
		}
		if b.Latest == "" || b.Latest == zeroRev64 {
			continue
		}
		remoteMap[b.Name] = b.Latest
	}
	if bootstrapMainRev != "" && len(remoteMap) > 1 && dbRefs["main"] == "" {
		if mainRev, ok := remoteMap["main"]; ok && mainRev == bootstrapMainRev {
			delete(remoteMap, "main")
		}
	}
	if len(remoteMap) == 0 && len(dbRefs) == 0 {
		return false
	}
	if len(remoteMap) != len(dbRefs) {
		return true
	}
	for name, rev := range remoteMap {
		if dbRefs[name] != rev {
			return true
		}
	}
	return false
}

func (a *App) loadSyncCandidates(ctx context.Context, projectID int64) ([]syncCandidate, error) {
	query := `
		SELECT module_id, project_id, name, repository_id, repository_url, mount_path, created_at
		FROM modules
		WHERE archived_at IS NULL`
	var args []any
	if projectID > 0 {
		query += ` AND project_id = ?`
		args = append(args, projectID)
	}
	query += ` ORDER BY module_id ASC`

	rows, err := a.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	var mods []project.Module
	for rows.Next() {
		var m project.Module
		if err := rows.Scan(&m.ID, &m.ProjectID, &m.Name, &m.RepositoryID, &m.RepositoryURL, &m.MountPath, &m.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		mods = append(mods, m)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	refsByMod := map[int64]map[string]string{}
	rQuery := `
		SELECT r.module_id, r.ref_name, r.lore_revision
		FROM module_refs r
		JOIN modules m ON m.module_id = r.module_id
		WHERE m.archived_at IS NULL AND r.ref_type = 'branch'`
	var rArgs []any
	if projectID > 0 {
		rQuery += ` AND m.project_id = ?`
		rArgs = append(rArgs, projectID)
	}
	rRows, err := a.DB.QueryContext(ctx, rQuery, rArgs...)
	if err != nil {
		return nil, err
	}
	for rRows.Next() {
		var mid int64
		var refName, rev string
		if err := rRows.Scan(&mid, &refName, &rev); err != nil {
			rRows.Close()
			return nil, err
		}
		if refsByMod[mid] == nil {
			refsByMod[mid] = map[string]string{}
		}
		refsByMod[mid][refName] = rev
	}
	if err := rRows.Close(); err != nil {
		return nil, err
	}

	bootByMod := map[int64]string{}
	bRows, err := a.DB.QueryContext(ctx, `
		SELECT module_id, bootstrap_main_rev
		FROM import_job_items
		WHERE module_id IS NOT NULL AND bootstrap_main_rev <> ''
		ORDER BY item_id ASC
	`)
	if err == nil {
		for bRows.Next() {
			var mid int64
			var boot string
			if bRows.Scan(&mid, &boot) == nil && boot != "" {
				bootByMod[mid] = boot
			}
		}
		_ = bRows.Close()
	}

	out := make([]syncCandidate, 0, len(mods))
	for _, m := range mods {
		localDir, _ := a.managedLocalRepoDir(ctx, m.ID)
		dbRefs := refsByMod[m.ID]
		if dbRefs == nil {
			dbRefs = map[string]string{}
		}
		out = append(out, syncCandidate{
			module:           m,
			localDir:         localDir,
			bootstrapMainRev: bootByMod[m.ID],
			dbRefs:           dbRefs,
		})
	}
	return out, nil
}

func (a *App) runHistoryAutoSync(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	if a.PublishLore == nil || a.Tokens == nil {
		return
	}
	interval := a.Config.History.AutoSyncInterval
	notifyPath := strings.TrimSpace(a.Config.History.PushNotifyFile)
	if interval <= 0 && notifyPath == "" {
		return
	}

	var lastNotifyMod time.Time
	if notifyPath != "" {
		if st, err := os.Stat(notifyPath); err == nil {
			lastNotifyMod = st.ModTime()
		}
	}

	var periodicCh <-chan time.Time
	if interval > 0 {
		pt := time.NewTicker(interval)
		defer pt.Stop()
		periodicCh = pt.C
	}

	var notifyCh <-chan time.Time
	if notifyPath != "" {
		nt := time.NewTicker(time.Second)
		defer nt.Stop()
		notifyCh = nt.C
	}

	// Run one initial catch-up sweep shortly after startup.
	initTimer := time.NewTimer(2 * time.Second)
	defer initTimer.Stop()

	runSweep := func() {
		sweepCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		if _, err := a.SyncChangedModules(sweepCtx, 0, false); err != nil && ctx.Err() == nil && a.Log != nil {
			a.Log.Warn("background history sync failed", map[string]any{"err": err.Error()})
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-initTimer.C:
			runSweep()
		case <-periodicCh:
			runSweep()
		case <-notifyCh:
			st, err := os.Stat(notifyPath)
			if err != nil {
				continue
			}
			mt := st.ModTime()
			if mt.After(lastNotifyMod) {
				lastNotifyMod = mt
				runSweep()
			}
		}
	}
}
