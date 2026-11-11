package gitimport

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"lore-monorepo/internal/database"
	"lore-monorepo/internal/history"
	"lore-monorepo/internal/loreadapter"
	"lore-monorepo/internal/loreexec"
	"lore-monorepo/internal/project"
)

var (
	ErrConflict = errors.New("gitimport: target module conflict")
	ErrVerify   = errors.New("gitimport: post-import integrity verification failed")

	repoID32Re = regexp.MustCompile(`[0-9a-f]{32}`)
)

const zeroHash64 = "0000000000000000000000000000000000000000000000000000000000000000"

// VerificationReport records the automated pre/post integrity checks for one imported repository.
type VerificationReport struct {
	Passed                bool     `json:"passed"`
	SourceCommits         int      `json:"source_commits"`
	MappedCommits         int      `json:"mapped_commits"`
	IndexedCommits        int      `json:"indexed_commits"`
	SyntheticMergeBridges int      `json:"synthetic_merge_bridges"`
	SourceBranches        int      `json:"source_branches"`
	ImportedBranches      int      `json:"imported_branches"`
	SourceTags            int      `json:"source_tags"`
	ImportedTags          int      `json:"imported_tags"`
	MergeCommitsVerified  int      `json:"merge_commits_verified"`
	OctopusMergesVerified int      `json:"octopus_merges_verified"`
	SpecialObjectsCount   int      `json:"special_objects_count"`
	HeadBranch            string   `json:"head_branch"`
	HeadGitDigest         string   `json:"head_git_digest"`
	HeadLoreDigest        string   `json:"head_lore_digest"`
	HeadFileCount         int      `json:"head_file_count"`
	AdvertisedHiddenRefs  []string `json:"advertised_hidden_refs,omitempty"`
	ShallowMissingParents []string `json:"shallow_missing_parents,omitempty"`
	LFSFetchAttempted     bool     `json:"lfs_fetch_attempted"`
	LFSFetchSucceeded     bool     `json:"lfs_fetch_succeeded"`
	Mismatches            []string `json:"mismatches,omitempty"`
}

// ItemResult is the per-repository outcome in a single or batch import job.
type ItemResult struct {
	ItemID            int64              `json:"item_id"`
	Ord               int                `json:"ord"`
	ModuleName        string             `json:"module_name"`
	MountPath         string             `json:"mount_path"`
	SourceURL         string             `json:"source_url"`
	Platform          string             `json:"platform"`
	AuthMethod        string             `json:"auth_method"`
	Status            string             `json:"status"`
	ConflictReason    string             `json:"conflict_reason,omitempty"`
	ModuleID          int64              `json:"module_id,omitempty"`
	LoreRepositoryID  string             `json:"lore_repository_id,omitempty"`
	LoreRepositoryURL string             `json:"lore_repository_url,omitempty"`
	RemoteRefs        *RemoteRefSummary  `json:"remote_refs,omitempty"`
	Verification      VerificationReport `json:"verification"`
	Error             string             `json:"error,omitempty"`
}

// JobResult is the complete response for a dry-run, single import, or batch import job.
type JobResult struct {
	JobID          int64        `json:"job_id"`
	JobKey         string       `json:"job_key"`
	ProjectID      int64        `json:"project_id"`
	ProjectName    string       `json:"project_name"`
	Mode           string       `json:"mode"`
	Status         string       `json:"status"`
	ManifestHash   string       `json:"manifest_hash"`
	TotalItems     int          `json:"total_items"`
	SucceededItems int          `json:"succeeded_items"`
	FailedItems    int          `json:"failed_items"`
	SkippedItems   int          `json:"skipped_items"`
	Items          []ItemResult `json:"items"`
}

type itemCheckpoint struct {
	LoreRepositoryID  string            `json:"lore_repository_id,omitempty"`
	LoreRepositoryURL string            `json:"lore_repository_url,omitempty"`
	ModuleID          int64             `json:"module_id,omitempty"`
	CommitMap         map[string]string `json:"commit_map,omitempty"` // git sha -> lore 64-hex revision
	SyntheticCount    int               `json:"synthetic_count,omitempty"`
	HelperBranches    []string          `json:"helper_branches,omitempty"`
	PushedBranches    map[string]bool   `json:"pushed_branches,omitempty"`
}

// Importer orchestrates single and batch external Git imports into Monorepo-Lore.
type Importer struct {
	DB        *sql.DB
	Lore      *loreadapter.Client
	GitBinary string
	// WorkspaceRoot holds git bare mirrors and managed Lore repositories/workspaces.
	WorkspaceRoot string
	// RemoteBaseURL is the Lore Server/Gateway base URL (e.g. "grpcs://host:53747")
	// when pushing imported modules to a live Lore Server. When empty, modules are
	// created in offline managed storage (`lore://local/<slug>`) so full DAG replay
	// and verification work without requiring a running Lore Server.
	RemoteBaseURL string
	// FaultHook is a test-only hook invoked after replayCommitIndex (0-based) for
	// deterministic crash/interruption and checkpoint-resume testing.
	FaultHook func(moduleName string, replayCommitIndex int) error
}

// Run executes a dry-run or live import manifest with idempotency, failure isolation,
// checkpoint resume, and full DAG/tree integrity verification.
func (im *Importer) Run(ctx context.Context, actor string, m Manifest) (JobResult, error) {
	if im.DB == nil {
		return JobResult{}, errors.New("gitimport: database is nil")
	}
	if !m.DryRun && im.Lore == nil {
		return JobResult{}, errors.New("gitimport: lore client is nil")
	}
	if strings.TrimSpace(actor) == "" {
		return JobResult{}, errors.New("gitimport: actor is required")
	}
	if err := NormalizeAndValidateManifest(&m); err != nil {
		return JobResult{}, err
	}
	if im.WorkspaceRoot == "" {
		return JobResult{}, errors.New("gitimport: workspace root is required")
	}
	if err := os.MkdirAll(im.WorkspaceRoot, 0o755); err != nil {
		return JobResult{}, err
	}

	proj, err := project.GetProject(ctx, im.DB, m.Project)
	if err != nil {
		return JobResult{}, err
	}

	mHash := HashManifest(m)
	mode := "import"
	if m.DryRun {
		mode = "dry_run"
	}
	jobKey := strings.TrimSpace(m.JobKey)
	if jobKey == "" {
		if m.DryRun {
			jobKey = fmt.Sprintf("dryrun-%d-%s-%d", proj.ID, mHash[:12], time.Now().UnixNano())
		} else {
			jobKey = fmt.Sprintf("import-%d-%s", proj.ID, mHash[:16])
		}
	}

	jobID, items, alreadyDone, err := im.loadOrCreateJob(ctx, actor, proj, mode, jobKey, mHash, m)
	if err != nil {
		return JobResult{}, err
	}
	if alreadyDone {
		return im.readJobResult(ctx, jobID, proj.Name)
	}

	// Execute items (respecting m.Concurrency while isolating per-item failures).
	results := make([]ItemResult, len(items))
	sem := make(chan struct{}, m.Concurrency)
	var wg sync.WaitGroup
	for idx := range items {
		idx := idx
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if m.DryRun {
				results[idx] = im.runDryRunItem(ctx, proj, items[idx], m.Repositories[idx])
			} else {
				results[idx] = im.runImportItem(ctx, actor, proj, items[idx], m.Repositories[idx])
			}
		}()
	}
	wg.Wait()

	succeeded, failed, skipped := 0, 0, 0
	for _, r := range results {
		switch r.Status {
		case "succeeded", "planned":
			succeeded++
		case "skipped":
			skipped++
		default:
			failed++
		}
	}
	jobStatus := "succeeded"
	if failed > 0 && (succeeded > 0 || skipped > 0) {
		jobStatus = "partial_failed"
	} else if failed > 0 {
		jobStatus = "failed"
	}

	summaryBytes, _ := json.Marshal(map[string]any{
		"succeeded": succeeded, "failed": failed, "skipped": skipped,
	})
	_, err = im.DB.ExecContext(ctx, `
		UPDATE import_jobs
		SET status=?, succeeded_items=?, failed_items=?, skipped_items=?, summary_json=?,
		    updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now'),
		    finished_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')
		WHERE job_id=?
	`, jobStatus, succeeded, failed, skipped, string(summaryBytes), jobID)
	if err != nil {
		return JobResult{}, err
	}
	_ = database.Audit(ctx, im.DB, actor, "git_import_"+mode, proj.Name,
		fmt.Sprintf("job=%d status=%s ok=%d failed=%d skipped=%d", jobID, jobStatus, succeeded, failed, skipped))

	return JobResult{
		JobID:          jobID,
		JobKey:         jobKey,
		ProjectID:      proj.ID,
		ProjectName:    proj.Name,
		Mode:           mode,
		Status:         jobStatus,
		ManifestHash:   mHash,
		TotalItems:     len(results),
		SucceededItems: succeeded,
		FailedItems:    failed,
		SkippedItems:   skipped,
		Items:          results,
	}, nil
}

type storedItem struct {
	ItemID         int64
	JobID          int64
	Ord            int
	Status         string
	ModuleID       int64
	LoreRepoID     string
	LoreRepoURL    string
	GitMirrorPath  string
	LoreWorkPath   string
	CheckpointJSON string
	VerifyJSON     string
	Error          string
}

func (im *Importer) loadOrCreateJob(
	ctx context.Context,
	actor string,
	proj *project.Project,
	mode, jobKey, manifestHash string,
	m Manifest,
) (jobID int64, items []storedItem, alreadySucceeded bool, err error) {
	var existingStatus, existingHash string
	qErr := im.DB.QueryRowContext(ctx, `SELECT job_id, status, manifest_hash FROM import_jobs WHERE job_key=?`, jobKey).
		Scan(&jobID, &existingStatus, &existingHash)
	if qErr == nil {
		if existingHash != manifestHash {
			return 0, nil, false, fmt.Errorf("%w: job_key %q already exists with a different manifest", ErrConflict, jobKey)
		}
		if existingStatus == "succeeded" && mode == "import" {
			return jobID, nil, true, nil
		}
		if _, uErr := im.DB.ExecContext(ctx, `UPDATE import_jobs SET status='running', updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE job_id=?`, jobID); uErr != nil {
			return 0, nil, false, uErr
		}
	} else if errors.Is(qErr, sql.ErrNoRows) {
		err = database.Tx(ctx, im.DB, func(tx *sql.Tx) error {
			res, iErr := tx.ExecContext(ctx, `
				INSERT INTO import_jobs (job_key, project_id, mode, status, manifest_hash, requested_by, total_items)
				VALUES (?, ?, ?, 'running', ?, ?, ?)
			`, jobKey, proj.ID, mode, manifestHash, actor, len(m.Repositories))
			if iErr != nil {
				return iErr
			}
			jobID, _ = res.LastInsertId()
			for i, r := range m.Repositories {
				_, _, authMethod, _ := BuildGitAuthEnv(r.SourceURL, r.Platform, r.Auth)
				mirrorPath := filepath.Join(im.WorkspaceRoot, fmt.Sprintf("proj-%d", proj.ID), "mirrors", r.ModuleName+".git")
				workPath := filepath.Join(im.WorkspaceRoot, fmt.Sprintf("proj-%d", proj.ID), "lore", r.ModuleName)
				if _, iErr := tx.ExecContext(ctx, `
					INSERT INTO import_job_items (
						job_id, ord, source_url, platform, auth_method, module_name, mount_path,
						conflict_policy, git_mirror_path, lore_work_path, status
					) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
				`, jobID, i, r.SourceURL, r.Platform, authMethod, r.ModuleName, r.MountPath, r.ConflictPolicy, mirrorPath, workPath); iErr != nil {
					return iErr
				}
			}
			return nil
		})
		if err != nil {
			return 0, nil, false, err
		}
	} else {
		return 0, nil, false, qErr
	}

	rows, err := im.DB.QueryContext(ctx, `
		SELECT item_id, job_id, ord, status, COALESCE(module_id,0), lore_repository_id, lore_repository_url,
		       git_mirror_path, lore_work_path, checkpoint_json, verification_json, error
		FROM import_job_items
		WHERE job_id=?
		ORDER BY ord ASC
	`, jobID)
	if err != nil {
		return 0, nil, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var it storedItem
		if err := rows.Scan(&it.ItemID, &it.JobID, &it.Ord, &it.Status, &it.ModuleID, &it.LoreRepoID, &it.LoreRepoURL,
			&it.GitMirrorPath, &it.LoreWorkPath, &it.CheckpointJSON, &it.VerifyJSON, &it.Error); err != nil {
			return 0, nil, false, err
		}
		items = append(items, it)
	}
	return jobID, items, false, rows.Err()
}

func (im *Importer) readJobResult(ctx context.Context, jobID int64, projectName string) (JobResult, error) {
	var res JobResult
	res.ProjectName = projectName
	err := im.DB.QueryRowContext(ctx, `
		SELECT job_id, job_key, project_id, mode, status, manifest_hash, total_items, succeeded_items, failed_items, skipped_items
		FROM import_jobs WHERE job_id=?
	`, jobID).Scan(&res.JobID, &res.JobKey, &res.ProjectID, &res.Mode, &res.Status, &res.ManifestHash,
		&res.TotalItems, &res.SucceededItems, &res.FailedItems, &res.SkippedItems)
	if err != nil {
		return res, err
	}
	rows, err := im.DB.QueryContext(ctx, `
		SELECT item_id, ord, module_name, mount_path, source_url, platform, auth_method,
		       status, COALESCE(module_id,0), lore_repository_id, lore_repository_url, verification_json, error
		FROM import_job_items WHERE job_id=? ORDER BY ord ASC
	`, jobID)
	if err != nil {
		return res, err
	}
	defer rows.Close()
	for rows.Next() {
		var it ItemResult
		var verRaw string
		if err := rows.Scan(&it.ItemID, &it.Ord, &it.ModuleName, &it.MountPath, &it.SourceURL, &it.Platform, &it.AuthMethod,
			&it.Status, &it.ModuleID, &it.LoreRepositoryID, &it.LoreRepositoryURL, &verRaw, &it.Error); err != nil {
			return res, err
		}
		_ = json.Unmarshal([]byte(verRaw), &it.Verification)
		res.Items = append(res.Items, it)
	}
	return res, rows.Err()
}

func (im *Importer) checkModuleConflict(ctx context.Context, projectID int64, spec RepoSpec) (existing *project.Module, conflictReason string, err error) {
	mods, err := project.ListModules(ctx, im.DB, projectID, false)
	if err != nil {
		return nil, "", err
	}
	for i := range mods {
		m := &mods[i]
		if m.Name == spec.ModuleName {
			return m, fmt.Sprintf("module %q already exists in project", spec.ModuleName), nil
		}
		if mountsOverlap(m.MountPath, spec.MountPath) {
			return nil, fmt.Sprintf("mount_path %q overlaps with existing module %q (%s)", spec.MountPath, m.Name, m.MountPath), nil
		}
	}
	return nil, "", nil
}

func (im *Importer) runDryRunItem(ctx context.Context, proj *project.Project, st storedItem, spec RepoSpec) ItemResult {
	extraEnv, secrets, authMethod, authErr := BuildGitAuthEnv(spec.SourceURL, spec.Platform, spec.Auth)
	out := ItemResult{
		ItemID:     st.ItemID,
		Ord:        st.Ord,
		ModuleName: spec.ModuleName,
		MountPath:  spec.MountPath,
		SourceURL:  spec.SourceURL,
		Platform:   spec.Platform,
		AuthMethod: authMethod,
	}
	if authErr != nil {
		out.Status = "failed"
		out.Error = authErr.Error()
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}

	existing, reason, cErr := im.checkModuleConflict(ctx, proj.ID, spec)
	if cErr != nil {
		out.Status = "failed"
		out.Error = cErr.Error()
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}
	if existing != nil {
		out.ModuleID = existing.ID
		out.LoreRepositoryID = existing.RepositoryID
		out.LoreRepositoryURL = existing.RepositoryURL
		switch spec.ConflictPolicy {
		case ConflictSkipIfImported:
			out.Status = "skipped"
			out.ConflictReason = reason
			im.saveItemFinal(ctx, st.ItemID, out)
			return out
		case ConflictFail:
			out.Status = "conflict"
			out.ConflictReason = reason
			out.Error = reason
			im.saveItemFinal(ctx, st.ItemID, out)
			return out
		}
	}

	refs, err := InspectRemoteRefs(ctx, im.GitBinary, spec.SourceURL, extraEnv, secrets)
	if err != nil {
		out.Status = "failed"
		out.Error = err.Error()
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}
	out.RemoteRefs = &refs
	out.Verification = VerificationReport{
		Passed:               true,
		SourceBranches:       len(refs.Branches),
		SourceTags:           len(refs.Tags),
		HeadBranch:           refs.DefaultBranch,
		AdvertisedHiddenRefs: refs.AdvertisedHiddenRefs,
	}
	out.Status = "planned"
	im.saveItemFinal(ctx, st.ItemID, out)
	return out
}

func (im *Importer) runImportItem(ctx context.Context, actor string, proj *project.Project, st storedItem, spec RepoSpec) ItemResult {
	// Idempotency: if this item already succeeded in an earlier run of this job, return its saved result!
	if st.Status == "succeeded" {
		var ver VerificationReport
		_ = json.Unmarshal([]byte(st.VerifyJSON), &ver)
		return ItemResult{
			ItemID: st.ItemID, Ord: st.Ord, ModuleName: spec.ModuleName, MountPath: spec.MountPath,
			SourceURL: spec.SourceURL, Platform: spec.Platform, Status: "succeeded",
			ModuleID: st.ModuleID, LoreRepositoryID: st.LoreRepoID, LoreRepositoryURL: st.LoreRepoURL,
			Verification: ver,
		}
	}

	extraEnv, secrets, authMethod, authErr := BuildGitAuthEnv(spec.SourceURL, spec.Platform, spec.Auth)
	out := ItemResult{
		ItemID:     st.ItemID,
		Ord:        st.Ord,
		ModuleName: spec.ModuleName,
		MountPath:  spec.MountPath,
		SourceURL:  spec.SourceURL,
		Platform:   spec.Platform,
		AuthMethod: authMethod,
	}
	if authErr != nil {
		out.Status = "failed"
		out.Error = authErr.Error()
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}

	var cp itemCheckpoint
	_ = json.Unmarshal([]byte(st.CheckpointJSON), &cp)
	if cp.CommitMap == nil {
		cp.CommitMap = map[string]string{}
	}
	if cp.PushedBranches == nil {
		cp.PushedBranches = map[string]bool{}
	}

	// Check existing module collisions BEFORE mutating anything.
	existing, reason, cErr := im.checkModuleConflict(ctx, proj.ID, spec)
	if cErr != nil {
		out.Status = "failed"
		out.Error = cErr.Error()
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}
	if existing != nil && existing.ID != cp.ModuleID {
		switch spec.ConflictPolicy {
		case ConflictSkipIfImported:
			// Check if existing module was already imported cleanly; if so, skip idempotently!
			var importedCount int
			_ = im.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM module_commits WHERE module_id=? AND origin_kind='git_import'`, existing.ID).Scan(&importedCount)
			if importedCount > 0 || existing.Name == spec.ModuleName {
				out.Status = "skipped"
				out.ModuleID = existing.ID
				out.LoreRepositoryID = existing.RepositoryID
				out.LoreRepositoryURL = existing.RepositoryURL
				out.ConflictReason = reason
				im.saveItemFinal(ctx, st.ItemID, out)
				return out
			}
		case ConflictResume:
			if existing.Name == spec.ModuleName && existing.MountPath == spec.MountPath {
				cp.ModuleID = existing.ID
				cp.LoreRepositoryID = existing.RepositoryID
				cp.LoreRepositoryURL = existing.RepositoryURL
				// Load already-mapped commits from module_commits so incremental/resume import skips them!
				_, gitToLore, lErr := loadExistingGitCommits(ctx, im.DB, existing.ID)
				if lErr == nil {
					for k, v := range gitToLore {
						cp.CommitMap[k] = v
					}
				}
			} else {
				out.Status = "conflict"
				out.ConflictReason = reason
				out.Error = reason
				im.saveItemFinal(ctx, st.ItemID, out)
				return out
			}
		default: // ConflictFail
			out.Status = "conflict"
			out.ConflictReason = reason
			out.Error = reason
			im.saveItemFinal(ctx, st.ItemID, out)
			return out
		}
	}

	// Step 1: Inspect remote refs & sync bare Git mirror.
	im.updateItemProgress(ctx, st.ItemID, "cloning", cp)
	remoteRefs, refErr := InspectRemoteRefs(ctx, im.GitBinary, spec.SourceURL, extraEnv, secrets)
	if refErr != nil {
		out.Status = "failed"
		out.Error = refErr.Error()
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}
	out.RemoteRefs = &remoteRefs

	lfsAttempted, lfsOK, syncErr := SyncBareMirror(ctx, im.GitBinary, spec.SourceURL, st.GitMirrorPath, spec.LFSMode, extraEnv, secrets)
	if syncErr != nil {
		out.Status = "failed"
		out.Error = syncErr.Error()
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}

	graph, gErr := ReadMirrorGraph(ctx, im.GitBinary, st.GitMirrorPath, remoteRefs.DefaultBranch)
	if gErr != nil {
		out.Status = "failed"
		out.Error = gErr.Error()
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}
	graph.LFSFetchAttempted = lfsAttempted
	graph.LFSFetchSucceeded = lfsOK

	// Step 2: Prepare Lore repository & register module (idempotently).
	im.updateItemProgress(ctx, st.ItemID, "replaying", cp)
	if err := im.ensureLoreRepoAndModule(ctx, actor, proj.ID, spec, st.LoreWorkPath, &cp); err != nil {
		out.Status = "failed"
		out.Error = err.Error()
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}
	out.ModuleID = cp.ModuleID
	out.LoreRepositoryID = cp.LoreRepositoryID
	out.LoreRepositoryURL = cp.LoreRepositoryURL

	// Step 3: Replay Git commit DAG into Lore repository with per-commit checkpointing!
	if err := im.replayGraphIntoLore(ctx, st.ItemID, spec, st.GitMirrorPath, st.LoreWorkPath, &graph, &cp); err != nil {
		out.Status = "failed"
		out.Error = err.Error()
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}

	// Step 4: If targeting a remote Lore Server, push all active branches.
	if im.RemoteBaseURL != "" {
		im.updateItemProgress(ctx, st.ItemID, "pushing", cp)
		branchesToPush := sortedKeys(graph.Branches)
		for _, bName := range branchesToPush {
			if cp.PushedBranches[bName] {
				continue
			}
			if err := im.Lore.PushBranch(ctx, st.LoreWorkPath, bName); err != nil {
				out.Status = "failed"
				out.Error = err.Error()
				im.saveItemFinal(ctx, st.ItemID, out)
				return out
			}
			cp.PushedBranches[bName] = true
			im.updateItemProgress(ctx, st.ItemID, "pushing", cp)
		}
	}

	// Step 5: Persist branch and tag refs (including annotated tag metadata) & verify end-to-end integrity!
	im.updateItemProgress(ctx, st.ItemID, "verifying", cp)
	if err := im.persistRefs(ctx, cp.ModuleID, st.LoreWorkPath, graph, cp.CommitMap); err != nil {
		out.Status = "failed"
		out.Error = err.Error()
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}

	ver, vErr := im.verifyImportedModule(ctx, cp.ModuleID, st.GitMirrorPath, st.LoreWorkPath, spec.LFSMode, remoteRefs, graph, cp)
	out.Verification = ver
	if vErr != nil || !ver.Passed {
		out.Status = "failed"
		if vErr != nil {
			out.Error = vErr.Error()
		} else {
			out.Error = fmt.Sprintf("%s: %s", ErrVerify.Error(), strings.Join(ver.Mismatches, "; "))
		}
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}

	out.Status = "succeeded"
	im.saveItemFinal(ctx, st.ItemID, out)
	return out
}

func (im *Importer) ensureLoreRepoAndModule(
	ctx context.Context,
	actor string,
	projectID int64,
	spec RepoSpec,
	loreWorkPath string,
	cp *itemCheckpoint,
) error {
	slug := strings.ToLower(strings.ReplaceAll(spec.ModuleName, "/", "-"))
	dotLoreExists := false
	if st, err := os.Stat(filepath.Join(loreWorkPath, ".lore")); err == nil && st.IsDir() {
		dotLoreExists = true
	}

	if !dotLoreExists {
		// If local Lore repo is missing, any unpushed local commit mappings must be replayed fresh.
		if im.RemoteBaseURL == "" {
			cp.CommitMap = map[string]string{}
			cp.HelperBranches = nil
			cp.SyntheticCount = 0
		}
		if err := os.RemoveAll(loreWorkPath); err != nil {
			return err
		}
		if err := os.MkdirAll(loreWorkPath, 0o755); err != nil {
			return err
		}
		if im.RemoteBaseURL != "" {
			remoteURL := strings.TrimRight(im.RemoteBaseURL, "/") + "/" + fmt.Sprintf("p%d-%s", projectID, slug)
			if cp.LoreRepositoryID == "" {
				seedDir := loreWorkPath + "-seed"
				_ = os.RemoveAll(seedDir)
				if err := os.MkdirAll(seedDir, 0o755); err != nil {
					return err
				}
				defer os.RemoveAll(seedDir)
				res, err := im.Lore.Exec.Run(ctx, loreexec.Request{
					Argv: []string{"--non-interactive", "--json", "repository", "create", remoteURL},
					Dir:  seedDir,
					Env:  im.Lore.Env,
				})
				if err != nil {
					return err
				}
				ids := repoID32Re.FindAllString(res.Stdout+"\n"+res.Stderr, -1)
				if res.ExitCode != 0 || len(ids) == 0 {
					return fmt.Errorf("gitimport: remote lore repository create failed (exit %d)", res.ExitCode)
				}
				cp.LoreRepositoryID = ids[len(ids)-1]
				cp.LoreRepositoryURL = remoteURL
			}
			_ = os.RemoveAll(loreWorkPath)
			res, err := im.Lore.Exec.Run(ctx, loreexec.Request{
				Argv: []string{"--non-interactive", "clone", cp.LoreRepositoryURL, loreWorkPath},
				Dir:  filepath.Dir(loreWorkPath),
				Env:  im.Lore.Env,
			})
			if err != nil || res.ExitCode != 0 {
				return fmt.Errorf("gitimport: clone target lore repository failed")
			}
		} else {
			repoID, err := im.Lore.CreateOfflineRepository(ctx, loreWorkPath, spec.ModuleName)
			if err != nil {
				return err
			}
			cp.LoreRepositoryID = repoID
			cp.LoreRepositoryURL = fmt.Sprintf("lore://local/p%d-%s", projectID, slug)
		}
	}

	if cp.ModuleID == 0 {
		mod, err := project.CreateModule(ctx, im.DB, actor, project.Module{
			ProjectID:     projectID,
			Name:          spec.ModuleName,
			RepositoryID:  cp.LoreRepositoryID,
			RepositoryURL: cp.LoreRepositoryURL,
			MountPath:     spec.MountPath,
		})
		if err != nil {
			return err
		}
		cp.ModuleID = mod.ID
	}
	return nil
}

type dagPlan struct {
	OrderedCommits   []GitCommit
	LaneOf           map[string]string // git sha -> Lore branch name
	LaneFirstCommit  map[string]string // lane name -> first git sha in lane
	HelperLanes      []string
	PostCreateRefs   map[string]string // Git branch names with 0 exclusive commits -> target git sha
}

func planDAGLanes(g MirrorGraph) dagPlan {
	plan := dagPlan{
		LaneOf:          map[string]string{},
		LaneFirstCommit: map[string]string{},
		PostCreateRefs:  map[string]string{},
	}
	if len(g.Commits) == 0 {
		return plan
	}

	assignChainFrom := func(tipSHA, laneName string) bool {
		var revChain []string
		cur := tipSHA
		for cur != "" {
			if _, assigned := plan.LaneOf[cur]; assigned {
				break
			}
			c, ok := g.CommitsBySHA[cur]
			if !ok {
				break
			}
			revChain = append(revChain, cur)
			if len(c.Parents) > 0 {
				cur = c.Parents[0]
			} else {
				cur = ""
			}
		}
		if len(revChain) == 0 {
			return false
		}
		for _, sha := range revChain {
			plan.LaneOf[sha] = laneName
		}
		// revChain[len-1] is the oldest unassigned commit in this lane!
		plan.LaneFirstCommit[laneName] = revChain[len(revChain)-1]
		return true
	}

	usedLanes := map[string]bool{"main": true}

	// 1. Assign Lore's initial `"main"` branch.
	if mainTip, hasMain := g.Branches["main"]; hasMain && mainTip != "" {
		assignChainFrom(mainTip, "main")
	} else if g.DefaultBranch != "" && g.Branches[g.DefaultBranch] != "" {
		assignChainFrom(g.Branches[g.DefaultBranch], "main")
		plan.PostCreateRefs[g.DefaultBranch] = g.Branches[g.DefaultBranch]
	} else {
		assignChainFrom(g.Commits[len(g.Commits)-1].SHA, "main")
	}

	// 2. Assign remaining named Git branches deterministically.
	for _, bName := range sortedKeys(g.Branches) {
		if bName == "main" || (bName == g.DefaultBranch && plan.PostCreateRefs[bName] != "") {
			continue
		}
		tip := g.Branches[bName]
		if _, already := plan.LaneOf[tip]; already {
			plan.PostCreateRefs[bName] = tip
			continue
		}
		laneName := bName
		if usedLanes[laneName] || strings.HasPrefix(laneName, "_import_") {
			laneName = fmt.Sprintf("_import_b_%d", len(usedLanes))
			plan.HelperLanes = append(plan.HelperLanes, laneName)
			plan.PostCreateRefs[bName] = tip
		}
		usedLanes[laneName] = true
		assignChainFrom(tip, laneName)
	}

	// 3. Assign any remaining commits (merged-and-deleted side branches, tag-only branches) to helper lanes.
	helperSeq := 1
	for i := len(g.Commits) - 1; i >= 0; i-- {
		sha := g.Commits[i].SHA
		if _, assigned := plan.LaneOf[sha]; assigned {
			continue
		}
		laneName := fmt.Sprintf("_import_lane_%d", helperSeq)
		helperSeq++
		usedLanes[laneName] = true
		plan.HelperLanes = append(plan.HelperLanes, laneName)
		assignChainFrom(sha, laneName)
	}

	// 4. Ensure `"main"`'s first root commit is at index 0 of OrderedCommits (preserving topological order,
	// since it has 0 parents) so Lore always initializes revision 1 on `"main"`.
	ordered := make([]GitCommit, 0, len(g.Commits))
	mainRoot := plan.LaneFirstCommit["main"]
	if mainRoot != "" {
		if rootCommit, ok := g.CommitsBySHA[mainRoot]; ok && len(rootCommit.Parents) == 0 {
			ordered = append(ordered, rootCommit)
		} else {
			mainRoot = ""
		}
	}
	for _, c := range g.Commits {
		if c.SHA == mainRoot {
			continue
		}
		ordered = append(ordered, c)
	}
	plan.OrderedCommits = ordered
	return plan
}

func (im *Importer) replayGraphIntoLore(
	ctx context.Context,
	itemID int64,
	spec RepoSpec,
	mirrorDir, loreWorkDir string,
	g *MirrorGraph,
	cp *itemCheckpoint,
) error {
	if len(g.Commits) == 0 {
		return nil
	}
	plan := planDAGLanes(*g)

	// Inspect current local Lore branches so resume knows which branches already exist and their latest revisions.
	existingBranches := map[string]string{}
	currentBranch := ""
	if branches, err := im.Lore.ListBranchesAt(ctx, loreWorkDir, false); err == nil {
		for _, b := range branches {
			if !b.Archived {
				existingBranches[b.Name] = b.Latest
				if b.IsCurrent {
					currentBranch = b.Name
				}
			}
		}
	}

	reader, err := NewBatchBlobReader(ctx, im.GitBinary, mirrorDir)
	if err != nil {
		return err
	}
	defer reader.Close()

	// Note: cachedBlobs is only safe across consecutive commits when Lore never touched
	// the working tree via `sync` or `branch switch --reset` or `branch merge`. Whenever
	// Lore switches/syncs/merges, we clear cachedBlobs so MaterializeGitTree verifies disk state!
	cachedBlobs := map[string]string{}
	helperSet := map[string]bool{}
	for _, h := range cp.HelperBranches {
		helperSet[h] = true
	}
	for _, h := range plan.HelperLanes {
		helperSet[h] = true
	}
	mpSeq := len(cp.HelperBranches) + 1

	var firstRootLoreRev string
	if mainFirst := plan.LaneFirstCommit["main"]; mainFirst != "" {
		firstRootLoreRev = cp.CommitMap[mainFirst]
	}

	for idx, c := range plan.OrderedCommits {
		if existingRev := cp.CommitMap[c.SHA]; existingRev != "" {
			if firstRootLoreRev == "" {
				firstRootLoreRev = existingRev
			}
			continue
		}

		lane := plan.LaneOf[c.SHA]
		// Ensure we are positioned on `lane` at `P1(c)`!
		if lane == "main" && (existingBranches["main"] == zeroHash64 || existingBranches["main"] == "") {
			// Very first commit on `main`.
			if currentBranch != "main" && existingBranches["main"] != "" {
				if err := im.Lore.SwitchBranchRevision(ctx, loreWorkDir, "main", "", true, true); err != nil {
					return err
				}
				cachedBlobs = map[string]string{}
				currentBranch = "main"
			}
		} else if _, created := existingBranches[lane]; !created {
			// First commit of a non-main lane! Branch from P1(c) (or firstRootLoreRev for an orphan root).
			baseRev := firstRootLoreRev
			if len(c.Parents) > 0 {
				p1Rev := cp.CommitMap[c.Parents[0]]
				if p1Rev == "" {
					return fmt.Errorf("gitimport: missing mapped parent %s for %s", c.Parents[0], c.SHA)
				}
				baseRev = p1Rev
			}
			if err := im.Lore.SyncOffline(ctx, loreWorkDir, baseRev); err != nil {
				return err
			}
			if err := im.Lore.CreateBranchSlash(ctx, loreWorkDir, lane, true); err != nil {
				return err
			}
			cachedBlobs = map[string]string{}
			existingBranches[lane] = baseRev
			currentBranch = lane
		} else if currentBranch != lane {
			if err := im.Lore.SwitchBranchRevision(ctx, loreWorkDir, lane, "", true, true); err != nil {
				return err
			}
			cachedBlobs = map[string]string{}
			currentBranch = lane
		}

		// Handle merge parents (2-parent native Lore merge, or chained synthetic bridges for octopus >= 3 parents).
		var extraMeta map[string]string
		if len(c.Parents) == 0 && lane != "main" && firstRootLoreRev != "" {
			extraMeta = map[string]string{"lore.orphan_anchor": firstRootLoreRev}
		}

		if len(c.Parents) >= 2 {
			// For octopus merges (len >= 3), chain synthetic bridge merges for Parents[1 .. len-2],
			// then perform the final merge for Parents[len-1] with c's exact tree and metadata!
			for mIdx := 1; mIdx < len(c.Parents); mIdx++ {
				pSHA := c.Parents[mIdx]
				pRev := cp.CommitMap[pSHA]
				if pRev == "" {
					return fmt.Errorf("gitimport: missing merge parent %s for %s", pSHA, c.SHA)
				}
				isFinalStep := mIdx == len(c.Parents)-1

				// Find a branch whose current latest equals pRev, or create a temporary helper branch at pRev.
				mergeSourceBranch := ""
				for bName, bLatest := range existingBranches {
					if bName != lane && bLatest == pRev {
						mergeSourceBranch = bName
						break
					}
				}
				if mergeSourceBranch == "" {
					mpSeq++
					mergeSourceBranch = fmt.Sprintf("_import_mp_%d", mpSeq)
					if err := im.Lore.SyncOffline(ctx, loreWorkDir, pRev); err != nil {
						return err
					}
					if err := im.Lore.CreateBranchSlash(ctx, loreWorkDir, mergeSourceBranch, true); err != nil {
						return err
					}
					existingBranches[mergeSourceBranch] = pRev
					helperSet[mergeSourceBranch] = true
					if err := im.Lore.SwitchBranchRevision(ctx, loreWorkDir, lane, "", true, true); err != nil {
						return err
					}
					currentBranch = lane
				}

				hasConflicts, err := im.Lore.MergeStartNoCommit(ctx, loreWorkDir, mergeSourceBranch, true)
				if err != nil {
					return err
				}
				cachedBlobs = map[string]string{}

				if !isFinalStep {
					// Synthetic intermediate bridge for octopus merge!
					if hasConflicts {
						if _, err := MaterializeGitTree(ctx, im.GitBinary, mirrorDir, loreWorkDir, c.TreeSHA, spec.LFSMode, reader, nil); err != nil {
							return err
						}
						if err := im.Lore.MergeResolve(ctx, loreWorkDir, true); err != nil {
							return err
						}
					}
					if err := im.Lore.StageScan(ctx, loreWorkDir, true); err != nil {
						return err
					}
					synthMeta := map[string]string{
						"git.synthetic": "1",
						"git.octopus":   c.SHA,
					}
					if err := im.Lore.SetStagedMetadata(ctx, loreWorkDir, synthMeta, true); err != nil {
						return err
					}
					synthRev, err := im.Lore.CommitFull(ctx, loreWorkDir, fmt.Sprintf("octopus merge bridge %d for %s", mIdx, c.SHA[:12]), true, true)
					if err != nil {
						return err
					}
					existingBranches[lane] = synthRev
					cp.SyntheticCount++
					if err := database.Tx(ctx, im.DB, func(tx *sql.Tx) error {
						return history.UpsertCommit(ctx, tx, history.CommitInput{
							ModuleID:        cp.ModuleID,
							LoreRevision:    synthRev,
							OriginKind:      history.OriginGitImport,
							IsSynthetic:     true,
							AuthorName:      c.AuthorName,
							AuthorEmail:     c.AuthorEmail,
							AuthoredAt:      c.AuthoredAt,
							AuthoredUnixMS:  c.AuthoredUnixMS,
							CommitterName:   c.CommitterName,
							CommitterEmail:  c.CommitterEmail,
							CommittedAt:     c.CommittedAt,
							CommittedUnixMS: c.CommittedUnixMS,
							Message:         "octopus merge bridge",
						})
					}); err != nil {
						return err
					}
				} else {
					// Final merge step: materialize exact Git merge tree (resolving any conflict or evil merge!).
					mat, err := MaterializeGitTree(ctx, im.GitBinary, mirrorDir, loreWorkDir, c.TreeSHA, spec.LFSMode, reader, cachedBlobs)
					if err != nil {
						return err
					}
					if hasConflicts {
						if err := im.Lore.MergeResolve(ctx, loreWorkDir, true); err != nil {
							return err
						}
					}
					loreRev, err := im.commitAndIndexGitCommit(ctx, loreWorkDir, cp.ModuleID, c, mat, cp.CommitMap, extraMeta)
					if err != nil {
						return err
					}
					existingBranches[lane] = loreRev
					cp.CommitMap[c.SHA] = loreRev
				}
			}
		} else {
			// Root or single-parent commit!
			mat, err := MaterializeGitTree(ctx, im.GitBinary, mirrorDir, loreWorkDir, c.TreeSHA, spec.LFSMode, reader, cachedBlobs)
			if err != nil {
				return err
			}
			loreRev, err := im.commitAndIndexGitCommit(ctx, loreWorkDir, cp.ModuleID, c, mat, cp.CommitMap, extraMeta)
			if err != nil {
				return err
			}
			existingBranches[lane] = loreRev
			cp.CommitMap[c.SHA] = loreRev
			if firstRootLoreRev == "" {
				firstRootLoreRev = loreRev
			}
		}

		// Save checkpoint so any interruption/crash resumes cleanly without duplicating commits!
		cp.HelperBranches = sortedBoolKeys(helperSet)
		im.updateItemProgress(ctx, itemID, "replaying", *cp)

		if im.FaultHook != nil {
			if fErr := im.FaultHook(spec.ModuleName, idx); fErr != nil {
				return fErr
			}
		}
	}

	// Create any Git branches that pointed to commits on other lanes (e.g. `release` or `master` when mapped to `main`).
	for _, bName := range sortedKeys(plan.PostCreateRefs) {
		targetSHA := plan.PostCreateRefs[bName]
		targetRev := cp.CommitMap[targetSHA]
		if targetRev == "" {
			return fmt.Errorf("gitimport: missing revision for branch %s (%s)", bName, targetSHA)
		}
		if existingBranches[bName] == targetRev {
			continue
		}
		if _, exists := existingBranches[bName]; !exists {
			if err := im.Lore.SyncOffline(ctx, loreWorkDir, targetRev); err != nil {
				return err
			}
			if err := im.Lore.CreateBranchSlash(ctx, loreWorkDir, bName, true); err != nil {
				return err
			}
			existingBranches[bName] = targetRev
			currentBranch = bName
		}
	}

	// Switch working tree to the default branch (or `"main"`) so helper branches are never current when archived,
	// and so HEAD working files match the default branch tip for verification and Snapshot Publisher!
	checkoutBranch := "main"
	if g.DefaultBranch != "" && existingBranches[g.DefaultBranch] != "" {
		checkoutBranch = g.DefaultBranch
	}
	if err := im.Lore.SwitchBranchRevision(ctx, loreWorkDir, checkoutBranch, "", true, true); err != nil {
		return err
	}

	// Archive all helper `_import_*` branches so `lore branch list` stays completely clean!
	for _, hName := range sortedBoolKeys(helperSet) {
		if hName == checkoutBranch {
			continue
		}
		if _, exists := existingBranches[hName]; exists {
			_ = im.Lore.ArchiveBranch(ctx, loreWorkDir, hName, true)
		}
	}
	return nil
}

func (im *Importer) commitAndIndexGitCommit(
	ctx context.Context,
	loreWorkDir string,
	moduleID int64,
	c GitCommit,
	mat TreeMaterializeResult,
	commitMap map[string]string,
	extraMeta map[string]string,
) (string, error) {
	if err := im.Lore.StageScan(ctx, loreWorkDir, true); err != nil {
		return "", err
	}
	createdBy := c.AuthorName
	if c.AuthorEmail != "" {
		createdBy = fmt.Sprintf("%s <%s>", c.AuthorName, c.AuthorEmail)
	}
	meta := map[string]string{
		"created-by":            createdBy,
		"git.commit":            c.SHA,
		"git.tree":              c.TreeSHA,
		"git.parents":           strings.Join(c.Parents, ","),
		"git.author.name":       c.AuthorName,
		"git.author.email":      c.AuthorEmail,
		"git.author.time":       c.AuthoredAt,
		"git.author.unix_ms":    strconv.FormatInt(c.AuthoredUnixMS, 10),
		"git.committer.name":    c.CommitterName,
		"git.committer.email":   c.CommitterEmail,
		"git.committer.time":    c.CommittedAt,
		"git.committer.unix_ms": strconv.FormatInt(c.CommittedUnixMS, 10),
	}
	if c.Encoding != "" {
		meta["git.encoding"] = c.Encoding
	}
	if c.SignatureStatus != "" && c.SignatureStatus != "N" {
		meta["git.gpg_status"] = c.SignatureStatus
	}
	for k, v := range extraMeta {
		meta[k] = v
	}

	if err := im.Lore.SetStagedMetadata(ctx, loreWorkDir, meta, true); err != nil {
		return "", err
	}
	// Pass force=true so Git empty commits (`git commit --allow-empty` or submodule-only commits)
	// still create distinct 1-to-1 Lore revisions with full metadata!
	loreRev, err := im.Lore.CommitFull(ctx, loreWorkDir, c.Message, true, true)
	if err != nil {
		return "", err
	}

	parents := make([]history.ParentLink, len(c.Parents))
	for i, pSHA := range c.Parents {
		parents[i] = history.ParentLink{
			Ord:            i,
			SourceCommitID: pSHA,
			LoreRevision:   commitMap[pSHA],
		}
	}

	sysExtra := map[string]string{}
	if c.Encoding != "" {
		sysExtra["git.encoding"] = c.Encoding
	}
	if c.SignatureStatus != "" && c.SignatureStatus != "N" {
		sysExtra["git.gpg_status"] = c.SignatureStatus
	}
	for k, v := range extraMeta {
		sysExtra[k] = v
	}

	err = database.Tx(ctx, im.DB, func(tx *sql.Tx) error {
		if err := history.UpsertCommit(ctx, tx, history.CommitInput{
			ModuleID:            moduleID,
			LoreRevision:        loreRev,
			SourceCommitID:      c.SHA,
			OriginKind:          history.OriginGitImport,
			IsSynthetic:         false,
			AuthorName:          c.AuthorName,
			AuthorEmail:         c.AuthorEmail,
			AuthoredAt:          c.AuthoredAt,
			AuthoredUnixMS:      c.AuthoredUnixMS,
			CommitterName:       c.CommitterName,
			CommitterEmail:      c.CommitterEmail,
			CommittedAt:         c.CommittedAt,
			CommittedUnixMS:     c.CommittedUnixMS,
			LoreCommittedUnixMS: time.Now().UnixMilli(),
			Message:             c.Message,
			GitTreeID:           c.TreeSHA,
			ExtraMetadata:       sysExtra,
			Parents:             parents,
		}); err != nil {
			return err
		}
		for _, sp := range mat.Specials {
			sp.LoreRevision = loreRev
			sp.SourceCommitID = c.SHA
			if err := history.UpsertSpecialObject(ctx, tx, moduleID, sp); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return loreRev, nil
}

func (im *Importer) persistRefs(
	ctx context.Context,
	moduleID int64,
	loreWorkDir string,
	g MirrorGraph,
	commitMap map[string]string,
) error {
	loreBranchIDs := map[string]string{}
	if lbs, err := im.Lore.ListBranchesAt(ctx, loreWorkDir, false); err == nil {
		for _, b := range lbs {
			if !b.Archived {
				loreBranchIDs[b.Name] = b.ID
			}
		}
	}

	return database.Tx(ctx, im.DB, func(tx *sql.Tx) error {
		for _, bName := range sortedKeys(g.Branches) {
			sha := g.Branches[bName]
			rev := commitMap[sha]
			if rev == "" {
				return fmt.Errorf("gitimport: branch %s commit %s has no lore revision", bName, sha)
			}
			if err := history.UpsertRef(ctx, tx, history.RefDetail{
				ModuleID:       moduleID,
				Type:           "branch",
				Name:           bName,
				LoreRevision:   rev,
				SourceCommitID: sha,
				LoreBranchID:   loreBranchIDs[bName],
				IsDefault:      bName == g.DefaultBranch,
			}); err != nil {
				return err
			}
		}
		for _, t := range g.Tags {
			rev := commitMap[t.TargetSHA]
			if rev == "" {
				return fmt.Errorf("gitimport: tag %s target %s has no lore revision", t.Name, t.TargetSHA)
			}
			if err := history.UpsertRef(ctx, tx, history.RefDetail{
				ModuleID:          moduleID,
				Type:              "tag",
				Name:              t.Name,
				LoreRevision:      rev,
				SourceCommitID:    t.TargetSHA,
				SourceTagObjectID: t.TagObjectID,
				IsAnnotated:       t.IsAnnotated,
				TaggerName:        t.TaggerName,
				TaggerEmail:       t.TaggerEmail,
				TaggedAt:          t.TaggedAt,
				TagMessage:        t.Message,
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

func (im *Importer) verifyImportedModule(
	ctx context.Context,
	moduleID int64,
	mirrorDir, loreWorkDir, lfsMode string,
	remoteRefs RemoteRefSummary,
	g MirrorGraph,
	cp itemCheckpoint,
) (VerificationReport, error) {
	rep := VerificationReport{
		SourceCommits:         len(g.Commits),
		MappedCommits:         len(cp.CommitMap),
		SyntheticMergeBridges: cp.SyntheticCount,
		SourceBranches:        len(g.Branches),
		SourceTags:            len(g.Tags),
		HeadBranch:            g.DefaultBranch,
		AdvertisedHiddenRefs:  remoteRefs.AdvertisedHiddenRefs,
		ShallowMissingParents: g.ShallowMissingParents,
		LFSFetchAttempted:     g.LFSFetchAttempted,
		LFSFetchSucceeded:     g.LFSFetchSucceeded,
	}

	// 1. Check DB indexed non-synthetic commit count and 1-to-1 SHA mapping.
	if err := im.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM module_commits WHERE module_id=? AND is_synthetic=0 AND origin_kind='git_import'`, moduleID).
		Scan(&rep.IndexedCommits); err != nil {
		return rep, err
	}
	if rep.IndexedCommits != rep.SourceCommits {
		rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("indexed commits %d != source commits %d", rep.IndexedCommits, rep.SourceCommits))
	}

	for _, c := range g.Commits {
		rev := cp.CommitMap[c.SHA]
		if rev == "" {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("missing mapping for commit %s", c.SHA))
			continue
		}
		if len(c.Parents) >= 2 {
			var pCount int
			_ = im.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM module_commit_parents WHERE module_id=? AND lore_revision=?`, moduleID, rev).Scan(&pCount)
			if pCount != len(c.Parents) {
				rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("merge %s parent count %d != %d", c.SHA[:12], pCount, len(c.Parents)))
			} else {
				rep.MergeCommitsVerified++
				if len(c.Parents) >= 3 {
					rep.OctopusMergesVerified++
				}
			}
		}
	}

	// 2. Check branches and tags counts in module_refs.
	_ = im.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM module_refs WHERE module_id=? AND ref_type='branch'`, moduleID).Scan(&rep.ImportedBranches)
	_ = im.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM module_refs WHERE module_id=? AND ref_type='tag'`, moduleID).Scan(&rep.ImportedTags)
	_ = im.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM module_special_objects WHERE module_id=?`, moduleID).Scan(&rep.SpecialObjectsCount)

	if rep.ImportedBranches < rep.SourceBranches {
		rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("imported branches %d < source branches %d", rep.ImportedBranches, rep.SourceBranches))
	}
	if rep.ImportedTags < rep.SourceTags {
		rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("imported tags %d < source tags %d", rep.ImportedTags, rep.SourceTags))
	}

	// 3. Verify HEAD working tree content digest matches Git HEAD tree byte-for-byte!
	if g.DefaultBranch != "" && g.Branches[g.DefaultBranch] != "" {
		headCommit, ok := g.CommitsBySHA[g.Branches[g.DefaultBranch]]
		if ok {
			reader, err := NewBatchBlobReader(ctx, im.GitBinary, mirrorDir)
			if err != nil {
				return rep, err
			}
			defer reader.Close()
			gitFiles, gitDigest, err := ComputeGitTreeContentDigest(ctx, im.GitBinary, mirrorDir, headCommit.TreeSHA, lfsMode, reader)
			if err != nil {
				return rep, err
			}
			loreFiles, loreDigest, err := ComputeWorkdirDigest(loreWorkDir)
			if err != nil {
				return rep, err
			}
			rep.HeadFileCount = loreFiles
			rep.HeadGitDigest = gitDigest
			rep.HeadLoreDigest = loreDigest
			if gitFiles != loreFiles || gitDigest != loreDigest {
				rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("HEAD tree digest mismatch (git %d:%s vs lore %d:%s)", gitFiles, gitDigest[:12], loreFiles, loreDigest[:12]))
			}
		}
	}

	rep.Passed = len(rep.Mismatches) == 0
	return rep, nil
}

func (im *Importer) updateItemProgress(ctx context.Context, itemID int64, status string, cp itemCheckpoint) {
	b, _ := json.Marshal(cp)
	_, _ = im.DB.ExecContext(ctx, `
		UPDATE import_job_items
		SET status=?, module_id=NULLIF(?,0), lore_repository_id=?, lore_repository_url=?, checkpoint_json=?,
		    started_at=COALESCE(started_at, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
		WHERE item_id=?
	`, status, cp.ModuleID, cp.LoreRepositoryID, cp.LoreRepositoryURL, string(b), itemID)
}

func (im *Importer) saveItemFinal(ctx context.Context, itemID int64, res ItemResult) {
	verBytes, _ := json.Marshal(res.Verification)
	_, _ = im.DB.ExecContext(ctx, `
		UPDATE import_job_items
		SET status=?, module_id=NULLIF(?,0), lore_repository_id=?, lore_repository_url=?,
		    verification_json=?, error=?,
		    started_at=COALESCE(started_at, strftime('%Y-%m-%dT%H:%M:%SZ','now')),
		    finished_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')
		WHERE item_id=?
	`, res.Status, res.ModuleID, res.LoreRepositoryID, res.LoreRepositoryURL, string(verBytes), res.Error, itemID)
}

func loadExistingGitCommits(ctx context.Context, db *sql.DB, moduleID int64) (int, map[string]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT source_commit_id, lore_revision FROM module_commits WHERE module_id=? AND is_synthetic=0 AND source_commit_id IS NOT NULL`, moduleID)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var sha, rev string
		if err := rows.Scan(&sha, &rev); err != nil {
			return 0, nil, err
		}
		if sha != "" && rev != "" {
			out[sha] = rev
		}
	}
	return len(out), out, rows.Err()
}

// GetJob returns a stored import job and its per-repository items for projectID.
func (im *Importer) GetJob(ctx context.Context, projectID, jobID int64, projectName string) (JobResult, error) {
	res, err := im.readJobResult(ctx, jobID, projectName)
	if err != nil {
		return JobResult{}, err
	}
	if res.ProjectID != projectID {
		return JobResult{}, project.ErrNotFound
	}
	return res, nil
}

// ListJobs lists import jobs for projectID in reverse chronological order.
func (im *Importer) ListJobs(ctx context.Context, projectID int64, projectName string) ([]JobResult, error) {
	rows, err := im.DB.QueryContext(ctx, `SELECT job_id FROM import_jobs WHERE project_id=? ORDER BY job_id DESC LIMIT 100`, projectID)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	out := make([]JobResult, 0, len(ids))
	for _, id := range ids {
		j, err := im.readJobResult(ctx, id, projectName)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedBoolKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
