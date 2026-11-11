package gitimport

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"lore-monorepo/internal/database"
	"lore-monorepo/internal/loreadapter"
	"lore-monorepo/internal/project"
)

var (
	ErrConflict = errors.New("gitimport: target module conflict")
	ErrJobBusy  = errors.New("gitimport: import job is already running")
	ErrVerify   = errors.New("gitimport: post-import integrity verification failed")

	repoID32Re = regexp.MustCompile(`[0-9a-f]{32}`)

	mirrorLocks sync.Map // map[string]*sync.Mutex
	targetLocks sync.Map // map[string]*sync.Mutex
)

const zeroHash64 = "0000000000000000000000000000000000000000000000000000000000000000"

func lockByKey(m *sync.Map, key string) func() {
	actual, _ := m.LoadOrStore(key, &sync.Mutex{})
	mu := actual.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func tryLockByKey(m *sync.Map, key string) (func(), bool) {
	actual, _ := m.LoadOrStore(key, &sync.Mutex{})
	mu := actual.(*sync.Mutex)
	if !mu.TryLock() {
		return nil, false
	}
	return mu.Unlock, true
}

func newWorkerToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// VerificationReport records the automated pre/post 3-layer integrity checks for one imported repository.
type VerificationReport struct {
	Passed                bool     `json:"passed"`
	SourceSubdir          string   `json:"source_subdir,omitempty"`
	RawSourceCommits      int      `json:"raw_source_commits,omitempty"`
	SourceCommits         int      `json:"source_commits"`
	AliasedCommits        int      `json:"aliased_commits,omitempty"`
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
	SkippedEmptyBranches  []string `json:"skipped_empty_branches,omitempty"`
	SkippedEmptyTags      []string `json:"skipped_empty_tags,omitempty"`
	UnmappedPathsCount    int      `json:"unmapped_paths_count,omitempty"`
	UnmappedPaths         []string `json:"unmapped_paths,omitempty"`
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
	SourceSubdir      string             `json:"source_subdir,omitempty"`
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
	BootstrapMainRev  string            `json:"bootstrap_main_rev,omitempty"`
	CommitMap         map[string]string `json:"commit_map,omitempty"` // projected git sha -> lore 64-hex revision
	SyntheticCount    int               `json:"synthetic_count,omitempty"`
	HelperBranches    []string          `json:"helper_branches,omitempty"`
	PushedBranches    map[string]bool   `json:"pushed_branches,omitempty"`
}

// Importer orchestrates single and batch external Git imports into Monorepo-Lore.
type Importer struct {
	DB            *sql.DB
	Lore          *loreadapter.Client
	GitBinary     string
	WorkspaceRoot string
	RemoteBaseURL string

	// Security policy boundaries enforced on the server:
	// - Manager HTTP API sets RestrictLocalSources = true and configures AllowedLocalDirs / AllowedSSHKeyDirs.
	// - Server-side BuildGitAuthEnv ALWAYS forbids reading os.Getenv(TokenEnv / SSHKeyEnv).
	RestrictLocalSources bool
	AllowedLocalDirs     []string
	RestrictSSHKeyPaths  bool
	AllowedSSHKeyDirs    []string

	// FaultHook is a test-only hook invoked after replayCommitIndex (0-based) for
	// deterministic crash/interruption and checkpoint-resume testing.
	FaultHook func(moduleName string, replayCommitIndex int) error
}

func (im *Importer) authPolicy() AuthPolicy {
	return AuthPolicy{
		DisallowProcessEnv: true,
		RestrictSSHPaths:   im.RestrictSSHKeyPaths,
		AllowedSSHKeyDirs:  im.AllowedSSHKeyDirs,
	}
}

func sharedMirrorDir(workspaceRoot string, projID int64, sourceURL string) string {
	sum := sha256.Sum256([]byte(sourceURL))
	return filepath.Join(workspaceRoot, fmt.Sprintf("proj-%d", projID), "mirrors", hex.EncodeToString(sum[:12])+".git")
}

// RecoverInterruptedJobs resets stale `running` import jobs left behind by an
// unexpected Manager process exit so they can be safely resumed without deadlocks.
func RecoverInterruptedJobs(ctx context.Context, db *sql.DB) error {
	return database.Tx(ctx, db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			UPDATE import_job_items
			SET status='failed',
			    error=CASE WHEN error='' THEN 'interrupted by manager restart; re-run job to resume from checkpoint' ELSE error END,
			    finished_at=COALESCE(finished_at, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
			WHERE status IN ('pending','cloning','replaying','pushing','verifying')
			  AND job_id IN (SELECT job_id FROM import_jobs WHERE status='running')
		`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `
			UPDATE import_jobs
			SET status='failed',
			    worker_token='',
			    updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now'),
			    finished_at=COALESCE(finished_at, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
			WHERE status='running'
		`)
		return err
	})
}

// Run executes a dry-run or live import manifest with job-level concurrency mutex,
// shared mirror locking, per-module target locking, 4-state conflict classification,
// checkpoint reconciliation, and 3-layer DAG verification.
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

	workerTok := newWorkerToken()
	jobID, items, alreadyDone, err := im.acquireOrCreateJob(ctx, actor, proj, mode, jobKey, mHash, workerTok, m)
	if err != nil {
		return JobResult{}, err
	}
	if alreadyDone {
		return im.readJobResult(ctx, jobID, proj.Name)
	}

	// Group sibling subdirs by source_url so monorepo splitting knows all declared module prefixes
	// and shares one MirrorGraph + TreeCache per source_url!
	siblingSubdirsByURL := map[string][]string{}
	for _, r := range m.Repositories {
		if r.SourceSubdir != "" {
			siblingSubdirsByURL[r.SourceURL] = append(siblingSubdirsByURL[r.SourceURL], r.SourceSubdir)
		}
	}

	mirrorStates := map[string]*sharedMirrorState{}
	for _, r := range m.Repositories {
		if _, exists := mirrorStates[r.SourceURL]; !exists {
			mirrorStates[r.SourceURL] = &sharedMirrorState{tc: NewTreeCache()}
		}
	}

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
			spec := m.Repositories[idx]
			ms := mirrorStates[spec.SourceURL]
			siblings := siblingSubdirsByURL[spec.SourceURL]
			if m.DryRun {
				results[idx] = im.runDryRunItem(ctx, proj, items[idx], spec)
			} else {
				results[idx] = im.runImportItem(ctx, actor, proj, items[idx], spec, siblings, func() (string, RemoteRefSummary, MirrorGraph, *TreeCache, error) {
					return ms.get(func() (string, RemoteRefSummary, MirrorGraph, *TreeCache, error) {
						return im.syncSharedMirror(ctx, items[idx].GitMirrorPath, spec, ms.tc)
					})
				})
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
		SET status=?, worker_token='', succeeded_items=?, failed_items=?, skipped_items=?, summary_json=?,
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
	SourceSubdir   string
	Status         string
	ModuleID       int64
	LoreRepoID     string
	LoreRepoURL    string
	BootstrapRev   string
	GitMirrorPath  string
	LoreWorkPath   string
	CheckpointJSON string
	VerifyJSON     string
	Error          string
}

func (im *Importer) acquireOrCreateJob(
	ctx context.Context,
	actor string,
	proj *project.Project,
	mode, jobKey, manifestHash, workerToken string,
	m Manifest,
) (jobID int64, items []storedItem, alreadySucceeded bool, err error) {
	err = database.Tx(ctx, im.DB, func(tx *sql.Tx) error {
		var existingStatus, existingHash, existingWorker string
		qErr := tx.QueryRowContext(ctx, `SELECT job_id, status, manifest_hash, worker_token FROM import_jobs WHERE job_key=?`, jobKey).
			Scan(&jobID, &existingStatus, &existingHash, &existingWorker)
		if qErr == nil {
			if existingHash != manifestHash {
				return fmt.Errorf("%w: job_key %q already exists with a different manifest", ErrConflict, jobKey)
			}
			if existingStatus == "running" {
				return fmt.Errorf("%w: job_key %q", ErrJobBusy, jobKey)
			}
			if existingStatus == "succeeded" && mode == "import" {
				alreadySucceeded = true
				return nil
			}
			res, uErr := tx.ExecContext(ctx, `
				UPDATE import_jobs
				SET status='running', worker_token=?, updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')
				WHERE job_id=? AND status<>'running'
			`, workerToken, jobID)
			if uErr != nil {
				return uErr
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return fmt.Errorf("%w: job_key %q", ErrJobBusy, jobKey)
			}
			return nil
		}
		if !errors.Is(qErr, sql.ErrNoRows) {
			return qErr
		}

		res, iErr := tx.ExecContext(ctx, `
			INSERT INTO import_jobs (job_key, project_id, mode, status, manifest_hash, requested_by, total_items, worker_token)
			VALUES (?, ?, ?, 'running', ?, ?, ?, ?)
		`, jobKey, proj.ID, mode, manifestHash, actor, len(m.Repositories), workerToken)
		if iErr != nil {
			if strings.Contains(iErr.Error(), "UNIQUE") {
				return fmt.Errorf("%w: job_key %q", ErrJobBusy, jobKey)
			}
			return iErr
		}
		jobID, _ = res.LastInsertId()
		for i, r := range m.Repositories {
			authMethod := inferAuthMethodLabel(r.Auth)
			mirrorPath := sharedMirrorDir(im.WorkspaceRoot, proj.ID, r.SourceURL)
			workPath := filepath.Join(im.WorkspaceRoot, fmt.Sprintf("proj-%d", proj.ID), "lore", r.ModuleName)
			if _, iErr := tx.ExecContext(ctx, `
				INSERT INTO import_job_items (
					job_id, ord, source_url, source_subdir, platform, auth_method, module_name, mount_path,
					conflict_policy, git_mirror_path, lore_work_path, status
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
			`, jobID, i, r.SourceURL, r.SourceSubdir, r.Platform, authMethod, r.ModuleName, r.MountPath, r.ConflictPolicy, mirrorPath, workPath); iErr != nil {
				return iErr
			}
		}
		return nil
	})
	if err != nil || alreadySucceeded {
		return jobID, nil, alreadySucceeded, err
	}

	rows, err := im.DB.QueryContext(ctx, `
		SELECT item_id, job_id, ord, source_subdir, status, COALESCE(module_id,0), lore_repository_id, lore_repository_url,
		       bootstrap_main_rev, git_mirror_path, lore_work_path, checkpoint_json, verification_json, error
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
		if err := rows.Scan(&it.ItemID, &it.JobID, &it.Ord, &it.SourceSubdir, &it.Status, &it.ModuleID, &it.LoreRepoID, &it.LoreRepoURL,
			&it.BootstrapRev, &it.GitMirrorPath, &it.LoreWorkPath, &it.CheckpointJSON, &it.VerifyJSON, &it.Error); err != nil {
			return 0, nil, false, err
		}
		items = append(items, it)
	}
	return jobID, items, false, rows.Err()
}

func inferAuthMethodLabel(a AuthConfig) string {
	m := strings.ToLower(strings.TrimSpace(a.Method))
	if m != "" {
		return m
	}
	switch {
	case a.Token != "" || a.TokenEnv != "":
		return AuthHTTPSToken
	case a.SSHKeyPath != "" || a.SSHKeyEnv != "":
		return AuthSSHKey
	default:
		return AuthNone
	}
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
		SELECT item_id, ord, module_name, mount_path, source_url, source_subdir, platform, auth_method,
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
		if err := rows.Scan(&it.ItemID, &it.Ord, &it.ModuleName, &it.MountPath, &it.SourceURL, &it.SourceSubdir, &it.Platform, &it.AuthMethod,
			&it.Status, &it.ModuleID, &it.LoreRepositoryID, &it.LoreRepositoryURL, &verRaw, &it.Error); err != nil {
			return res, err
		}
		_ = json.Unmarshal([]byte(verRaw), &it.Verification)
		res.Items = append(res.Items, it)
	}
	return res, rows.Err()
}

// moduleImportState classifies an existing module for rigorous skip_if_imported / resume / fail handling:
//   - "ordinary": normal manually created module with NO git_import history or import_job_items
//   - "complete": verified completed import matching `(source_url, source_subdir)`
//   - "partial": interrupted/failed import matching `(source_url, source_subdir)` with consistent state
//   - "uncertain": mismatched source_url/source_subdir, unverified status, or inconsistent commit records
func (im *Importer) classifyExistingModule(ctx context.Context, mod *project.Module, spec RepoSpec) (state, detail string, lastWorkDir, lastBootstrap string) {
	if mod.Name != spec.ModuleName || mod.MountPath != spec.MountPath {
		return "ordinary", fmt.Sprintf("mount_path %q conflicts with existing module %q (%s)", spec.MountPath, mod.Name, mod.MountPath), "", ""
	}

	var gitImportCommits, nativeCommits int
	_ = im.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM module_commits WHERE module_id=? AND origin_kind='git_import' AND is_synthetic=0`, mod.ID).Scan(&gitImportCommits)
	_ = im.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM module_commits WHERE module_id=? AND origin_kind='native_lore'`, mod.ID).Scan(&nativeCommits)

	var itemCount int
	_ = im.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM import_job_items WHERE module_id=? AND job_id IN (SELECT job_id FROM import_jobs WHERE mode='import')`, mod.ID).Scan(&itemCount)

	if itemCount == 0 && gitImportCommits == 0 {
		return "ordinary", fmt.Sprintf("ordinary module %q already exists and was not created by git import", mod.Name), "", ""
	}
	if itemCount == 0 && gitImportCommits > 0 {
		return "uncertain", fmt.Sprintf("module %q has %d git_import commits without an authoritative import job record; manual inspection required", mod.Name, gitImportCommits), "", ""
	}

	var lastSourceURL, lastSubdir, lastStatus, verRaw string
	err := im.DB.QueryRowContext(ctx, `
		SELECT i.source_url, i.source_subdir, i.status, i.verification_json, i.lore_work_path, i.bootstrap_main_rev
		FROM import_job_items i
		JOIN import_jobs j ON j.job_id = i.job_id
		WHERE i.module_id = ? AND j.mode = 'import' AND i.status NOT IN ('conflict', 'skipped', 'planned')
		ORDER BY i.item_id DESC LIMIT 1
	`, mod.ID).Scan(&lastSourceURL, &lastSubdir, &lastStatus, &verRaw, &lastWorkDir, &lastBootstrap)
	if errors.Is(err, sql.ErrNoRows) {
		if gitImportCommits == 0 {
			return "ordinary", fmt.Sprintf("ordinary module %q already exists and was not created by git import", mod.Name), "", ""
		}
		return "uncertain", fmt.Sprintf("module %q has %d git_import commits without an authoritative import job record; manual inspection required", mod.Name, gitImportCommits), "", ""
	}
	if err != nil {
		return "uncertain", fmt.Sprintf("module %q import state could not be read: %v", mod.Name, err), "", ""
	}

	if lastSourceURL != spec.SourceURL || lastSubdir != spec.SourceSubdir {
		return "uncertain", fmt.Sprintf("module %q was previously associated with (%s, subdir=%q), which conflicts with (%s, subdir=%q)",
			mod.Name, lastSourceURL, lastSubdir, spec.SourceURL, spec.SourceSubdir), "", ""
	}

	if lastStatus == "succeeded" {
		var ver VerificationReport
		if json.Unmarshal([]byte(verRaw), &ver) == nil && ver.Passed && ver.IndexedCommits == ver.SourceCommits && gitImportCommits >= ver.IndexedCommits {
			return "complete", fmt.Sprintf("module %q already completely imported and verified (%d commits)", mod.Name, ver.IndexedCommits), lastWorkDir, lastBootstrap
		}
		return "uncertain", fmt.Sprintf("module %q marked succeeded but verification or commit count (%d) is inconsistent; manual inspection required", mod.Name, gitImportCommits), lastWorkDir, lastBootstrap
	}

	if lastStatus == "cloning" || lastStatus == "replaying" || lastStatus == "pushing" || lastStatus == "verifying" || lastStatus == "pending" {
		return "uncertain", fmt.Sprintf("module %q has an active or unrecovered import item in state %q", mod.Name, lastStatus), lastWorkDir, lastBootstrap
	}

	if lastStatus == "failed" {
		if nativeCommits > 0 {
			return "uncertain", fmt.Sprintf("module %q has partial import plus %d native commits; manual inspection required", mod.Name, nativeCommits), lastWorkDir, lastBootstrap
		}
		return "partial", fmt.Sprintf("module %q has a resumable partial import (%d commits indexed so far)", mod.Name, gitImportCommits), lastWorkDir, lastBootstrap
	}

	return "uncertain", fmt.Sprintf("module %q is in ambiguous import state %q; manual inspection required", mod.Name, lastStatus), lastWorkDir, lastBootstrap
}

func (im *Importer) findCollidingModule(ctx context.Context, projectID int64, spec RepoSpec) (*project.Module, error) {
	mods, err := project.ListModules(ctx, im.DB, projectID, false)
	if err != nil {
		return nil, err
	}
	for i := range mods {
		m := &mods[i]
		if m.Name == spec.ModuleName || mountsOverlap(m.MountPath, spec.MountPath) {
			return m, nil
		}
	}
	return nil, nil
}

func (im *Importer) validateSourceAndAuth(spec RepoSpec) (resolvedSourceURL string, extraEnv, secrets []string, authMethod string, err error) {
	resolvedSourceURL = spec.SourceURL
	if spec.Platform == PlatformLocalGit {
		cleanLocal, lErr := ValidateLocalSourceAccess(spec.SourceURL, im.RestrictLocalSources, im.AllowedLocalDirs)
		if lErr != nil {
			return "", nil, nil, inferAuthMethodLabel(spec.Auth), lErr
		}
		resolvedSourceURL = cleanLocal
	}
	extraEnv, secrets, authMethod, err = BuildGitAuthEnv(resolvedSourceURL, spec.Platform, spec.Auth, im.authPolicy())
	if err != nil {
		return "", nil, nil, authMethod, err
	}
	return resolvedSourceURL, extraEnv, secrets, authMethod, nil
}

func (im *Importer) runDryRunItem(ctx context.Context, proj *project.Project, st storedItem, spec RepoSpec) ItemResult {
	resolvedSourceURL, extraEnv, secrets, authMethod, authErr := im.validateSourceAndAuth(spec)
	out := ItemResult{
		ItemID:       st.ItemID,
		Ord:          st.Ord,
		ModuleName:   spec.ModuleName,
		MountPath:    spec.MountPath,
		SourceURL:    spec.SourceURL,
		SourceSubdir: spec.SourceSubdir,
		Platform:     spec.Platform,
		AuthMethod:   authMethod,
	}
	if authErr != nil {
		out.Status = "failed"
		out.Error = authErr.Error()
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}

	existing, cErr := im.findCollidingModule(ctx, proj.ID, spec)
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
		state, detail, _, _ := im.classifyExistingModule(ctx, existing, spec)
		out.ConflictReason = detail
		switch state {
		case "complete":
			if spec.ConflictPolicy == ConflictSkipIfImported {
				out.Status = "skipped"
				im.saveItemFinal(ctx, st.ItemID, out)
				return out
			}
			if spec.ConflictPolicy == ConflictFail {
				out.Status = "conflict"
				out.Error = detail
				im.saveItemFinal(ctx, st.ItemID, out)
				return out
			}
			// ConflictResume on an already complete module falls through to planned/resumable preview.
		case "partial":
			if spec.ConflictPolicy == ConflictSkipIfImported || spec.ConflictPolicy == ConflictResume {
				// Partial import: Dry-run previews that it will resume rather than falsely skipping!
			} else {
				out.Status = "conflict"
				out.Error = detail
				im.saveItemFinal(ctx, st.ItemID, out)
				return out
			}
		case "ordinary", "uncertain":
			out.Status = "conflict"
			out.Error = detail
			im.saveItemFinal(ctx, st.ItemID, out)
			return out
		}
	}

	refs, err := InspectRemoteRefs(ctx, im.GitBinary, resolvedSourceURL, extraEnv, secrets)
	if err != nil {
		out.Status = "failed"
		out.Error = err.Error()
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}
	out.RemoteRefs = &refs
	out.Verification = VerificationReport{
		Passed:               true,
		SourceSubdir:         spec.SourceSubdir,
		SourceBranches:       len(refs.Branches),
		SourceTags:           len(refs.Tags),
		HeadBranch:           refs.DefaultBranch,
		AdvertisedHiddenRefs: refs.AdvertisedHiddenRefs,
	}
	out.Status = "planned"
	im.saveItemFinal(ctx, st.ItemID, out)
	return out
}

func (im *Importer) syncSharedMirror(
	ctx context.Context,
	mirrorDir string,
	spec RepoSpec,
	tc *TreeCache,
) (string, RemoteRefSummary, MirrorGraph, *TreeCache, error) {
	resolvedSourceURL, extraEnv, secrets, _, authErr := im.validateSourceAndAuth(spec)
	if authErr != nil {
		return "", RemoteRefSummary{}, MirrorGraph{}, tc, authErr
	}

	unlockMirror := lockByKey(&mirrorLocks, mirrorDir)
	defer unlockMirror()

	refs, err := InspectRemoteRefs(ctx, im.GitBinary, resolvedSourceURL, extraEnv, secrets)
	if err != nil {
		return "", RemoteRefSummary{}, MirrorGraph{}, tc, err
	}
	lfsAttempted, lfsOK, err := SyncBareMirror(ctx, im.GitBinary, resolvedSourceURL, mirrorDir, spec.LFSMode, extraEnv, secrets)
	if err != nil {
		return "", RemoteRefSummary{}, MirrorGraph{}, tc, err
	}
	graph, err := ReadMirrorGraph(ctx, im.GitBinary, mirrorDir, refs.DefaultBranch)
	if err != nil {
		return "", RemoteRefSummary{}, MirrorGraph{}, tc, err
	}
	graph.LFSFetchAttempted = lfsAttempted
	graph.LFSFetchSucceeded = lfsOK
	return resolvedSourceURL, refs, graph, tc, nil
}
