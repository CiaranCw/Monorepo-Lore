package gitimport

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"lore-monorepo/internal/database"
	"lore-monorepo/internal/history"
	"lore-monorepo/internal/loreexec"
	"lore-monorepo/internal/project"
	"lore-monorepo/internal/user"
)

type sharedMirrorState struct {
	once sync.Once
	url  string
	refs RemoteRefSummary
	g    MirrorGraph
	tc   *TreeCache
	err  error
}

func (s *sharedMirrorState) get(fn func() (string, RemoteRefSummary, MirrorGraph, *TreeCache, error)) (string, RemoteRefSummary, MirrorGraph, *TreeCache, error) {
	s.once.Do(func() {
		s.url, s.refs, s.g, s.tc, s.err = fn()
	})
	return s.url, s.refs, s.g, s.tc, s.err
}

func (im *Importer) runImportItem(
	ctx context.Context,
	actor string,
	proj *project.Project,
	st storedItem,
	spec RepoSpec,
	siblingSubdirs []string,
	foreignMappings []PathMapping,
	pathRules []PathRule,
	manifestModNames map[string]bool,
	getMirror func() (string, RemoteRefSummary, MirrorGraph, *TreeCache, error),
) ItemResult {
	if st.Status == "succeeded" {
		var ver VerificationReport
		_ = json.Unmarshal([]byte(st.VerifyJSON), &ver)
		return ItemResult{
			ItemID: st.ItemID, Ord: st.Ord, ModuleName: spec.ModuleName, MountPath: spec.MountPath,
			SourceURL: spec.SourceURL, SourceSubdir: spec.SourceSubdir, Platform: spec.Platform,
			AuthMethod: inferAuthMethodLabel(spec.Auth), Status: "succeeded",
			ModuleID: st.ModuleID, LoreRepositoryID: st.LoreRepoID, LoreRepositoryURL: st.LoreRepoURL,
			Verification: ver,
		}
	}

	// Acquire per-target module mutex so two jobs can NEVER operate on the same target module or Lore workdir concurrently!
	targetKey := fmt.Sprintf("proj-%d:mod-%s", proj.ID, spec.ModuleName)
	unlockTarget, acquired := tryLockByKey(&targetLocks, targetKey)
	if !acquired {
		out := ItemResult{
			ItemID: st.ItemID, Ord: st.Ord, ModuleName: spec.ModuleName, MountPath: spec.MountPath,
			SourceURL: spec.SourceURL, SourceSubdir: spec.SourceSubdir, Platform: spec.Platform,
			AuthMethod: inferAuthMethodLabel(spec.Auth), Status: "conflict",
			ConflictReason: fmt.Sprintf("target module %q is currently locked by another active import operation", spec.ModuleName),
			Error:          fmt.Sprintf("target module %q is currently locked by another active import operation", spec.ModuleName),
		}
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}
	defer unlockTarget()

	// Validate auth & local source policy upfront before any mirror or DB work.
	_, _, _, authMethod, authErr := im.validateSourceAndAuth(spec)
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

	var cp itemCheckpoint
	_ = json.Unmarshal([]byte(st.CheckpointJSON), &cp)
	if cp.CommitMap == nil {
		cp.CommitMap = map[string]string{}
	}
	if cp.PushedBranches == nil {
		cp.PushedBranches = map[string]bool{}
	}
	if st.BootstrapRev != "" && cp.BootstrapMainRev == "" {
		cp.BootstrapMainRev = st.BootstrapRev
	}

	// Check existing module collisions and classify into 4 strict states:
	//   "complete", "partial", "ordinary", "uncertain"
	existing, cErr := im.findCollidingModule(ctx, proj.ID, spec)
	if cErr != nil {
		out.Status = "failed"
		out.Error = cErr.Error()
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}
	if existing != nil && existing.ID != cp.ModuleID {
		state, detail, prevWorkDir, prevBootstrap := im.classifyExistingModule(ctx, existing, spec)
		out.ModuleID = existing.ID
		out.LoreRepositoryID = existing.RepositoryID
		out.LoreRepositoryURL = existing.RepositoryURL

		switch state {
		case "complete":
			if spec.ConflictPolicy == ConflictSkipIfImported {
				ver, sourceJob := im.priorPassedVerification(ctx, existing.ID)
				if !ver.Passed || sourceJob == 0 {
					out.Status = "conflict"
					out.Error = "skip refused: the previous import has no passed verification"
					out.ConflictReason = detail
					im.saveItemFinal(ctx, st.ItemID, out)
					return out
				}
				ver.ReusedFromJobID = sourceJob
				out.Verification = ver
				out.Status = "skipped"
				out.ConflictReason = detail
				im.saveItemFinal(ctx, st.ItemID, out)
				return out
			}
			if spec.ConflictPolicy == ConflictResume {
				cp.ModuleID = existing.ID
				cp.LoreRepositoryID = existing.RepositoryID
				cp.LoreRepositoryURL = existing.RepositoryURL
				if prevBootstrap != "" {
					cp.BootstrapMainRev = prevBootstrap
				}
				if prevWorkDir != "" {
					st.LoreWorkPath = prevWorkDir
				}
			} else {
				out.Status = "conflict"
				out.ConflictReason = detail
				out.Error = detail
				im.saveItemFinal(ctx, st.ItemID, out)
				return out
			}

		case "partial":
			if spec.ConflictPolicy == ConflictSkipIfImported || spec.ConflictPolicy == ConflictResume {
				cp.ModuleID = existing.ID
				cp.LoreRepositoryID = existing.RepositoryID
				cp.LoreRepositoryURL = existing.RepositoryURL
				if prevBootstrap != "" {
					cp.BootstrapMainRev = prevBootstrap
				}
				if prevWorkDir != "" {
					st.LoreWorkPath = prevWorkDir
				}
			} else {
				out.Status = "conflict"
				out.ConflictReason = detail
				out.Error = detail
				im.saveItemFinal(ctx, st.ItemID, out)
				return out
			}

		default: // "ordinary" or "uncertain" -> NEVER silently skip or overwrite!
			out.Status = "conflict"
			out.ConflictReason = detail
			out.Error = detail
			im.saveItemFinal(ctx, st.ItemID, out)
			return out
		}
	}

	// Step 1: Sync shared Bare Git Mirror & read full source MirrorGraph.
	im.updateItemProgress(ctx, st.ItemID, "cloning", cp)
	_, remoteRefs, rawGraph, treeCache, mErr := getMirror()
	if mErr != nil {
		out.Status = "failed"
		out.Error = mErr.Error()
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}
	out.RemoteRefs = &remoteRefs
	if pinnedBytes, pErr := json.Marshal(remoteRefs); pErr == nil {
		_, _ = im.DB.ExecContext(ctx, `UPDATE import_job_items SET pinned_refs_json=? WHERE item_id=? AND (pinned_refs_json='' OR pinned_refs_json='{}')`,
			string(pinnedBytes), st.ItemID)
	}

	// Gate 1: Reject shallow / missing-parent Git history immediately before mutating Lore!
	if rawGraph.IsShallow || len(rawGraph.ShallowMissingParents) > 0 {
		out.Status = "failed"
		out.Verification = VerificationReport{
			Passed:                false,
			SourceSubdir:          spec.SourceSubdir,
			RawSourceCommits:      len(rawGraph.Commits),
			ShallowMissingParents: rawGraph.ShallowMissingParents,
			Mismatches:            []string{"incomplete/shallow git commit graph: missing parent objects"},
		}
		out.Error = fmt.Sprintf("%s: shallow or missing parent commits (%v)", ErrVerify.Error(), rawGraph.ShallowMissingParents)
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}

	// Step 2: Project MirrorGraph onto this module's independent DAG (`source_subdir` or whole repo).
	projGraph, pErr := ProjectMirrorGraph(ctx, im.GitBinary, st.GitMirrorPath, rawGraph, spec.SourceSubdir, siblingSubdirs, pathRules, treeCache, spec.EffectiveMappings(), foreignMappings)
	if pErr != nil {
		out.Status = "failed"
		out.Error = pErr.Error()
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}
	if len(projGraph.Commits) == 0 {
		out.Status = "failed"
		out.Error = fmt.Sprintf("gitimport: zero commits matched module %q (source_subdir=%q)", spec.ModuleName, spec.SourceSubdir)
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}
	// A `separate_module` classification is only complete when that target
	// module is explicitly present in this same reviewed manifest.
	for _, classified := range projGraph.ClassifiedSeparateModule {
		if classified.TargetModule == "" || !manifestModNames[classified.TargetModule] {
			projGraph.CoverageComplete = false
			projGraph.UndecidedPaths = append(projGraph.UndecidedPaths, classified.Path)
		}
	}
	sort.Strings(projGraph.UndecidedPaths)

	// Gate 2: Enforce 4-category Global/Unmapped Path Classification Policy BEFORE mutating Lore!
	if spec.SourceSubdir != "" && spec.GlobalFilesPolicy == GlobalPolicyStrict && !projGraph.CoverageComplete {
		out.Status = "failed"
		limit := len(projGraph.UndecidedPaths)
		if limit > 32 {
			limit = 32
		}
		out.Verification = VerificationReport{
			Passed:                   false,
			CoverageComplete:         false,
			SourceSubdir:             spec.SourceSubdir,
			RawSourceCommits:         len(rawGraph.Commits),
			SourceCommits:            len(projGraph.Commits),
			UnmappedPathsCount:       len(projGraph.UnmappedPaths),
			ClassifiedExcluded:       projGraph.ClassifiedExcluded,
			ClassifiedSeparateModule: projGraph.ClassifiedSeparateModule,
			UndecidedPaths:           projGraph.UndecidedPaths[:limit],
			Mismatches:               []string{fmt.Sprintf("%d unclassified monorepo path(s) outside module subdirectories", len(projGraph.UndecidedPaths))},
		}
		out.Error = fmt.Sprintf("%s: %d undecided path(s) (first: %s)", ErrUnclassifiedGlobalPaths.Error(), len(projGraph.UndecidedPaths), projGraph.UndecidedPaths[0])
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}

	// Step 3: Prepare Lore repository, reconcile checkpoint against physical Lore revisions, and register module!
	im.updateItemProgress(ctx, st.ItemID, "replaying", cp)
	if err := im.ensureLoreRepoAndReconcileCheckpoint(ctx, st.ItemID, actor, proj.ID, spec, st.LoreWorkPath, &cp); err != nil {
		out.Status = "failed"
		out.Error = err.Error()
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}
	out.ModuleID = cp.ModuleID
	out.LoreRepositoryID = cp.LoreRepositoryID
	out.LoreRepositoryURL = cp.LoreRepositoryURL

	// Step 4: Replay projected module DAG into Lore repository with per-commit checkpointing!
	if err := im.replayGraphIntoLore(ctx, st.ItemID, spec, st.GitMirrorPath, st.LoreWorkPath, &projGraph, &cp, treeCache); err != nil {
		out.Status = "failed"
		out.Error = err.Error()
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}

	// Step 5: If targeting a remote Lore Server, push active branches idempotently (checking remote branch head first).
	if im.RemoteBaseURL != "" {
		im.updateItemProgress(ctx, st.ItemID, "pushing", cp)
		remoteHeads := map[string]string{}
		if rbs, rErr := im.Lore.ListBranchesAt(ctx, st.LoreWorkPath, true); rErr == nil {
			for _, rb := range rbs {
				if !rb.Archived {
					remoteHeads[rb.Name] = rb.Latest
				}
			}
		}
		for _, bName := range sortedKeys(projGraph.Branches) {
			wantRev := cp.CommitMap[projGraph.Branches[bName]]
			if remoteHeads[bName] == wantRev {
				cp.PushedBranches[bName] = true
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

	// Step 6: Persist per-module commit aliases, branch & tag refs, and run 3-Layer DAG Integrity Verification!
	im.updateItemProgress(ctx, st.ItemID, "verifying", cp)
	if err := im.persistAliasesAndRefs(ctx, cp.ModuleID, st.LoreWorkPath, spec.SourceSubdir, rawGraph, projGraph, cp.CommitMap); err != nil {
		out.Status = "failed"
		out.Error = err.Error()
		im.saveItemFinal(ctx, st.ItemID, out)
		return out
	}

	ver, vErr := im.verifyImportedModule(ctx, proj.ID, cp.ModuleID, st.GitMirrorPath, st.LoreWorkPath, spec, remoteRefs, rawGraph, projGraph, cp, manifestModNames, treeCache)
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

func (im *Importer) registerRemoteModuleForClone(ctx context.Context, actor string, projectID int64, spec RepoSpec, cp *itemCheckpoint) error {
	if cp.LoreRepositoryID == "" {
		return nil
	}
	account, _, err := user.Get(ctx, im.DB, actor)
	if err != nil {
		return err
	}
	if cp.ModuleID != 0 {
		mod, gErr := project.GetModuleByID(ctx, im.DB, cp.ModuleID)
		if gErr != nil {
			return gErr
		}
		if mod.RepositoryID != cp.LoreRepositoryID {
			return fmt.Errorf("gitimport: module %s is bound to repository %s", spec.ModuleName, mod.RepositoryID)
		}
		if mod.Archived() {
			if err := project.ReactivateModule(ctx, im.DB, actor, mod.ID, spec.MountPath); err != nil {
				return err
			}
		}
	} else if existing, gErr := project.GetModule(ctx, im.DB, projectID, spec.ModuleName); gErr == nil {
		if existing.RepositoryID != cp.LoreRepositoryID {
			return fmt.Errorf("gitimport: module %s is bound to repository %s", spec.ModuleName, existing.RepositoryID)
		}
		cp.ModuleID = existing.ID
		if existing.Archived() {
			if err := project.ReactivateModule(ctx, im.DB, actor, existing.ID, spec.MountPath); err != nil {
				return err
			}
		}
	} else {
		mod, cErr := project.CreateModule(ctx, im.DB, actor, project.Module{
			ProjectID: projectID, Name: spec.ModuleName, RepositoryID: cp.LoreRepositoryID,
			RepositoryURL: cp.LoreRepositoryURL, MountPath: spec.MountPath,
		})
		if cErr != nil {
			return cErr
		}
		cp.ModuleID = mod.ID
	}
	err = project.GrantModule(ctx, im.DB, actor, account.ID, cp.ModuleID)
	if errors.Is(err, project.ErrConflict) {
		return nil
	}
	if err != nil && cp.ModuleID != 0 {
		im.concealEmptyImportModule(ctx, actor, cp.ModuleID)
	}
	return err
}

// concealEmptyImportModule removes a module that has no imported commits from
// human listings. The Lore repository id stays reserved so a retry adopts it
// instead of creating a second repository. A module that already has commits
// is left in place.
func (im *Importer) concealEmptyImportModule(ctx context.Context, actor string, moduleID int64) {
	if moduleID == 0 || im.DB == nil {
		return
	}
	var n int
	if err := im.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM module_commits WHERE module_id=?`, moduleID).Scan(&n); err != nil || n > 0 {
		return
	}
	if account, _, err := user.Get(ctx, im.DB, actor); err == nil {
		_ = project.RevokeModulePermission(ctx, im.DB, actor, account.ID, moduleID)
	}
	_ = project.ArchiveModule(ctx, im.DB, actor, moduleID)
}

func (im *Importer) ensureLoreRepoAndReconcileCheckpoint(
	ctx context.Context,
	itemID int64,
	actor string,
	projectID int64,
	spec RepoSpec,
	loreWorkPath string,
	cp *itemCheckpoint,
) error {
	slug := strings.ToLower(strings.ReplaceAll(spec.ModuleName, "/", "-"))
	dotLoreExists := false
	if st, err := os.Stat(filepath.Join(loreWorkPath, ".lore", "id")); err == nil && !st.IsDir() {
		dotLoreExists = true
		if cp.LoreRepositoryID == "" {
			if stInfo, sErr := im.Lore.Status(ctx, loreWorkPath); sErr == nil && repoID32Re.MatchString(stInfo.RepositoryID) {
				cp.LoreRepositoryID = stInfo.RepositoryID
			} else if rawID, rErr := os.ReadFile(filepath.Join(loreWorkPath, ".lore", "id")); rErr == nil {
				if len(rawID) == 16 {
					cp.LoreRepositoryID = hex.EncodeToString(rawID)
				} else if m := repoID32Re.FindString(strings.ToLower(string(rawID))); m != "" {
					cp.LoreRepositoryID = m
				}
			}
			if cp.LoreRepositoryID == "" {
				// Incomplete `.lore` directory from an aborted create: recreate cleanly!
				dotLoreExists = false
			}
		}
		if dotLoreExists && cp.LoreRepositoryURL == "" {
			if im.RemoteBaseURL != "" {
				cp.LoreRepositoryURL = strings.TrimRight(im.RemoteBaseURL, "/") + "/" + fmt.Sprintf("p%d-%s", projectID, slug)
			} else {
				cp.LoreRepositoryURL = fmt.Sprintf("lore://local/p%d-%s", projectID, slug)
			}
		}
	}

	if !dotLoreExists {
		cp.CommitMap = map[string]string{}
		cp.HelperBranches = nil
		cp.SyntheticCount = 0
		cp.PushedBranches = map[string]bool{}
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
				if res.ExitCode != 0 {
					ids = nil
					info, infoErr := im.Lore.Exec.Run(ctx, loreexec.Request{
						Argv: []string{"--non-interactive", "--json", "repository", "info", remoteURL},
						Dir:  seedDir,
						Env:  im.Lore.Env,
					})
					if infoErr == nil && info.ExitCode == 0 {
						ids = repoID32Re.FindAllString(info.Stdout+"\n"+info.Stderr, -1)
					}
				}
				if len(ids) == 0 {
					return fmt.Errorf("gitimport: remote lore repository create failed (exit %d)", res.ExitCode)
				}
				cp.LoreRepositoryID = ids[len(ids)-1]
				cp.LoreRepositoryURL = strings.TrimRight(im.RemoteBaseURL, "/") + "/" + cp.LoreRepositoryID
			}
			im.updateItemProgress(ctx, itemID, "cloning", *cp)
			if err := im.registerRemoteModuleForClone(ctx, actor, projectID, spec, cp); err != nil {
				im.updateItemProgress(ctx, itemID, "cloning", *cp)
				return err
			}
			im.updateItemProgress(ctx, itemID, "cloning", *cp)
			_ = os.RemoveAll(loreWorkPath)
			res, err := im.Lore.Exec.Run(ctx, loreexec.Request{
				Argv: []string{"--non-interactive", "clone", cp.LoreRepositoryURL, loreWorkPath},
				Dir:  filepath.Dir(loreWorkPath),
				Env:  im.Lore.Env,
			})
			if err != nil || res.ExitCode != 0 {
				im.concealEmptyImportModule(ctx, actor, cp.ModuleID)
				im.updateItemProgress(ctx, itemID, "cloning", *cp)
				detail := ""
				if res.Stderr != "" || res.Stdout != "" {
					detail = strings.TrimSpace(res.Stderr + " " + res.Stdout)
					if len(detail) > 300 {
						detail = detail[:300]
					}
				}
				return fmt.Errorf("gitimport: clone target lore repository failed: %s", detail)
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
		unlockRegistration := lockByKey(&projectRegistrationLocks, strconv.FormatInt(projectID, 10))
		var mod *project.Module
		var err error
		for attempt := 0; attempt < 12; attempt++ {
			mod, err = project.CreateModule(ctx, im.DB, actor, project.Module{
				ProjectID:     projectID,
				Name:          spec.ModuleName,
				RepositoryID:  cp.LoreRepositoryID,
				RepositoryURL: cp.LoreRepositoryURL,
				MountPath:     spec.MountPath,
			})
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "database is locked") {
				break
			}
			select {
			case <-ctx.Done():
				err = ctx.Err()
				attempt = 12
			case <-time.After(time.Duration(attempt+1) * 100 * time.Millisecond):
			}
		}
		unlockRegistration()
		if err != nil {
			return err
		}
		cp.ModuleID = mod.ID
	}

	// Immediately checkpoint LoreRepositoryID & ModuleID before replay begins so even an instant crash preserves them!
	im.updateItemProgress(ctx, itemID, "replaying", *cp)
	// Why? If Manager crashed AFTER `lore commit` succeeded on disk, or BEFORE SQLite flushed `checkpoint_json`,
	// scanning physical Lore revisions recovers any unrecorded `git.commit -> lore_revision` mapping AND evicts
	// any stale checkpoint entries that do not physically exist in Lore!
	var seedRevs []string
	for _, r := range cp.CommitMap {
		seedRevs = append(seedRevs, r)
	}
	_, dbMap, _ := loadExistingGitCommits(ctx, im.DB, cp.ModuleID)
	for _, r := range dbMap {
		seedRevs = append(seedRevs, r)
	}

	physicalDAG, _, err := readActualLoreDAG(ctx, im.Lore, loreWorkPath, seedRevs)
	if err == nil {
		reconciled := map[string]string{}
		synthCount := 0
		for rev, e := range physicalDAG {
			if e.Metadata["git.synthetic"] == "1" {
				synthCount++
				continue
			}
			if sha := e.Metadata["git.commit"]; sha != "" {
				reconciled[sha] = rev
			}
		}
		cp.CommitMap = reconciled
		cp.SyntheticCount = synthCount
	}
	return nil
}

type dagPlan struct {
	OrderedCommits  []GitCommit
	LaneOf          map[string]string // projected git sha -> Lore branch name
	LaneFirstCommit map[string]string // lane name -> first git sha in lane
	HelperLanes     []string
	PostCreateRefs  map[string]string // Git branch names with 0 exclusive commits -> target git sha
	UsesBootstrap   bool              // true when Git has NO "main" branch so Lore's initial "main" only holds C1
}

func planDAGLanes(g ProjectedGraph) dagPlan {
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
		plan.LaneFirstCommit[laneName] = revChain[len(revChain)-1]
		return true
	}

	usedLanes := map[string]bool{"main": true}

	if mainTip, hasMain := g.Branches["main"]; hasMain && mainTip != "" {
		assignChainFrom(mainTip, "main")
	} else {
		// Git repository has NO `"main"` branch (e.g. `"master"`-only)!
		// Lore requires the very first root commit of a fresh repository to be committed on `"main"`,
		// and refuses deleting `"main"`. So we commit ONLY the primary root commit on `"main"`,
		// record `BootstrapMainRev`, and immediately branch `g.DefaultBranch` (e.g. `"master"`) at that root!
		plan.UsesBootstrap = true
		var primaryTip string
		if g.DefaultBranch != "" && g.Branches[g.DefaultBranch] != "" {
			primaryTip = g.Branches[g.DefaultBranch]
		} else {
			primaryTip = g.Commits[len(g.Commits)-1].SHA
		}
		// Walk down primaryTip's first-parent chain to find its root commit.
		rootSHA := primaryTip
		for {
			c := g.CommitsBySHA[rootSHA]
			if len(c.Parents) == 0 {
				break
			}
			rootSHA = c.Parents[0]
		}
		plan.LaneOf[rootSHA] = "main"
		plan.LaneFirstCommit["main"] = rootSHA

		if g.DefaultBranch != "" && g.Branches[g.DefaultBranch] != "" {
			usedLanes[g.DefaultBranch] = true
			if g.Branches[g.DefaultBranch] == rootSHA {
				plan.PostCreateRefs[g.DefaultBranch] = rootSHA
			} else {
				assignChainFrom(g.Branches[g.DefaultBranch], g.DefaultBranch)
			}
		}
	}

	for _, bName := range sortedKeys(g.Branches) {
		if bName == "main" || usedLanes[bName] {
			continue
		}
		tip := g.Branches[bName]
		if _, already := plan.LaneOf[tip]; already {
			plan.PostCreateRefs[bName] = tip
			continue
		}
		laneName := bName
		if strings.HasPrefix(laneName, "_import_") {
			laneName = fmt.Sprintf("_import_b_%d", len(usedLanes))
			plan.HelperLanes = append(plan.HelperLanes, laneName)
			plan.PostCreateRefs[bName] = tip
		}
		usedLanes[laneName] = true
		assignChainFrom(tip, laneName)
	}

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
	g *ProjectedGraph,
	cp *itemCheckpoint,
	treeCache *TreeCache,
) error {
	if len(g.Commits) == 0 {
		return nil
	}
	plan := planDAGLanes(*g)

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
			// Ensure SQLite also has this commit indexed (in case crash occurred between Lore commit & SQLite tx!).
			allEntries, tErr := treeCache.Entries(ctx, im.GitBinary, mirrorDir, c.TreeSHA)
			if tErr != nil {
				return tErr
			}
			specs, sErr := InspectExpectedSpecialObjects(mirrorDir, spec.SourceSubdir, spec.LFSMode, allEntries, reader, spec.EffectiveMappings())
			if sErr != nil {
				return sErr
			}
			var extraMeta map[string]string
			if len(c.Parents) == 0 && plan.LaneOf[c.SHA] != "main" && firstRootLoreRev != "" {
				extraMeta = map[string]string{"lore.orphan_anchor": firstRootLoreRev}
			}
			if err := im.indexProjectedCommitInDB(ctx, cp.ModuleID, existingRev, spec.SourceSubdir, c, specs, cp.CommitMap, extraMeta); err != nil {
				return err
			}
			if err := im.recordPathProjection(ctx, cp.ModuleID, existingRev, c.SHA, allEntries, spec.EffectiveMappings()); err != nil {
				return err
			}
			continue
		}

		lane := plan.LaneOf[c.SHA]
		if lane == "main" && (existingBranches["main"] == zeroHash64 || existingBranches["main"] == "") {
			if currentBranch != "main" && existingBranches["main"] != "" {
				if err := im.Lore.SwitchBranchRevision(ctx, loreWorkDir, "main", "", true, true); err != nil {
					return err
				}
				cachedBlobs = map[string]string{}
				currentBranch = "main"
			}
		} else if _, created := existingBranches[lane]; !created {
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
		} else {
			// Verify `lane` is actually positioned at `P1(c)`! If an earlier interrupted run left `lane` elsewhere, sync/switch cleanly.
			if currentBranch != lane {
				if err := im.Lore.SwitchBranchRevision(ctx, loreWorkDir, lane, "", true, true); err != nil {
					return err
				}
				cachedBlobs = map[string]string{}
				currentBranch = lane
			}
		}

		var extraMeta map[string]string
		if len(c.Parents) == 0 && lane != "main" && firstRootLoreRev != "" {
			extraMeta = map[string]string{"lore.orphan_anchor": firstRootLoreRev}
		}
		if rawP := g.RawGitParents[c.SHA]; len(rawP) > 0 && spec.SourceSubdir != "" {
			rawJoined := strings.Join(rawP, ",")
			if rawJoined != strings.Join(c.Parents, ",") {
				if extraMeta == nil {
					extraMeta = map[string]string{}
				}
				extraMeta["git.raw_parents"] = rawJoined
			}
		}

		allEntries, tErr := treeCache.Entries(ctx, im.GitBinary, mirrorDir, c.TreeSHA)
		if tErr != nil {
			return tErr
		}

		if len(c.Parents) >= 2 {
			for mIdx := 1; mIdx < len(c.Parents); mIdx++ {
				pSHA := c.Parents[mIdx]
				pRev := cp.CommitMap[pSHA]
				if pRev == "" {
					return fmt.Errorf("gitimport: missing merge parent %s for %s", pSHA, c.SHA)
				}
				isFinalStep := mIdx == len(c.Parents)-1

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
					if hasConflicts {
						if _, err := materializeScopedEntries(mirrorDir, loreWorkDir, spec.SourceSubdir, spec.EffectiveMappings(), spec.LFSMode, allEntries, reader, nil); err != nil {
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
					if spec.SourceSubdir != "" {
						synthMeta["git.subdir"] = spec.SourceSubdir
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
							SourceSubdir:    spec.SourceSubdir,
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
					mat, err := materializeScopedEntries(mirrorDir, loreWorkDir, spec.SourceSubdir, spec.EffectiveMappings(), spec.LFSMode, allEntries, reader, cachedBlobs)
					if err != nil {
						return err
					}
					if hasConflicts {
						if err := im.Lore.MergeResolve(ctx, loreWorkDir, true); err != nil {
							return err
						}
					}
					loreRev, err := im.commitAndIndexGitCommit(ctx, loreWorkDir, cp.ModuleID, spec.SourceSubdir, c, mat, cp.CommitMap, extraMeta)
					if err != nil {
						return err
					}
					if err := im.recordPathProjection(ctx, cp.ModuleID, loreRev, c.SHA, allEntries, spec.EffectiveMappings()); err != nil {
						return err
					}
					existingBranches[lane] = loreRev
					cp.CommitMap[c.SHA] = loreRev
				}
			}
		} else {
			mat, err := materializeScopedEntries(mirrorDir, loreWorkDir, spec.SourceSubdir, spec.EffectiveMappings(), spec.LFSMode, allEntries, reader, cachedBlobs)
			if err != nil {
				return err
			}
			loreRev, err := im.commitAndIndexGitCommit(ctx, loreWorkDir, cp.ModuleID, spec.SourceSubdir, c, mat, cp.CommitMap, extraMeta)
			if err != nil {
				return err
			}
			if err := im.recordPathProjection(ctx, cp.ModuleID, loreRev, c.SHA, allEntries, spec.EffectiveMappings()); err != nil {
				return err
			}
			existingBranches[lane] = loreRev
			cp.CommitMap[c.SHA] = loreRev
			if firstRootLoreRev == "" {
				firstRootLoreRev = loreRev
			}
			if plan.UsesBootstrap && lane == "main" {
				cp.BootstrapMainRev = loreRev
			}
		}

		cp.HelperBranches = sortedBoolKeys(helperSet)
		im.updateItemProgress(ctx, itemID, "replaying", *cp)

		if im.FaultHook != nil {
			if fErr := im.FaultHook(spec.ModuleName, idx); fErr != nil {
				return fErr
			}
		}
	}

	if plan.UsesBootstrap && cp.BootstrapMainRev == "" && firstRootLoreRev != "" {
		cp.BootstrapMainRev = firstRootLoreRev
	}

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

	checkoutBranch := "main"
	if g.DefaultBranch != "" && existingBranches[g.DefaultBranch] != "" {
		checkoutBranch = g.DefaultBranch
	}
	if err := im.Lore.SwitchBranchRevision(ctx, loreWorkDir, checkoutBranch, "", true, true); err != nil {
		return err
	}

	for _, hName := range sortedBoolKeys(helperSet) {
		if hName == checkoutBranch {
			continue
		}
		if _, exists := existingBranches[hName]; exists {
			_ = im.Lore.ArchiveBranch(ctx, loreWorkDir, hName, true)
		}
	}

	im.updateItemProgress(ctx, itemID, "replaying", *cp)
	return nil
}

func (im *Importer) commitAndIndexGitCommit(
	ctx context.Context,
	loreWorkDir string,
	moduleID int64,
	sourceSubdir string,
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
		"git.subdir":            sourceSubdir,
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
	loreRev, err := im.Lore.CommitFull(ctx, loreWorkDir, c.Message, true, true)
	if err != nil {
		return "", err
	}
	if err := im.indexProjectedCommitInDB(ctx, moduleID, loreRev, sourceSubdir, c, mat.Specials, commitMap, extraMeta); err != nil {
		return "", err
	}
	return loreRev, nil
}

func (im *Importer) indexProjectedCommitInDB(
	ctx context.Context,
	moduleID int64,
	loreRev, sourceSubdir string,
	c GitCommit,
	specials []history.SpecialObject,
	commitMap map[string]string,
	extraMeta map[string]string,
) error {
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

	return database.Tx(ctx, im.DB, func(tx *sql.Tx) error {
		if err := history.UpsertCommit(ctx, tx, history.CommitInput{
			ModuleID:            moduleID,
			LoreRevision:        loreRev,
			SourceCommitID:      c.SHA,
			SourceSubdir:        sourceSubdir,
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
		for _, sp := range specials {
			sp.LoreRevision = loreRev
			sp.SourceCommitID = c.SHA
			if err := history.UpsertSpecialObject(ctx, tx, moduleID, sp); err != nil {
				return err
			}
		}
		return nil
	})
}

func (im *Importer) recordPathProjection(ctx context.Context, moduleID int64, loreRev, sourceSHA string, entries []treeEntry, mappings []PathMapping) error {
	mapped, _, err := ApplyPathMappings(entries, mappings)
	if err != nil {
		return err
	}
	return database.Tx(ctx, im.DB, func(tx *sql.Tx) error {
		for _, e := range mapped {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO module_path_projections(
					module_id, source_commit_id, lore_revision, source_path, mapped_path, path_rule_id, projection_type
				) VALUES (?,?,?,?,?,?,?)
				ON CONFLICT(module_id, source_commit_id, source_path) DO UPDATE SET
					lore_revision=excluded.lore_revision,
					mapped_path=excluded.mapped_path,
					path_rule_id=excluded.path_rule_id,
					projection_type=excluded.projection_type
			`, moduleID, sourceSHA, loreRev, e.SourcePath, e.Path, e.RuleID, e.ProjectionType); err != nil {
				return err
			}
		}
		return nil
	})
}

func (im *Importer) persistAliasesAndRefs(
	ctx context.Context,
	moduleID int64,
	loreWorkDir string,
	sourceSubdir string,
	rawGraph MirrorGraph,
	g ProjectedGraph,
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
		// 1. Persist complete per-module source commit alias map in SQLite!
		if _, err := tx.ExecContext(ctx, `DELETE FROM module_commit_aliases WHERE module_id=?`, moduleID); err != nil {
			return err
		}
		for _, rc := range rawGraph.Commits {
			effSHA := g.EffectiveCommitOf[rc.SHA]
			var status, loreRev string
			if effSHA == "" {
				status = history.AliasPreModule
			} else if effSHA == rc.SHA {
				status = history.AliasDirect
				loreRev = commitMap[rc.SHA]
				if loreRev == "" {
					return fmt.Errorf("gitimport: direct commit %s missing lore revision for alias persistence", rc.SHA)
				}
			} else {
				status = history.AliasUnchanged
				loreRev = commitMap[effSHA]
				if loreRev == "" {
					return fmt.Errorf("gitimport: folded commit %s effective target %s missing lore revision", rc.SHA, effSHA)
				}
			}
			if err := history.UpsertCommitAlias(ctx, tx, history.CommitAlias{
				ModuleID:                moduleID,
				SourceCommitID:          rc.SHA,
				AliasStatus:             status,
				EffectiveSourceCommitID: effSHA,
				LoreRevision:            loreRev,
				SourceSubdir:            sourceSubdir,
			}); err != nil {
				return err
			}
		}

		// 2. Prune stale branch/tag refs and write authoritative projected refs with original commit provenance.
		if _, err := tx.ExecContext(ctx, `DELETE FROM module_refs WHERE module_id=?`, moduleID); err != nil {
			return err
		}
		for _, bName := range sortedKeys(g.Branches) {
			sha := g.Branches[bName]
			rev := commitMap[sha]
			if rev == "" {
				return fmt.Errorf("gitimport: branch %s commit %s has no lore revision", bName, sha)
			}
			origSHA := g.OriginalBranches[bName]
			if origSHA == "" {
				origSHA = sha
			}
			if err := history.UpsertRef(ctx, tx, history.RefDetail{
				ModuleID:               moduleID,
				Type:                   "branch",
				Name:                   bName,
				LoreRevision:           rev,
				SourceCommitID:         sha,
				OriginalSourceCommitID: origSHA,
				LoreBranchID:           loreBranchIDs[bName],
				IsDefault:              bName == g.DefaultBranch,
			}); err != nil {
				return err
			}
		}
		for _, t := range g.Tags {
			rev := commitMap[t.TargetSHA]
			if rev == "" {
				return fmt.Errorf("gitimport: tag %s target %s has no lore revision", t.Name, t.TargetSHA)
			}
			origSHA := t.OriginalTargetSHA
			if origSHA == "" {
				origSHA = t.TargetSHA
			}
			if err := history.UpsertRef(ctx, tx, history.RefDetail{
				ModuleID:               moduleID,
				Type:                   "tag",
				Name:                   t.Name,
				LoreRevision:           rev,
				SourceCommitID:         t.TargetSHA,
				OriginalSourceCommitID: origSHA,
				SourceTagObjectID:      t.TagObjectID,
				IsAnnotated:            t.IsAnnotated,
				TaggerName:             t.TaggerName,
				TaggerEmail:            t.TaggerEmail,
				TaggedAt:               t.TaggedAt,
				TagMessage:             t.Message,
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

func (im *Importer) updateItemProgress(ctx context.Context, itemID int64, status string, cp itemCheckpoint) {
	b, _ := json.Marshal(cp)
	_, _ = im.DB.ExecContext(ctx, `
		UPDATE import_job_items
		SET status=?, module_id=NULLIF(?,0), lore_repository_id=?, lore_repository_url=?,
		    bootstrap_main_rev=?, checkpoint_json=?,
		    started_at=COALESCE(started_at, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
		WHERE item_id=?
	`, status, cp.ModuleID, cp.LoreRepositoryID, cp.LoreRepositoryURL, cp.BootstrapMainRev, string(b), itemID)
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
