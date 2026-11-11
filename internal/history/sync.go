package history

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"lore-monorepo/internal/database"
	"lore-monorepo/internal/loreadapter"
)

const (
	zeroHash64       = "0000000000000000000000000000000000000000000000000000000000000000"
	historyChunkSize = 200
)

var moduleSyncLocks sync.Map // map[int64]*sync.Mutex

func lockModuleSync(moduleID int64) func() {
	actual, _ := moduleSyncLocks.LoadOrStore(moduleID, &sync.Mutex{})
	mu := actual.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// CommitInput is used by both the Git importer and the Lore DAG crawler to
// persist a commit and its ordered parents idempotently.
type CommitInput struct {
	ModuleID            int64
	LoreRevision        string
	LoreRevisionNumber  int
	SourceCommitID      string
	SourceSubdir        string
	OriginKind          string
	IsSynthetic         bool
	AuthorName          string
	AuthorEmail         string
	AuthoredAt          string
	AuthoredUnixMS      int64
	CommitterName       string
	CommitterEmail      string
	CommittedAt         string
	CommittedUnixMS     int64
	LoreCommittedUnixMS int64
	Message             string
	GitTreeID           string
	LoreBranchID        string
	ExtraMetadata       map[string]string
	Parents             []ParentLink
}

// UpsertCommit writes one commit and its ordered parents inside tx.
func UpsertCommit(ctx context.Context, tx *sql.Tx, in CommitInput) error {
	if in.ModuleID == 0 || in.LoreRevision == "" {
		return fmt.Errorf("history: module_id and lore_revision are required")
	}
	if in.OriginKind == "" {
		if in.SourceCommitID != "" {
			in.OriginKind = OriginGitImport
		} else {
			in.OriginKind = OriginNativeLore
		}
	}
	canonical := in.LoreRevision
	var srcCommit any
	if in.SourceCommitID != "" {
		canonical = in.SourceCommitID
		srcCommit = in.SourceCommitID
	}
	var gitTree any
	if in.GitTreeID != "" {
		gitTree = in.GitTreeID
	}
	var branchID any
	if in.LoreBranchID != "" {
		branchID = in.LoreBranchID
	}
	if in.CommittedAt == "" {
		in.CommittedAt = unixMSToRFC3339(in.CommittedUnixMS)
	}
	if in.AuthoredAt == "" {
		if in.AuthoredUnixMS != 0 {
			in.AuthoredAt = unixMSToRFC3339(in.AuthoredUnixMS)
		} else {
			in.AuthoredUnixMS = in.CommittedUnixMS
			in.AuthoredAt = in.CommittedAt
		}
	}
	subject := firstLine(in.Message)
	extra := "{}"
	if len(in.ExtraMetadata) > 0 {
		if b, err := json.Marshal(in.ExtraMetadata); err == nil {
			extra = string(b)
		}
	}
	synth := 0
	if in.IsSynthetic {
		synth = 1
	}
	parentCount := len(in.Parents)
	isMerge := 0
	if parentCount >= 2 {
		isMerge = 1
	}

	_, err := tx.ExecContext(ctx, `
		INSERT INTO module_commits (
			module_id, lore_revision, lore_revision_number, source_commit_id, source_subdir, canonical_id,
			origin_kind, is_synthetic, is_merge, parent_count,
			author_name, author_email, authored_at, authored_unix_ms,
			committer_name, committer_email, committed_at, committed_unix_ms, lore_committed_unix_ms,
			subject, message, git_tree_id, lore_branch_id, extra_metadata_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(module_id, lore_revision) DO UPDATE SET
			lore_revision_number   = CASE WHEN excluded.lore_revision_number > 0 THEN excluded.lore_revision_number ELSE module_commits.lore_revision_number END,
			source_commit_id       = COALESCE(excluded.source_commit_id, module_commits.source_commit_id),
			source_subdir          = CASE WHEN excluded.source_subdir <> '' THEN excluded.source_subdir ELSE module_commits.source_subdir END,
			canonical_id           = CASE WHEN excluded.source_commit_id IS NOT NULL THEN excluded.source_commit_id ELSE module_commits.canonical_id END,
			origin_kind            = CASE WHEN module_commits.origin_kind = 'git_import' THEN 'git_import' ELSE excluded.origin_kind END,
			is_synthetic           = MAX(module_commits.is_synthetic, excluded.is_synthetic),
			is_merge               = excluded.is_merge,
			parent_count           = excluded.parent_count,
			author_name            = CASE WHEN excluded.author_name <> '' THEN excluded.author_name ELSE module_commits.author_name END,
			author_email           = CASE WHEN excluded.author_email <> '' THEN excluded.author_email ELSE module_commits.author_email END,
			authored_at            = CASE WHEN module_commits.origin_kind = 'git_import' AND excluded.origin_kind <> 'git_import' THEN module_commits.authored_at ELSE excluded.authored_at END,
			authored_unix_ms       = CASE WHEN module_commits.origin_kind = 'git_import' AND excluded.origin_kind <> 'git_import' THEN module_commits.authored_unix_ms ELSE excluded.authored_unix_ms END,
			committer_name         = CASE WHEN excluded.committer_name <> '' THEN excluded.committer_name ELSE module_commits.committer_name END,
			committer_email        = CASE WHEN excluded.committer_email <> '' THEN excluded.committer_email ELSE module_commits.committer_email END,
			committed_at           = CASE WHEN module_commits.origin_kind = 'git_import' AND excluded.origin_kind <> 'git_import' THEN module_commits.committed_at ELSE excluded.committed_at END,
			committed_unix_ms      = CASE WHEN module_commits.origin_kind = 'git_import' AND excluded.origin_kind <> 'git_import' THEN module_commits.committed_unix_ms ELSE excluded.committed_unix_ms END,
			lore_committed_unix_ms = CASE WHEN excluded.lore_committed_unix_ms > 0 THEN excluded.lore_committed_unix_ms ELSE module_commits.lore_committed_unix_ms END,
			subject                = excluded.subject,
			message                = excluded.message,
			git_tree_id            = COALESCE(excluded.git_tree_id, module_commits.git_tree_id),
			lore_branch_id         = COALESCE(excluded.lore_branch_id, module_commits.lore_branch_id),
			extra_metadata_json    = CASE WHEN excluded.extra_metadata_json <> '{}' THEN excluded.extra_metadata_json ELSE module_commits.extra_metadata_json END
	`,
		in.ModuleID, in.LoreRevision, in.LoreRevisionNumber, srcCommit, in.SourceSubdir, canonical,
		in.OriginKind, synth, isMerge, parentCount,
		in.AuthorName, in.AuthorEmail, in.AuthoredAt, in.AuthoredUnixMS,
		in.CommitterName, in.CommitterEmail, in.CommittedAt, in.CommittedUnixMS, in.LoreCommittedUnixMS,
		subject, in.Message, gitTree, branchID, extra,
	)
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM module_commit_parents WHERE module_id=? AND lore_revision=?`, in.ModuleID, in.LoreRevision); err != nil {
		return err
	}
	for i, p := range in.Parents {
		var srcParent any
		if p.SourceCommitID != "" {
			srcParent = p.SourceCommitID
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO module_commit_parents (module_id, lore_revision, parent_ord, parent_lore_revision, parent_source_commit_id)
			VALUES (?, ?, ?, ?, ?)
		`, in.ModuleID, in.LoreRevision, i, p.LoreRevision, srcParent); err != nil {
			return err
		}
	}
	return nil
}

// UpsertRef inserts or updates a branch or tag record for a module.
func UpsertRef(ctx context.Context, tx *sql.Tx, ref RefDetail) error {
	var srcCommit, srcTagObj, branchID any
	if ref.SourceCommitID != "" {
		srcCommit = ref.SourceCommitID
	}
	if ref.SourceTagObjectID != "" {
		srcTagObj = ref.SourceTagObjectID
	}
	if ref.LoreBranchID != "" {
		branchID = ref.LoreBranchID
	}
	isDef, isAnn := 0, 0
	if ref.IsDefault {
		isDef = 1
	}
	if ref.IsAnnotated {
		isAnn = 1
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO module_refs (
			module_id, ref_type, ref_name, lore_revision, source_commit_id, source_tag_object_id,
			lore_branch_id, is_default, is_annotated, tagger_name, tagger_email, tagged_at, tag_message,
			updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
		ON CONFLICT(module_id, ref_type, ref_name) DO UPDATE SET
			lore_revision        = excluded.lore_revision,
			source_commit_id     = COALESCE(excluded.source_commit_id, module_refs.source_commit_id),
			source_tag_object_id = COALESCE(excluded.source_tag_object_id, module_refs.source_tag_object_id),
			lore_branch_id       = COALESCE(excluded.lore_branch_id, module_refs.lore_branch_id),
			is_default           = excluded.is_default,
			is_annotated         = excluded.is_annotated,
			tagger_name          = excluded.tagger_name,
			tagger_email         = excluded.tagger_email,
			tagged_at            = excluded.tagged_at,
			tag_message          = excluded.tag_message,
			updated_at           = strftime('%Y-%m-%dT%H:%M:%SZ','now')
	`,
		ref.ModuleID, ref.Type, ref.Name, ref.LoreRevision, srcCommit, srcTagObj,
		branchID, isDef, isAnn, ref.TaggerName, ref.TaggerEmail, ref.TaggedAt, ref.TagMessage,
	)
	return err
}

// UpsertSpecialObject records a Git LFS object, submodule gitlink, or symlink on a revision.
func UpsertSpecialObject(ctx context.Context, tx *sql.Tx, moduleID int64, obj SpecialObject) error {
	var srcCommit any
	if obj.SourceCommitID != "" {
		srcCommit = obj.SourceCommitID
	}
	detail := obj.DetailJSON
	if strings.TrimSpace(detail) == "" {
		detail = "{}"
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO module_special_objects (module_id, lore_revision, source_commit_id, kind, path, oid, size_bytes, detail_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(module_id, lore_revision, kind, path) DO UPDATE SET
			source_commit_id = COALESCE(excluded.source_commit_id, module_special_objects.source_commit_id),
			oid              = excluded.oid,
			size_bytes       = excluded.size_bytes,
			detail_json      = excluded.detail_json
	`, moduleID, obj.LoreRevision, srcCommit, obj.Kind, obj.Path, obj.OID, obj.SizeBytes, detail)
	return err
}

func isNoRemoteConfiguredErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "No remote configured") || strings.Contains(msg, "errorCode\":111") || strings.Contains(msg, "status\":111")
}

// SyncModuleFromLore walks the entire reachable Lore revision DAG across all branches
// (including both parents of merge commits, without truncation), fails explicitly when
// a trustworthy branch list cannot be obtained, preserves non-`main` default branches,
// and prunes deleted/archived branches without touching tags.
func SyncModuleFromLore(ctx context.Context, db *sql.DB, client *loreadapter.Client, moduleID int64, repoDir string) (SyncStats, error) {
	var stats SyncStats
	if client == nil {
		return stats, fmt.Errorf("history: lore client is nil")
	}

	unlock := lockModuleSync(moduleID)
	defer unlock()

	known, gitToLore, err := loadExistingMaps(ctx, db, moduleID)
	if err != nil {
		return stats, err
	}
	existingBranchNames, existingDefaultBranch, bootstrapMainRev, err := loadExistingBranchState(ctx, db, moduleID)
	if err != nil {
		return stats, err
	}
	danglingParents, err := loadDanglingParentRevisions(ctx, db, moduleID)
	if err != nil {
		return stats, err
	}
	usersByID, err := loadUsernames(ctx, db)
	if err != nil {
		return stats, err
	}

	// 1. Discover local and remote branches explicitly. Never swallow branch discovery failures!
	localBranches, localErr := client.ListBranchesAt(ctx, repoDir, false)
	if localErr != nil {
		return stats, fmt.Errorf("%w: local branch list failed: %v", ErrBranchDiscovery, localErr)
	}
	remoteBranches, remoteErr := client.ListBranchesAt(ctx, repoDir, true)
	if remoteErr == nil {
		stats.BranchSource = "local_and_remote"
	} else if isNoRemoteConfiguredErr(remoteErr) {
		stats.BranchSource = "local_only"
	} else {
		return stats, fmt.Errorf("%w: remote branch list failed (partial state refused): %v", ErrBranchDiscovery, remoteErr)
	}

	branchMap := map[string]loreadapter.Branch{}
	archivedRemote := map[string]bool{}
	if remoteErr == nil {
		for _, b := range remoteBranches {
			if isInternalHelperBranch(b.Name) {
				continue
			}
			if b.Archived {
				archivedRemote[b.Name] = true
				continue
			}
			if b.Latest != "" && b.Latest != zeroHash64 {
				branchMap[b.Name] = b
			}
		}
	}
	for _, b := range localBranches {
		if isInternalHelperBranch(b.Name) || b.Archived || archivedRemote[b.Name] {
			continue
		}
		if b.Latest == "" || b.Latest == zeroHash64 {
			continue
		}
		if _, fromRemote := branchMap[b.Name]; !fromRemote {
			branchMap[b.Name] = b
		} else if b.IsCurrent {
			// Preserve IsCurrent flag while keeping authoritative latest if remote was not ahead.
			branchMap[b.Name] = b
		}
	}

	// If `"main"` was purely Lore's un-deletable bootstrap branch for a non-`"main"` Git import
	// (e.g. `"master"`-only repository) and nobody ever committed new work onto `"main"`, omit it!
	if bootstrapMainRev != "" && len(branchMap) > 1 && !existingBranchNames["main"] {
		if mb, hasMain := branchMap["main"]; hasMain && mb.Latest == bootstrapMainRev {
			delete(branchMap, "main")
		}
	}

	// 2. Resolve true default branch without hardcoding `"main"`.
	defaultBranch := ""
	if existingDefaultBranch != "" {
		if _, active := branchMap[existingDefaultBranch]; active {
			defaultBranch = existingDefaultBranch
		}
	}
	if defaultBranch == "" {
		if metaDef, mErr := client.DefaultBranchName(ctx, repoDir); mErr == nil && metaDef != "" {
			if _, active := branchMap[metaDef]; active {
				defaultBranch = metaDef
			}
		}
	}
	if defaultBranch == "" {
		if st, sErr := client.Status(ctx, repoDir); sErr == nil && st.BranchName != "" {
			if _, active := branchMap[st.BranchName]; active {
				defaultBranch = st.BranchName
			}
		}
	}
	if defaultBranch == "" {
		if _, hasMain := branchMap["main"]; hasMain {
			defaultBranch = "main"
		} else if _, hasMaster := branchMap["master"]; hasMaster {
			defaultBranch = "master"
		} else {
			names := make([]string, 0, len(branchMap))
			for name := range branchMap {
				names = append(names, name)
			}
			sort.Strings(names)
			if len(names) > 0 {
				defaultBranch = names[0]
			}
		}
	}

	// 3. Breadth-first DAG scan across all active branch heads AND any unindexed parent edges.
	var queue []string
	queued := map[string]bool{}
	enqueue := func(rev string) {
		if rev == "" || rev == zeroHash64 || len(rev) != 64 || queued[rev] || known[rev] {
			return
		}
		queued[rev] = true
		queue = append(queue, rev)
	}

	sortedBranchNames := make([]string, 0, len(branchMap))
	for name := range branchMap {
		sortedBranchNames = append(sortedBranchNames, name)
	}
	sort.Strings(sortedBranchNames)
	for _, name := range sortedBranchNames {
		enqueue(branchMap[name].Latest)
	}
	for _, dp := range danglingParents {
		enqueue(dp)
	}

	// Even when a branch tip is ALREADY in `known`, verify its direct Lore parents aren't unindexed side-branches!
	for _, name := range sortedBranchNames {
		tip := branchMap[name].Latest
		if known[tip] {
			missing, mErr := findMissingParentsOfKnownCommit(ctx, db, moduleID, tip)
			if mErr == nil {
				for _, mp := range missing {
					enqueue(mp)
				}
			}
		}
	}

	discovered := map[string]loreadapter.HistoryEntry{}
	var order []string

	for len(queue) > 0 {
		start := queue[0]
		queue = queue[1:]
		if known[start] {
			continue
		}
		if _, seen := discovered[start]; seen {
			continue
		}

		entries, err := client.History(ctx, repoDir, historyChunkSize, start)
		if err != nil {
			return stats, err
		}
		stats.RevisionsScanned += len(entries)
		for idx, e := range entries {
			if e.Revision == "" || e.Revision == zeroHash64 {
				continue
			}
			// Always check BOTH parents BEFORE breaking on a known boundary commit
			// so an already-indexed merge commit never hides an unindexed side branch!
			if len(e.Parent) > 1 && e.Parent[1] != "" && e.Parent[1] != zeroHash64 && !known[e.Parent[1]] {
				enqueue(e.Parent[1])
			}
			if known[e.Revision] {
				if len(e.Parent) > 0 && e.Parent[0] != "" && e.Parent[0] != zeroHash64 && !known[e.Parent[0]] {
					enqueue(e.Parent[0])
				}
				break
			}
			if _, dup := discovered[e.Revision]; !dup {
				discovered[e.Revision] = e
				order = append(order, e.Revision)
				if gc := e.Metadata["git.commit"]; gc != "" && e.Metadata["git.synthetic"] != "1" {
					gitToLore[gc] = e.Revision
				}
			}
			if idx == len(entries)-1 && len(e.Parent) > 0 && e.Parent[0] != "" && e.Parent[0] != zeroHash64 {
				enqueue(e.Parent[0])
			}
		}
	}

	// 4. Persist commits (ancestors first), update active branch refs, and prune deleted/archived branches
	//    while strictly preserving all `ref_type='tag'` rows!
	err = database.Tx(ctx, db, func(tx *sql.Tx) error {
		for i := len(order) - 1; i >= 0; i-- {
			e := discovered[order[i]]
			in := buildCommitInputFromLore(moduleID, e, gitToLore, usersByID)
			if err := UpsertCommit(ctx, tx, in); err != nil {
				return err
			}
			stats.CommitsUpserted++
		}

		// Prune stale branches (deleted or archived in Lore), NEVER touching `ref_type='tag'`.
		if len(sortedBranchNames) == 0 {
			res, dErr := tx.ExecContext(ctx, `DELETE FROM module_refs WHERE module_id=? AND ref_type='branch'`, moduleID)
			if dErr != nil {
				return dErr
			}
			n, _ := res.RowsAffected()
			stats.BranchesPruned = int(n)
		} else {
			placeholders := make([]string, len(sortedBranchNames))
			delArgs := make([]any, 0, len(sortedBranchNames)+1)
			delArgs = append(delArgs, moduleID)
			for i, bName := range sortedBranchNames {
				placeholders[i] = "?"
				delArgs = append(delArgs, bName)
			}
			res, dErr := tx.ExecContext(ctx, fmt.Sprintf(
				`DELETE FROM module_refs WHERE module_id=? AND ref_type='branch' AND ref_name NOT IN (%s)`,
				strings.Join(placeholders, ",")), delArgs...)
			if dErr != nil {
				return dErr
			}
			n, _ := res.RowsAffected()
			stats.BranchesPruned = int(n)
		}

		// Reset `is_default=0` on branches if default branch changed, then upsert active branches.
		if _, err := tx.ExecContext(ctx, `UPDATE module_refs SET is_default=0 WHERE module_id=? AND ref_type='branch' AND ref_name<>?`,
			moduleID, defaultBranch); err != nil {
			return err
		}

		for _, bName := range sortedBranchNames {
			b := branchMap[bName]
			var srcCommit string
			if e, ok := discovered[b.Latest]; ok {
				srcCommit = e.Metadata["git.commit"]
			} else {
				_ = tx.QueryRowContext(ctx, `SELECT COALESCE(source_commit_id,'') FROM module_commits WHERE module_id=? AND lore_revision=?`,
					moduleID, b.Latest).Scan(&srcCommit)
			}
			if err := UpsertRef(ctx, tx, RefDetail{
				ModuleID:       moduleID,
				Type:           "branch",
				Name:           b.Name,
				LoreRevision:   b.Latest,
				SourceCommitID: srcCommit,
				LoreBranchID:   b.ID,
				IsDefault:      b.Name == defaultBranch,
			}); err != nil {
				return err
			}
			stats.BranchesIndexed++
		}
		return nil
	})
	return stats, err
}

func loadExistingBranchState(ctx context.Context, db *sql.DB, moduleID int64) (names map[string]bool, defaultBranch, bootstrapMainRev string, err error) {
	names = map[string]bool{}
	rows, err := db.QueryContext(ctx, `SELECT ref_name, is_default FROM module_refs WHERE module_id=? AND ref_type='branch'`, moduleID)
	if err != nil {
		return nil, "", "", err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var isDef int
		if err := rows.Scan(&name, &isDef); err != nil {
			return nil, "", "", err
		}
		names[name] = true
		if isDef == 1 && defaultBranch == "" {
			defaultBranch = name
		}
	}
	if err := rows.Err(); err != nil {
		return nil, "", "", err
	}
	_ = db.QueryRowContext(ctx, `
		SELECT COALESCE(bootstrap_main_rev,'')
		FROM import_job_items
		WHERE module_id=? AND bootstrap_main_rev <> ''
		ORDER BY item_id DESC LIMIT 1
	`, moduleID).Scan(&bootstrapMainRev)
	return names, defaultBranch, bootstrapMainRev, nil
}

func loadDanglingParentRevisions(ctx context.Context, db *sql.DB, moduleID int64) ([]string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT p.parent_lore_revision
		FROM module_commit_parents p
		LEFT JOIN module_commits c
		  ON c.module_id = p.module_id AND c.lore_revision = p.parent_lore_revision
		WHERE p.module_id = ? AND p.parent_lore_revision <> '' AND c.lore_revision IS NULL
	`, moduleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var rev string
		if err := rows.Scan(&rev); err != nil {
			return nil, err
		}
		out = append(out, rev)
	}
	return out, rows.Err()
}

func findMissingParentsOfKnownCommit(ctx context.Context, db *sql.DB, moduleID int64, rev string) ([]string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT p.parent_lore_revision
		FROM module_commit_parents p
		LEFT JOIN module_commits c
		  ON c.module_id = p.module_id AND c.lore_revision = p.parent_lore_revision
		WHERE p.module_id = ? AND p.lore_revision = ? AND p.parent_lore_revision <> '' AND c.lore_revision IS NULL
	`, moduleID, rev)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var pr string
		if err := rows.Scan(&pr); err != nil {
			return nil, err
		}
		out = append(out, pr)
	}
	return out, rows.Err()
}

func buildCommitInputFromLore(moduleID int64, e loreadapter.HistoryEntry, gitToLore map[string]string, usersByID map[string]string) CommitInput {
	meta := e.Metadata
	if meta == nil {
		meta = map[string]string{}
	}
	in := CommitInput{
		ModuleID:            moduleID,
		LoreRevision:        e.Revision,
		LoreRevisionNumber:  e.RevisionNumber,
		LoreCommittedUnixMS: e.TimestampUnixMS,
		Message:             meta["message"],
		LoreBranchID:        meta["branch"],
		ExtraMetadata:       map[string]string{},
	}

	for k, v := range meta {
		switch k {
		case "message", "timestamp", "branch", "created-by", "committed-by",
			"git.commit", "git.subdir", "git.tree", "git.parents", "git.synthetic",
			"git.author.name", "git.author.email", "git.author.time", "git.author.unix_ms",
			"git.committer.name", "git.committer.email", "git.committer.time", "git.committer.unix_ms":
		default:
			in.ExtraMetadata[k] = v
		}
	}

	if gc := meta["git.commit"]; gc != "" || meta["git.synthetic"] == "1" {
		in.OriginKind = OriginGitImport
		in.SourceCommitID = gc
		in.SourceSubdir = meta["git.subdir"]
		in.GitTreeID = meta["git.tree"]
		in.IsSynthetic = meta["git.synthetic"] == "1"
		in.AuthorName = meta["git.author.name"]
		in.AuthorEmail = meta["git.author.email"]
		in.AuthoredAt = meta["git.author.time"]
		in.AuthoredUnixMS = parseTimestampMS(meta["git.author.unix_ms"], in.AuthoredAt, e.TimestampUnixMS)
		in.CommitterName = meta["git.committer.name"]
		in.CommitterEmail = meta["git.committer.email"]
		in.CommittedAt = meta["git.committer.time"]
		in.CommittedUnixMS = parseTimestampMS(meta["git.committer.unix_ms"], in.CommittedAt, e.TimestampUnixMS)
		if in.AuthorName == "" {
			in.AuthorName, in.AuthorEmail = parseActor(meta["created-by"], usersByID)
		}
		if in.CommitterName == "" {
			in.CommitterName, in.CommitterEmail = parseActor(meta["committed-by"], usersByID)
		}
		if rawParents, hasKey := meta["git.parents"]; hasKey {
			if strings.TrimSpace(rawParents) != "" {
				for idx, gp := range strings.Split(rawParents, ",") {
					gp = strings.TrimSpace(gp)
					if gp == "" {
						continue
					}
					in.Parents = append(in.Parents, ParentLink{
						Ord:            idx,
						SourceCommitID: gp,
						LoreRevision:   gitToLore[gp],
					})
				}
			}
			return in
		}
	} else {
		in.OriginKind = OriginNativeLore
		in.AuthorName, in.AuthorEmail = parseActor(meta["created-by"], usersByID)
		in.CommitterName, in.CommitterEmail = parseActor(meta["committed-by"], usersByID)
		if in.AuthorName == "" {
			in.AuthorName = in.CommitterName
			in.AuthorEmail = in.CommitterEmail
		}
		in.CommittedUnixMS = e.TimestampUnixMS
		in.CommittedAt = unixMSToRFC3339(e.TimestampUnixMS)
		in.AuthoredUnixMS = e.TimestampUnixMS
		in.AuthoredAt = in.CommittedAt
	}

	ord := 0
	for _, p := range e.Parent {
		if p == "" || p == zeroHash64 {
			continue
		}
		in.Parents = append(in.Parents, ParentLink{Ord: ord, LoreRevision: p})
		ord++
	}
	return in
}

func loadExistingMaps(ctx context.Context, db *sql.DB, moduleID int64) (map[string]bool, map[string]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT lore_revision, COALESCE(source_commit_id,''), is_synthetic FROM module_commits WHERE module_id=?`, moduleID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	known := map[string]bool{}
	gitToLore := map[string]string{}
	for rows.Next() {
		var rev, gitID string
		var synth int
		if err := rows.Scan(&rev, &gitID, &synth); err != nil {
			return nil, nil, err
		}
		known[rev] = true
		if gitID != "" && synth == 0 {
			gitToLore[gitID] = rev
		}
	}
	return known, gitToLore, rows.Err()
}

func loadUsernames(ctx context.Context, db *sql.DB) (map[string]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT user_id, username FROM users`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out[strconv.FormatInt(id, 10)] = name
	}
	return out, rows.Err()
}

func parseActor(raw string, usersByID map[string]string) (name, email string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	if mapped, ok := usersByID[raw]; ok {
		return mapped, ""
	}
	if lt := strings.LastIndexByte(raw, '<'); lt >= 0 && strings.HasSuffix(raw, ">") {
		n := strings.TrimSpace(raw[:lt])
		em := strings.TrimSpace(raw[lt+1 : len(raw)-1])
		return n, em
	}
	return raw, ""
}

func parseTimestampMS(rawMS, rawISO string, fallback int64) int64 {
	if rawMS != "" {
		if n, err := strconv.ParseInt(strings.TrimSpace(rawMS), 10, 64); err == nil {
			return n
		}
	}
	if rawISO != "" {
		if t, err := time.Parse(time.RFC3339Nano, rawISO); err == nil {
			return t.UnixMilli()
		}
		if t, err := time.Parse(time.RFC3339, rawISO); err == nil {
			return t.UnixMilli()
		}
	}
	return fallback
}

func unixMSToRFC3339(ms int64) string {
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

func firstLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		return s[:idx]
	}
	return s
}

func isInternalHelperBranch(name string) bool {
	return strings.HasPrefix(name, "_import_")
}
