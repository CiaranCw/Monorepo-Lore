package history

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"lore-monorepo/internal/database"
	"lore-monorepo/internal/loreadapter"
)

const (
	zeroHash64       = "0000000000000000000000000000000000000000000000000000000000000000"
	historyChunkSize = 200
)

// CommitInput is used by both the Git importer and the Lore DAG crawler to
// persist a commit and its ordered parents idempotently.
type CommitInput struct {
	ModuleID            int64
	LoreRevision        string
	LoreRevisionNumber  int
	SourceCommitID      string
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
			module_id, lore_revision, lore_revision_number, source_commit_id, canonical_id,
			origin_kind, is_synthetic, is_merge, parent_count,
			author_name, author_email, authored_at, authored_unix_ms,
			committer_name, committer_email, committed_at, committed_unix_ms, lore_committed_unix_ms,
			subject, message, git_tree_id, lore_branch_id, extra_metadata_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(module_id, lore_revision) DO UPDATE SET
			lore_revision_number   = excluded.lore_revision_number,
			source_commit_id       = COALESCE(excluded.source_commit_id, module_commits.source_commit_id),
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
		in.ModuleID, in.LoreRevision, in.LoreRevisionNumber, srcCommit, canonical,
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

// SyncModuleFromLore walks the entire reachable Lore revision DAG across all branches
// (including both parents of merge commits, without any 100-revision truncation)
// and indexes every unindexed revision and branch pointer into SQLite.
func SyncModuleFromLore(ctx context.Context, db *sql.DB, client *loreadapter.Client, moduleID int64, repoDir string) (SyncStats, error) {
	var stats SyncStats
	if client == nil {
		return stats, fmt.Errorf("history: lore client is nil")
	}

	known, gitToLore, err := loadExistingMaps(ctx, db, moduleID)
	if err != nil {
		return stats, err
	}
	usersByID, err := loadUsernames(ctx, db)
	if err != nil {
		return stats, err
	}

	// Collect both local and remote branches (ignoring offline failure on --remote).
	branchMap := map[string]loreadapter.Branch{}
	if localBranches, err := client.ListBranchesAt(ctx, repoDir, false); err == nil {
		for _, b := range localBranches {
			if isInternalHelperBranch(b.Name) || b.Archived {
				continue
			}
			branchMap[b.Name] = b
		}
	}
	if remoteBranches, err := client.ListBranchesAt(ctx, repoDir, true); err == nil {
		for _, b := range remoteBranches {
			if isInternalHelperBranch(b.Name) || b.Archived {
				continue
			}
			if b.Latest != "" && b.Latest != zeroHash64 {
				branchMap[b.Name] = b
			} else if _, exists := branchMap[b.Name]; !exists {
				branchMap[b.Name] = b
			}
		}
	}

	defaultBranch := "main"
	if st, err := client.Status(ctx, repoDir); err == nil {
		if st.BranchName != "" && !isInternalHelperBranch(st.BranchName) {
			if _, ok := branchMap[st.BranchName]; !ok && st.Revision != "" && st.Revision != zeroHash64 {
				branchMap[st.BranchName] = loreadapter.Branch{
					ID: st.BranchID, Name: st.BranchName, Latest: st.Revision, IsCurrent: true,
				}
			}
		}
	}

	var queue []string
	queued := map[string]bool{}
	enqueue := func(rev string) {
		if rev == "" || rev == zeroHash64 || len(rev) != 64 || queued[rev] || known[rev] {
			return
		}
		queued[rev] = true
		queue = append(queue, rev)
	}

	for _, b := range branchMap {
		if b.Latest != "" && b.Latest != zeroHash64 {
			enqueue(b.Latest)
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
			if known[e.Revision] {
				// First-parent chain from here is already indexed; still check any merge parent above!
				break
			}
			if _, dup := discovered[e.Revision]; !dup {
				discovered[e.Revision] = e
				order = append(order, e.Revision)
				if gc := e.Metadata["git.commit"]; gc != "" && e.Metadata["git.synthetic"] != "1" {
					gitToLore[gc] = e.Revision
				}
			}
			// Always enqueue second parent (parent[1]) of merges!
			if len(e.Parent) > 1 && e.Parent[1] != "" && e.Parent[1] != zeroHash64 {
				enqueue(e.Parent[1])
			}
			// At the end of the chunk, enqueue parent[0] to continue walking arbitrarily deep histories!
			if idx == len(entries)-1 && len(e.Parent) > 0 && e.Parent[0] != "" && e.Parent[0] != zeroHash64 {
				enqueue(e.Parent[0])
			}
		}
	}

	// Persist in reverse discovery order (ancestors first) inside one transaction.
	err = database.Tx(ctx, db, func(tx *sql.Tx) error {
		for i := len(order) - 1; i >= 0; i-- {
			e := discovered[order[i]]
			in := buildCommitInputFromLore(moduleID, e, gitToLore, usersByID)
			if err := UpsertCommit(ctx, tx, in); err != nil {
				return err
			}
			stats.CommitsUpserted++
		}

		// Sync active branch pointers (removing stale branch refs no longer in Lore, while preserving tags).
		for _, b := range branchMap {
			if b.Latest == "" || b.Latest == zeroHash64 {
				continue
			}
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
			"git.commit", "git.tree", "git.parents", "git.synthetic",
			"git.author.name", "git.author.email", "git.author.time", "git.author.unix_ms",
			"git.committer.name", "git.committer.email", "git.committer.time", "git.committer.unix_ms":
		default:
			in.ExtraMetadata[k] = v
		}
	}

	if gc := meta["git.commit"]; gc != "" || meta["git.synthetic"] == "1" {
		in.OriginKind = OriginGitImport
		in.SourceCommitID = gc
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
