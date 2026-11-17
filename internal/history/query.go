package history

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"lore-monorepo/internal/permission"
	"lore-monorepo/internal/project"
)

// Service provides permission-enforced module and monorepo aggregated history queries.
type Service struct {
	DB *sql.DB
}

type cursorToken struct {
	CommittedUnixMS int64  `json:"c"`
	AuthoredUnixMS  int64  `json:"a"`
	ModuleID        int64  `json:"m"`
	LoreRevision    string `json:"r"`
	Order           string `json:"o"`
}

func encodeCursor(c cursorToken) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(raw, wantOrder string) (cursorToken, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return cursorToken{}, ErrInvalidCursor
	}
	var tok cursorToken
	if err := json.Unmarshal(b, &tok); err != nil || tok.LoreRevision == "" || tok.ModuleID <= 0 {
		return cursorToken{}, ErrInvalidCursor
	}
	if tok.Order != "" && tok.Order != wantOrder {
		return cursorToken{}, ErrInvalidCursor
	}
	return tok, nil
}

func normalizeFilter(f Filter) (Filter, error) {
	if f.Order == "" {
		f.Order = OrderDesc
	} else {
		f.Order = strings.ToLower(strings.TrimSpace(f.Order))
		if f.Order != OrderDesc && f.Order != OrderAsc {
			return f, fmt.Errorf("%w: order must be desc or asc", ErrInvalidFilter)
		}
	}
	if f.MergesOnly && f.NoMerges {
		return f, fmt.Errorf("%w: merges_only and no_merges are mutually exclusive", ErrInvalidFilter)
	}
	if f.Limit <= 0 {
		f.Limit = DefaultLimit
	} else if f.Limit > MaxLimit {
		f.Limit = MaxLimit
	}
	if f.SinceUnixMS != nil && f.UntilUnixMS != nil && *f.SinceUnixMS > *f.UntilUnixMS {
		return f, fmt.Errorf("%w: since is after until", ErrInvalidFilter)
	}
	return f, nil
}

// ModuleHistory returns paginated commit history for one module.
// Read permission is verified live on every call (including cursor-paginated calls);
// missing or unauthorized modules both return ErrNotFound so existence never leaks.
func (s Service) ModuleHistory(ctx context.Context, userID, moduleID int64, filter Filter) (Page, error) {
	f, err := normalizeFilter(filter)
	if err != nil {
		return Page{}, err
	}
	perms := permission.Service{DB: s.DB}
	if err := perms.CanReadModule(ctx, userID, moduleID); err != nil {
		return Page{}, ErrNotFound
	}
	mod, err := project.GetModuleByID(ctx, s.DB, moduleID)
	if err != nil || mod.Archived() {
		return Page{}, ErrNotFound
	}
	proj, err := project.GetProjectByID(ctx, s.DB, mod.ProjectID)
	if err != nil {
		return Page{}, ErrNotFound
	}

	var startRev string
	if f.Branch != "" || f.Tag != "" || f.FromRevision != "" {
		startRev, err = s.resolveStartRevision(ctx, moduleID, f.Branch, f.Tag, f.FromRevision)
		if err != nil {
			return Page{}, err
		}
	}

	page, err := s.runHistoryQuery(ctx, []int64{moduleID}, startRev, f)
	if err != nil {
		return Page{}, err
	}
	page.Scope = "module"
	page.ProjectID = proj.ID
	page.ProjectName = proj.Name
	page.ModuleID = mod.ID
	page.ModuleName = mod.Name
	return page, nil
}

// ProjectHistory returns the unified timeline across all active modules in projectID
// that userID is currently authorized to read.
//
// Permissions are re-evaluated live on every request (including paginated cursor
// requests): revoking a module grant immediately removes that module's commits from
// subsequent page fetches even if the caller holds an earlier pagination cursor.
func (s Service) ProjectHistory(ctx context.Context, userID, projectID int64, filter Filter) (Page, error) {
	f, err := normalizeFilter(filter)
	if err != nil {
		return Page{}, err
	}
	if f.Branch != "" || f.Tag != "" || f.FromRevision != "" {
		return Page{}, fmt.Errorf("%w: branch/tag/from_revision require a single module", ErrInvalidFilter)
	}
	proj, err := project.GetProjectByID(ctx, s.DB, projectID)
	if err != nil {
		return Page{}, ErrNotFound
	}
	var memberCount int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM project_members WHERE project_id=? AND user_id=?`, projectID, userID).Scan(&memberCount); err != nil {
		return Page{}, err
	}
	if memberCount == 0 {
		return Page{}, ErrNotFound
	}

	perms := permission.Service{DB: s.DB}
	accessible, err := perms.ListAccessibleModules(ctx, userID)
	if err != nil {
		return Page{}, err
	}

	wantNames := map[string]bool{}
	for _, raw := range f.Modules {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				wantNames[part] = true
			}
		}
	}

	var modIDs []int64
	var summaries []ModuleSummary
	for _, m := range accessible {
		if m.ProjectID != projectID {
			continue
		}
		if len(wantNames) > 0 && !wantNames[m.Name] && !wantNames[m.MountPath] {
			continue
		}
		modIDs = append(modIDs, m.ModuleID)
		summaries = append(summaries, ModuleSummary{
			ModuleID:     m.ModuleID,
			Name:         m.Name,
			MountPath:    m.MountPath,
			RepositoryID: m.RepositoryID,
			Permission:   m.Permission,
		})
	}

	if len(modIDs) == 0 {
		if f.Cursor != "" {
			if _, err := decodeCursor(f.Cursor, f.Order); err != nil {
				return Page{}, err
			}
		}
		return Page{
			Scope:             "project_aggregated",
			ProjectID:         proj.ID,
			ProjectName:       proj.Name,
			AuthorizedModules: []ModuleSummary{},
			Commits:           []Commit{},
			TotalMatching:     0,
		}, nil
	}

	page, err := s.runHistoryQuery(ctx, modIDs, "", f)
	if err != nil {
		return Page{}, err
	}
	page.Scope = "project_aggregated"
	page.ProjectID = proj.ID
	page.ProjectName = proj.Name
	page.AuthorizedModules = summaries
	return page, nil
}

// GetCommit fetches a single commit in moduleID by its 64-hex Lore revision,
// its direct Git commit SHA, or a persisted folded source commit alias in module_commit_aliases.
func (s Service) GetCommit(ctx context.Context, userID, moduleID int64, refID string) (Commit, error) {
	refID = strings.TrimSpace(refID)
	if refID == "" {
		return Commit{}, ErrNotFound
	}
	perms := permission.Service{DB: s.DB}
	if err := perms.CanReadModule(ctx, userID, moduleID); err != nil {
		return Commit{}, ErrNotFound
	}
	rows, err := s.DB.QueryContext(ctx, commitSelectSQL+`
		WHERE mc.module_id = ? AND mc.is_synthetic = 0
		  AND (mc.lore_revision = ? OR mc.source_commit_id = ?)
		LIMIT 1
	`, moduleID, refID, refID)
	if err != nil {
		return Commit{}, err
	}
	list, err := scanCommits(rows)
	rows.Close()
	if err != nil {
		return Commit{}, err
	}
	if len(list) > 0 {
		if err := s.hydrateCommits(ctx, list); err != nil {
			return Commit{}, err
		}
		if list[0].SourceCommitID == refID {
			list[0].AliasStatus = AliasDirect
		}
		return list[0], nil
	}

	// Check persistent per-module alias mapping (survives Manager restarts!).
	var aliasStatus, effLoreRev string
	aErr := s.DB.QueryRowContext(ctx, `
		SELECT alias_status, lore_revision
		FROM module_commit_aliases
		WHERE module_id = ? AND source_commit_id = ?
	`, moduleID, refID).Scan(&aliasStatus, &effLoreRev)
	if errors.Is(aErr, sql.ErrNoRows) || effLoreRev == "" {
		return Commit{}, ErrNotFound
	}
	if aErr != nil {
		return Commit{}, aErr
	}

	aRows, err := s.DB.QueryContext(ctx, commitSelectSQL+`
		WHERE mc.module_id = ? AND mc.is_synthetic = 0 AND mc.lore_revision = ?
		LIMIT 1
	`, moduleID, effLoreRev)
	if err != nil {
		return Commit{}, err
	}
	defer aRows.Close()
	aList, err := scanCommits(aRows)
	if err != nil {
		return Commit{}, err
	}
	if len(aList) == 0 {
		return Commit{}, ErrNotFound
	}
	if err := s.hydrateCommits(ctx, aList); err != nil {
		return Commit{}, err
	}
	out := aList[0]
	out.QueriedSourceCommit = refID
	out.ResolvedViaAlias = aliasStatus == AliasUnchanged
	out.AliasStatus = aliasStatus
	return out, nil
}

// GetCommitAlias returns the persisted per-module CommitAlias record for sourceCommitID
// (including `pre_module_empty` commits that predate a module subdirectory).
func (s Service) GetCommitAlias(ctx context.Context, userID, moduleID int64, sourceCommitID string) (CommitAlias, error) {
	sourceCommitID = strings.TrimSpace(sourceCommitID)
	if sourceCommitID == "" {
		return CommitAlias{}, ErrNotFound
	}
	perms := permission.Service{DB: s.DB}
	if err := perms.CanReadModule(ctx, userID, moduleID); err != nil {
		return CommitAlias{}, ErrNotFound
	}
	mod, err := project.GetModuleByID(ctx, s.DB, moduleID)
	if err != nil || mod.Archived() {
		return CommitAlias{}, ErrNotFound
	}
	var a CommitAlias
	err = s.DB.QueryRowContext(ctx, `
		SELECT module_id, source_commit_id, alias_status, effective_source_commit_id, lore_revision, source_subdir, updated_at
		FROM module_commit_aliases
		WHERE module_id = ? AND source_commit_id = ?
	`, moduleID, sourceCommitID).Scan(&a.ModuleID, &a.SourceCommitID, &a.AliasStatus, &a.EffectiveSourceCommitID, &a.LoreRevision, &a.SourceSubdir, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return CommitAlias{}, ErrNotFound
	}
	return a, err
}

// ListModuleRefs returns branches and/or tags for one accessible module.
func (s Service) ListModuleRefs(ctx context.Context, userID, moduleID int64, refType string) ([]RefDetail, error) {
	perms := permission.Service{DB: s.DB}
	if err := perms.CanReadModule(ctx, userID, moduleID); err != nil {
		return nil, ErrNotFound
	}
	mod, err := project.GetModuleByID(ctx, s.DB, moduleID)
	if err != nil || mod.Archived() {
		return nil, ErrNotFound
	}
	query := `
		SELECT r.module_id, m.name, r.ref_type, r.ref_name, r.lore_revision,
		       COALESCE(r.source_commit_id,''), r.original_source_commit_id, COALESCE(r.source_tag_object_id,''), COALESCE(r.lore_branch_id,''),
		       r.is_default, r.is_annotated, r.tagger_name, r.tagger_email, r.tagged_at, r.tag_message, r.updated_at
		FROM module_refs r
		JOIN modules m ON m.module_id = r.module_id
		WHERE r.module_id = ?`
	args := []any{moduleID}
	if refType != "" {
		if refType != "branch" && refType != "tag" {
			return nil, fmt.Errorf("%w: ref type must be branch or tag", ErrInvalidFilter)
		}
		query += ` AND r.ref_type = ?`
		args = append(args, refType)
	}
	query += ` ORDER BY r.ref_type ASC, r.is_default DESC, r.ref_name ASC`
	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RefDetail{}
	for rows.Next() {
		var d RefDetail
		var isDef, isAnn int
		if err := rows.Scan(
			&d.ModuleID, &d.ModuleName, &d.Type, &d.Name, &d.LoreRevision,
			&d.SourceCommitID, &d.OriginalSourceCommitID, &d.SourceTagObjectID, &d.LoreBranchID,
			&isDef, &isAnn, &d.TaggerName, &d.TaggerEmail, &d.TaggedAt, &d.TagMessage, &d.UpdatedAt,
		); err != nil {
			return nil, err
		}
		d.IsDefault = isDef == 1
		d.IsAnnotated = isAnn == 1
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s Service) resolveStartRevision(ctx context.Context, moduleID int64, branch, tag, rev string) (string, error) {
	n := 0
	for _, x := range []string{branch, tag, rev} {
		if x != "" {
			n++
		}
	}
	if n > 1 {
		return "", fmt.Errorf("%w: specify at most one of branch, tag, or revision", ErrInvalidFilter)
	}
	if branch != "" {
		var target string
		err := s.DB.QueryRowContext(ctx, `SELECT lore_revision FROM module_refs WHERE module_id=? AND ref_type='branch' AND ref_name=?`, moduleID, branch).Scan(&target)
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return target, err
	}
	if tag != "" {
		var target string
		err := s.DB.QueryRowContext(ctx, `SELECT lore_revision FROM module_refs WHERE module_id=? AND ref_type='tag' AND ref_name=?`, moduleID, tag).Scan(&target)
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return target, err
	}
	var target string
	err := s.DB.QueryRowContext(ctx, `SELECT lore_revision FROM module_commits WHERE module_id=? AND is_synthetic=0 AND (lore_revision=? OR source_commit_id=?) LIMIT 1`,
		moduleID, rev, rev).Scan(&target)
	if err == nil {
		return target, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	// Fall back to persisted folded commit alias in module_commit_aliases!
	err = s.DB.QueryRowContext(ctx, `
		SELECT lore_revision FROM module_commit_aliases
		WHERE module_id=? AND source_commit_id=? AND lore_revision <> ''
		LIMIT 1
	`, moduleID, rev).Scan(&target)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return target, err
}

const commitSelectSQL = `
	SELECT pr.project_id, pr.name, m.module_id, m.name, m.mount_path, m.repository_id,
	       mc.canonical_id, mc.lore_revision, mc.lore_revision_number, COALESCE(mc.source_commit_id,''), mc.source_subdir,
	       mc.origin_kind, mc.is_merge, mc.parent_count,
	       mc.author_name, mc.author_email, mc.authored_at, mc.authored_unix_ms,
	       mc.committer_name, mc.committer_email, mc.committed_at, mc.committed_unix_ms, mc.lore_committed_unix_ms,
	       mc.subject, mc.message, COALESCE(mc.git_tree_id,''), COALESCE(mc.lore_branch_id,''), mc.extra_metadata_json
	FROM module_commits mc
	JOIN modules m ON m.module_id = mc.module_id
	JOIN projects pr ON pr.project_id = m.project_id
`

func (s Service) runHistoryQuery(ctx context.Context, modIDs []int64, startRev string, f Filter) (Page, error) {
	var cte string
	var baseArgs []any

	if startRev != "" && len(modIDs) == 1 {
		firstOnly := 0
		if f.FirstParentOnly {
			firstOnly = 1
		}
		cte = `
		WITH RECURSIVE reachable(lore_revision) AS (
			SELECT ?
			UNION
			SELECT p.parent_lore_revision
			FROM module_commit_parents p
			JOIN reachable r ON p.module_id = ? AND p.lore_revision = r.lore_revision
			WHERE p.parent_lore_revision <> '' AND (? = 0 OR p.parent_ord = 0)
		) `
		baseArgs = append(baseArgs, startRev, modIDs[0], firstOnly)
	}

	placeholders := make([]string, len(modIDs))
	for i, id := range modIDs {
		placeholders[i] = "?"
		baseArgs = append(baseArgs, id)
	}

	where := fmt.Sprintf(" WHERE mc.module_id IN (%s) AND mc.is_synthetic = 0 AND m.archived_at IS NULL", strings.Join(placeholders, ","))
	if startRev != "" && len(modIDs) == 1 {
		where += " AND mc.lore_revision IN (SELECT lore_revision FROM reachable)"
	}

	if author := strings.TrimSpace(f.Author); author != "" {
		like := "%" + strings.ToLower(author) + "%"
		where += " AND (LOWER(mc.author_name) LIKE ? OR LOWER(mc.author_email) LIKE ?)"
		baseArgs = append(baseArgs, like, like)
	}
	if q := strings.TrimSpace(f.Search); q != "" {
		like := "%" + strings.ToLower(q) + "%"
		where += " AND (LOWER(mc.message) LIKE ? OR LOWER(COALESCE(mc.source_commit_id,'')) LIKE ? OR LOWER(mc.lore_revision) LIKE ?)"
		baseArgs = append(baseArgs, like, like, like)
	}
	if f.SinceUnixMS != nil {
		where += " AND mc.committed_unix_ms >= ?"
		baseArgs = append(baseArgs, *f.SinceUnixMS)
	}
	if f.UntilUnixMS != nil {
		where += " AND mc.committed_unix_ms <= ?"
		baseArgs = append(baseArgs, *f.UntilUnixMS)
	}
	if f.MergesOnly {
		where += " AND mc.is_merge = 1"
	}
	if f.NoMerges {
		where += " AND mc.is_merge = 0"
	}

	// Count total matching commits (independent of cursor position).
	countSQL := cte + `SELECT COUNT(*) FROM module_commits mc JOIN modules m ON m.module_id = mc.module_id` + where
	var total int
	if err := s.DB.QueryRowContext(ctx, countSQL, baseArgs...).Scan(&total); err != nil {
		return Page{}, err
	}

	pageWhere := where
	pageArgs := append([]any{}, baseArgs...)
	if f.Cursor != "" {
		tok, err := decodeCursor(f.Cursor, f.Order)
		if err != nil {
			return Page{}, err
		}
		if f.Order == OrderDesc {
			pageWhere += ` AND (
				mc.committed_unix_ms < ?
				OR (mc.committed_unix_ms = ? AND mc.authored_unix_ms < ?)
				OR (mc.committed_unix_ms = ? AND mc.authored_unix_ms = ? AND mc.module_id > ?)
				OR (mc.committed_unix_ms = ? AND mc.authored_unix_ms = ? AND mc.module_id = ? AND mc.lore_revision > ?)
			)`
		} else {
			pageWhere += ` AND (
				mc.committed_unix_ms > ?
				OR (mc.committed_unix_ms = ? AND mc.authored_unix_ms > ?)
				OR (mc.committed_unix_ms = ? AND mc.authored_unix_ms = ? AND mc.module_id > ?)
				OR (mc.committed_unix_ms = ? AND mc.authored_unix_ms = ? AND mc.module_id = ? AND mc.lore_revision > ?)
			)`
		}
		pageArgs = append(pageArgs,
			tok.CommittedUnixMS,
			tok.CommittedUnixMS, tok.AuthoredUnixMS,
			tok.CommittedUnixMS, tok.AuthoredUnixMS, tok.ModuleID,
			tok.CommittedUnixMS, tok.AuthoredUnixMS, tok.ModuleID, tok.LoreRevision,
		)
	}

	var orderBy string
	if f.Order == OrderDesc {
		orderBy = " ORDER BY mc.committed_unix_ms DESC, mc.authored_unix_ms DESC, mc.module_id ASC, mc.lore_revision ASC"
	} else {
		orderBy = " ORDER BY mc.committed_unix_ms ASC, mc.authored_unix_ms ASC, mc.module_id ASC, mc.lore_revision ASC"
	}

	pageArgs = append(pageArgs, f.Limit+1)
	query := cte + commitSelectSQL + pageWhere + orderBy + " LIMIT ?"
	rows, err := s.DB.QueryContext(ctx, query, pageArgs...)
	if err != nil {
		return Page{}, err
	}
	defer rows.Close()
	commits, err := scanCommits(rows)
	if err != nil {
		return Page{}, err
	}

	hasMore := false
	nextCursor := ""
	if len(commits) > f.Limit {
		hasMore = true
		commits = commits[:f.Limit]
		last := commits[len(commits)-1]
		nextCursor = encodeCursor(cursorToken{
			CommittedUnixMS: last.CommittedUnixMS,
			AuthoredUnixMS:  last.AuthoredUnixMS,
			ModuleID:        last.ModuleID,
			LoreRevision:    last.LoreRevision,
			Order:           f.Order,
		})
	}

	if err := s.hydrateCommits(ctx, commits); err != nil {
		return Page{}, err
	}
	return Page{
		Commits:       commits,
		TotalMatching: total,
		NextCursor:    nextCursor,
		HasMore:       hasMore,
	}, nil
}

func scanCommits(rows *sql.Rows) ([]Commit, error) {
	out := []Commit{}
	for rows.Next() {
		var c Commit
		var isMerge int
		var extraRaw string
		if err := rows.Scan(
			&c.ProjectID, &c.ProjectName, &c.ModuleID, &c.ModuleName, &c.MountPath, &c.RepositoryID,
			&c.CanonicalID, &c.LoreRevision, &c.LoreRevisionNumber, &c.SourceCommitID, &c.SourceSubdir,
			&c.OriginKind, &isMerge, &c.ParentCount,
			&c.AuthorName, &c.AuthorEmail, &c.AuthoredAt, &c.AuthoredUnixMS,
			&c.CommitterName, &c.CommitterEmail, &c.CommittedAt, &c.CommittedUnixMS, &c.LoreCommittedUnixMS,
			&c.Subject, &c.Message, &c.GitTreeID, &c.LoreBranchID, &extraRaw,
		); err != nil {
			return nil, err
		}
		c.IsMerge = isMerge == 1
		c.Parents = []ParentLink{}
		if extraRaw != "" && extraRaw != "{}" {
			var m map[string]string
			if json.Unmarshal([]byte(extraRaw), &m) == nil && len(m) > 0 {
				c.ExtraMetadata = m
			}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

type modRevKey struct {
	modID int64
	rev   string
}

func (s Service) hydrateCommits(ctx context.Context, commits []Commit) error {
	if len(commits) == 0 {
		return nil
	}
	idxByKey := make(map[modRevKey][]int, len(commits))
	modSet := map[int64]bool{}
	for i := range commits {
		k := modRevKey{modID: commits[i].ModuleID, rev: commits[i].LoreRevision}
		idxByKey[k] = append(idxByKey[k], i)
		modSet[commits[i].ModuleID] = true
	}

	modPlaceholders := make([]string, 0, len(modSet))
	modArgs := make([]any, 0, len(modSet))
	for id := range modSet {
		modPlaceholders = append(modPlaceholders, "?")
		modArgs = append(modArgs, id)
	}
	inClause := strings.Join(modPlaceholders, ",")

	// 1. Parents (ordered by parent_ord ASC).
	pRows, err := s.DB.QueryContext(ctx, fmt.Sprintf(`
		SELECT module_id, lore_revision, parent_ord, parent_lore_revision, COALESCE(parent_source_commit_id,'')
		FROM module_commit_parents
		WHERE module_id IN (%s)
		ORDER BY module_id, lore_revision, parent_ord ASC
	`, inClause), modArgs...)
	if err != nil {
		return err
	}
	for pRows.Next() {
		var mid int64
		var rev string
		var link ParentLink
		if err := pRows.Scan(&mid, &rev, &link.Ord, &link.LoreRevision, &link.SourceCommitID); err != nil {
			pRows.Close()
			return err
		}
		for _, pos := range idxByKey[modRevKey{modID: mid, rev: rev}] {
			commits[pos].Parents = append(commits[pos].Parents, link)
		}
	}
	if err := pRows.Close(); err != nil {
		return err
	}

	// 2. Branch and Tag badges.
	rRows, err := s.DB.QueryContext(ctx, fmt.Sprintf(`
		SELECT module_id, lore_revision, ref_type, ref_name, is_default, is_annotated
		FROM module_refs
		WHERE module_id IN (%s)
		ORDER BY ref_type ASC, is_default DESC, ref_name ASC
	`, inClause), modArgs...)
	if err != nil {
		return err
	}
	for rRows.Next() {
		var mid int64
		var rev string
		var b RefBadge
		var isDef, isAnn int
		if err := rRows.Scan(&mid, &rev, &b.Type, &b.Name, &isDef, &isAnn); err != nil {
			rRows.Close()
			return err
		}
		b.IsDefault = isDef == 1
		b.IsAnnotated = isAnn == 1
		for _, pos := range idxByKey[modRevKey{modID: mid, rev: rev}] {
			commits[pos].Refs = append(commits[pos].Refs, b)
		}
	}
	if err := rRows.Close(); err != nil {
		return err
	}

	// 3. Special objects (LFS / submodule / symlink).
	oRows, err := s.DB.QueryContext(ctx, fmt.Sprintf(`
		SELECT module_id, lore_revision, COALESCE(source_commit_id,''), kind, path, oid, size_bytes, detail_json
		FROM module_special_objects
		WHERE module_id IN (%s)
		ORDER BY path ASC
	`, inClause), modArgs...)
	if err != nil {
		return err
	}
	for oRows.Next() {
		var mid int64
		var obj SpecialObject
		if err := oRows.Scan(&mid, &obj.LoreRevision, &obj.SourceCommitID, &obj.Kind, &obj.Path, &obj.OID, &obj.SizeBytes, &obj.DetailJSON); err != nil {
			oRows.Close()
			return err
		}
		for _, pos := range idxByKey[modRevKey{modID: mid, rev: obj.LoreRevision}] {
			commits[pos].SpecialObjects = append(commits[pos].SpecialObjects, obj)
		}
	}
	return oRows.Close()
}
