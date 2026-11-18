package manager

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"lore-monorepo/internal/database"
	"lore-monorepo/internal/project"
	"lore-monorepo/internal/user"
)

var consoleUsernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,62}$`)

type meProjectInfo struct {
	ProjectID int64  `json:"project_id"`
	Name      string `json:"name"`
	Role      string `json:"role"`
}

func (a *App) meProjects(ctx context.Context, userID int64, kind string) []meProjectInfo {
	out := []meProjectInfo{}
	if a.DB == nil || kind == "service" {
		return out
	}
	rows, err := a.DB.QueryContext(ctx, `
		SELECT p.project_id, p.name, pm.role
		FROM project_members pm
		JOIN projects p ON p.project_id = pm.project_id
		WHERE pm.user_id = ?
		ORDER BY p.name
	`, userID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var item meProjectInfo
		if err := rows.Scan(&item.ProjectID, &item.Name, &item.Role); err != nil {
			return out
		}
		out = append(out, item)
	}
	return out
}

type overviewHeadCommit struct {
	CanonicalID  string `json:"canonical_id"`
	LoreRevision string `json:"lore_revision"`
	AuthorName   string `json:"author_name"`
	CommittedAt  string `json:"committed_at"`
	Subject      string `json:"subject"`
}

type overviewModule struct {
	ModuleID      int64               `json:"module_id"`
	Name          string              `json:"name"`
	DisplayName   string              `json:"display_name"`
	Description   string              `json:"description"`
	MountPath     string              `json:"mount_path"`
	RepositoryID  string              `json:"repository_id"`
	RepositoryURL string              `json:"repository_url"`
	DefaultBranch string              `json:"default_branch"`
	ArchivedAt    string              `json:"archived_at,omitempty"`
	CreatedAt     string              `json:"created_at"`
	MyPermission  string              `json:"my_permission"`
	GrantedCount  int                 `json:"granted_count,omitempty"`
	BranchCount   int                 `json:"branch_count"`
	TagCount      int                 `json:"tag_count"`
	CommitCount   int                 `json:"commit_count"`
	HeadCommit    *overviewHeadCommit `json:"head_commit,omitempty"`
}

func (a *App) projectOverview(w http.ResponseWriter, r *http.Request, actor *user.User, p *project.Project) {
	ctx := r.Context()
	isAdmin := a.perms().CanManageProject(ctx, actor.ID, p.ID) == nil
	role := project.RoleMember
	if isAdmin {
		role = project.RoleAdmin
	}

	myPerms := map[int64]string{}
	pRows, err := a.DB.QueryContext(ctx, `
		SELECT m.module_id, mp.permission
		FROM module_permissions mp
		JOIN modules m ON m.module_id = mp.module_id
		WHERE mp.user_id = ? AND m.project_id = ? AND m.archived_at IS NULL
	`, actor.ID, p.ID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	for pRows.Next() {
		var mid int64
		var perm string
		if err := pRows.Scan(&mid, &perm); err != nil {
			pRows.Close()
			writeAPIError(w, err)
			return
		}
		myPerms[mid] = perm
	}
	if err := pRows.Close(); err != nil {
		writeAPIError(w, err)
		return
	}

	allMods, err := project.ListModules(ctx, a.DB, p.ID, isAdmin)
	if err != nil {
		writeAPIError(w, err)
		return
	}

	type refStat struct {
		defaultBranch string
		branches      int
		tags          int
	}
	refsByMod := map[int64]refStat{}
	rRows, err := a.DB.QueryContext(ctx, `
		SELECT r.module_id,
		       COALESCE(MAX(CASE WHEN r.ref_type='branch' AND r.is_default=1 THEN r.ref_name END), ''),
		       COALESCE(SUM(CASE WHEN r.ref_type='branch' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN r.ref_type='tag' THEN 1 ELSE 0 END), 0)
		FROM module_refs r
		JOIN modules m ON m.module_id = r.module_id
		WHERE m.project_id = ?
		GROUP BY r.module_id
	`, p.ID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	for rRows.Next() {
		var mid int64
		var st refStat
		if err := rRows.Scan(&mid, &st.defaultBranch, &st.branches, &st.tags); err != nil {
			rRows.Close()
			writeAPIError(w, err)
			return
		}
		refsByMod[mid] = st
	}
	if err := rRows.Close(); err != nil {
		writeAPIError(w, err)
		return
	}

	commitsByMod := map[int64]int{}
	cRows, err := a.DB.QueryContext(ctx, `
		SELECT mc.module_id, COUNT(*)
		FROM module_commits mc
		JOIN modules m ON m.module_id = mc.module_id
		WHERE m.project_id = ? AND mc.is_synthetic = 0
		GROUP BY mc.module_id
	`, p.ID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	for cRows.Next() {
		var mid int64
		var cnt int
		if err := cRows.Scan(&mid, &cnt); err != nil {
			cRows.Close()
			writeAPIError(w, err)
			return
		}
		commitsByMod[mid] = cnt
	}
	if err := cRows.Close(); err != nil {
		writeAPIError(w, err)
		return
	}

	headByMod := map[int64]overviewHeadCommit{}
	// Prefer the default branch tip commit, falling back to the most recent non-synthetic commit.
	hRows, err := a.DB.QueryContext(ctx, `
		SELECT module_id, canonical_id, lore_revision, author_name, committed_at, subject
		FROM (
			SELECT mc.module_id, mc.canonical_id, mc.lore_revision, mc.author_name, mc.committed_at, mc.subject,
			       ROW_NUMBER() OVER (
			           PARTITION BY mc.module_id
			           ORDER BY CASE WHEN r.module_id IS NOT NULL THEN 0 ELSE 1 END ASC,
			                    mc.committed_unix_ms DESC, mc.authored_unix_ms DESC, mc.lore_revision ASC
			       ) AS rn
			FROM module_commits mc
			JOIN modules m ON m.module_id = mc.module_id
			LEFT JOIN module_refs r
			       ON r.module_id = mc.module_id
			      AND r.ref_type = 'branch'
			      AND r.is_default = 1
			      AND r.lore_revision = mc.lore_revision
			WHERE m.project_id = ? AND mc.is_synthetic = 0
		) ranked
		WHERE rn = 1
	`, p.ID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	for hRows.Next() {
		var mid int64
		var hc overviewHeadCommit
		if err := hRows.Scan(&mid, &hc.CanonicalID, &hc.LoreRevision, &hc.AuthorName, &hc.CommittedAt, &hc.Subject); err != nil {
			hRows.Close()
			writeAPIError(w, err)
			return
		}
		headByMod[mid] = hc
	}
	if err := hRows.Close(); err != nil {
		writeAPIError(w, err)
		return
	}

	grantedByMod := map[int64]int{}
	memberCount := 0
	if isAdmin {
		gRows, err := a.DB.QueryContext(ctx, `
			SELECT mp.module_id, COUNT(*)
			FROM module_permissions mp
			JOIN modules m ON m.module_id = mp.module_id
			JOIN users u ON u.user_id = mp.user_id
			WHERE m.project_id = ? AND u.kind = 'user' AND u.status = 'active'
			GROUP BY mp.module_id
		`, p.ID)
		if err != nil {
			writeAPIError(w, err)
			return
		}
		for gRows.Next() {
			var mid int64
			var cnt int
			if err := gRows.Scan(&mid, &cnt); err != nil {
				gRows.Close()
				writeAPIError(w, err)
				return
			}
			grantedByMod[mid] = cnt
		}
		if err := gRows.Close(); err != nil {
			writeAPIError(w, err)
			return
		}
		if err := a.DB.QueryRowContext(ctx, `
			SELECT COUNT(*)
			FROM project_members pm
			JOIN users u ON u.user_id = pm.user_id
			WHERE pm.project_id = ? AND u.kind = 'user'
		`, p.ID).Scan(&memberCount); err != nil {
			writeAPIError(w, err)
			return
		}
	}

	var latestSnapID int64
	var latestSnapAt string
	_ = a.DB.QueryRowContext(ctx, `
		SELECT snapshot_id, created_at FROM snapshots WHERE project_id = ? ORDER BY snapshot_id DESC LIMIT 1
	`, p.ID).Scan(&latestSnapID, &latestSnapAt)

	outMods := make([]overviewModule, 0, len(allMods))
	activeCount, archivedCount := 0, 0
	for _, m := range allMods {
		myPerm := myPerms[m.ID]
		if !isAdmin && myPerm == "" {
			continue
		}
		if m.Archived() {
			archivedCount++
		} else {
			activeCount++
		}
		rs := refsByMod[m.ID]
		om := overviewModule{
			ModuleID:      m.ID,
			Name:          m.Name,
			DisplayName:   m.DisplayName,
			Description:   m.Description,
			MountPath:     m.MountPath,
			RepositoryID:  m.RepositoryID,
			RepositoryURL: m.RepositoryURL,
			DefaultBranch: rs.defaultBranch,
			ArchivedAt:    m.ArchivedAt,
			CreatedAt:     m.CreatedAt,
			MyPermission:  myPerm,
		}
		if isAdmin {
			om.GrantedCount = grantedByMod[m.ID]
		}
		// Repository content details (commit counts, ref counts, and commit subjects)
		// are exposed only when the caller holds an explicit read/write grant on this module.
		if myPerm != "" {
			om.BranchCount = rs.branches
			om.TagCount = rs.tags
			om.CommitCount = commitsByMod[m.ID]
			if hc, ok := headByMod[m.ID]; ok {
				copyHC := hc
				om.HeadCommit = &copyHC
			}
		}
		outMods = append(outMods, om)
	}

	summary := map[string]any{
		"active_modules":     activeCount,
		"archived_modules":   archivedCount,
		"latest_snapshot_id": latestSnapID,
		"latest_snapshot_at": latestSnapAt,
	}
	if isAdmin {
		summary["member_count"] = memberCount
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"project": map[string]any{
			"id":         p.ID,
			"name":       p.Name,
			"created_at": p.CreatedAt,
		},
		"role":    role,
		"summary": summary,
		"modules": outMods,
	})
}

func (a *App) bulkModuleMetadata(w http.ResponseWriter, r *http.Request, actor *user.User, p *project.Project) {
	if err := a.perms().CanManageProject(r.Context(), actor.ID, p.ID); err != nil {
		writeAPIError(w, err)
		return
	}
	var body struct {
		Items []struct {
			ModuleName  string  `json:"module_name"`
			DisplayName string  `json:"display_name"`
			Description *string `json:"description"`
		} `json:"items"`
	}
	if !decode(w, r, &body) {
		return
	}
	items := make([]project.MetadataItem, 0, len(body.Items))
	for _, it := range body.Items {
		items = append(items, project.MetadataItem{
			ModuleName:  it.ModuleName,
			DisplayName: it.DisplayName,
			Description: it.Description,
		})
	}
	updated, err := project.BulkUpdateModuleMetadata(r.Context(), a.DB, actor.Username, p.ID, items)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "updated",
		"updated": updated,
	})
}

type memberView struct {
	UserID           int64  `json:"user_id"`
	Username         string `json:"username"`
	Role             string `json:"role"`
	Status           string `json:"status"`
	AddedBy          string `json:"added_by"`
	AddedAt          string `json:"added_at"`
	WriteCount       int    `json:"write_count"`
	ReadCount        int    `json:"read_count"`
	CanManageAccount bool   `json:"can_manage_account"`
}

func (a *App) listMembers(w http.ResponseWriter, r *http.Request, actor *user.User, p *project.Project) {
	ctx := r.Context()
	if err := a.perms().CanManageProject(ctx, actor.ID, p.ID); err != nil {
		writeAPIError(w, err)
		return
	}
	rows, err := a.DB.QueryContext(ctx, `
		SELECT u.user_id, u.username, pm.role, u.status, pm.added_by, pm.added_at,
		       COALESCE((
		           SELECT COUNT(*) FROM module_permissions mp
		           JOIN modules m ON m.module_id = mp.module_id
		           WHERE mp.user_id = u.user_id AND m.project_id = pm.project_id AND m.archived_at IS NULL AND mp.permission = 'write'
		       ), 0) AS write_cnt,
		       COALESCE((
		           SELECT COUNT(*) FROM module_permissions mp
		           JOIN modules m ON m.module_id = mp.module_id
		           WHERE mp.user_id = u.user_id AND m.project_id = pm.project_id AND m.archived_at IS NULL AND mp.permission = 'read'
		       ), 0) AS read_cnt,
		       (
		           SELECT COUNT(*) FROM project_members tm
		           WHERE tm.user_id = u.user_id
		             AND NOT EXISTS (
		                 SELECT 1 FROM project_members am
		                 WHERE am.project_id = tm.project_id
		                   AND am.user_id = ?
		                   AND am.role = 'project_admin'
		             )
		       ) AS unmanaged_cnt
		FROM project_members pm
		JOIN users u ON u.user_id = pm.user_id
		WHERE pm.project_id = ? AND u.kind = 'user'
		ORDER BY CASE WHEN pm.role = 'project_admin' THEN 0 ELSE 1 END ASC, u.username ASC
	`, actor.ID, p.ID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	defer rows.Close()
	members := []memberView{}
	for rows.Next() {
		var mv memberView
		var unmanaged int
		if err := rows.Scan(&mv.UserID, &mv.Username, &mv.Role, &mv.Status, &mv.AddedBy, &mv.AddedAt, &mv.WriteCount, &mv.ReadCount, &unmanaged); err != nil {
			writeAPIError(w, err)
			return
		}
		mv.CanManageAccount = unmanaged == 0
		members = append(members, mv)
	}
	if err := rows.Err(); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": members})
}

func (a *App) createProjectUser(w http.ResponseWriter, r *http.Request, actor *user.User, p *project.Project) {
	ctx := r.Context()
	if err := a.perms().CanManageProject(ctx, actor.ID, p.ID); err != nil {
		writeAPIError(w, err)
		return
	}
	var body struct {
		Username  string  `json:"username"`
		Password  string  `json:"password"`
		Role      string  `json:"role"`
		GrantMode string  `json:"grant_mode"`
		ModuleIDs []int64 `json:"module_ids"`
	}
	if !decode(w, r, &body) {
		return
	}
	username := strings.TrimSpace(body.Username)
	password := body.Password
	body.Password = ""
	defer func() { password = "" }()

	if !consoleUsernameRe.MatchString(username) {
		writeError(w, http.StatusBadRequest, "invalid username (lowercase, 2-63 chars, [a-z0-9._-])")
		return
	}
	role := strings.TrimSpace(body.Role)
	if role == "" {
		role = project.RoleMember
	}
	if role != project.RoleAdmin && role != project.RoleMember {
		writeError(w, http.StatusBadRequest, "invalid role")
		return
	}
	grantMode := strings.TrimSpace(body.GrantMode)
	if grantMode == "" {
		grantMode = "none"
	}
	switch grantMode {
	case "all_write", "all_read", "selected_write", "selected_read", "none":
	default:
		writeError(w, http.StatusBadRequest, "invalid grant_mode")
		return
	}

	hash, err := user.HashPassword(password)
	if err != nil {
		writeError(w, http.StatusBadRequest, "password must not be empty")
		return
	}

	var createdUID int64
	var grantedCount int
	err = database.Tx(ctx, a.DB, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO users(username, password_hash, kind) VALUES (?,?,'user')`, username, hash)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return project.ErrConflict
			}
			return err
		}
		createdUID, _ = res.LastInsertId()
		if err := database.Audit(ctx, tx, actor.Username, "user_create", username, "kind=user"); err != nil {
			return err
		}

		if _, err := tx.ExecContext(ctx, `INSERT INTO project_members(project_id, user_id, role, added_by) VALUES (?,?,?,?)`,
			p.ID, createdUID, role, actor.Username); err != nil {
			return err
		}
		if err := database.Audit(ctx, tx, actor.Username, "project_member_add", strconv.FormatInt(p.ID, 10),
			fmt.Sprintf("user=%d role=%s", createdUID, role)); err != nil {
			return err
		}

		if grantMode == "none" {
			return nil
		}

		perm := project.PermWrite
		if grantMode == "all_read" || grantMode == "selected_read" {
			perm = project.PermRead
		}

		var targetMods []int64
		if grantMode == "all_write" || grantMode == "all_read" {
			mRows, err := tx.QueryContext(ctx, `SELECT module_id FROM modules WHERE project_id=? AND archived_at IS NULL ORDER BY module_id`, p.ID)
			if err != nil {
				return err
			}
			for mRows.Next() {
				var mid int64
				if err := mRows.Scan(&mid); err != nil {
					mRows.Close()
					return err
				}
				targetMods = append(targetMods, mid)
			}
			if err := mRows.Close(); err != nil {
				return err
			}
		} else {
			activeSet := map[int64]bool{}
			mRows, err := tx.QueryContext(ctx, `SELECT module_id FROM modules WHERE project_id=? AND archived_at IS NULL`, p.ID)
			if err != nil {
				return err
			}
			for mRows.Next() {
				var mid int64
				if err := mRows.Scan(&mid); err != nil {
					mRows.Close()
					return err
				}
				activeSet[mid] = true
			}
			if err := mRows.Close(); err != nil {
				return err
			}
			seen := map[int64]bool{}
			for _, mid := range body.ModuleIDs {
				if !activeSet[mid] {
					return project.ErrNotFound
				}
				if !seen[mid] {
					seen[mid] = true
					targetMods = append(targetMods, mid)
				}
			}
		}

		for _, mid := range targetMods {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO module_permissions(user_id, module_id, granted_by, permission)
				VALUES (?,?,?,?)
			`, createdUID, mid, actor.Username, perm); err != nil {
				return err
			}
			grantedCount++
		}
		if grantedCount > 0 {
			if err := database.Audit(ctx, tx, actor.Username, "module_permission_batch", strconv.FormatInt(p.ID, 10),
				fmt.Sprintf("user=%d mode=%s granted=%d", createdUID, grantMode, grantedCount)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"user_id":         createdUID,
		"username":        username,
		"role":            role,
		"granted_modules": grantedCount,
	})
}

func (a *App) updateMemberRole(w http.ResponseWriter, r *http.Request, actor *user.User, p *project.Project, rawUserID string) {
	ctx := r.Context()
	if err := a.perms().CanManageProject(ctx, actor.ID, p.ID); err != nil {
		writeAPIError(w, err)
		return
	}
	targetID, err := strconv.ParseInt(rawUserID, 10, 64)
	if err != nil || targetID <= 0 {
		writeError(w, http.StatusBadRequest, "invalid user")
		return
	}
	var body struct {
		Role string `json:"role"`
	}
	if !decode(w, r, &body) {
		return
	}
	if targetID == actor.ID && body.Role != project.RoleAdmin {
		writeError(w, http.StatusConflict, "cannot demote your own admin session")
		return
	}
	if err := project.UpdateMemberRole(ctx, a.DB, actor.Username, p.ID, targetID, body.Role); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id": targetID,
		"role":    body.Role,
	})
}

// loadProjectManagedUser verifies that actor is project_admin of projectID, that targetUsername
// is a human member of projectID, and that targetUsername does not belong to any project actor
// does not administer. Violations of target membership/isolation return project.ErrNotFound so
// cross-project existence is never leaked.
func (a *App) loadProjectManagedUser(ctx context.Context, actor *user.User, targetUsername string, projectID int64) (*user.User, error) {
	if err := a.perms().CanManageProject(ctx, actor.ID, projectID); err != nil {
		return nil, err
	}
	target, _, err := user.Get(ctx, a.DB, targetUsername)
	if err != nil || target.Kind == "service" {
		return nil, project.ErrNotFound
	}
	var memberInProject int
	if err := a.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM project_members WHERE project_id=? AND user_id=?`, projectID, target.ID).Scan(&memberInProject); err != nil {
		return nil, err
	}
	if memberInProject == 0 {
		return nil, project.ErrNotFound
	}
	var unmanagedMemberships int
	if err := a.DB.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM project_members target_membership
		WHERE target_membership.user_id=?
		  AND NOT EXISTS (
			SELECT 1
			FROM project_members actor_membership
			WHERE actor_membership.project_id=target_membership.project_id
			  AND actor_membership.user_id=?
			  AND actor_membership.role='project_admin'
		  )
	`, target.ID, actor.ID).Scan(&unmanagedMemberships); err != nil {
		return nil, err
	}
	if unmanagedMemberships > 0 {
		return nil, project.ErrNotFound
	}
	return target, nil
}

func (a *App) ensureNotDisablingLastAdmin(ctx context.Context, targetUserID int64) error {
	var orphanedProjects int
	if err := a.DB.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM project_members pm
		WHERE pm.user_id = ?
		  AND pm.role = 'project_admin'
		  AND NOT EXISTS (
			SELECT 1
			FROM project_members pm2
			JOIN users u2 ON u2.user_id = pm2.user_id
			WHERE pm2.project_id = pm.project_id
			  AND pm2.role = 'project_admin'
			  AND u2.status = 'active'
			  AND u2.kind = 'user'
			  AND pm2.user_id <> ?
		  )
	`, targetUserID, targetUserID).Scan(&orphanedProjects); err != nil {
		return err
	}
	if orphanedProjects > 0 {
		return project.ErrLastAdmin
	}
	return nil
}

type matrixModuleInfo struct {
	ModuleID    int64  `json:"module_id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	MountPath   string `json:"mount_path"`
}

type matrixMemberInfo struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Status   string `json:"status"`
}

type matrixGrantInfo struct {
	UserID     int64  `json:"user_id"`
	ModuleID   int64  `json:"module_id"`
	Permission string `json:"permission"`
	GrantedBy  string `json:"granted_by"`
	GrantedAt  string `json:"granted_at"`
}

func (a *App) projectPermissions(w http.ResponseWriter, r *http.Request, actor *user.User, p *project.Project) {
	ctx := r.Context()
	if err := a.perms().CanManageProject(ctx, actor.ID, p.ID); err != nil {
		writeAPIError(w, err)
		return
	}
	mods, err := project.ListModules(ctx, a.DB, p.ID, false)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	outMods := make([]matrixModuleInfo, 0, len(mods))
	for _, m := range mods {
		outMods = append(outMods, matrixModuleInfo{
			ModuleID:    m.ID,
			Name:        m.Name,
			DisplayName: m.DisplayName,
			MountPath:   m.MountPath,
		})
	}

	mRows, err := a.DB.QueryContext(ctx, `
		SELECT u.user_id, u.username, pm.role, u.status
		FROM project_members pm
		JOIN users u ON u.user_id = pm.user_id
		WHERE pm.project_id = ? AND u.kind = 'user'
		ORDER BY CASE WHEN pm.role = 'project_admin' THEN 0 ELSE 1 END ASC, u.username ASC
	`, p.ID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	defer mRows.Close()
	outMembers := []matrixMemberInfo{}
	for mRows.Next() {
		var mi matrixMemberInfo
		if err := mRows.Scan(&mi.UserID, &mi.Username, &mi.Role, &mi.Status); err != nil {
			writeAPIError(w, err)
			return
		}
		outMembers = append(outMembers, mi)
	}
	if err := mRows.Err(); err != nil {
		writeAPIError(w, err)
		return
	}

	gRows, err := a.DB.QueryContext(ctx, `
		SELECT mp.user_id, mp.module_id, mp.permission, mp.granted_by, mp.granted_at
		FROM module_permissions mp
		JOIN modules m ON m.module_id = mp.module_id
		JOIN project_members pm ON pm.project_id = m.project_id AND pm.user_id = mp.user_id
		JOIN users u ON u.user_id = mp.user_id
		WHERE m.project_id = ? AND m.archived_at IS NULL AND u.kind = 'user'
		ORDER BY mp.module_id, mp.user_id
	`, p.ID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	defer gRows.Close()
	outGrants := []matrixGrantInfo{}
	for gRows.Next() {
		var gi matrixGrantInfo
		if err := gRows.Scan(&gi.UserID, &gi.ModuleID, &gi.Permission, &gi.GrantedBy, &gi.GrantedAt); err != nil {
			writeAPIError(w, err)
			return
		}
		outGrants = append(outGrants, gi)
	}
	if err := gRows.Err(); err != nil {
		writeAPIError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"modules":   outMods,
		"members":   outMembers,
		"grants":    outGrants,
		"lore_note": "Lore 0.10.1 cannot enforce read separately from write; already-issued access tokens remain valid for up to 5 minutes.",
	})
}

func (a *App) batchProjectPermissions(w http.ResponseWriter, r *http.Request, actor *user.User, p *project.Project) {
	ctx := r.Context()
	if err := a.perms().CanManageProject(ctx, actor.ID, p.ID); err != nil {
		writeAPIError(w, err)
		return
	}
	var body struct {
		Changes []struct {
			UserID     int64  `json:"user_id"`
			ModuleID   int64  `json:"module_id"`
			Permission string `json:"permission"`
		} `json:"changes"`
	}
	if !decode(w, r, &body) {
		return
	}
	changes := make([]project.PermissionChange, 0, len(body.Changes))
	for _, c := range body.Changes {
		changes = append(changes, project.PermissionChange{
			UserID:     c.UserID,
			ModuleID:   c.ModuleID,
			Permission: strings.TrimSpace(c.Permission),
		})
	}
	applied, err := project.BatchSetModulePermissions(ctx, a.DB, actor.Username, p.ID, changes)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "updated",
		"applied":           applied,
		"lore_enforcement":  "access",
		"revocation_window": "up to 5m for active Lore access tokens",
	})
}

type auditEntryView struct {
	AuditID int64  `json:"audit_id"`
	At      string `json:"at"`
	Actor   string `json:"actor"`
	Action  string `json:"action"`
	Target  string `json:"target"`
	Detail  string `json:"detail"`
}

func (a *App) projectAudit(w http.ResponseWriter, r *http.Request, actor *user.User, p *project.Project) {
	ctx := r.Context()
	if err := a.perms().CanManageProject(ctx, actor.ID, p.ID); err != nil {
		writeAPIError(w, err)
		return
	}
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 300 {
			writeError(w, http.StatusBadRequest, "invalid limit (1..300)")
			return
		}
		limit = n
	}

	pidStr := strconv.FormatInt(p.ID, 10)
	modPrefix := "project=" + pidStr + " %"
	rows, err := a.DB.QueryContext(ctx, `
		SELECT audit_id, at, actor, action, COALESCE(target,''), COALESCE(detail,'')
		FROM audit_log
		WHERE (
			(action IN ('project_update','project_member_add','project_member_role','project_member_remove','module_permission_batch','module_metadata_bulk','snapshot_publish_start') AND target = ?)
			OR (action IN ('project_create','batch_clone','batch_status','batch_sync','batch_stage','batch_commit','batch_push') AND target = ?)
			OR (action = 'module_create' AND target LIKE ?)
			OR (action IN ('module_update','module_archive','module_reactivate','module_permission_set','module_permission_revoke')
			    AND target IN (SELECT CAST(module_id AS TEXT) FROM modules WHERE project_id = ?))
			OR (action IN ('user_create','user_status','user_password_change','login_success','login_failure')
			    AND target IN (
			        SELECT u.username
			        FROM users u
			        JOIN project_members pm ON pm.user_id = u.user_id
			        WHERE pm.project_id = ? AND u.kind = 'user'
			          AND NOT EXISTS (
			              SELECT 1 FROM project_members tm
			              WHERE tm.user_id = u.user_id
			                AND NOT EXISTS (
			                    SELECT 1 FROM project_members am
			                    WHERE am.project_id = tm.project_id
			                      AND am.user_id = ?
			                      AND am.role = 'project_admin'
			                )
			          )
			    ))
		)
		ORDER BY audit_id DESC
		LIMIT ?
	`, pidStr, p.Name, modPrefix, p.ID, p.ID, actor.ID, limit)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	defer rows.Close()
	out := []auditEntryView{}
	for rows.Next() {
		var e auditEntryView
		if err := rows.Scan(&e.AuditID, &e.At, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			writeAPIError(w, err)
			return
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out})
}
