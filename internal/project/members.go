package project

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"lore-monorepo/internal/database"
)

const (
	RoleAdmin  = "project_admin"
	RoleMember = "project_member"
	PermRead   = "read"
	PermWrite  = "write"
	PermNone   = "none"
)

// ErrLastAdmin indicates an operation would leave a project with zero active project_admin users.
var ErrLastAdmin = errors.New("last active project_admin")

// Member is one project membership.
type Member struct {
	ProjectID int64
	UserID    int64
	Role      string
	AddedBy   string
	AddedAt   string
}

// PermissionChange describes one desired (user, module) permission state inside a project.
// Permission must be "read", "write", or "none" (which revokes any existing grant).
type PermissionChange struct {
	UserID     int64
	ModuleID   int64
	Permission string
}

func ensureNotRemovingLastAdminTx(ctx context.Context, tx *sql.Tx, projectID, targetUserID int64) error {
	var curRole string
	err := tx.QueryRowContext(ctx, `SELECT role FROM project_members WHERE project_id=? AND user_id=?`, projectID, targetUserID).Scan(&curRole)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if curRole != RoleAdmin {
		return nil
	}
	var otherAdmins int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM project_members pm
		JOIN users u ON u.user_id = pm.user_id
		WHERE pm.project_id = ?
		  AND pm.role = ?
		  AND u.status = 'active'
		  AND u.kind = 'user'
		  AND pm.user_id <> ?
	`, projectID, RoleAdmin, targetUserID).Scan(&otherAdmins); err != nil {
		return err
	}
	if otherAdmins == 0 {
		return fmt.Errorf("%w: project %d must retain at least one active project_admin", ErrLastAdmin, projectID)
	}
	return nil
}

// AddMember inserts a project role. The parent repository is not granted.
func AddMember(ctx context.Context, db *sql.DB, actor string, projectID, userID int64, role string) error {
	if actor == "" {
		return invalid("actor is required")
	}
	if role != RoleAdmin && role != RoleMember {
		return invalid("role %q", role)
	}
	return database.Tx(ctx, db, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO project_members(project_id, user_id, role, added_by) VALUES (?,?,?,?)`,
			projectID, userID, role, actor)
		if err != nil {
			return mapConstraint(err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrConflict
		}
		return database.Audit(ctx, tx, actor, "project_member_add", itoa(projectID), "user="+itoa(userID)+" role="+role)
	})
}

// UpdateMemberRole changes an existing project member's role between project_member and project_admin.
// Demoting the last active project_admin is refused with ErrLastAdmin.
func UpdateMemberRole(ctx context.Context, db *sql.DB, actor string, projectID, userID int64, role string) error {
	if actor == "" {
		return invalid("actor is required")
	}
	if role != RoleAdmin && role != RoleMember {
		return invalid("role %q", role)
	}
	return database.Tx(ctx, db, func(tx *sql.Tx) error {
		var curRole string
		err := tx.QueryRowContext(ctx, `SELECT role FROM project_members WHERE project_id=? AND user_id=?`, projectID, userID).Scan(&curRole)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if curRole == role {
			return nil
		}
		if curRole == RoleAdmin && role != RoleAdmin {
			if err := ensureNotRemovingLastAdminTx(ctx, tx, projectID, userID); err != nil {
				return err
			}
		}
		res, err := tx.ExecContext(ctx, `UPDATE project_members SET role=? WHERE project_id=? AND user_id=?`, role, projectID, userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		return database.Audit(ctx, tx, actor, "project_member_role", itoa(projectID), "user="+itoa(userID)+" role="+curRole+"->"+role)
	})
}

// RemoveMember drops a membership. Module grants are removed with it so a
// removed member does not keep a new-token path into the project.
// Removing the last active project_admin is refused with ErrLastAdmin.
func RemoveMember(ctx context.Context, db *sql.DB, actor string, projectID, userID int64) error {
	if actor == "" {
		return invalid("actor is required")
	}
	return database.Tx(ctx, db, func(tx *sql.Tx) error {
		if err := ensureNotRemovingLastAdminTx(ctx, tx, projectID, userID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM module_permissions
			WHERE user_id=? AND module_id IN (SELECT module_id FROM modules WHERE project_id=?)`, userID, projectID); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM project_members WHERE project_id=? AND user_id=?`, projectID, userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		return database.Audit(ctx, tx, actor, "project_member_remove", itoa(projectID), "user="+itoa(userID))
	})
}

// SetModulePermission sets read or write. It does not grant the parent repository.
// read is recorded for a future Lore that can enforce it. Lore 0.10.1 still
// treats any issued access token as repository access, including push.
func SetModulePermission(ctx context.Context, db *sql.DB, actor string, userID, moduleID int64, perm string) error {
	if actor == "" {
		return invalid("actor is required")
	}
	if perm != PermRead && perm != PermWrite {
		return invalid("permission %q", perm)
	}
	return database.Tx(ctx, db, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO module_permissions(user_id, module_id, granted_by, permission)
			VALUES (?,?,?,?)
			ON CONFLICT(user_id, module_id) DO UPDATE SET permission=excluded.permission, granted_by=excluded.granted_by,
				granted_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')`, userID, moduleID, actor, perm)
		if err != nil {
			return mapConstraint(err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrConflict
		}
		return database.Audit(ctx, tx, actor, "module_permission_set", itoa(moduleID), "user="+itoa(userID)+" permission="+perm)
	})
}

// RevokeModulePermission removes one module grant.
func RevokeModulePermission(ctx context.Context, db *sql.DB, actor string, userID, moduleID int64) error {
	if actor == "" {
		return invalid("actor is required")
	}
	return database.Tx(ctx, db, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM module_permissions WHERE user_id=? AND module_id=?`, userID, moduleID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		return database.Audit(ctx, tx, actor, "module_permission_revoke", itoa(moduleID), "user="+itoa(userID))
	})
}

// BatchSetModulePermissions atomically sets or revokes up to 5000 module grants within projectID.
// Every user_id must be a non-service member of projectID, and every module_id must be an active
// module of projectID; otherwise the entire transaction rolls back.
func BatchSetModulePermissions(ctx context.Context, db *sql.DB, actor string, projectID int64, changes []PermissionChange) (int, error) {
	if actor == "" {
		return 0, invalid("actor is required")
	}
	if len(changes) == 0 {
		return 0, invalid("changes must not be empty")
	}
	if len(changes) > 5000 {
		return 0, invalid("too many permission changes (%d > 5000)", len(changes))
	}
	for _, c := range changes {
		if c.UserID <= 0 || c.ModuleID <= 0 {
			return 0, invalid("invalid user_id or module_id")
		}
		if c.Permission != PermRead && c.Permission != PermWrite && c.Permission != PermNone {
			return 0, invalid("permission %q", c.Permission)
		}
	}

	applied := 0
	err := database.Tx(ctx, db, func(tx *sql.Tx) error {
		validUsers := map[int64]bool{}
		uRows, err := tx.QueryContext(ctx, `
			SELECT pm.user_id
			FROM project_members pm
			JOIN users u ON u.user_id = pm.user_id
			WHERE pm.project_id = ? AND u.kind = 'user'
		`, projectID)
		if err != nil {
			return err
		}
		for uRows.Next() {
			var id int64
			if err := uRows.Scan(&id); err != nil {
				uRows.Close()
				return err
			}
			validUsers[id] = true
		}
		if err := uRows.Close(); err != nil {
			return err
		}

		validModules := map[int64]bool{}
		mRows, err := tx.QueryContext(ctx, `
			SELECT module_id FROM modules WHERE project_id = ? AND archived_at IS NULL
		`, projectID)
		if err != nil {
			return err
		}
		for mRows.Next() {
			var id int64
			if err := mRows.Scan(&id); err != nil {
				mRows.Close()
				return err
			}
			validModules[id] = true
		}
		if err := mRows.Close(); err != nil {
			return err
		}

		// Deduplicate in caller order so last write for the same (user, module) wins deterministically.
		type pair struct{ u, m int64 }
		dedup := make([]PermissionChange, 0, len(changes))
		idxByPair := map[pair]int{}
		for _, c := range changes {
			if !validUsers[c.UserID] {
				return fmt.Errorf("%w: user %d is not a project member", ErrNotFound, c.UserID)
			}
			if !validModules[c.ModuleID] {
				return fmt.Errorf("%w: active module %d not found in project", ErrNotFound, c.ModuleID)
			}
			k := pair{u: c.UserID, m: c.ModuleID}
			if idx, exists := idxByPair[k]; exists {
				dedup[idx] = c
			} else {
				idxByPair[k] = len(dedup)
				dedup = append(dedup, c)
			}
		}

		sets, revokes := 0, 0
		for _, c := range dedup {
			if c.Permission == PermNone {
				res, err := tx.ExecContext(ctx, `DELETE FROM module_permissions WHERE user_id=? AND module_id=?`, c.UserID, c.ModuleID)
				if err != nil {
					return err
				}
				if n, _ := res.RowsAffected(); n > 0 {
					applied++
					revokes++
				}
				continue
			}
			var prev string
			err := tx.QueryRowContext(ctx, `SELECT permission FROM module_permissions WHERE user_id=? AND module_id=?`, c.UserID, c.ModuleID).Scan(&prev)
			if err == nil && prev == c.Permission {
				continue
			}
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO module_permissions(user_id, module_id, granted_by, permission)
				VALUES (?,?,?,?)
				ON CONFLICT(user_id, module_id) DO UPDATE SET
					permission=excluded.permission,
					granted_by=excluded.granted_by,
					granted_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')
			`, c.UserID, c.ModuleID, actor, c.Permission); err != nil {
				return mapConstraint(err)
			}
			applied++
			sets++
		}
		return database.Audit(ctx, tx, actor, "module_permission_batch", itoa(projectID),
			fmt.Sprintf("requested=%d applied=%d set=%d revoked=%d", len(dedup), applied, sets, revokes))
	})
	return applied, err
}
