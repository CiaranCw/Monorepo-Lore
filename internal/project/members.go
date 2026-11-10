package project

import (
	"context"
	"database/sql"

	"lore-monorepo/internal/database"
)

const (
	RoleAdmin  = "project_admin"
	RoleMember = "project_member"
	PermRead   = "read"
	PermWrite  = "write"
)

// Member is one project membership.
type Member struct {
	ProjectID int64
	UserID    int64
	Role      string
	AddedBy   string
	AddedAt   string
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

// RemoveMember drops a membership. Module grants are removed with it so a
// removed member does not keep a new-token path into the project.
func RemoveMember(ctx context.Context, db *sql.DB, actor string, projectID, userID int64) error {
	if actor == "" {
		return invalid("actor is required")
	}
	return database.Tx(ctx, db, func(tx *sql.Tx) error {
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
