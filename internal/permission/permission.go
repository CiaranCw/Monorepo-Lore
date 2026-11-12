// Package permission is the single authorization check for HTTP, gRPC, and the CLI.
//
// Lore 0.10.1 cannot enforce read and write separately inside one repository.
// read is stored so a later Lore change can honor it. A read grant still becomes
// a Lore "access" token, and that token can push. Callers must not describe read
// as a safe read-only Lore permission.
//
// The parent repository is never included in a member's Lore resource list.
// project_admin does not receive it either.
package permission

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"lore-monorepo/internal/database"
	"lore-monorepo/internal/user"
)

const (
	RoleAdmin  = "project_admin"
	RoleMember = "project_member"
	PermRead   = "read"
	PermWrite  = "write"
)

var (
	ErrNotFound = errors.New("not found")
	ErrDenied   = errors.New("not permitted")
)

// Module is one activity module a caller can see.
type Module struct {
	ProjectID     int64
	ProjectName   string
	ModuleID      int64
	Name          string
	RepositoryID  string
	RepositoryURL string
	MountPath       string
	Permission      string
	// DefaultBranch is the module's recorded default branch. Empty means the
	// client should keep whatever branch Lore checked out.
	DefaultBranch string
	// LoreEnforcement is always "access". Lore does not enforce read versus write.
	LoreEnforcement string
}

// Service reads project membership and module permissions.
type Service struct {
	DB *sql.DB
}

func (s Service) userActive(ctx context.Context, userID int64) error {
	var status string
	err := s.DB.QueryRowContext(ctx, `SELECT status FROM users WHERE user_id=?`, userID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if status != "active" {
		return fmt.Errorf("%w: disabled", user.ErrDisabled)
	}
	return nil
}

// CanManageProject reports whether the user is an active project_admin.
// It does not grant the parent repository.
func (s Service) CanManageProject(ctx context.Context, userID, projectID int64) error {
	if err := s.userActive(ctx, userID); err != nil {
		return err
	}
	var role string
	err := s.DB.QueryRowContext(ctx, `SELECT role FROM project_members WHERE project_id=? AND user_id=?`, projectID, userID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && role != RoleAdmin) {
		return ErrDenied
	}
	return err
}

// CanReadModule is true for an active read or write grant on an active module.
func (s Service) CanReadModule(ctx context.Context, userID, moduleID int64) error {
	return s.moduleAllows(ctx, userID, moduleID, false)
}

// CanWriteModule is true only for an active write grant.
func (s Service) CanWriteModule(ctx context.Context, userID, moduleID int64) error {
	return s.moduleAllows(ctx, userID, moduleID, true)
}

func (s Service) moduleAllows(ctx context.Context, userID, moduleID int64, write bool) error {
	if err := s.userActive(ctx, userID); err != nil {
		return err
	}
	var perm, archived sql.NullString
	err := s.DB.QueryRowContext(ctx, `SELECT p.permission, m.archived_at
		FROM module_permissions p
		JOIN modules m ON m.module_id=p.module_id
		WHERE p.user_id=? AND p.module_id=?`, userID, moduleID).Scan(&perm, &archived)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrDenied
	}
	if err != nil {
		return err
	}
	if archived.Valid && archived.String != "" {
		return ErrDenied
	}
	if write && perm.String != PermWrite {
		return ErrDenied
	}
	if perm.String != PermRead && perm.String != PermWrite {
		return ErrDenied
	}
	return nil
}

// ListAccessibleModules returns active modules the user can clone.
// Disabled users and archived modules are omitted. The parent repository is omitted.
func (s Service) ListAccessibleModules(ctx context.Context, userID int64) ([]Module, error) {
	if err := s.userActive(ctx, userID); err != nil {
		if errors.Is(err, user.ErrDisabled) {
			return nil, nil
		}
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT pr.project_id, pr.name, m.module_id, m.name, m.repository_id,
		m.repository_url, m.mount_path, mp.permission,
		COALESCE((SELECT r.ref_name FROM module_refs r
			WHERE r.module_id=m.module_id AND r.ref_type='branch' AND r.is_default=1
			ORDER BY r.ref_name LIMIT 1), '')
		FROM module_permissions mp
		JOIN modules m ON m.module_id=mp.module_id
		JOIN projects pr ON pr.project_id=m.project_id
		WHERE mp.user_id=? AND m.archived_at IS NULL AND mp.permission IN ('read','write')
		ORDER BY pr.name, m.mount_path`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Module
	for rows.Next() {
		var m Module
		if err := rows.Scan(&m.ProjectID, &m.ProjectName, &m.ModuleID, &m.Name, &m.RepositoryID, &m.RepositoryURL, &m.MountPath, &m.Permission, &m.DefaultBranch); err != nil {
			return nil, err
		}
		m.LoreEnforcement = "access"
		out = append(out, m)
	}
	return out, rows.Err()
}

// RepositoryIDs is the Lore resource list for an access token.
// It is the accessible module ids only.
func (s Service) RepositoryIDs(ctx context.Context, userID int64) ([]string, error) {
	mods, err := s.ListAccessibleModules(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(mods))
	for _, m := range mods {
		out = append(out, m.RepositoryID)
	}
	var username, kind string
	if err := s.DB.QueryRowContext(ctx, `SELECT username, kind FROM users WHERE user_id=?`, userID).Scan(&username, &kind); err != nil {
		return nil, err
	}
	if kind != "service" {
		return out, nil
	}
	if err := database.Audit(ctx, s.DB, username, "service_repository_list", username, "parent_and_module_repositories"); err != nil {
		return nil, err
	}
	// Archived modules stay visible to the publisher. A historical snapshot
	// still names those repository ids, and Lore cannot fetch a pin the
	// caller is not allowed to resolve. Human lists above omit them.
	rows, err := s.DB.QueryContext(ctx, `SELECT parent_repository_id FROM projects
		UNION SELECT repository_id FROM modules
		ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ByRepository returns one accessible module. A missing id and an id the
// caller cannot access produce the same not-found error.
func (s Service) ByRepository(ctx context.Context, userID int64, repositoryID string) (Module, error) {
	mods, err := s.ListAccessibleModules(ctx, userID)
	if err != nil {
		return Module{}, err
	}
	for _, m := range mods {
		if m.RepositoryID == repositoryID {
			return m, nil
		}
	}
	return Module{}, ErrNotFound
}
