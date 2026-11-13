// Package project manages the Manager's project and module registry.
//
// A project owns exactly one parent (root) Lore repository; a module is one independent
// Lore repository mounted at a path under the project. Lore stays authoritative for
// revisions and links; this package only stores the index the Manager needs.
package project

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"lore-monorepo/internal/database"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
	ErrInvalid  = errors.New("invalid argument")

	nameRe    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,62}$`)
	repoIDRe  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	segmentRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
)

// Lore URL schemes accepted by the 0.10.1 client (P3-A appendix A §0.4).
var loreSchemes = map[string]bool{"lore": true, "lores": true, "urc": true, "grpc": true, "grpcs": true}

// Project is one row of projects.
type Project struct {
	ID                  int64
	Name                string
	ParentRepositoryID  string
	ParentRepositoryURL string
	CreatedBy           int64
	CreatedAt           string
}

// Module is one row of modules.
type Module struct {
	ID            int64
	ProjectID     int64
	Name          string
	RepositoryID  string
	RepositoryURL string
	MountPath     string
	ArchivedAt    string // empty when active
	CreatedAt     string
}

// Archived reports whether the module has been archived.
func (m Module) Archived() bool { return m.ArchivedAt != "" }

// RepositoryRole says what a Lore repository id is to the Manager.
type RepositoryRole string

const (
	RoleUnknown     RepositoryRole = ""
	RoleProjectRoot RepositoryRole = "project_root"
	RoleModule      RepositoryRole = "module"
)

// ---------------------------------------------------------------- validation

func invalid(format string, a ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// ValidateName checks project and module names.
func ValidateName(name string) error {
	if !nameRe.MatchString(name) {
		return invalid("name %q must match %s", name, nameRe.String())
	}
	return nil
}

// ValidateRepositoryID checks a 32-hex Lore repository id (lowercase, as Lore prints it).
func ValidateRepositoryID(id string) error {
	if !repoIDRe.MatchString(id) {
		return invalid("repository id %q must be 32 lowercase hex characters", id)
	}
	return nil
}

// ValidateRepositoryURL checks scheme://host[:port]/<name> without credentials or query.
func ValidateRepositoryURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return invalid("repository url %q: %v", raw, err)
	}
	if !loreSchemes[u.Scheme] {
		return invalid("repository url %q: scheme must be one of lore, lores, urc, grpc, grpcs", raw)
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return invalid("repository url %q: need host, no credentials, query or fragment", raw)
	}
	p := strings.Trim(u.Path, "/")
	if p == "" || strings.Contains(p, "/") {
		return invalid("repository url %q: path must be exactly one repository name", raw)
	}
	return nil
}

// NormalizeMountPath validates a mount path and returns its canonical form ("A/B").
// Rules: relative, '/' separated, no empty/'.'/'..' segments, no backslash,
// no segment starting with ".lore" (Lore metadata), at most 4 segments.
func NormalizeMountPath(p string) (string, error) {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, `\`) {
		return "", invalid("mount path %q must be relative and use '/'", p)
	}
	segs := strings.Split(strings.TrimSuffix(p, "/"), "/")
	if len(segs) > 4 {
		return "", invalid("mount path %q is deeper than 4 segments", p)
	}
	for _, s := range segs {
		if s == "." || s == ".." || !segmentRe.MatchString(s) || strings.HasPrefix(strings.ToLower(s), ".lore") {
			return "", invalid("mount path %q has invalid segment %q", p, s)
		}
	}
	return strings.Join(segs, "/"), nil
}

// mountsOverlap reports whether one mount path equals or contains the other
// (case-insensitive, because Windows/macOS clients use case-insensitive filesystems).
func mountsOverlap(a, b string) bool {
	a, b = strings.ToLower(a), strings.ToLower(b)
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func mapConstraint(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return fmt.Errorf("%w: %v", ErrConflict, err)
	}
	return err
}

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
}

// repositoryInUse returns an error if repoID is already registered as any project root or module.
func repositoryInUse(ctx context.Context, q queryer, repoID string, exceptModuleID int64) error {
	var n int
	if err := q.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM projects WHERE parent_repository_id=?) +
		(SELECT COUNT(*) FROM modules WHERE repository_id=? AND module_id<>?)`, repoID, repoID, exceptModuleID).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%w: repository %s is already registered", ErrConflict, repoID)
	}
	return nil
}

// ---------------------------------------------------------------- projects

const projectCols = `project_id, name, parent_repository_id, parent_repository_url, created_by, created_at`

func scanProject(row interface{ Scan(...interface{}) error }) (*Project, error) {
	p := &Project{}
	err := row.Scan(&p.ID, &p.Name, &p.ParentRepositoryID, &p.ParentRepositoryURL, &p.CreatedBy, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return p, err
}

// CreateProject registers a project and its parent repository (already created in Lore).
func CreateProject(ctx context.Context, db *sql.DB, actor string, p Project) (*Project, error) {
	if err := ValidateName(p.Name); err != nil {
		return nil, err
	}
	if err := ValidateRepositoryID(p.ParentRepositoryID); err != nil {
		return nil, err
	}
	if err := ValidateRepositoryURL(p.ParentRepositoryURL); err != nil {
		return nil, err
	}
	var out *Project
	err := database.Tx(ctx, db, func(tx *sql.Tx) error {
		if err := repositoryInUse(ctx, tx, p.ParentRepositoryID, 0); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO projects(name, parent_repository_id, parent_repository_url, created_by)
			VALUES (?,?,?,?)`, p.Name, p.ParentRepositoryID, p.ParentRepositoryURL, p.CreatedBy)
		if err != nil {
			return mapConstraint(err)
		}
		id, _ := res.LastInsertId()
		if out, err = scanProject(tx.QueryRowContext(ctx, `SELECT `+projectCols+` FROM projects WHERE project_id=?`, id)); err != nil {
			return err
		}
		return database.Audit(ctx, tx, actor, "project_create", p.Name, "parent_repository_id="+p.ParentRepositoryID)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetProject loads a project by name.
func GetProject(ctx context.Context, db *sql.DB, name string) (*Project, error) {
	return scanProject(db.QueryRowContext(ctx, `SELECT `+projectCols+` FROM projects WHERE name=?`, name))
}

// GetProjectByID loads a project by id.
func GetProjectByID(ctx context.Context, db *sql.DB, id int64) (*Project, error) {
	return scanProject(db.QueryRowContext(ctx, `SELECT `+projectCols+` FROM projects WHERE project_id=?`, id))
}

// ListProjects returns all projects ordered by name.
func ListProjects(ctx context.Context, db *sql.DB) ([]Project, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+projectCols+` FROM projects ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// ProjectUpdate lists the mutable project fields; nil means unchanged.
// The parent repository id is immutable: it is the identity of the snapshot history.
type ProjectUpdate struct {
	Name                *string
	ParentRepositoryURL *string
}

// UpdateProject applies u to project id.
func UpdateProject(ctx context.Context, db *sql.DB, actor string, id int64, u ProjectUpdate) (*Project, error) {
	var out *Project
	err := database.Tx(ctx, db, func(tx *sql.Tx) error {
		cur, err := scanProject(tx.QueryRowContext(ctx, `SELECT `+projectCols+` FROM projects WHERE project_id=?`, id))
		if err != nil {
			return err
		}
		var changes []string
		if u.Name != nil && *u.Name != cur.Name {
			if err := ValidateName(*u.Name); err != nil {
				return err
			}
			changes = append(changes, "name="+cur.Name+"->"+*u.Name)
			cur.Name = *u.Name
		}
		if u.ParentRepositoryURL != nil && *u.ParentRepositoryURL != cur.ParentRepositoryURL {
			if err := ValidateRepositoryURL(*u.ParentRepositoryURL); err != nil {
				return err
			}
			changes = append(changes, "parent_repository_url="+cur.ParentRepositoryURL+"->"+*u.ParentRepositoryURL)
			cur.ParentRepositoryURL = *u.ParentRepositoryURL
		}
		out = cur
		if len(changes) == 0 {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE projects SET name=?, parent_repository_url=? WHERE project_id=?`,
			cur.Name, cur.ParentRepositoryURL, id); err != nil {
			return mapConstraint(err)
		}
		return database.Audit(ctx, tx, actor, "project_update", fmt.Sprint(id), strings.Join(changes, "; "))
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ---------------------------------------------------------------- modules

const moduleCols = `module_id, project_id, name, repository_id, repository_url, mount_path, COALESCE(archived_at,''), created_at`

func scanModule(row interface{ Scan(...interface{}) error }) (*Module, error) {
	m := &Module{}
	err := row.Scan(&m.ID, &m.ProjectID, &m.Name, &m.RepositoryID, &m.RepositoryURL, &m.MountPath, &m.ArchivedAt, &m.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return m, err
}

// checkMount fails if mount overlaps an active module of the project (other than exceptID).
func checkMount(ctx context.Context, q queryer, projectID int64, mount string, exceptID int64) error {
	rows, err := q.QueryContext(ctx, `SELECT module_id, mount_path FROM modules
		WHERE project_id=? AND archived_at IS NULL AND module_id<>?`, projectID, exceptID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var other string
		if err := rows.Scan(&id, &other); err != nil {
			return err
		}
		if mountsOverlap(mount, other) {
			return fmt.Errorf("%w: mount path %q overlaps existing mount %q", ErrConflict, mount, other)
		}
	}
	return rows.Err()
}

// CreateModule registers a module repository (already created in Lore) under a project.
func CreateModule(ctx context.Context, db *sql.DB, actor string, m Module) (*Module, error) {
	if err := ValidateName(m.Name); err != nil {
		return nil, err
	}
	if err := ValidateRepositoryID(m.RepositoryID); err != nil {
		return nil, err
	}
	if err := ValidateRepositoryURL(m.RepositoryURL); err != nil {
		return nil, err
	}
	mount, err := NormalizeMountPath(m.MountPath)
	if err != nil {
		return nil, err
	}
	var out *Module
	err = database.Tx(ctx, db, func(tx *sql.Tx) error {
		if _, err := scanProject(tx.QueryRowContext(ctx, `SELECT `+projectCols+` FROM projects WHERE project_id=?`, m.ProjectID)); err != nil {
			return err
		}
		if err := repositoryInUse(ctx, tx, m.RepositoryID, 0); err != nil {
			return err
		}
		if err := checkMount(ctx, tx, m.ProjectID, mount, 0); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO modules(project_id, name, repository_id, repository_url, mount_path)
			VALUES (?,?,?,?,?)`, m.ProjectID, m.Name, m.RepositoryID, m.RepositoryURL, mount)
		if err != nil {
			return mapConstraint(err)
		}
		id, _ := res.LastInsertId()
		if out, err = scanModule(tx.QueryRowContext(ctx, `SELECT `+moduleCols+` FROM modules WHERE module_id=?`, id)); err != nil {
			return err
		}
		return database.Audit(ctx, tx, actor, "module_create", fmt.Sprintf("project=%d module=%s", m.ProjectID, m.Name),
			"repository_id="+m.RepositoryID+" mount="+mount)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetModule loads a module by project id and name.
func GetModule(ctx context.Context, db *sql.DB, projectID int64, name string) (*Module, error) {
	return scanModule(db.QueryRowContext(ctx, `SELECT `+moduleCols+` FROM modules WHERE project_id=? AND name=?`, projectID, name))
}

// GetModuleByID loads a module by id.
func GetModuleByID(ctx context.Context, db *sql.DB, id int64) (*Module, error) {
	return scanModule(db.QueryRowContext(ctx, `SELECT `+moduleCols+` FROM modules WHERE module_id=?`, id))
}

// ListModules returns the modules of a project ordered by mount path.
func ListModules(ctx context.Context, db *sql.DB, projectID int64, includeArchived bool) ([]Module, error) {
	q := `SELECT ` + moduleCols + ` FROM modules WHERE project_id=?`
	if !includeArchived {
		q += ` AND archived_at IS NULL`
	}
	rows, err := db.QueryContext(ctx, q+` ORDER BY mount_path`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Module
	for rows.Next() {
		m, err := scanModule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

// ModuleUpdate lists the mutable module fields; nil means unchanged.
// The repository id is immutable: re-pointing a module would silently change what
// existing grants and snapshots refer to. Archive it and add a new module instead.
//
// Changing MountPath only changes the Manager index. Moving the link inside the parent
// repository is a Snapshot Manager (P3-B3) operation and is not done here.
type ModuleUpdate struct {
	Name          *string
	RepositoryURL *string
	MountPath     *string
}

// UpdateModule applies u to module id. Archived modules cannot be updated.
func UpdateModule(ctx context.Context, db *sql.DB, actor string, id int64, u ModuleUpdate) (*Module, error) {
	var out *Module
	err := database.Tx(ctx, db, func(tx *sql.Tx) error {
		cur, err := scanModule(tx.QueryRowContext(ctx, `SELECT `+moduleCols+` FROM modules WHERE module_id=?`, id))
		if err != nil {
			return err
		}
		if cur.Archived() {
			return invalid("module %d is archived", id)
		}
		var changes []string
		if u.Name != nil && *u.Name != cur.Name {
			if err := ValidateName(*u.Name); err != nil {
				return err
			}
			changes = append(changes, "name="+cur.Name+"->"+*u.Name)
			cur.Name = *u.Name
		}
		if u.RepositoryURL != nil && *u.RepositoryURL != cur.RepositoryURL {
			if err := ValidateRepositoryURL(*u.RepositoryURL); err != nil {
				return err
			}
			changes = append(changes, "repository_url="+cur.RepositoryURL+"->"+*u.RepositoryURL)
			cur.RepositoryURL = *u.RepositoryURL
		}
		if u.MountPath != nil {
			mount, err := NormalizeMountPath(*u.MountPath)
			if err != nil {
				return err
			}
			if mount != cur.MountPath {
				if err := checkMount(ctx, tx, cur.ProjectID, mount, id); err != nil {
					return err
				}
				changes = append(changes, "mount_path="+cur.MountPath+"->"+mount)
				cur.MountPath = mount
			}
		}
		out = cur
		if len(changes) == 0 {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE modules SET name=?, repository_url=?, mount_path=? WHERE module_id=?`,
			cur.Name, cur.RepositoryURL, cur.MountPath, id); err != nil {
			return mapConstraint(err)
		}
		return database.Audit(ctx, tx, actor, "module_update", fmt.Sprint(id), strings.Join(changes, "; "))
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ArchiveModule marks a module archived. Its repository id stays reserved (not reusable),
// so old grants and snapshots can never be redirected to a different repository.
//
// The mount path is released. modules has UNIQUE(project_id, mount_path) on every row,
// including archived ones, so the stored path is moved to a value NormalizeMountPath
// rejects. The previous path is kept in the audit detail.
func ArchiveModule(ctx context.Context, db *sql.DB, actor string, id int64) error {
	return database.Tx(ctx, db, func(tx *sql.Tx) error {
		var mount string
		err := tx.QueryRowContext(ctx, `SELECT mount_path FROM modules WHERE module_id=? AND archived_at IS NULL`, id).Scan(&mount)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: active module %d", ErrNotFound, id)
		}
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE modules
			SET archived_at=strftime('%Y-%m-%dT%H:%M:%SZ','now'), mount_path=?
			WHERE module_id=? AND archived_at IS NULL`, fmt.Sprintf("~archived/%d", id), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("%w: active module %d", ErrNotFound, id)
		}
		return database.Audit(ctx, tx, actor, "module_archive", fmt.Sprint(id), "mount_released="+mount)
	})
}

// ReactivateModule restores an archived module to mount. It refuses a mount
// that another module already holds. Callers use this to retry an import whose
// empty module was archived after a failed clone.
func ReactivateModule(ctx context.Context, db *sql.DB, actor string, id int64, mount string) error {
	if actor == "" {
		return invalid("actor is required")
	}
	mount, err := NormalizeMountPath(mount)
	if err != nil {
		return err
	}
	return database.Tx(ctx, db, func(tx *sql.Tx) error {
		var projectID int64
		var archived sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT project_id, archived_at FROM modules WHERE module_id=?`, id).Scan(&projectID, &archived)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: module %d", ErrNotFound, id)
		}
		if err != nil {
			return err
		}
		if !archived.Valid || archived.String == "" {
			return nil
		}
		var holder int64
		err = tx.QueryRowContext(ctx, `SELECT module_id FROM modules WHERE project_id=? AND mount_path=? AND module_id<>?`, projectID, mount, id).Scan(&holder)
		if err == nil {
			return fmt.Errorf("%w: mount path %q is in use", ErrConflict, mount)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE modules SET archived_at=NULL, mount_path=? WHERE module_id=? AND archived_at IS NOT NULL`, mount, id)
		if err != nil {
			return mapConstraint(err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("%w: archived module %d", ErrNotFound, id)
		}
		return database.Audit(ctx, tx, actor, "module_reactivate", fmt.Sprint(id), "mount="+mount)
	})
}

// ResolveRepository tells what a Lore repository id is: a project root, an active module,
// or unknown (archived modules resolve to RoleUnknown so they grant nothing).
func ResolveRepository(ctx context.Context, db *sql.DB, repoID string) (RepositoryRole, *Project, *Module, error) {
	if err := ValidateRepositoryID(repoID); err != nil {
		return RoleUnknown, nil, nil, err
	}
	p, err := scanProject(db.QueryRowContext(ctx, `SELECT `+projectCols+` FROM projects WHERE parent_repository_id=?`, repoID))
	if err == nil {
		return RoleProjectRoot, p, nil, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return RoleUnknown, nil, nil, err
	}
	m, err := scanModule(db.QueryRowContext(ctx, `SELECT `+moduleCols+` FROM modules WHERE repository_id=? AND archived_at IS NULL`, repoID))
	if errors.Is(err, ErrNotFound) {
		return RoleUnknown, nil, nil, nil
	}
	if err != nil {
		return RoleUnknown, nil, nil, err
	}
	p, err = GetProjectByID(ctx, db, m.ProjectID)
	if err != nil {
		return RoleUnknown, nil, nil, err
	}
	return RoleModule, p, m, nil
}
