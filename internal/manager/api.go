package manager

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"lore-monorepo/internal/authbridge"
	"lore-monorepo/internal/permission"
	"lore-monorepo/internal/project"
	"lore-monorepo/internal/publish"
	"lore-monorepo/internal/user"
)

func (a *App) dispatchAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1"), "/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	session, err := authbridge.AuthenticateIdentity(r.Context(), a.Tokens, authbridge.UserDirectory{Get: a.userByID}, bearerToken(r))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	if session.User.Kind == "service" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	switch parts[0] {
	case "projects":
		a.projects(w, r, session.User, parts[1:])
	case "modules":
		a.modules(w, r, session.User, parts[1:])
	case "users":
		a.users(w, r, session.User, parts[1:])
	case "me":
		a.meModules(w, r, session.User, parts[1:])
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func (a *App) projects(w http.ResponseWriter, r *http.Request, actor *user.User, rest []string) {
	if len(rest) == 0 {
		switch r.Method {
		case http.MethodPost:
			a.createProject(w, r, actor)
		case http.MethodGet:
			a.listProjects(w, r, actor)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}
	p, err := a.projectRef(r, rest[0])
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if err := a.seesProject(r, actor.ID, p.ID); err != nil {
		writeAPIError(w, err)
		return
	}
	if len(rest) == 1 {
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, publicProject(p))
			return
		}
		if r.Method == http.MethodPatch {
			a.patchProject(w, r, actor, p)
			return
		}
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	switch rest[1] {
	case "overview":
		if len(rest) == 2 && r.Method == http.MethodGet {
			a.projectOverview(w, r, actor, p)
			return
		}
	case "modules":
		if len(rest) == 2 && r.Method == http.MethodPost {
			a.createModule(w, r, actor, p)
			return
		}
		if len(rest) == 2 && r.Method == http.MethodGet {
			a.listModules(w, r, actor, p)
			return
		}
		if len(rest) == 3 && rest[2] == "metadata" && r.Method == http.MethodPost {
			a.bulkModuleMetadata(w, r, actor, p)
			return
		}
	case "members":
		if len(rest) == 2 && r.Method == http.MethodGet {
			a.listMembers(w, r, actor, p)
			return
		}
		if len(rest) == 2 && r.Method == http.MethodPost {
			a.addMember(w, r, actor, p)
			return
		}
		if len(rest) == 3 && r.Method == http.MethodPatch {
			a.updateMemberRole(w, r, actor, p, rest[2])
			return
		}
		if len(rest) == 3 && r.Method == http.MethodDelete {
			a.removeMember(w, r, actor, p, rest[2])
			return
		}
	case "users":
		if len(rest) == 2 && r.Method == http.MethodPost {
			a.createProjectUser(w, r, actor, p)
			return
		}
	case "permissions":
		if len(rest) == 2 && r.Method == http.MethodGet {
			a.projectPermissions(w, r, actor, p)
			return
		}
		if len(rest) == 3 && rest[2] == "batch" && r.Method == http.MethodPost {
			a.batchProjectPermissions(w, r, actor, p)
			return
		}
	case "audit":
		if len(rest) == 2 && r.Method == http.MethodGet {
			a.projectAudit(w, r, actor, p)
			return
		}
	case "publish":
		if r.Method == http.MethodPost {
			a.publishProject(w, r, actor, p)
			return
		}
	case "snapshots":
		if r.Method == http.MethodGet {
			a.projectSnapshots(w, r, actor, p)
			return
		}
	case "status":
		if r.Method == http.MethodGet {
			a.projectStatus(w, r, actor, p)
			return
		}
	case "history":
		if len(rest) == 2 {
			a.projectHistory(w, r, actor, p)
			return
		}
		if len(rest) == 3 && rest[2] == "sync" && r.Method == http.MethodPost {
			a.syncProjectHistory(w, r, actor, p)
			return
		}
	case "imports":
		a.projectImports(w, r, actor, p, rest[2:])
		return
	}
	writeError(w, http.StatusNotFound, "not found")
}

func (a *App) modules(w http.ResponseWriter, r *http.Request, actor *user.User, rest []string) {
	if len(rest) < 1 {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	id, err := strconv.ParseInt(rest[0], 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid module")
		return
	}
	m, err := project.GetModuleByID(r.Context(), a.DB, id)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if a.perms().CanManageProject(r.Context(), actor.ID, m.ProjectID) != nil && a.perms().CanReadModule(r.Context(), actor.ID, m.ID) != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if len(rest) == 1 && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, m)
		return
	}
	if len(rest) == 1 && r.Method == http.MethodPatch {
		a.patchModule(w, r, actor, m)
		return
	}
	if len(rest) == 2 && rest[1] == "archive" && r.Method == http.MethodPost {
		if err := a.perms().CanManageProject(r.Context(), actor.ID, m.ProjectID); err != nil {
			writeAPIError(w, err)
			return
		}
		if err := project.ArchiveModule(r.Context(), a.DB, actor.Username, m.ID); err != nil {
			writeAPIError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "archived"})
		return
	}
	if len(rest) >= 2 && rest[1] == "permissions" {
		a.modulePermissions(w, r, actor, m, rest[2:])
		return
	}
	if len(rest) >= 2 && rest[1] == "history" {
		a.moduleHistoryRoutes(w, r, actor, m, rest[2:])
		return
	}
	if len(rest) >= 2 && rest[1] == "commits" {
		a.moduleCommitDetail(w, r, actor, m, rest[2:])
		return
	}
	if len(rest) >= 2 && rest[1] == "refs" {
		a.moduleRefsRoute(w, r, actor, m, rest[2:])
		return
	}
	if len(rest) >= 2 && rest[1] == "aliases" {
		a.moduleAliasesRoute(w, r, actor, m, rest[2:])
		return
	}
	writeError(w, http.StatusNotFound, "not found")
}

func (a *App) users(w http.ResponseWriter, r *http.Request, actor *user.User, rest []string) {
	if len(rest) != 2 || r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	switch rest[1] {
	case "status":
		var body struct {
			Status    string `json:"status"`
			ProjectID int64  `json:"project_id"`
		}
		if !decode(w, r, &body) {
			return
		}
		target, err := a.loadProjectManagedUser(r.Context(), actor, rest[0], body.ProjectID)
		if err != nil {
			writeAPIError(w, err)
			return
		}
		if body.Status == "disabled" {
			if target.ID == actor.ID {
				writeError(w, http.StatusConflict, "cannot disable your own active session")
				return
			}
			if err := a.ensureNotDisablingLastAdmin(r.Context(), target.ID); err != nil {
				writeAPIError(w, err)
				return
			}
		}
		if err := user.SetStatus(r.Context(), a.DB, actor.Username, target.Username, body.Status); err != nil {
			writeAPIError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": body.Status})

	case "password":
		var body struct {
			Password  string `json:"password"`
			ProjectID int64  `json:"project_id"`
		}
		if !decode(w, r, &body) {
			return
		}
		pw := body.Password
		body.Password = ""
		defer func() { pw = "" }()

		target, err := a.loadProjectManagedUser(r.Context(), actor, rest[0], body.ProjectID)
		if err != nil {
			writeAPIError(w, err)
			return
		}
		if err := user.SetPassword(r.Context(), a.DB, actor.Username, target.Username, pw); err != nil {
			writeAPIError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})

	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func (a *App) meModules(w http.ResponseWriter, r *http.Request, actor *user.User, rest []string) {
	if len(rest) == 0 {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	switch rest[0] {
	case "modules":
		if len(rest) != 1 || r.Method != http.MethodGet {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		mods, err := a.perms().ListAccessibleModules(r.Context(), actor.ID)
		if err != nil {
			writeAPIError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"modules": mods, "note": "read is not a Lore read-only ACL; an access token can push"})
	case "repositories":
		if len(rest) != 2 || r.Method != http.MethodGet {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		m, err := a.perms().ByRepository(r.Context(), actor.ID, rest[1])
		if err != nil {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeJSON(w, http.StatusOK, m)
	case "search":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		mods, err := a.perms().ListAccessibleModules(r.Context(), actor.ID)
		if err != nil {
			writeAPIError(w, err)
			return
		}
		q := r.URL.Query().Get("q")
		projectName := r.URL.Query().Get("project")
		found := []permission.Module{}
		for _, m := range mods {
			if projectName != "" && m.ProjectName != projectName {
				continue
			}
			if q != "" && m.Name != q && m.MountPath != q && m.RepositoryID != q && m.RepositoryURL != q {
				continue
			}
			found = append(found, m)
		}
		writeJSON(w, http.StatusOK, map[string]any{"modules": found})
	case "batch":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		a.batch(w, r, actor)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func (a *App) createProject(w http.ResponseWriter, r *http.Request, actor *user.User) {
	var body struct {
		Name                string `json:"name"`
		ParentRepositoryID  string `json:"parent_repository_id"`
		ParentRepositoryURL string `json:"parent_repository_url"`
	}
	if !decode(w, r, &body) {
		return
	}
	p, err := project.CreateProject(r.Context(), a.DB, actor.Username, project.Project{
		Name: body.Name, ParentRepositoryID: body.ParentRepositoryID, ParentRepositoryURL: body.ParentRepositoryURL, CreatedBy: actor.ID,
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if err := project.AddMember(r.Context(), a.DB, actor.Username, p.ID, actor.ID, project.RoleAdmin); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, publicProject(p))
}

func (a *App) listProjects(w http.ResponseWriter, r *http.Request, actor *user.User) {
	rows, err := a.DB.QueryContext(r.Context(), `SELECT p.project_id FROM projects p
		JOIN project_members m ON m.project_id=p.project_id WHERE m.user_id=? ORDER BY p.name`, actor.ID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	defer rows.Close()
	out := []projectPublic{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			writeAPIError(w, err)
			return
		}
		p, err := project.GetProjectByID(r.Context(), a.DB, id)
		if err != nil {
			writeAPIError(w, err)
			return
		}
		out = append(out, publicProject(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"projects": out})
}

func (a *App) patchProject(w http.ResponseWriter, r *http.Request, actor *user.User, p *project.Project) {
	if err := a.perms().CanManageProject(r.Context(), actor.ID, p.ID); err != nil {
		writeAPIError(w, err)
		return
	}
	var body struct {
		Name                string `json:"name"`
		ParentRepositoryURL string `json:"parent_repository_url"`
	}
	if !decode(w, r, &body) {
		return
	}
	upd := project.ProjectUpdate{}
	if body.Name != "" {
		upd.Name = &body.Name
	}
	if body.ParentRepositoryURL != "" {
		upd.ParentRepositoryURL = &body.ParentRepositoryURL
	}
	updated, err := project.UpdateProject(r.Context(), a.DB, actor.Username, p.ID, upd)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, publicProject(updated))
}

func (a *App) createModule(w http.ResponseWriter, r *http.Request, actor *user.User, p *project.Project) {
	if err := a.perms().CanManageProject(r.Context(), actor.ID, p.ID); err != nil {
		writeAPIError(w, err)
		return
	}
	var body struct {
		Name          string `json:"name"`
		DisplayName   string `json:"display_name"`
		Description   string `json:"description"`
		RepositoryID  string `json:"repository_id"`
		RepositoryURL string `json:"repository_url"`
		MountPath     string `json:"mount_path"`
	}
	if !decode(w, r, &body) {
		return
	}
	m, err := project.CreateModule(r.Context(), a.DB, actor.Username, project.Module{
		ProjectID: p.ID, Name: body.Name, DisplayName: body.DisplayName, Description: body.Description,
		RepositoryID: body.RepositoryID, RepositoryURL: body.RepositoryURL, MountPath: body.MountPath,
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, m)
}

func (a *App) listModules(w http.ResponseWriter, r *http.Request, actor *user.User, p *project.Project) {
	admin := a.perms().CanManageProject(r.Context(), actor.ID, p.ID) == nil
	mods, err := project.ListModules(r.Context(), a.DB, p.ID, admin)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if admin {
		writeJSON(w, http.StatusOK, map[string]any{"modules": mods})
		return
	}
	accessible, err := a.perms().ListAccessibleModules(r.Context(), actor.ID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	var mine []permission.Module
	for _, m := range accessible {
		if m.ProjectID == p.ID {
			mine = append(mine, m)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"modules": mine})
}

func (a *App) addMember(w http.ResponseWriter, r *http.Request, actor *user.User, p *project.Project) {
	if err := a.perms().CanManageProject(r.Context(), actor.ID, p.ID); err != nil {
		writeAPIError(w, err)
		return
	}
	var body struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	if !decode(w, r, &body) {
		return
	}
	account, _, err := user.Get(r.Context(), a.DB, body.Username)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if err := project.AddMember(r.Context(), a.DB, actor.Username, p.ID, account.ID, body.Role); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user_id": account.ID, "role": body.Role})
}

func (a *App) removeMember(w http.ResponseWriter, r *http.Request, actor *user.User, p *project.Project, raw string) {
	if err := a.perms().CanManageProject(r.Context(), actor.ID, p.ID); err != nil {
		writeAPIError(w, err)
		return
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user")
		return
	}
	if id == actor.ID {
		writeError(w, http.StatusConflict, "cannot remove yourself from project")
		return
	}
	if err := project.RemoveMember(r.Context(), a.DB, actor.Username, p.ID, id); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

func (a *App) modulePermissions(w http.ResponseWriter, r *http.Request, actor *user.User, m *project.Module, rest []string) {
	if err := a.perms().CanManageProject(r.Context(), actor.ID, m.ProjectID); err != nil {
		writeAPIError(w, err)
		return
	}
	if len(rest) == 0 && r.Method == http.MethodPost {
		var body struct {
			Username   string `json:"username"`
			Permission string `json:"permission"`
		}
		if !decode(w, r, &body) {
			return
		}
		account, _, err := user.Get(r.Context(), a.DB, body.Username)
		if err != nil {
			writeAPIError(w, err)
			return
		}
		if err := project.SetModulePermission(r.Context(), a.DB, actor.Username, account.ID, m.ID, body.Permission); err != nil {
			writeAPIError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"permission": body.Permission, "lore_enforcement": "access",
			"note": "Lore 0.10.1 cannot enforce read separately from write",
		})
		return
	}
	if len(rest) == 1 && r.Method == http.MethodDelete {
		id, err := strconv.ParseInt(rest[0], 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid user")
			return
		}
		if err := project.RevokeModulePermission(r.Context(), a.DB, actor.Username, id, m.ID); err != nil {
			writeAPIError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
		return
	}
	writeError(w, http.StatusNotFound, "not found")
}

func (a *App) patchModule(w http.ResponseWriter, r *http.Request, actor *user.User, m *project.Module) {
	if err := a.perms().CanManageProject(r.Context(), actor.ID, m.ProjectID); err != nil {
		writeAPIError(w, err)
		return
	}
	var body struct {
		MountPath   string  `json:"mount_path"`
		DisplayName *string `json:"display_name"`
		Description *string `json:"description"`
	}
	if !decode(w, r, &body) {
		return
	}
	upd := project.ModuleUpdate{
		DisplayName: body.DisplayName,
		Description: body.Description,
	}
	if body.MountPath != "" {
		upd.MountPath = &body.MountPath
	}
	updated, err := project.UpdateModule(r.Context(), a.DB, actor.Username, m.ID, upd)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (a *App) publishProject(w http.ResponseWriter, r *http.Request, actor *user.User, p *project.Project) {
	if err := a.perms().CanManageProject(r.Context(), actor.ID, p.ID); err != nil {
		writeAPIError(w, err)
		return
	}
	var body struct {
		Message string `json:"message"`
	}
	if !decode(w, r, &body) {
		return
	}
	if a.PublishDriver == nil {
		writeError(w, http.StatusServiceUnavailable, "publisher unavailable")
		return
	}
	preparer := a.prepareSnapshot
	if a.snapshotPreparer != nil {
		preparer = a.snapshotPreparer
	}
	parentDir, moduleDirs, err := preparer(r.Context(), p)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	requestDriver := a.PublishDriver
	if shared, ok := a.PublishDriver.(*publish.LoreDriver); ok {
		scoped := *shared
		scoped.ParentURL = p.ParentRepositoryURL
		requestDriver = &scoped
	}
	result, err := (publish.Publisher{DB: a.DB, Driver: requestDriver}).Publish(r.Context(), publish.Request{
		ProjectID: p.ID, ParentDir: parentDir, ModuleDirs: moduleDirs, Actor: actor.Username, Message: body.Message,
	})
	if err != nil {
		if a.PublishRoot != "" {
			_ = os.WriteFile(filepath.Join(a.PublishRoot, "publish-error.txt"), []byte(err.Error()), 0o644)
		}
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

type projectPublic struct {
	ID        int64
	Name      string
	CreatedAt string
}

func publicProject(p *project.Project) projectPublic {
	return projectPublic{ID: p.ID, Name: p.Name, CreatedAt: p.CreatedAt}
}

func (a *App) seesProject(r *http.Request, userID, projectID int64) error {
	var n int
	err := a.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM project_members WHERE project_id=? AND user_id=?`, projectID, userID).Scan(&n)
	if err != nil {
		return err
	}
	if n == 0 {
		return project.ErrNotFound
	}
	return nil
}

func (a *App) visibleNamed(r *http.Request, userID int64, projectName string, names []string) ([]permission.Module, error) {
	mods, err := a.perms().ListAccessibleModules(r.Context(), userID)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, name := range names {
		if name != "" {
			want[name] = true
		}
	}
	out := []permission.Module{}
	for _, m := range mods {
		if projectName != "" && m.ProjectName != projectName {
			continue
		}
		if len(want) > 0 && !want[m.Name] && !want[m.MountPath] {
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

func (a *App) batch(w http.ResponseWriter, r *http.Request, actor *user.User) {
	var body struct {
		Action  string   `json:"action"`
		Project string   `json:"project"`
		Modules []string `json:"modules"`
	}
	if !decode(w, r, &body) {
		return
	}
	switch body.Action {
	case "clone", "status", "sync", "stage", "commit", "push":
	default:
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	mods, err := a.visibleNamed(r, actor.ID, body.Project, body.Modules)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if _, err := a.DB.ExecContext(r.Context(), `INSERT INTO audit_log(actor, action, target, detail) VALUES (?,?,?,?)`,
		actor.Username, "batch_"+body.Action, body.Project, "selected="+strconv.Itoa(len(mods))); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"action": body.Action, "results": mods, "summary": map[string]int{"selected": len(mods)},
	})
}

func (a *App) projectSnapshots(w http.ResponseWriter, r *http.Request, actor *user.User, p *project.Project) {
	isAdmin := a.perms().CanManageProject(r.Context(), actor.ID, p.ID) == nil
	mods, err := a.perms().ListAccessibleModules(r.Context(), actor.ID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	allowed := map[string]bool{}
	for _, m := range mods {
		if m.ProjectID == p.ID {
			allowed[m.RepositoryID] = true
		}
	}
	rows, err := a.DB.QueryContext(r.Context(), `SELECT snapshot_id, COALESCE(description,''), created_at, pins_json FROM snapshots WHERE project_id=? ORDER BY snapshot_id`, p.ID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	defer rows.Close()
	type view struct {
		ID          int64
		Description string
		CreatedAt   string
		TotalPins   int `json:",omitempty"`
		Pins        []publish.Pin
	}
	out := []view{}
	for rows.Next() {
		var id int64
		var desc, createdAt, raw string
		if err := rows.Scan(&id, &desc, &createdAt, &raw); err != nil {
			writeAPIError(w, err)
			return
		}
		var pins []publish.Pin
		if err := json.Unmarshal([]byte(raw), &pins); err != nil {
			writeAPIError(w, err)
			return
		}
		visible := []publish.Pin{}
		for _, pin := range pins {
			if allowed[pin.RepositoryID] {
				visible = append(visible, pin)
			}
		}
		v := view{ID: id, Description: desc, CreatedAt: createdAt, Pins: visible}
		if isAdmin {
			v.TotalPins = len(pins)
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"snapshots": out})
}

func (a *App) projectStatus(w http.ResponseWriter, r *http.Request, actor *user.User, p *project.Project) {
	mods, err := a.visibleNamed(r, actor.ID, p.Name, nil)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"project": p.Name, "modules": mods})
}

func (a *App) perms() permission.Service { return permission.Service{DB: a.DB} }

func (a *App) projectRef(r *http.Request, ref string) (*project.Project, error) {
	if id, err := strconv.ParseInt(ref, 10, 64); err == nil && strconv.FormatInt(id, 10) == ref {
		return project.GetProjectByID(r.Context(), a.DB, id)
	}
	return project.GetProject(r.Context(), a.DB, ref)
}

func decode(w http.ResponseWriter, r *http.Request, dest any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dest); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return false
	}
	return true
}

func writeAPIError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, permission.ErrDenied):
		writeError(w, http.StatusForbidden, "not permitted")
	case errors.Is(err, project.ErrNotFound), errors.Is(err, user.ErrNotFound), errors.Is(err, permission.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, project.ErrLastAdmin):
		writeError(w, http.StatusConflict, "project must retain at least one active project_admin")
	case errors.Is(err, project.ErrConflict):
		writeError(w, http.StatusConflict, "conflict")
	case errors.Is(err, project.ErrInvalid):
		writeError(w, http.StatusBadRequest, "invalid request")
	case errors.Is(err, publish.ErrBusy):
		writeError(w, http.StatusConflict, "publish already running")
	case errors.Is(err, user.ErrDisabled):
		writeError(w, http.StatusForbidden, "account disabled")
	default:
		writeError(w, http.StatusBadRequest, "invalid request")
	}
}
