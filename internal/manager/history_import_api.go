package manager

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"lore-monorepo/internal/gitimport"
	"lore-monorepo/internal/history"
	"lore-monorepo/internal/permission"
	"lore-monorepo/internal/project"
	"lore-monorepo/internal/user"
)

func (a *App) historySvc() history.Service {
	return history.Service{DB: a.DB}
}

func (a *App) projectHistory(w http.ResponseWriter, r *http.Request, actor *user.User, p *project.Project) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	filter, syncNow, err := parseHistoryFilter(r)
	if err != nil {
		writeHistoryError(w, err)
		return
	}
	if syncNow {
		mods, lErr := a.perms().ListAccessibleModules(r.Context(), actor.ID)
		if lErr != nil {
			writeHistoryError(w, lErr)
			return
		}
		wantNames := map[string]bool{}
		for _, raw := range filter.Modules {
			for _, part := range strings.Split(raw, ",") {
				part = strings.TrimSpace(part)
				if part != "" {
					wantNames[part] = true
				}
			}
		}
		for _, m := range mods {
			if m.ProjectID != p.ID {
				continue
			}
			if len(wantNames) > 0 && !wantNames[m.Name] && !wantNames[m.MountPath] {
				continue
			}
			modRow, gErr := project.GetModuleByID(r.Context(), a.DB, m.ModuleID)
			if gErr != nil {
				writeError(w, http.StatusBadGateway, fmt.Sprintf("history sync failed for module %s", m.Name))
				return
			}
			if _, sErr := a.syncModuleHistoryOnServer(r.Context(), modRow, ""); sErr != nil {
				writeError(w, http.StatusBadGateway, fmt.Sprintf("history sync failed for module %s", m.Name))
				return
			}
		}
	}
	page, err := a.historySvc().ProjectHistory(r.Context(), actor.ID, p.ID, filter)
	if err != nil {
		writeHistoryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (a *App) moduleHistoryRoutes(w http.ResponseWriter, r *http.Request, actor *user.User, m *project.Module, sub []string) {
	if len(sub) == 0 {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		filter, syncNow, err := parseHistoryFilter(r)
		if err != nil {
			writeHistoryError(w, err)
			return
		}
		if err := a.perms().CanReadModule(r.Context(), actor.ID, m.ID); err != nil {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if syncNow {
			if _, sErr := a.syncModuleHistoryOnServer(r.Context(), m, ""); sErr != nil {
				writeError(w, http.StatusBadGateway, "module history sync failed")
				return
			}
		}
		page, err := a.historySvc().ModuleHistory(r.Context(), actor.ID, m.ID, filter)
		if err != nil {
			writeHistoryError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, page)
		return
	}
	if len(sub) == 1 && sub[0] == "sync" {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if err := a.perms().CanReadModule(r.Context(), actor.ID, m.ID); err != nil {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		var body struct {
			RepoDir string `json:"repo_dir"`
		}
		if r.ContentLength != 0 {
			dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
				writeError(w, http.StatusBadRequest, "invalid request")
				return
			}
		}
		if strings.TrimSpace(body.RepoDir) != "" {
			if err := a.perms().CanManageProject(r.Context(), actor.ID, m.ProjectID); err != nil {
				writeAPIError(w, err)
				return
			}
			// Enforce AllowedLocalDirs on explicit repo_dir as well so project_admin cannot point Lore at arbitrary server paths!
			if a.Importer != nil && a.Importer.RestrictLocalSources {
				cleanDir, lErr := gitimport.ValidateLocalSourceAccess(body.RepoDir, true, a.Importer.AllowedLocalDirs)
				if lErr != nil {
					writeError(w, http.StatusForbidden, lErr.Error())
					return
				}
				body.RepoDir = cleanDir
			}
		}
		stats, err := a.syncModuleHistoryOnServer(r.Context(), m, body.RepoDir)
		if err != nil {
			writeError(w, http.StatusBadGateway, "history sync failed")
			return
		}
		writeJSON(w, http.StatusOK, stats)
		return
	}
	writeError(w, http.StatusNotFound, "not found")
}

func (a *App) moduleCommitDetail(w http.ResponseWriter, r *http.Request, actor *user.User, m *project.Module, sub []string) {
	if len(sub) != 1 || sub[0] == "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	c, err := a.historySvc().GetCommit(r.Context(), actor.ID, m.ID, sub[0])
	if err != nil {
		writeHistoryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (a *App) moduleRefsRoute(w http.ResponseWriter, r *http.Request, actor *user.User, m *project.Module, sub []string) {
	if len(sub) != 0 {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	refs, err := a.historySvc().ListModuleRefs(r.Context(), actor.ID, m.ID, strings.TrimSpace(r.URL.Query().Get("type")))
	if err != nil {
		writeHistoryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"refs": refs})
}

func (a *App) moduleAliasesRoute(w http.ResponseWriter, r *http.Request, actor *user.User, m *project.Module, sub []string) {
	if len(sub) != 1 || sub[0] == "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	al, err := a.historySvc().GetCommitAlias(r.Context(), actor.ID, m.ID, sub[0])
	if err != nil {
		writeHistoryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, al)
}

type importAPIRequest struct {
	JobKey            string               `json:"job_key,omitempty"`
	DryRun            bool                 `json:"dry_run,omitempty"`
	ConflictPolicy    string               `json:"conflict_policy,omitempty"`
	GlobalFilesPolicy string               `json:"global_files_policy,omitempty"`
	Concurrency       int                  `json:"concurrency,omitempty"`
	PathRules         []gitimport.PathRule `json:"path_rules,omitempty"`
	Repositories      []gitimport.RepoSpec `json:"repositories"`
	// RuntimeTokens supplies in-memory HTTPS tokens keyed by module_name from the client.
	// Manager NEVER evaluates client-supplied TokenEnv or SSHKeyEnv names against server os.Getenv!
	RuntimeTokens map[string]string `json:"runtime_tokens,omitempty"`
}

func (a *App) projectImports(w http.ResponseWriter, r *http.Request, actor *user.User, p *project.Project, sub []string) {
	if err := a.perms().CanManageProject(r.Context(), actor.ID, p.ID); err != nil {
		writeAPIError(w, err)
		return
	}
	if a.Importer == nil {
		writeError(w, http.StatusServiceUnavailable, "importer unavailable")
		return
	}
	if len(sub) == 0 {
		switch r.Method {
		case http.MethodGet:
			jobs, err := a.Importer.ListJobs(r.Context(), p.ID, p.Name)
			if err != nil {
				writeAPIError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs})
			return
		case http.MethodPost:
			var req importAPIRequest
			if !decode(w, r, &req) {
				return
			}
			manifest := gitimport.Manifest{
				JobKey:            req.JobKey,
				Project:           p.Name,
				DryRun:            req.DryRun,
				ConflictPolicy:    req.ConflictPolicy,
				GlobalFilesPolicy: req.GlobalFilesPolicy,
				Concurrency:       req.Concurrency,
				PathRules:         req.PathRules,
				Repositories:      req.Repositories,
			}
			defer func() {
				for i := range manifest.Repositories {
					manifest.Repositories[i].Auth.Token = ""
				}
				for k := range req.RuntimeTokens {
					delete(req.RuntimeTokens, k)
				}
			}()

			// Reject SSHKeyEnv over the API unconditionally, and reject TokenEnv unless the client
			// actually resolved and transmitted the token in RuntimeTokens[ModuleName], then strip TokenEnv!
			for i := range manifest.Repositories {
				repo := &manifest.Repositories[i]
				if strings.TrimSpace(repo.Auth.SSHKeyEnv) != "" {
					writeError(w, http.StatusBadRequest, gitimport.ErrServerEnvAccessDenied.Error())
					return
				}
				if tok, hasRuntime := req.RuntimeTokens[repo.ModuleName]; hasRuntime && tok != "" {
					repo.Auth.Token = tok
					repo.Auth.TokenEnv = ""
				} else if strings.TrimSpace(repo.Auth.TokenEnv) != "" {
					writeError(w, http.StatusBadRequest, gitimport.ErrServerEnvAccessDenied.Error())
					return
				}
			}

			res, err := a.Importer.Run(r.Context(), actor.Username, manifest)
			if err != nil {
				switch {
				case errors.Is(err, gitimport.ErrConflict), errors.Is(err, gitimport.ErrJobBusy):
					writeError(w, http.StatusConflict, err.Error())
				case errors.Is(err, gitimport.ErrLocalSourceNotAllowed), errors.Is(err, gitimport.ErrSSHPathNotAllowed):
					writeError(w, http.StatusForbidden, err.Error())
				default:
					writeError(w, http.StatusBadRequest, err.Error())
				}
				return
			}
			writeJSON(w, http.StatusOK, res)
			return
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
	}
	if len(sub) == 1 && r.Method == http.MethodGet {
		jobID, err := strconv.ParseInt(sub[0], 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid job id")
			return
		}
		job, err := a.Importer.GetJob(r.Context(), p.ID, jobID, p.Name)
		if err != nil {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeJSON(w, http.StatusOK, job)
		return
	}
	writeError(w, http.StatusNotFound, "not found")
}

func parseHistoryFilter(r *http.Request) (history.Filter, bool, error) {
	q := r.URL.Query()
	var f history.Filter
	f.Modules = q["module"]
	f.Branch = strings.TrimSpace(q.Get("branch"))
	f.Tag = strings.TrimSpace(q.Get("tag"))
	f.FromRevision = strings.TrimSpace(q.Get("from_revision"))
	f.FirstParentOnly = parseQueryBool(q.Get("first_parent"))
	f.Author = strings.TrimSpace(q.Get("author"))
	f.Search = strings.TrimSpace(q.Get("q"))
	if f.Search == "" {
		f.Search = strings.TrimSpace(q.Get("search"))
	}
	f.MergesOnly = parseQueryBool(q.Get("merges_only"))
	f.NoMerges = parseQueryBool(q.Get("no_merges"))
	f.Order = strings.TrimSpace(q.Get("order"))
	f.Cursor = strings.TrimSpace(q.Get("cursor"))

	if rawLim := strings.TrimSpace(q.Get("limit")); rawLim != "" {
		lim, err := strconv.Atoi(rawLim)
		if err != nil || lim <= 0 {
			return f, false, history.ErrInvalidFilter
		}
		f.Limit = lim
	}
	if rawSince := strings.TrimSpace(q.Get("since")); rawSince != "" {
		ms, err := parseQueryTimeMS(rawSince)
		if err != nil {
			return f, false, history.ErrInvalidFilter
		}
		f.SinceUnixMS = &ms
	}
	if rawUntil := strings.TrimSpace(q.Get("until")); rawUntil != "" {
		ms, err := parseQueryTimeMS(rawUntil)
		if err != nil {
			return f, false, history.ErrInvalidFilter
		}
		f.UntilUnixMS = &ms
	}
	return f, parseQueryBool(q.Get("sync")), nil
}

func parseQueryBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

func parseQueryTimeMS(raw string) (int64, error) {
	if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return n, nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UnixMilli(), nil
		}
	}
	return 0, history.ErrInvalidFilter
}

func writeHistoryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, history.ErrNotFound), errors.Is(err, permission.ErrNotFound), errors.Is(err, permission.ErrDenied):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, history.ErrInvalidCursor), errors.Is(err, history.ErrInvalidFilter):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeAPIError(w, err)
	}
}
