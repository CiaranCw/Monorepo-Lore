package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"lore-monorepo/internal/client"
	"lore-monorepo/internal/gitimport"
	"lore-monorepo/internal/history"
)

func historyCmd(args []string) error {
	var (
		projectName string
		targetMod   string
		filterMods  []string
		branch      string
		tag         string
		fromRev     string
		firstParent bool
		author      string
		search      string
		since       string
		until       string
		mergesOnly  bool
		noMerges    bool
		order       string
		limit       int
		cursor      string
		allPages    bool
		syncNow     bool
		asJSON      bool
		rest        []string
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, val, hasEq := splitFlag(arg)
		needVal := func() (string, error) {
			if hasEq {
				return val, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("missing value for %s", name)
			}
			i++
			return args[i], nil
		}

		switch name {
		case "--all":
			// explicit project-wide aggregated history
		case "--all-pages":
			allPages = true
		case "--first-parent":
			firstParent = true
		case "--merges":
			mergesOnly = true
		case "--no-merges":
			noMerges = true
		case "--sync":
			syncNow = true
		case "--json":
			asJSON = true
		case "--project":
			v, err := needVal()
			if err != nil {
				return err
			}
			projectName = v
		case "--module":
			v, err := needVal()
			if err != nil {
				return err
			}
			filterMods = append(filterMods, v)
		case "--branch":
			v, err := needVal()
			if err != nil {
				return err
			}
			branch = v
		case "--tag":
			v, err := needVal()
			if err != nil {
				return err
			}
			tag = v
		case "--from":
			v, err := needVal()
			if err != nil {
				return err
			}
			fromRev = v
		case "--author":
			v, err := needVal()
			if err != nil {
				return err
			}
			author = v
		case "--search", "-S":
			v, err := needVal()
			if err != nil {
				return err
			}
			search = v
		case "--since":
			v, err := needVal()
			if err != nil {
				return err
			}
			since = v
		case "--until":
			v, err := needVal()
			if err != nil {
				return err
			}
			until = v
		case "--order":
			v, err := needVal()
			if err != nil {
				return err
			}
			order = v
		case "--cursor":
			v, err := needVal()
			if err != nil {
				return err
			}
			cursor = v
		case "--limit", "-n":
			v, err := needVal()
			if err != nil {
				return err
			}
			n, convErr := strconv.Atoi(v)
			if convErr != nil || n <= 0 {
				return fmt.Errorf("invalid limit %q", v)
			}
			limit = n
		case "--config", "--manager", "--lore-binary", "--auth-url", "--auth-path", "--auth-store":
			v, err := needVal()
			if err != nil {
				return err
			}
			rest = append(rest, name, v)
		default:
			if strings.HasPrefix(arg, "-") {
				return fmt.Errorf("unknown argument %s", arg)
			}
			if targetMod != "" {
				return fmt.Errorf("unexpected extra argument %s", arg)
			}
			targetMod = arg
		}
	}

	cfg, err := loadCmd(rest)
	if err != nil {
		return err
	}
	if projectName == "" {
		projectName = cfg.Project
	}
	if projectName == "" && targetMod == "" {
		return fmt.Errorf("history needs a selected project (or --project) or a module name")
	}

	var endpoint string
	if targetMod != "" {
		modID, err := resolveAccessibleModuleID(cfg, projectName, targetMod)
		if err != nil {
			return err
		}
		endpoint = fmt.Sprintf("/api/v1/modules/%d/history", modID)
	} else {
		endpoint = "/api/v1/projects/" + url.PathEscape(projectName) + "/history"
	}

	buildQuery := func(cur string, syncFlag bool) string {
		q := url.Values{}
		for _, m := range filterMods {
			q.Add("module", m)
		}
		if branch != "" {
			q.Set("branch", branch)
		}
		if tag != "" {
			q.Set("tag", tag)
		}
		if fromRev != "" {
			q.Set("from_revision", fromRev)
		}
		if firstParent {
			q.Set("first_parent", "1")
		}
		if author != "" {
			q.Set("author", author)
		}
		if search != "" {
			q.Set("q", search)
		}
		if since != "" {
			q.Set("since", since)
		}
		if until != "" {
			q.Set("until", until)
		}
		if mergesOnly {
			q.Set("merges_only", "1")
		}
		if noMerges {
			q.Set("no_merges", "1")
		}
		if order != "" {
			q.Set("order", order)
		}
		if limit > 0 {
			q.Set("limit", strconv.Itoa(limit))
		}
		if cur != "" {
			q.Set("cursor", cur)
		}
		if syncFlag {
			q.Set("sync", "1")
		}
		enc := q.Encode()
		if enc == "" {
			return endpoint
		}
		return endpoint + "?" + enc
	}

	var combined history.Page
	cur := cursor
	firstReq := true
	for {
		raw, err := managerGETWithCfg(cfg, buildQuery(cur, syncNow && firstReq))
		if err != nil {
			return err
		}
		firstReq = false
		var page history.Page
		if err := json.Unmarshal(raw, &page); err != nil {
			return fmt.Errorf("history parse failed")
		}
		if !allPages {
			combined = page
			break
		}
		if combined.Scope == "" {
			combined = page
		} else {
			combined.Commits = append(combined.Commits, page.Commits...)
			combined.NextCursor = page.NextCursor
			combined.HasMore = page.HasMore
		}
		if !page.HasMore || page.NextCursor == "" {
			combined.HasMore = false
			combined.NextCursor = ""
			break
		}
		cur = page.NextCursor
	}

	if asJSON {
		enc, _ := json.MarshalIndent(combined, "", "  ")
		fmt.Fprintln(stdout, string(enc))
		return nil
	}

	for _, c := range combined.Commits {
		idCol := shortID(c.CanonicalID)
		if c.SourceCommitID != "" && c.LoreRevision != "" {
			idCol = fmt.Sprintf("%s (lore:%s)", shortID(c.SourceCommitID), shortID(c.LoreRevision))
		}
		var tags []string
		if c.IsMerge {
			tags = append(tags, fmt.Sprintf("merge:%dp", c.ParentCount))
		}
		for _, r := range c.Refs {
			tags = append(tags, r.Type+":"+r.Name)
		}
		badge := ""
		if len(tags) > 0 {
			badge = " [" + strings.Join(tags, ", ") + "]"
		}
		fmt.Fprintf(stdout, "%s/%s\t%s\t%s\t%s\t%s%s\n",
			c.ProjectName, c.ModuleName, idCol, c.CommittedAt, c.AuthorName, c.Subject, badge)
	}
	if combined.HasMore && combined.NextCursor != "" {
		fmt.Fprintf(stdout, "next_cursor=%s (showing %d of %d)\n", combined.NextCursor, len(combined.Commits), combined.TotalMatching)
	} else {
		fmt.Fprintf(stdout, "total=%d\n", combined.TotalMatching)
	}
	return nil
}

func refsCmd(args []string) error {
	var (
		projectName string
		modName     string
		refType     string
		asJSON      bool
		rest        []string
	)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, val, hasEq := splitFlag(arg)
		needVal := func() (string, error) {
			if hasEq {
				return val, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("missing value for %s", name)
			}
			i++
			return args[i], nil
		}
		switch name {
		case "--json":
			asJSON = true
		case "--project":
			v, err := needVal()
			if err != nil {
				return err
			}
			projectName = v
		case "--type":
			v, err := needVal()
			if err != nil {
				return err
			}
			refType = v
		case "--config", "--manager", "--lore-binary", "--auth-url", "--auth-path", "--auth-store":
			v, err := needVal()
			if err != nil {
				return err
			}
			rest = append(rest, name, v)
		default:
			if strings.HasPrefix(arg, "-") || modName != "" {
				return fmt.Errorf("unknown argument %s", arg)
			}
			modName = arg
		}
	}
	if modName == "" {
		return fmt.Errorf("refs needs a module name")
	}
	cfg, err := loadCmd(rest)
	if err != nil {
		return err
	}
	if projectName == "" {
		projectName = cfg.Project
	}
	modID, err := resolveAccessibleModuleID(cfg, projectName, modName)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/api/v1/modules/%d/refs", modID)
	if refType != "" {
		path += "?type=" + url.QueryEscape(refType)
	}
	raw, err := managerGETWithCfg(cfg, path)
	if err != nil {
		return err
	}
	if asJSON {
		fmt.Fprintln(stdout, strings.TrimSpace(string(raw)))
		return nil
	}
	var parsed struct {
		Refs []history.RefDetail `json:"refs"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return fmt.Errorf("refs parse failed")
	}
	for _, r := range parsed.Refs {
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n", r.Type, r.Name, shortID(r.SourceCommitID), shortID(r.LoreRevision))
	}
	return nil
}

func showCmd(args []string) error {
	var (
		projectName string
		positional  []string
		asJSON      bool
		rest        []string
	)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, val, hasEq := splitFlag(arg)
		needVal := func() (string, error) {
			if hasEq {
				return val, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("missing value for %s", name)
			}
			i++
			return args[i], nil
		}
		switch name {
		case "--json":
			asJSON = true
		case "--project":
			v, err := needVal()
			if err != nil {
				return err
			}
			projectName = v
		case "--config", "--manager", "--lore-binary", "--auth-url", "--auth-path", "--auth-store":
			v, err := needVal()
			if err != nil {
				return err
			}
			rest = append(rest, name, v)
		default:
			if strings.HasPrefix(arg, "-") {
				return fmt.Errorf("unknown argument %s", arg)
			}
			positional = append(positional, arg)
		}
	}
	if len(positional) != 2 {
		return fmt.Errorf("show needs <module> <commit-or-revision>")
	}
	cfg, err := loadCmd(rest)
	if err != nil {
		return err
	}
	if projectName == "" {
		projectName = cfg.Project
	}
	modID, err := resolveAccessibleModuleID(cfg, projectName, positional[0])
	if err != nil {
		return err
	}
	raw, err := managerGETWithCfg(cfg, fmt.Sprintf("/api/v1/modules/%d/commits/%s", modID, url.PathEscape(positional[1])))
	if err != nil {
		return err
	}
	if asJSON {
		fmt.Fprintln(stdout, strings.TrimSpace(string(raw)))
		return nil
	}
	var c history.Commit
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("show parse failed")
	}
	fmt.Fprintf(stdout, "Module:    %s/%s (%s)\n", c.ProjectName, c.ModuleName, c.OriginKind)
	fmt.Fprintf(stdout, "LoreRev:   %s\n", c.LoreRevision)
	if c.SourceCommitID != "" {
		fmt.Fprintf(stdout, "GitCommit: %s\n", c.SourceCommitID)
	}
	if c.GitTreeID != "" {
		fmt.Fprintf(stdout, "GitTree:   %s\n", c.GitTreeID)
	}
	for _, p := range c.Parents {
		fmt.Fprintf(stdout, "Parent[%d]: git=%s lore=%s\n", p.Ord, p.SourceCommitID, p.LoreRevision)
	}
	fmt.Fprintf(stdout, "Author:    %s <%s>  %s\n", c.AuthorName, c.AuthorEmail, c.AuthoredAt)
	fmt.Fprintf(stdout, "Committer: %s <%s>  %s\n", c.CommitterName, c.CommitterEmail, c.CommittedAt)
	fmt.Fprintf(stdout, "\n%s\n", c.Message)
	return nil
}

func importCmd(args []string) error {
	if len(args) > 0 && args[0] == "jobs" {
		return importJobsCmd(args[1:])
	}
	var (
		manifestPath string
		projectName  string
		sourceURL    string
		sourceSubdir string
		modName      string
		mountPath    string
		platform     string
		authMethod   string
		tokenEnv     string
		tokenUser    string
		sshKey       string
		lfsMode      string
		onConflict   string
		jobKey       string
		concurrency  int
		dryRun       bool
		asJSON       bool
		rest         []string
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, val, hasEq := splitFlag(arg)
		if name == "--token" || name == "--password" {
			return fmt.Errorf("credentials must not be passed on argv; use --token-env or --ssh-key")
		}
		needVal := func() (string, error) {
			if hasEq {
				return val, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("missing value for %s", name)
			}
			i++
			return args[i], nil
		}
		switch name {
		case "--dry-run":
			dryRun = true
		case "--json":
			asJSON = true
		case "--manifest", "-f":
			v, err := needVal()
			if err != nil {
				return err
			}
			manifestPath = v
		case "--project":
			v, err := needVal()
			if err != nil {
				return err
			}
			projectName = v
		case "--source":
			v, err := needVal()
			if err != nil {
				return err
			}
			sourceURL = v
		case "--subdir", "--source-subdir":
			v, err := needVal()
			if err != nil {
				return err
			}
			sourceSubdir = v
		case "--module":
			v, err := needVal()
			if err != nil {
				return err
			}
			modName = v
		case "--mount":
			v, err := needVal()
			if err != nil {
				return err
			}
			mountPath = v
		case "--platform":
			v, err := needVal()
			if err != nil {
				return err
			}
			platform = v
		case "--auth-method":
			v, err := needVal()
			if err != nil {
				return err
			}
			authMethod = v
		case "--token-env":
			v, err := needVal()
			if err != nil {
				return err
			}
			tokenEnv = v
		case "--token-user":
			v, err := needVal()
			if err != nil {
				return err
			}
			tokenUser = v
		case "--ssh-key":
			v, err := needVal()
			if err != nil {
				return err
			}
			sshKey = v
		case "--lfs-mode":
			v, err := needVal()
			if err != nil {
				return err
			}
			lfsMode = v
		case "--on-conflict":
			v, err := needVal()
			if err != nil {
				return err
			}
			onConflict = v
		case "--job-key":
			v, err := needVal()
			if err != nil {
				return err
			}
			jobKey = v
		case "--concurrency":
			v, err := needVal()
			if err != nil {
				return err
			}
			n, convErr := strconv.Atoi(v)
			if convErr != nil || n <= 0 {
				return fmt.Errorf("invalid concurrency %q", v)
			}
			concurrency = n
		case "--config", "--manager", "--lore-binary", "--auth-url", "--auth-path", "--auth-store":
			v, err := needVal()
			if err != nil {
				return err
			}
			rest = append(rest, name, v)
		default:
			return fmt.Errorf("unknown argument %s", arg)
		}
	}

	cfg, err := loadCmd(rest)
	if err != nil {
		return err
	}

	var manifest gitimport.Manifest
	if manifestPath != "" {
		manifest, err = gitimport.LoadManifest(manifestPath)
		if err != nil {
			return err
		}
		if projectName != "" {
			manifest.Project = projectName
		}
		if dryRun {
			manifest.DryRun = true
		}
		if onConflict != "" {
			manifest.ConflictPolicy = onConflict
			for i := range manifest.Repositories {
				manifest.Repositories[i].ConflictPolicy = onConflict
			}
		}
		if jobKey != "" {
			manifest.JobKey = jobKey
		}
		if concurrency > 0 {
			manifest.Concurrency = concurrency
		}
	} else {
		if projectName == "" {
			projectName = cfg.Project
		}
		if projectName == "" || sourceURL == "" || modName == "" {
			return fmt.Errorf("import requires either --manifest <file> or --source <url> --module <name> with a selected project")
		}
		manifest = gitimport.Manifest{
			JobKey:         jobKey,
			Project:        projectName,
			DryRun:         dryRun,
			ConflictPolicy: onConflict,
			Concurrency:    concurrency,
			Repositories: []gitimport.RepoSpec{{
				SourceURL:      sourceURL,
				SourceSubdir:   sourceSubdir,
				ModuleName:     modName,
				MountPath:      mountPath,
				Platform:       platform,
				ConflictPolicy: onConflict,
				LFSMode:        lfsMode,
				Auth: gitimport.AuthConfig{
					Method:        authMethod,
					TokenEnv:      tokenEnv,
					TokenUsername: tokenUser,
					SSHKeyPath:    sshKey,
				},
			}},
		}
		if err := gitimport.NormalizeAndValidateManifest(&manifest); err != nil {
			return err
		}
	}

	runtimeTokens := map[string]string{}
	for i := range manifest.Repositories {
		r := &manifest.Repositories[i]
		if r.Auth.SSHKeyEnv != "" {
			if kp := strings.TrimSpace(os.Getenv(r.Auth.SSHKeyEnv)); kp != "" {
				r.Auth.SSHKeyPath = kp
			}
			r.Auth.SSHKeyEnv = ""
		}
		if r.Auth.TokenEnv != "" {
			v := os.Getenv(r.Auth.TokenEnv)
			if strings.TrimSpace(v) == "" {
				return fmt.Errorf("environment variable %s for module %s is empty or unset", r.Auth.TokenEnv, r.ModuleName)
			}
			runtimeTokens[r.ModuleName] = v
			r.Auth.TokenEnv = ""
		}
	}

	reqBody := map[string]any{
		"job_key":             manifest.JobKey,
		"dry_run":             manifest.DryRun,
		"conflict_policy":     manifest.ConflictPolicy,
		"global_files_policy": manifest.GlobalFilesPolicy,
		"concurrency":         manifest.Concurrency,
		"path_rules":          manifest.PathRules,
		"repositories":        manifest.Repositories,
	}
	if len(runtimeTokens) > 0 {
		reqBody["runtime_tokens"] = runtimeTokens
	}
	payload, err := json.Marshal(reqBody)
	for k := range runtimeTokens {
		delete(runtimeTokens, k)
	}
	if err != nil {
		return fmt.Errorf("import encode failed")
	}
	defer wipe(payload)

	raw, err := managerPOST(cfg, "/api/v1/projects/"+url.PathEscape(manifest.Project)+"/imports", payload)
	if err != nil {
		return err
	}
	if asJSON {
		fmt.Fprintln(stdout, strings.TrimSpace(string(raw)))
		return nil
	}
	var job gitimport.JobResult
	if err := json.Unmarshal(raw, &job); err != nil {
		return fmt.Errorf("import parse failed")
	}
	for _, it := range job.Items {
		lfsNote := ""
		if it.Verification.LFSHydrationStatus == "pointer_only_unhydrated" {
			lfsNote = "\t[LFS:POINTER_ONLY_UNHYDRATED]"
		}
		fmt.Fprintf(stdout, "%s\t%s\t%s\tcommits=%d\tbranches=%d\ttags=%d%s\n",
			it.ModuleName, it.Platform, it.Status,
			it.Verification.IndexedCommits, it.Verification.ImportedBranches, it.Verification.ImportedTags, lfsNote)
	}
	fmt.Fprintf(stdout, "job=%d mode=%s status=%s ok=%d failed=%d skipped=%d\n",
		job.JobID, job.Mode, job.Status, job.SucceededItems, job.FailedItems, job.SkippedItems)
	if job.FailedItems > 0 {
		return fmt.Errorf("import reported %d failed item(s)", job.FailedItems)
	}
	return nil
}

func importJobsCmd(args []string) error {
	var (
		projectName string
		jobID       string
		asJSON      bool
		rest        []string
	)
	for i := 0; i < len(args); i++ {
		name, val, hasEq := splitFlag(args[i])
		needVal := func() (string, error) {
			if hasEq {
				return val, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("missing value for %s", name)
			}
			i++
			return args[i], nil
		}
		switch name {
		case "--json":
			asJSON = true
		case "--project":
			v, err := needVal()
			if err != nil {
				return err
			}
			projectName = v
		case "--job":
			v, err := needVal()
			if err != nil {
				return err
			}
			jobID = v
		case "--config", "--manager", "--lore-binary", "--auth-url", "--auth-path", "--auth-store":
			v, err := needVal()
			if err != nil {
				return err
			}
			rest = append(rest, name, v)
		default:
			return fmt.Errorf("unknown argument %s", args[i])
		}
	}
	cfg, err := loadCmd(rest)
	if err != nil {
		return err
	}
	if projectName == "" {
		projectName = cfg.Project
	}
	if projectName == "" {
		return fmt.Errorf("import jobs requires a selected project or --project")
	}
	path := "/api/v1/projects/" + url.PathEscape(projectName) + "/imports"
	if jobID != "" {
		path += "/" + url.PathEscape(jobID)
	}
	raw, err := managerGETWithCfg(cfg, path)
	if err != nil {
		return err
	}
	if asJSON {
		fmt.Fprintln(stdout, strings.TrimSpace(string(raw)))
		return nil
	}
	fmt.Fprintln(stdout, strings.TrimSpace(string(raw)))
	return nil
}

func resolveAccessibleModuleID(cfg client.Config, projectName, modName string) (int64, error) {
	raw, err := managerGETWithCfg(cfg, "/api/v1/me/modules")
	if err != nil {
		return 0, err
	}
	var parsed struct {
		Modules []struct {
			ModuleID    int64
			ProjectName string
			Name        string
			MountPath   string
		} `json:"modules"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return 0, fmt.Errorf("module lookup failed")
	}
	for _, m := range parsed.Modules {
		if projectName != "" && m.ProjectName != projectName {
			continue
		}
		if m.Name == modName || m.MountPath == modName {
			return m.ModuleID, nil
		}
	}
	return 0, fmt.Errorf("module is not accessible")
}

func managerGETWithCfg(cfg client.Config, path string) ([]byte, error) {
	token, err := identityToken(cfg)
	if err != nil {
		return nil, err
	}
	defer wipe([]byte(token))
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(cfg.ManagerURL, "/")+path, nil)
	if err != nil {
		return nil, fmt.Errorf("request failed")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.HTTPClient(cfg).Do(req)
	if err != nil {
		if client.IsTrustError(err) {
			return nil, err
		}
		return nil, fmt.Errorf("request failed")
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed")
	}
	return body, nil
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
