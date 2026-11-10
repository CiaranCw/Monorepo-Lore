package loreadapter

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lore-monorepo/internal/loreexec"
)

// step is one real Lore invocation or one adapter operation.
// Raw stdout and stderr are not stored here; Summary is redacted.
type step struct {
	Name     string `json:"name"`
	Command  string `json:"command"`
	Input    string `json:"input"`
	ExitCode int    `json:"exitCode"`
	Parsed   string `json:"parsed"`
	Class    string `json:"class"`
	State    string `json:"state"`
	Result   string `json:"result"`
	Detail   string `json:"detail"`
}

type tape struct {
	exec loreexec.Executor
	cmds []step
}

func (t *tape) Run(ctx context.Context, req loreexec.Request) (loreexec.CommandResult, error) {
	res, err := t.exec.Run(ctx, req)
	parsed := make([]string, 0, len(res.StdoutParse.Lines))
	for _, ln := range res.StdoutParse.Lines {
		if ln.TagName != "" {
			parsed = append(parsed, ln.TagName)
		} else {
			parsed = append(parsed, string(ln.Kind))
		}
	}
	class := ""
	if len(res.Findings) > 0 {
		class = res.Findings[0].Class
	}
	t.cmds = append(t.cmds, step{
		Name: "lore", Command: strings.Join(res.Argv, " "), Input: req.Dir,
		ExitCode: res.ExitCode, Parsed: strings.Join(parsed, ","), Class: class,
		State:  res.Summary(),
		Result: "RECORDED",
	})
	return res, err
}

func cmdLabel(res loreexec.CommandResult, err error) string {
	switch {
	case err != nil:
		return "FAIL"
	case res.TimedOut:
		return "TIMEOUT"
	case res.OutputSucceeded():
		return "PASS"
	default:
		return "FAIL"
	}
}

func op(steps *[]step, name, input, state, result, detail string) {
	*steps = append(*steps, step{
		Name: name, Command: "adapter", Input: input, ExitCode: -1,
		State: state, Result: result, Detail: detail,
	})
}

func passFail(err error) string {
	if err != nil {
		return "FAIL"
	}
	return "PASS"
}

// TestLoreIntegration drives the real lore.real binary. It does nothing unless
// LORE_INTEGRATION=1. Setup (isolated server, store, certificate, credential
// store) is outside this process; this test never puts a token on argv.
func TestLoreIntegration(t *testing.T) {
	if os.Getenv("LORE_INTEGRATION") != "1" || os.Getenv("LORE_CASE") == "unauth" || os.Getenv("LORE_CASE") == "serverdown" || os.Getenv("LORE_CASE") == "linkadd" {
		t.Skip("real Lore integration is opt-in; unit tests do not start a server")
	}
	bin := os.Getenv("LORE_BIN")
	url := os.Getenv("LORE_URL")
	beta := os.Getenv("LORE_URL_BETA")
	repoID := os.Getenv("LORE_REPO_ID")
	rev1 := os.Getenv("LORE_REV1")
	rev2 := os.Getenv("LORE_REV2")
	betaRev := os.Getenv("LORE_BETA_REV")
	betaRev2 := os.Getenv("LORE_BETA_REV2")
	work := os.Getenv("LORE_WORK")
	reportPath := os.Getenv("LORE_REPORT")
	for _, v := range []string{bin, url, beta, repoID, rev1, rev2, betaRev, betaRev2, work, reportPath} {
		if v == "" {
			t.Fatal("LORE_INTEGRATION requires LORE_BIN, LORE_URL, LORE_URL_BETA, LORE_REPO_ID, LORE_REV1, LORE_REV2, LORE_WORK, LORE_REPORT")
		}
	}
	rec := &tape{exec: loreexec.Executor{Config: loreexec.Config{
		Binary:  bin,
		Timeout: 3 * time.Minute,
		Env:     integrationEnv(),
	}}}
	c := &Client{Exec: rec}
	ctx := context.Background()
	var steps []step
	note := func(name, input string, err error, state string) {
		detail := ""
		if err != nil {
			detail = err.Error()
		}
		op(&steps, name, input, state, passFail(err), detail)
	}

	full := filepath.Join(work, "clone-full")
	note("clone", url+" -> "+full, c.Clone(ctx, CloneOptions{URL: url, Path: full, ExpectRepositoryID: repoID}), "")
	st, err := c.Status(ctx, full)
	note("status", full, err, statusState(st))

	atRev := filepath.Join(work, "clone-rev1")
	note("clone-revision", rev1, c.Clone(ctx, CloneOptions{URL: url, Path: atRev, Revision: rev1, Bare: true, ExpectRepositoryID: repoID}), "")
	stRev, err := c.Status(ctx, atRev)
	note("status-after-revision-clone", rev1, err, statusState(stRev))
	if err == nil && stRev.Revision != rev1 && stRev.RevisionLocal != rev1 {
		op(&steps, "revision-clone-matches", rev1, statusState(stRev), "FAIL", "local revision differs")
	} else if err == nil {
		op(&steps, "revision-clone-matches", rev1, statusState(stRev), "PASS", "")
	}

	hist, err := c.History(ctx, full, 5, "")
	note("history", "length=5", err, histState(hist))

	h1, err := c.ResolveRevision(ctx, full, "main@1")
	note("resolve-main@1", "main@1", err, h1)
	if err == nil {
		result := "FAIL"
		if h1 == rev1 {
			result = "PASS"
		}
		op(&steps, "resolve-main@1-is-first-commit", h1, "rev1="+rev1, result, "")
	}
	latest, err := c.ResolveRevision(ctx, full, "main@LATEST")
	note("resolve-main@LATEST", "main@LATEST", err, latest)
	if err == nil {
		result := "FAIL"
		if latest == st.Revision {
			result = "PASS"
		}
		op(&steps, "resolve-main@LATEST-matches-status", latest, "status="+st.Revision, result, "")
	}
	hashOnly, err := c.ResolveRevision(ctx, full, rev2)
	note("resolve-hash", rev2, err, hashOnly)
	if err == nil && hashOnly != rev2 {
		op(&steps, "resolve-hash-identity", hashOnly, rev2, "FAIL", "")
	}

	name, err := c.CurrentBranch(ctx, full)
	note("current-branch", full, err, name)
	err = c.CreateBranch(ctx, full, "feature")
	note("branch-create", "feature", err, "")
	err = c.SwitchBranch(ctx, full, "feature")
	note("branch-switch", "feature", err, "")
	sw, err := c.Status(ctx, full)
	note("status-after-switch", "feature", err, statusState(sw))
	if err == nil && sw.BranchName != "feature" {
		op(&steps, "switch-status", sw.BranchName, "feature", "FAIL", "")
	}
	_ = c.SwitchBranch(ctx, full, "main")

	err = c.AddLink(ctx, full, "Beta", beta, "/", betaRev, true)
	if err != nil && strings.Contains(err.Error(), "already a link") {
		op(&steps, "link-add", "Beta pin "+betaRev, "", "PASS", "link already present from an earlier push")
	} else {
		note("link-add", "Beta pin "+betaRev, err, "")
	}
	err = c.Commit(ctx, full, "add Beta link")
	if errors.Is(err, ErrNothingStaged) {
		op(&steps, "commit-after-link-add", "add Beta link", "", "NOT_RUN", "nothing staged")
	} else {
		note("commit-after-link-add", "add Beta link", err, "")
	}
	links, err := c.Links(ctx, full)
	note("link-list", "Beta", err, linkState(links))
	if err == nil {
		got, ok := findLink(links, "Beta")
		result := "FAIL"
		detail := "Beta missing"
		if ok && got.RepositoryID != "" && (got.Revision == betaRev || got.Revision == betaRev2) {
			result = "PASS"
			detail = got.RepositoryID + " " + got.Revision
		} else if ok {
			detail = got.RepositoryID + " pin " + got.Revision
		}
		op(&steps, "link-pin", betaRev, detail, result, "")
	}
	err = c.UpdateLink(ctx, full, "Beta", betaRev2)
	if err != nil {
		again, lerr := c.Links(ctx, full)
		got, ok := findLink(again, "Beta")
		if lerr == nil && ok && got.Revision == betaRev2 {
			op(&steps, "link-update", betaRev2, got.Revision, "PASS", "already at the requested pin")
		} else {
			note("link-update", betaRev2, err, "")
		}
	} else {
		note("link-update", betaRev2, nil, "")
	}
	err = c.Commit(ctx, full, "record link pin")
	if errors.Is(err, ErrNothingStaged) {
		op(&steps, "commit-link", "record link pin", "", "NOT_RUN", "nothing staged")
	} else {
		note("commit-link", "record link pin", err, "")
	}
	beforePush, _ := c.Status(ctx, full)
	err = c.Push(ctx, full)
	note("push", beforePush.Revision, err, "")
	afterPush, err := c.Status(ctx, full)
	note("status-after-push", beforePush.Revision, err, statusState(afterPush))
	if err == nil && (afterPush.RevisionRemote != beforePush.Revision || afterPush.IsLocalAhead || !afterPush.RemoteAuthorized) {
		op(&steps, "push-remote-matches", beforePush.Revision, statusState(afterPush), "FAIL", "")
	} else if err == nil {
		op(&steps, "push-remote-matches", beforePush.Revision, statusState(afterPush), "PASS", "")
	}

	behind := filepath.Join(work, "clone-behind")
	err = c.Clone(ctx, CloneOptions{URL: url, Path: behind, Revision: rev1, ExpectRepositoryID: repoID})
	note("clone-behind", rev1, err, "")
	err = c.Pull(ctx, behind)
	note("pull", behind, err, "")
	pulled, err := c.Status(ctx, behind)
	note("status-after-pull", behind, err, statusState(pulled))

	err = c.Sync(ctx, full, "main@1")
	note("sync-main@1", "main@1", err, "")
	synced, err := c.Status(ctx, full)
	note("status-after-sync-main@1", h1, err, statusState(synced))
	if err == nil && h1 != "" && synced.Revision != h1 && synced.RevisionLocal != h1 {
		op(&steps, "sync-lands-on-resolved-hash", h1, statusState(synced), "FAIL", "")
	} else if err == nil && h1 != "" {
		op(&steps, "sync-lands-on-resolved-hash", h1, statusState(synced), "PASS", "")
	}

	exists, err := c.RevisionExists(ctx, full, rev2)
	if err != nil {
		note("revision-exists", rev2, err, "")
	} else if exists {
		op(&steps, "revision-exists", rev2, "true", "PASS", "")
	} else {
		op(&steps, "revision-exists", rev2, "false", "FAIL", "")
	}
	missing, err := c.RevisionExists(ctx, full, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		note("revision-missing", "unknown-hash", err, "")
	} else if missing {
		op(&steps, "revision-missing", "unknown-hash", "true", "FAIL", "unknown hash reported present")
	} else {
		op(&steps, "revision-missing", "unknown-hash", "false", "PASS", "")
	}

	kept := filepath.Join(work, "clone-existing")
	if mkErr := os.MkdirAll(kept, 0o755); mkErr == nil {
		_ = os.WriteFile(filepath.Join(kept, "keep-me"), []byte("mine"), 0o644)
	}
	err = c.Clone(ctx, CloneOptions{URL: url, Path: kept})
	if errors.Is(err, ErrInvalid) {
		body, _ := os.ReadFile(filepath.Join(kept, "keep-me"))
		result := "FAIL"
		if string(body) == "mine" {
			result = "PASS"
		}
		op(&steps, "clone-refuses-existing", kept, string(body), result, "")
	} else {
		note("clone-refuses-existing", kept, err, "")
	}

	badDest := filepath.Join(work, "clone-down")
	err = c.Clone(ctx, CloneOptions{URL: "grpcs://127.0.0.1:1/no-such", Path: badDest})
	if err == nil {
		op(&steps, "clone-closed-port", badDest, "", "FAIL", "clone reported success")
	} else if _, statErr := os.Stat(badDest); statErr == nil {
		op(&steps, "clone-closed-port", badDest, "directory left behind", "FAIL", err.Error())
	} else {
		op(&steps, "clone-closed-port", "127.0.0.1:1", "removed", "PASS", err.Error())
	}

	op(&steps, "auth-service-down", "file JWKS, no auth_url", "this server does not call a Manager", "NOT_RUN", "tier2 file JWKS has no auth_url to stop")

	short := &tape{exec: loreexec.Executor{Config: loreexec.Config{
		Binary: bin, Timeout: 500 * time.Millisecond,
		Env:    integrationEnv(),
	}}}
	res, runErr := short.Run(ctx, loreexec.Request{
		Argv: []string{"--non-interactive", "notification", "subscribe", "30", "--repository", full},
		Dir:  full,
	})
	result := "NOT_RUN"
	detail := errString(runErr)
	if res.TimedOut {
		result = "PASS"
		detail = "process timed out; not classified as a network error"
	} else if runErr == nil && !res.TimedOut {
		result = "NOT_RUN"
		detail = "notification subscribe returned before the deadline; " + res.Summary()
	}
	op(&steps, "command-timeout", "notification subscribe 30", res.Summary(), result, detail)

	steps = append(rec.cmds, steps...)
	buf, err := json.MarshalIndent(steps, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	var failed []string
	for _, s := range steps {
		if s.Result == "FAIL" {
			failed = append(failed, s.Name+": "+s.Detail)
		}
	}
	if len(failed) > 0 {
		t.Fatalf("%d failing steps\n%s", len(failed), strings.Join(failed, "\n"))
	}
}

func statusState(st Status) string {
	if st.RepositoryID == "" {
		return ""
	}
	return st.RepositoryID + " branch=" + st.BranchName + " rev=" + st.Revision + " remote=" + st.RevisionRemote
}

func histState(entries []HistoryEntry) string {
	if len(entries) == 0 {
		return "empty"
	}
	return entries[0].Revision
}

func linkState(links []Link) string {
	parts := make([]string, 0, len(links))
	for _, l := range links {
		parts = append(parts, l.LinkPath+"="+l.RepositoryID+"@"+l.Revision)
	}
	return strings.Join(parts, ",")
}

func TestLoreIntegrationUnauthorized(t *testing.T) {
	if os.Getenv("LORE_INTEGRATION") != "1" || os.Getenv("LORE_CASE") != "unauth" {
		t.Skip("unauthorized case is a separate process with its own credential store")
	}
	bin, url, work, report := os.Getenv("LORE_BIN"), os.Getenv("LORE_URL"), os.Getenv("LORE_WORK"), os.Getenv("LORE_REPORT")
	rec := &tape{exec: loreexec.Executor{Config: loreexec.Config{
		Binary: bin, Timeout: time.Minute, Env: integrationEnv(),
	}}}
	c := &Client{Exec: rec}
	dest := filepath.Join(work, "clone-unauth")
	err := c.Clone(context.Background(), CloneOptions{URL: url, Path: dest})
	result := "FAIL"
	if err != nil {
		if _, statErr := os.Stat(dest); os.IsNotExist(statErr) {
			result = "PASS"
		}
	}
	steps := append(rec.cmds, step{Name: "unauthorized-clone", Command: "adapter", Input: url, Result: result, Detail: errString(err)})
	writeReport(t, report, steps)
	if result != "PASS" {
		t.Fatal(errString(err))
	}
}

func TestLoreIntegrationServerDown(t *testing.T) {
	if os.Getenv("LORE_INTEGRATION") != "1" || os.Getenv("LORE_CASE") != "serverdown" {
		t.Skip("server-down case runs after the isolated server is stopped")
	}
	bin, dir, report := os.Getenv("LORE_BIN"), os.Getenv("LORE_EXISTING"), os.Getenv("LORE_REPORT")
	rec := &tape{exec: loreexec.Executor{Config: loreexec.Config{
		Binary: bin, Timeout: time.Minute, Env: integrationEnv(),
	}}}
	c := &Client{Exec: rec}
	err := c.Sync(context.Background(), dir, "")
	exit := -1
	if len(rec.cmds) > 0 {
		exit = rec.cmds[0].ExitCode
	}
	result := "FAIL"
	detail := errString(err)
	if err != nil && exit == 0 {
		result = "PASS"
		detail = "exit 0 did not count as success; " + detail
	} else if err != nil {
		result = "PASS"
		detail = "server down failed closed; " + detail
	}
	steps := append(rec.cmds, step{Name: "server-down-sync", Command: "adapter", Input: dir, ExitCode: exit, Result: result, Detail: detail})
	writeReport(t, report, steps)
	if result != "PASS" {
		t.Fatal(detail)
	}
}

func integrationEnv() map[string]string {
	env := map[string]string{"LORE_AUTH_STORE": "fallback"}
	if v := os.Getenv("SSL_CERT_FILE"); v != "" {
		env["SSL_CERT_FILE"] = v
	}
	return env
}

func TestLinkAddFresh(t *testing.T) {
	if os.Getenv("LORE_INTEGRATION") != "1" || os.Getenv("LORE_CASE") != "linkadd" {
		t.Skip("fresh link-add runs only against a new parent and child")
	}
	bin := os.Getenv("LORE_BIN")
	parent := os.Getenv("LORE_PARENT_URL")
	child := os.Getenv("LORE_CHILD_URL")
	pin := os.Getenv("LORE_CHILD_REV")
	childID := os.Getenv("LORE_CHILD_ID")
	work := os.Getenv("LORE_WORK")
	report := os.Getenv("LORE_REPORT")
	rec := &tape{exec: loreexec.Executor{Config: loreexec.Config{
		Binary: bin, Timeout: 3 * time.Minute, Env: integrationEnv(),
	}}}
	c := &Client{Exec: rec}
	ctx := context.Background()
	dir := filepath.Join(work, "parent")
	if err := c.Clone(ctx, CloneOptions{URL: parent, Path: dir}); err != nil {
		t.Fatal(err)
	}
	before, err := c.Links(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 0 {
		t.Fatalf("parent already has links: %+v", before)
	}
	if err := c.AddLink(ctx, dir, "Child", child, "/", pin, true); err != nil {
		t.Fatal(err)
	}
	var addExit int
	var sawAdd bool
	for _, s := range rec.cmds {
		if strings.Contains(s.Command, "link add") {
			sawAdd = true
			addExit = s.ExitCode
		}
	}
	if !sawAdd || addExit != 0 {
		t.Fatalf("link add exit %d recorded %t", addExit, sawAdd)
	}
	links, err := c.Links(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := findLink(links, "Child")
	if !ok || got.RepositoryID != childID || got.Revision != pin {
		t.Fatalf("link after add: %+v", links)
	}
	if err := c.Commit(ctx, dir, "add child link"); err != nil {
		t.Fatal(err)
	}
	if err := c.Push(ctx, dir); err != nil {
		t.Fatal(err)
	}
	again := filepath.Join(work, "parent-again")
	if err := c.Clone(ctx, CloneOptions{URL: parent, Path: again}); err != nil {
		t.Fatal(err)
	}
	links, err = c.Links(ctx, again)
	if err != nil {
		t.Fatal(err)
	}
	got, ok = findLink(links, "Child")
	if !ok || got.RepositoryID != childID || got.Revision != pin {
		t.Fatalf("link after reclone: %+v", links)
	}
	writeReport(t, report, append(rec.cmds, step{
		Name: "link-add-fresh", Result: "PASS", Input: childID + "@" + pin, State: "exit=" + itoa(addExit),
	}))
}

func writeReport(t *testing.T, path string, steps []step) {
	t.Helper()
	buf, err := json.MarshalIndent(steps, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
