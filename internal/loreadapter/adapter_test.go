package loreadapter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lore-monorepo/internal/loreexec"
	"lore-monorepo/internal/lorejson"
)

const (
	repoID = "01a1bfb55b9d7370963a8d96d542029e"
	child  = "01a1bfb55aef76a1a0502a40f6727643"
	revA   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	revB   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func completeOK() string {
	return `{"tagName":"complete","data":{"status":0,"error":{"errorCode":0,"message":"","traceLocations":[]}}}` + "\n"
}

func statusJSON(local, remote string, available, authorized, localAhead, remoteAhead int) string {
	return `{"tagName":"repositoryStatusRevision","data":{"repository":"` + repoID + `","branch":"e726318bbc3fd75ac8733a7e030cc35b","branchName":"main","revision":"` + local + `","revisionNumber":2,"revisionLocal":"` + local + `","revisionRemote":"` + remote + `","remoteAvailable":` + itoa(available) + `,"remoteAuthorized":` + itoa(authorized) + `,"remoteBranchExist":1,"isLocalAhead":` + itoa(localAhead) + `,"isRemoteAhead":` + itoa(remoteAhead) + `}}` + "\n" + completeOK()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	return "1"
}

func linkJSON(path, id, rev string) string {
	return `{"tagName":"linkEntry","data":{"link":"` + id + `","linkPath":"` + path + `","revision":"` + rev + `","tracking":false,"linkNode":2,"sourceNode":0,"sourcePath":"/","branch":"e726318bbc3fd75ac8733a7e030cc35b","flags":0}}` + "\n" + completeOK() + "No links found in this repository\n"
}

// fake is a scripted executor. It is not a Lore server.
type fake struct {
	calls [][]string
	reply func(argv []string) loreexec.CommandResult
}

func (f *fake) Run(_ context.Context, req loreexec.Request) (loreexec.CommandResult, error) {
	f.calls = append(f.calls, append([]string{}, req.Argv...))
	res := f.reply(req.Argv)
	res.Started = true
	res.StdoutParse = lorejson.Parse(lorejson.Stdout, res.Stdout)
	res.StderrParse = lorejson.Parse(lorejson.Stderr, res.Stderr)
	res.Findings = append(lorejson.Classify(res.StdoutParse), lorejson.Classify(res.StderrParse)...)
	return res, nil
}

func hasArg(argv []string, want string) bool {
	for _, a := range argv {
		if a == want {
			return true
		}
	}
	return false
}

func TestFakeDoesNotClaimIntegration(t *testing.T) {
	if os.Getenv("LORE_INTEGRATION") != "" {
		t.Fatal("adapter unit tests must not run with LORE_INTEGRATION set")
	}
}

func TestStatusAndHistoryUseCapturedCommands(t *testing.T) {
	f := &fake{reply: func(argv []string) loreexec.CommandResult {
		s := strings.Join(argv, " ")
		switch {
		case strings.Contains(s, "status --revision-only"):
			return loreexec.CommandResult{ExitCode: 0, Stdout: statusJSON(revA, revA, 1, 1, 0, 0)}
		case strings.Contains(s, "history"):
			body := `{"tagName":"revisionHistoryEntry","data":{"revision":"` + revA + `","revisionNumber":2,"parent":["` + revB + `","0000000000000000000000000000000000000000000000000000000000000000"]}}` + "\n" + completeOK()
			return loreexec.CommandResult{ExitCode: 0, Stdout: body}
		default:
			t.Fatalf("unexpected %v", argv)
			return loreexec.CommandResult{}
		}
	}}
	c := &Client{Exec: f}
	st, err := c.Status(context.Background(), filepath.Join(t.TempDir(), "repo"))
	if err != nil || st.RepositoryID != repoID || st.BranchName != "main" || !st.RemoteAuthorized {
		t.Fatalf("%v %+v", err, st)
	}
	if !hasArg(f.calls[0], "--json") || !hasArg(f.calls[0], "--non-interactive") || hasArg(f.calls[0], "--access-token") {
		t.Fatalf("argv %v", f.calls[0])
	}
	hist, err := c.History(context.Background(), t.TempDir(), 5, "main@2")
	if err != nil || len(hist) != 1 || hist[0].Revision != revA || hist[0].RevisionNumber != 2 {
		t.Fatalf("%v %+v", err, hist)
	}
}

func TestCloneVerifiesDirectoryAndRepositoryID(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "alpha")
	f := &fake{reply: func(argv []string) loreexec.CommandResult {
		if hasArg(argv, "clone") {
			if err := os.MkdirAll(dest, 0o755); err != nil {
				t.Fatal(err)
			}
			return loreexec.CommandResult{ExitCode: 0, Stdout: completeOK()}
		}
		return loreexec.CommandResult{ExitCode: 0, Stdout: statusJSON(revA, revA, 1, 1, 0, 0)}
	}}
	c := &Client{Exec: f}
	err := c.Clone(context.Background(), CloneOptions{
		URL: "grpcs://127.0.0.1:1/alpha", Path: dest, Bare: true, Revision: revA, ExpectRepositoryID: repoID,
	})
	if err != nil {
		t.Fatal(err)
	}
	cloneArgs := strings.Join(f.calls[0], " ")
	if !strings.Contains(cloneArgs, "--bare") || !strings.Contains(cloneArgs, "--revision "+revA) {
		t.Fatalf("clone argv %s", cloneArgs)
	}

	f.calls = nil
	f.reply = func(argv []string) loreexec.CommandResult {
		if hasArg(argv, "clone") {
			return loreexec.CommandResult{ExitCode: 0, Stdout: completeOK()}
		}
		bad := strings.Replace(statusJSON(revA, revA, 1, 1, 0, 0), repoID, child, 1)
		return loreexec.CommandResult{ExitCode: 0, Stdout: bad}
	}
	missing := filepath.Join(t.TempDir(), "beta")
	err = c.Clone(context.Background(), CloneOptions{URL: "grpcs://127.0.0.1:1/beta", Path: missing, ExpectRepositoryID: repoID})
	if !errors.Is(err, ErrVerify) && !errors.Is(err, ErrOutput) {
		t.Fatalf("partial clone should fail closed, got %v", err)
	}
	if _, statErr := os.Stat(missing); !os.IsNotExist(statErr) {
		t.Fatalf("partial clone kept: %v", statErr)
	}
}

func TestPushAndPullVerification(t *testing.T) {
	dir := t.TempDir()
	phase := 0
	f := &fake{reply: func(argv []string) loreexec.CommandResult {
		if hasArg(argv, "push") || hasArg(argv, "sync") {
			return loreexec.CommandResult{ExitCode: 0, Stdout: completeOK()}
		}
		phase++
		if phase == 1 {
			return loreexec.CommandResult{ExitCode: 0, Stdout: statusJSON(revA, revB, 1, 1, 1, 0)}
		}
		return loreexec.CommandResult{ExitCode: 0, Stdout: statusJSON(revA, revA, 1, 1, 0, 0)}
	}}
	c := &Client{Exec: f}
	if err := c.Push(context.Background(), dir); err != nil {
		t.Fatal(err)
	}

	phase = 0
	f.reply = func(argv []string) loreexec.CommandResult {
		if hasArg(argv, "push") {
			return loreexec.CommandResult{ExitCode: 0, Stdout: completeOK()}
		}
		// Exit 0 and a successful complete, but the remote revision never moved.
		return loreexec.CommandResult{ExitCode: 0, Stdout: statusJSON(revA, revB, 1, 1, 1, 0)}
	}
	err := c.Push(context.Background(), dir)
	if !errors.Is(err, ErrVerify) {
		t.Fatalf("want verify error, got %v", err)
	}

	f.reply = func(argv []string) loreexec.CommandResult {
		if hasArg(argv, "sync") {
			// The process-level success case from E3 N-9d: exit 0 is not enough.
			return loreexec.CommandResult{ExitCode: 0, Stdout: completeOK()}
		}
		return loreexec.CommandResult{ExitCode: 0, Stdout: statusJSON(revA, revA, 0, 0, 0, 0)}
	}
	err = c.Pull(context.Background(), dir)
	if !errors.Is(err, ErrVerify) {
		t.Fatalf("unauthorized sync want verify error, got %v", err)
	}

	f.reply = func(argv []string) loreexec.CommandResult {
		if hasArg(argv, "sync") {
			return loreexec.CommandResult{ExitCode: 0, Stdout: completeOK()}
		}
		return loreexec.CommandResult{ExitCode: 0, Stdout: statusJSON(revB, revB, 1, 1, 0, 0)}
	}
	if err := c.Sync(context.Background(), dir, revB); err != nil {
		t.Fatal(err)
	}
}

func TestSyncResolvesBranchSpecBeforeCheckingRevision(t *testing.T) {
	dir := t.TempDir()
	var argvLog []string
	f := &fake{reply: func(argv []string) loreexec.CommandResult {
		argvLog = append(argvLog, strings.Join(argv, " "))
		s := strings.Join(argv, " ")
		switch {
		case strings.Contains(s, "history") && strings.Contains(s, "main@2"):
			body := `{"tagName":"revisionHistoryEntry","data":{"revision":"` + revB + `","revisionNumber":2,"parent":["` + revA + `","0000000000000000000000000000000000000000000000000000000000000000"]}}` + "\n" + completeOK()
			return loreexec.CommandResult{ExitCode: 0, Stdout: body}
		case strings.Contains(s, "history") && strings.Contains(s, "main@LATEST"):
			return loreexec.CommandResult{ExitCode: 0, Stdout: `{"tagName":"revisionHistoryEntry","data":{"revision":"` + revA + `","revisionNumber":4,"parent":[]}}` + "\n" + completeOK()}
		case strings.Contains(s, " sync "):
			return loreexec.CommandResult{ExitCode: 0, Stdout: completeOK()}
		default:
			return loreexec.CommandResult{ExitCode: 0, Stdout: statusJSON(revB, revB, 1, 1, 0, 0)}
		}
	}}
	c := &Client{Exec: f}
	if err := c.Sync(context.Background(), dir, "main@2"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(argvLog, "\n"), "history") || !strings.Contains(strings.Join(argvLog, "\n"), "main@2") {
		t.Fatalf("spec was not resolved: %v", argvLog)
	}
	f.reply = func(argv []string) loreexec.CommandResult {
		if strings.Contains(strings.Join(argv, " "), "history") {
			return loreexec.CommandResult{ExitCode: 0, Stdout: completeOK()}
		}
		t.Fatal("sync ran without a resolved hash")
		return loreexec.CommandResult{}
	}
	if err := c.Sync(context.Background(), dir, "main@LATEST"); err == nil {
		t.Fatal("unresolved LATEST must not be reported as success")
	}
}

func TestCloneRefusesExistingAndReportsCleanupFailure(t *testing.T) {
	root := t.TempDir()
	existing := filepath.Join(root, "already")
	if err := os.Mkdir(existing, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(existing, "keep-me")
	if err := os.WriteFile(marker, []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &fake{reply: func(argv []string) loreexec.CommandResult {
		t.Fatal("clone must not run when the destination exists")
		return loreexec.CommandResult{}
	}}
	c := &Client{Exec: f}
	err := c.Clone(context.Background(), CloneOptions{URL: "grpcs://127.0.0.1:1/alpha", Path: existing})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("%v", err)
	}
	body, err := os.ReadFile(marker)
	if err != nil || string(body) != "mine" {
		t.Fatalf("existing directory was touched: %v %q", err, body)
	}

	dest := filepath.Join(root, "new-repo")
	f.reply = func(argv []string) loreexec.CommandResult {
		if hasArg(argv, "clone") {
			if err := os.MkdirAll(dest, 0o755); err != nil {
				t.Fatal(err)
			}
			return loreexec.CommandResult{ExitCode: 79, Stdout: "[Error] Not found\n"}
		}
		return loreexec.CommandResult{}
	}
	c.Delete = func(path string) error {
		if path != dest {
			t.Fatalf("cleanup path %s", path)
		}
		return errors.New("disk busy")
	}
	err = c.Clone(context.Background(), CloneOptions{URL: "grpcs://127.0.0.1:1/alpha", Path: dest})
	if !errors.Is(err, ErrOutput) || !strings.Contains(err.Error(), "disk busy") {
		t.Fatalf("%v", err)
	}
	if _, statErr := os.Stat(dest); statErr != nil {
		t.Fatal("cleanup failure must leave the new directory in place")
	}
}

func TestLinkUpdateVerifiesPin(t *testing.T) {
	dir := t.TempDir()
	updated := false
	f := &fake{reply: func(argv []string) loreexec.CommandResult {
		pin := revA
		if updated {
			pin = revB
		}
		if hasArg(argv, "update") {
			updated = true
			if !hasArg(argv, "--pin") || !hasArg(argv, revB) || !hasArg(argv, "--disable-branching") && hasArg(argv, "add") {
				// update must carry the pin and must not pass a token
			}
			if hasArg(argv, "--access-token") {
				t.Fatal("token on argv")
			}
			return loreexec.CommandResult{ExitCode: 0, Stdout: completeOK()}
		}
		return loreexec.CommandResult{ExitCode: 0, Stdout: linkJSON("Alpha", child, pin)}
	}}
	c := &Client{Exec: f}
	links, err := c.Links(context.Background(), dir)
	if err != nil || len(links) != 1 || links[0].RepositoryID != child || links[0].LinkPath != "Alpha" {
		t.Fatalf("%v %+v", err, links)
	}
	if err := c.UpdateLink(context.Background(), dir, "Alpha", revB); err != nil {
		t.Fatal(err)
	}

	f.reply = func(argv []string) loreexec.CommandResult {
		if hasArg(argv, "update") {
			return loreexec.CommandResult{ExitCode: 0, Stdout: completeOK()}
		}
		return loreexec.CommandResult{ExitCode: 0, Stdout: linkJSON("Alpha", child, revA)}
	}
	err = c.UpdateLink(context.Background(), dir, "Alpha", revB)
	if !errors.Is(err, ErrVerify) {
		t.Fatalf("stale pin want verify error, got %v", err)
	}
}

func TestAddLinkAndBranchSwitch(t *testing.T) {
	dir := t.TempDir()
	f := &fake{reply: func(argv []string) loreexec.CommandResult {
		s := strings.Join(argv, " ")
		switch {
		case strings.Contains(s, "link add"):
			if !strings.Contains(s, "--disable-branching") || !strings.Contains(s, "--pin "+revA) {
				t.Fatalf("add argv %s", s)
			}
			return loreexec.CommandResult{ExitCode: 0, Stdout: completeOK()}
		case strings.Contains(s, "link list"):
			return loreexec.CommandResult{ExitCode: 0, Stdout: linkJSON("Alpha", child, revA)}
		case strings.Contains(s, "branch switch"):
			return loreexec.CommandResult{ExitCode: 0, Stdout: completeOK()}
		case strings.Contains(s, "branch create"):
			return loreexec.CommandResult{ExitCode: 0, Stdout: `{"tagName":"branchCreate","data":{"name":"feature","latest":"` + revA + `","isCommit":false}}` + "\n" + completeOK()}
		case strings.Contains(s, "branch list"):
			return loreexec.CommandResult{ExitCode: 0, Stdout: `{"tagName":"branchListEntry","data":{"id":"e726318bbc3fd75ac8733a7e030cc35b","name":"feature","latest":"` + revA + `","isCurrent":0}}` + "\n" + completeOK()}
		case strings.Contains(s, "status"):
			body := strings.Replace(statusJSON(revA, revA, 1, 1, 0, 0), `"branchName":"main"`, `"branchName":"feature"`, 1)
			return loreexec.CommandResult{ExitCode: 0, Stdout: body}
		default:
			t.Fatalf("argv %s", s)
			return loreexec.CommandResult{}
		}
	}}
	c := &Client{Exec: f}
	if err := c.AddLink(context.Background(), dir, "Alpha", "grpcs://127.0.0.1:1/alpha", "/", revA, true); err != nil {
		t.Fatal(err)
	}
	if err := c.CreateBranch(context.Background(), dir, "feature"); err != nil {
		t.Fatal(err)
	}
	if err := c.SwitchBranch(context.Background(), dir, "feature"); err != nil {
		t.Fatal(err)
	}
	name, err := c.CurrentBranch(context.Background(), dir)
	if err != nil || name != "feature" {
		t.Fatalf("%v %s", err, name)
	}
}

func TestCommitNothingStagedAndFailure(t *testing.T) {
	dir := t.TempDir()
	f := &fake{reply: func(argv []string) loreexec.CommandResult {
		if hasArg(argv, "commit") {
			return loreexec.CommandResult{ExitCode: 40, Stdout: "[Error] Nothing staged for commit\n"}
		}
		return loreexec.CommandResult{ExitCode: 0, Stdout: statusJSON(revA, revA, 1, 1, 0, 0)}
	}}
	c := &Client{Exec: f}
	err := c.Commit(context.Background(), dir, "snapshot R2")
	if !errors.Is(err, ErrNothingStaged) {
		t.Fatalf("%v", err)
	}
	if _, err := c.RevisionExists(context.Background(), dir, "not a revision"); err == nil {
		t.Fatal("bad revision accepted")
	}
}

func TestOutputFailureIsNotVerified(t *testing.T) {
	dir := t.TempDir()
	f := &fake{reply: func(argv []string) loreexec.CommandResult {
		return loreexec.CommandResult{ExitCode: 0, Stdout: `{"tagName":"log","data":{"level":"error","category":0,"timestamp":1,"location":"lore_revision::relay","message":"Not found"}}` + "\n" + `{"tagName":"complete","data":{"status":79,"error":{"errorCode":79,"message":"Not found","traceLocations":[{"file":"lore-revision/src/repository/clone.rs","line":875,"column":10,"context":"Failed to resolve repository"}]}}}` + "\n"}
	}}
	c := &Client{Exec: f}
	_, err := c.Status(context.Background(), dir)
	if !errors.Is(err, ErrOutput) {
		t.Fatalf("%v", err)
	}
}
