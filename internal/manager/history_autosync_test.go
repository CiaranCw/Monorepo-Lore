package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"lore-monorepo/internal/history"
	"lore-monorepo/internal/loreadapter"
	"lore-monorepo/internal/loreexec"
	"lore-monorepo/internal/lorejson"
	"lore-monorepo/internal/project"
	"lore-monorepo/internal/user"
)

func TestRemoteBranchesDiffer(t *testing.T) {
	r1 := strings.Repeat("a", 64)
	r2 := strings.Repeat("b", 64)
	boot := strings.Repeat("c", 64)

	dbRefs := map[string]string{"master": r1}
	branches := []loreadapter.Branch{
		{Name: "master", Latest: r1},
		{Name: "main", Latest: boot},
		{Name: "lore-link-1", Latest: r2},
		{Name: "old", Latest: r2, Archived: true},
		{Name: "empty", Latest: zeroRev64},
	}
	if remoteBranchesDiffer(branches, dbRefs, boot) {
		t.Fatal("expected identical branches (with omitted bootstrap main, link, archived, zero) not to differ")
	}

	branches[0].Latest = r2
	if !remoteBranchesDiffer(branches, dbRefs, boot) {
		t.Fatal("expected updated master tip to differ")
	}

	branches[0].Latest = r1
	branches = append(branches, loreadapter.Branch{Name: "feat/x", Latest: r2})
	if !remoteBranchesDiffer(branches, dbRefs, boot) {
		t.Fatal("expected added branch to differ")
	}
}

type mockAutoSyncRunner struct {
	mu          sync.Mutex
	modADir     string
	modBDir     string
	modARev     string
	modBRev     string
	syncCalls   map[string]int
	branchCalls map[string]int
}

func (m *mockAutoSyncRunner) Run(_ context.Context, req loreexec.Request) (loreexec.CommandResult, error) {
	argv := req.Argv
	joined := strings.Join(argv, " ")
	okOut := func(lines ...string) loreexec.CommandResult {
		body := strings.Join(lines, "\n") + "\n" + `{"tagName":"complete","data":{"status":0,"error":{"errorCode":0,"message":""}}}` + "\n"
		return loreexec.CommandResult{
			Started:     true,
			ExitCode:    0,
			Stdout:      body,
			StdoutParse: lorejson.Parse(lorejson.Stdout, body),
		}
	}

	if strings.Contains(joined, "login") {
		return okOut(), nil
	}

	repoDir := ""
	for i := 0; i < len(argv)-1; i++ {
		if argv[i] == "--repository" {
			repoDir = argv[i+1]
			break
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if strings.Contains(joined, "branch list") {
		isRemote := strings.Contains(joined, "--remote")
		if isRemote {
			m.branchCalls[repoDir]++
		}
		rev := m.modARev
		if repoDir == m.modBDir {
			rev = m.modBRev
		}
		loc := "local"
		if isRemote {
			loc = "remote"
		}
		return okOut(
			fmt.Sprintf(`{"tagName":"branchListBegin","data":{"location":%q}}`, loc),
			fmt.Sprintf(`{"tagName":"branchListEntry","data":{"location":%q,"id":"01010101010101010101010101010101","name":"main","latest":%q,"isCurrent":true,"archived":false}}`, loc, rev),
			fmt.Sprintf(`{"tagName":"branchListEnd","data":{"location":%q,"count":1}}`, loc),
		), nil
	}

	if strings.Contains(joined, "sync ") || strings.HasSuffix(joined, "sync") || (len(argv) >= 2 && argv[1] == "sync") {
		m.syncCalls[repoDir]++
		return okOut(), nil
	}
	if strings.Contains(joined, "status") {
		return okOut(`{"tagName":"repositoryStatus","data":{"branch":"main"}}`), nil
	}
	if strings.Contains(joined, "metadata get") {
		return okOut(`{"tagName":"metadata","data":{"key":"default-branch-name","value":{"tagName":"string","data":"main"}}}`), nil
	}
	if strings.Contains(joined, "history") {
		rev := m.modARev
		if repoDir == m.modBDir {
			rev = m.modBRev
		}
		return okOut(
			`{"tagName":"revisionHistory","data":{"repository":"repo","branch":"01010101010101010101010101010101"}}`,
			fmt.Sprintf(`{"tagName":"revisionHistoryEntry","data":{"revision":%q,"revisionNumber":2,"parent":[%q,%q]}}`, rev, strings.Repeat("1", 64), zeroRev64),
			`{"tagName":"metadata","data":{"key":"message","value":{"tagName":"string","data":"feat: new push"}}}`,
			`{"tagName":"metadata","data":{"key":"timestamp","value":{"tagName":"numeric","data":1795082713000}}}`,
			`{"tagName":"metadata","data":{"key":"created-by","value":{"tagName":"string","data":"dev"}}}`,
		), nil
	}
	return okOut(), nil
}

func TestSyncChangedModulesAndProjectHistorySyncAPI(t *testing.T) {
	app := testApp(t, fakeLore(t))
	ctx := context.Background()

	// Create service account + admin + non-member.
	svcID, err := user.Create(ctx, app.DB, "test", "kubee-publisher", "svc-pw", "service")
	if err != nil {
		t.Fatal(err)
	}
	_ = svcID
	adminID := makeAcct(t, app, "admin")
	outsiderID := makeAcct(t, app, "outsider")

	p, err := project.CreateProject(ctx, app.DB, "admin", project.Project{
		Name: "Kubee", ParentRepositoryID: strings.Repeat("a", 32), ParentRepositoryURL: "grpcs://127.0.0.1:57047/" + strings.Repeat("a", 32), CreatedBy: adminID,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = project.AddMember(ctx, app.DB, "admin", p.ID, adminID, project.RoleAdmin)

	modA, err := project.CreateModule(ctx, app.DB, "admin", project.Module{
		ProjectID: p.ID, Name: "ModA", MountPath: "ModA", RepositoryID: strings.Repeat("b", 32), RepositoryURL: "grpcs://127.0.0.1:57047/" + strings.Repeat("b", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	modB, err := project.CreateModule(ctx, app.DB, "admin", project.Module{
		ProjectID: p.ID, Name: "ModB", MountPath: "ModB", RepositoryID: strings.Repeat("c", 32), RepositoryURL: "grpcs://127.0.0.1:57047/" + strings.Repeat("c", 32),
	})
	if err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir()
	modADir := filepath.Join(tmp, "ModA")
	modBDir := filepath.Join(tmp, "ModB")
	for _, d := range []string{modADir, modBDir} {
		if err := os.MkdirAll(filepath.Join(d, ".lore"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Register managed lore_work_path entries via import_jobs + import_job_items.
	if _, err := app.DB.ExecContext(ctx, `
		INSERT INTO import_jobs(job_key, project_id, mode, status, manifest_hash, requested_by)
		VALUES ('j1', ?, 'import', 'succeeded', 'h', 'admin')
	`, p.ID); err != nil {
		t.Fatal(err)
	}
	var jobID int64
	_ = app.DB.QueryRowContext(ctx, `SELECT last_insert_rowid()`).Scan(&jobID)
	for idx, item := range []struct {
		mod *project.Module
		dir string
	}{{modA, modADir}, {modB, modBDir}} {
		if _, err := app.DB.ExecContext(ctx, `
			INSERT INTO import_job_items(job_id, ord, source_url, platform, auth_method, module_name, mount_path, conflict_policy, module_id, lore_repository_id, lore_repository_url, lore_work_path, status)
			VALUES (?, ?, 'https://example.com/r', 'local_git', 'none', ?, ?, 'fail', ?, ?, ?, ?, 'succeeded')
		`, jobID, idx, item.mod.Name, item.mod.MountPath, item.mod.ID, item.mod.RepositoryID, item.mod.RepositoryURL, item.dir); err != nil {
			t.Fatal(err)
		}
	}

	revA := strings.Repeat("1", 64)
	revB1 := strings.Repeat("2", 64)
	revB2 := strings.Repeat("3", 64)

	// Seed ModA at revA and ModB at revB1 (ModB remote will be at revB2).
	for _, seed := range []struct {
		id  int64
		rev string
	}{{modA.ID, revA}, {modB.ID, revB1}} {
		tx, _ := app.DB.BeginTx(ctx, nil)
		_ = history.UpsertCommit(ctx, tx, history.CommitInput{
			ModuleID: seed.id, LoreRevision: seed.rev,
			OriginKind: history.OriginNativeLore, AuthorName: "dev",
			AuthoredUnixMS: 1795000000000, CommittedUnixMS: 1795000000000, Message: "init",
		})
		_ = history.UpsertRef(ctx, tx, history.RefDetail{
			ModuleID: seed.id, Type: "branch", Name: "main", LoreRevision: seed.rev, IsDefault: true,
		})
		_ = tx.Commit()
	}

	runner := &mockAutoSyncRunner{
		modADir:     modADir,
		modBDir:     modBDir,
		modARev:     revA,
		modBRev:     revB2,
		syncCalls:   map[string]int{},
		branchCalls: map[string]int{},
	}
	app.PublishLore = &loreadapter.Client{Exec: runner}

	srv := httptestServer(t, app)
	adminTok, _ := app.Tokens.IssueIdentity(itoa(adminID), "admin", 1)
	outsiderTok, _ := app.Tokens.IssueIdentity(itoa(outsiderID), "outsider", 1)

	// Outsider cannot sync project.
	if st, _ := apiJSON(t, http.MethodPost, srv+"/api/v1/projects/Kubee/history/sync", outsiderTok, map[string]any{}); st != http.StatusNotFound {
		t.Fatalf("expected 404 for outsider sync, got %d", st)
	}

	// Admin triggers sync: only ModB should sync!
	st, body := apiJSON(t, http.MethodPost, srv+"/api/v1/projects/Kubee/history/sync", adminTok, map[string]any{})
	if st != http.StatusOK {
		raw, _ := json.Marshal(body)
		t.Fatalf("sync status=%d body=%s", st, raw)
	}
	if int(body["checked"].(float64)) != 2 || int(body["changed"].(float64)) != 1 || int(body["synced"].(float64)) != 1 || int(body["commits_upserted"].(float64)) != 1 {
		t.Fatalf("unexpected sync summary: %v", body)
	}
	if runner.syncCalls[modADir] != 0 || runner.syncCalls[modBDir] != 1 {
		t.Fatalf("expected only modB to run lore sync, got %+v", runner.syncCalls)
	}

	// Second sweep with no remote changes should report changed=0 and skip lore sync.
	st2, body2 := apiJSON(t, http.MethodPost, srv+"/api/v1/projects/Kubee/history/sync", adminTok, map[string]any{})
	if st2 != http.StatusOK || int(body2["changed"].(float64)) != 0 || int(body2["synced"].(float64)) != 0 {
		t.Fatalf("expected no-op second sweep, got status=%d body=%v", st2, body2)
	}
	if runner.syncCalls[modBDir] != 1 {
		t.Fatalf("expected modB sync count to remain 1, got %d", runner.syncCalls[modBDir])
	}
}

func TestPushNotifyTriggersAutoSync(t *testing.T) {
	app := testApp(t, fakeLore(t))
	ctx := context.Background()
	_, _ = user.Create(ctx, app.DB, "test", "kubee-publisher", "svc-pw", "service")
	adminID := makeAcct(t, app, "admin")
	p, err := project.CreateProject(ctx, app.DB, "admin", project.Project{
		Name: "Kubee", ParentRepositoryID: strings.Repeat("a", 32), ParentRepositoryURL: "grpcs://127.0.0.1:57047/" + strings.Repeat("a", 32), CreatedBy: adminID,
	})
	if err != nil {
		t.Fatal(err)
	}
	mod, err := project.CreateModule(ctx, app.DB, "admin", project.Module{
		ProjectID: p.ID, Name: "ModX", MountPath: "ModX", RepositoryID: strings.Repeat("d", 32), RepositoryURL: "grpcs://127.0.0.1:57047/" + strings.Repeat("d", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	modDir := filepath.Join(t.TempDir(), "ModX")
	_ = os.MkdirAll(filepath.Join(modDir, ".lore"), 0o755)
	_, _ = app.DB.ExecContext(ctx, `INSERT INTO import_jobs(job_key, project_id, mode, status, manifest_hash, requested_by) VALUES ('j1', ?, 'import', 'succeeded', 'h', 'admin')`, p.ID)
	var jobID int64
	_ = app.DB.QueryRowContext(ctx, `SELECT last_insert_rowid()`).Scan(&jobID)
	_, _ = app.DB.ExecContext(ctx, `INSERT INTO import_job_items(job_id, ord, source_url, platform, auth_method, module_name, mount_path, conflict_policy, module_id, lore_repository_id, lore_repository_url, lore_work_path, status) VALUES (?, 0, 'https://example.com/r', 'local_git', 'none', 'ModX', 'ModX', 'fail', ?, ?, ?, ?, 'succeeded')`, jobID, mod.ID, mod.RepositoryID, mod.RepositoryURL, modDir)

	rev1 := strings.Repeat("1", 64)
	rev2 := strings.Repeat("4", 64)
	tx, _ := app.DB.BeginTx(ctx, nil)
	_ = history.UpsertCommit(ctx, tx, history.CommitInput{
		ModuleID: mod.ID, LoreRevision: rev1, OriginKind: history.OriginNativeLore,
		AuthorName: "dev", AuthoredUnixMS: 1795000000000, CommittedUnixMS: 1795000000000, Message: "init",
	})
	_ = history.UpsertRef(ctx, tx, history.RefDetail{
		ModuleID: mod.ID, Type: "branch", Name: "main", LoreRevision: rev1, IsDefault: true,
	})
	_ = tx.Commit()

	notifyFile := filepath.Join(t.TempDir(), "push.notify")
	app.Config.History.AutoSyncInterval = 0
	app.Config.History.PushNotifyFile = notifyFile
	app.Config.History.Concurrency = 1

	runner := &mockAutoSyncRunner{
		modBDir:     modDir,
		modBRev:     rev1,
		syncCalls:   map[string]int{},
		branchCalls: map[string]int{},
	}
	app.PublishLore = &loreadapter.Client{Exec: runner}

	runCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go app.runHistoryAutoSync(runCtx, &wg)

	// Advance remote rev and touch notify file.
	runner.mu.Lock()
	runner.modBRev = rev2
	runner.mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	if err := os.WriteFile(notifyFile, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	gotSynced := 0
	for time.Now().Before(deadline) {
		runner.mu.Lock()
		gotSynced = runner.syncCalls[modDir]
		runner.mu.Unlock()
		if gotSynced > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	wg.Wait()

	if gotSynced < 1 {
		t.Fatalf("expected push notify to trigger history sync, got synced=%d", gotSynced)
	}
	var gotRev string
	_ = app.DB.QueryRowContext(ctx, `SELECT lore_revision FROM module_refs WHERE module_id=? AND ref_name='main'`, mod.ID).Scan(&gotRev)
	if gotRev != rev2 {
		t.Fatalf("expected main ref to advance to %s, got %s", rev2, gotRev)
	}
}
