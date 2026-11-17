package manager

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lore-monorepo/internal/client"
	"lore-monorepo/internal/config"
	"lore-monorepo/internal/gitimport"
	"lore-monorepo/internal/logging"
	"lore-monorepo/internal/loreadapter"
	"lore-monorepo/internal/loreexec"
	"lore-monorepo/internal/project"
	"lore-monorepo/internal/user"
)

const (
	importPushManager = "127.0.0.1:53700"
	importPushAuth    = "127.0.0.1:53710"
	importPushLore    = "127.0.0.1:53737"
	importPushHTTP    = "127.0.0.1:53739"
	importPushBase    = "grpcs://127.0.0.1:53737"
)

// TestRealImportPushSemantics records the Lore 0.10.1 behavior that the Git
// importer relies on. It is completely isolated and opt-in.
func TestRealImportPushSemantics(t *testing.T) {
	loreBin := os.Getenv("LORE_BIN")
	serverBin := os.Getenv("LORE_SERVER")
	report := os.Getenv("IMPORT_PUSH_REPORT")
	if loreBin == "" || serverBin == "" || report == "" {
		t.Skip("requires LORE_BIN, LORE_SERVER and IMPORT_PUSH_REPORT")
	}
	root := filepath.Join(report, "run")
	_ = os.RemoveAll(root)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app := startImportPushManager(t, ctx, root)
	accountID, err := user.Create(ctx, app.DB, "test", "importer", "correct-horse", "user")
	if err != nil {
		t.Fatal(err)
	}
	ca, cert, key := writeSnapshotCerts(t, root)
	server := startImportPushLore(t, serverBin, root, cert, key)
	defer server.Process.Kill()
	if !waitLog(filepath.Join(root, "loreserver.log"), "Registered public gRPC", 40*time.Second) {
		t.Fatal("isolated lore server did not become ready")
	}

	authDir := filepath.Join(root, "auth")
	ex := loreexec.Executor{Config: loreexec.Config{
		Binary:  loreBin,
		Timeout: 2 * time.Minute,
		Env: map[string]string{
			"LORE_AUTH_STORE": "fallback",
			"LORE_AUTH_PATH":  authDir,
			"SSL_CERT_FILE":   ca,
		},
	}}
	if err := client.Login(ctx, client.Config{
		ManagerURL: "http://" + importPushManager,
		LoreBinary: loreBin,
		AuthURL:    "http://" + importPushAuth,
		RemoteURL:  importPushBase + "/bootstrap",
		AuthStore:  "fallback",
		AuthPath:   authDir,
		CAFile:     ca,
	}, "importer", []byte("correct-horse"), ex); err != nil {
		t.Fatal(err)
	}

	projectRow, err := project.CreateProject(ctx, app.DB, "test", project.Project{
		Name:                "PushLab",
		ParentRepositoryID:  "00112233445566778899aabbccddeeff",
		ParentRepositoryURL: importPushBase + "/00112233445566778899aabbccddeeff",
		CreatedBy:           accountID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := project.AddMember(ctx, app.DB, "test", projectRow.ID, accountID, project.RoleAdmin); err != nil {
		t.Fatal(err)
	}

	results := map[string]any{}
	for _, tc := range []struct {
		name       string
		pushArgv   []string
		wantPushOK bool
	}{
		{name: "branch-push", pushArgv: []string{"branch", "push", "--repository"}, wantPushOK: true},
		{name: "push", pushArgv: []string{"push", "--repository"}, wantPushOK: true},
	} {
		id := createImportPushRepo(t, ex, root, tc.name)
		mod, err := project.CreateModule(ctx, app.DB, "test", project.Module{
			ProjectID: projectRow.ID, Name: tc.name, RepositoryID: id,
			RepositoryURL: importPushBase + "/" + id, MountPath: tc.name,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := project.SetModulePermission(ctx, app.DB, "test", accountID, mod.ID, project.PermWrite); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(root, "work-"+tc.name)
		if res := runLore(t, ex, root, "clone", importPushBase+"/"+id, dir); res.ExitCode != 0 {
			t.Fatalf("%s clone: %s", tc.name, trimResult(res))
		}
		first := commitOffline(t, ex, dir, "one", "c1")
		if res := runLore(t, ex, dir, "push", "--repository", dir); res.ExitCode != 0 {
			t.Fatalf("%s seed push: %s", tc.name, trimResult(res))
		}
		second := commitOffline(t, ex, dir, "two", "c2")
		third := commitOffline(t, ex, dir, "three", "c3")
		argv := append([]string{}, tc.pushArgv...)
		argv = append(argv, dir, "main")
		if tc.name == "push" {
			argv = []string{"push", "--repository", dir, "main"}
		}
		res := runLore(t, ex, dir, argv...)
		if (res.ExitCode == 0) != tc.wantPushOK {
			t.Fatalf("%s exit=%d wantOK=%v: %s", tc.name, res.ExitCode, tc.wantPushOK, trimResult(res))
		}
		remote := runLore(t, ex, dir, "--json", "status", "--revision-only", "--repository", dir)
		results[tc.name] = map[string]any{
			"repository_id": id,
			"first":         first, "second": second, "third": third,
			"push_exit":     res.ExitCode,
			"push_stdout":   redactText(res.Stdout),
			"push_stderr":   redactText(res.Stderr),
			"status_exit":   remote.ExitCode,
			"status_stdout": redactText(remote.Stdout),
		}
	}
	results["shared-dag"] = exerciseSharedDAG(t, ctx, app, ex, root, projectRow.ID, accountID)
	interrupted := exerciseInterruptedPush(t, ctx, app, ex, root, projectRow.ID, accountID)
	results["interrupted-push"] = interrupted
	results["git-import"] = exerciseRemoteGitImport(t, ctx, app, ex, root)
	writeReport(report, results)
}

func exerciseRemoteGitImport(t *testing.T, ctx context.Context, app *App, ex loreexec.Executor, root string) map[string]any {
	t.Helper()
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "git-source")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	runGitPushLab(t, gitBin, source, nil, "init", "-b", "main")
	if err := os.WriteFile(filepath.Join(source, "root.txt"), []byte("root"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitPushLab(t, gitBin, source, nil, "add", ".")
	runGitPushLab(t, gitBin, source, nil, "commit", "-m", "root")
	runGitPushLab(t, gitBin, source, nil, "checkout", "-b", "feature")
	if err := os.WriteFile(filepath.Join(source, "feature.txt"), []byte("feature"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitPushLab(t, gitBin, source, nil, "add", ".")
	runGitPushLab(t, gitBin, source, nil, "commit", "-m", "feature")
	runGitPushLab(t, gitBin, source, nil, "checkout", "main")
	if err := os.WriteFile(filepath.Join(source, "main.txt"), []byte("main"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitPushLab(t, gitBin, source, nil, "add", ".")
	runGitPushLab(t, gitBin, source, nil, "commit", "-m", "main")
	runGitPushLab(t, gitBin, source, nil, "merge", "--no-ff", "-m", "merge feature", "feature")

	importer := gitimport.Importer{
		DB: app.DB, Lore: &loreadapter.Client{Exec: ex, Env: ex.Config.Env},
		GitBinary: gitBin, WorkspaceRoot: filepath.Join(root, "import-work"),
		RemoteBaseURL: importPushBase, RestrictLocalSources: true,
		AllowedLocalDirs: []string{root},
	}
	manifest := gitimport.Manifest{
		JobKey: "push-lab-import", Project: "PushLab",
		Repositories: []gitimport.RepoSpec{{
			SourceURL: source, ModuleName: "ImportDAG", MountPath: "ImportDAG",
			Platform: gitimport.PlatformLocalGit, LFSMode: gitimport.LFSModeHydrate,
		}},
	}
	result, err := importer.Run(ctx, "importer", manifest)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "succeeded" || len(result.Items) != 1 || !result.Items[0].Verification.Passed {
		t.Fatalf("remote import failed: %+v", result)
	}
	item := result.Items[0]
	check := filepath.Join(root, "check-import-dag")
	clone := runLore(t, ex, root, "clone", item.LoreRepositoryURL, check)
	if clone.ExitCode != 0 {
		t.Fatal(trimResult(clone))
	}
	history := runLore(t, ex, check, "--json", "revision", "history", "--repository", check, "20")
	if history.ExitCode != 0 || strings.Count(history.Stdout, `"tagName":"revisionHistoryEntry"`) < 3 {
		t.Fatalf("remote history incomplete: %s", trimResult(history))
	}
	again, err := importer.Run(ctx, "importer", manifest)
	if err != nil || again.Status != "succeeded" {
		t.Fatalf("idempotent rerun failed: %+v %v", again, err)
	}
	return map[string]any{
		"repository_id":     item.LoreRepositoryID,
		"source_commits":    item.Verification.SourceCommits,
		"indexed_commits":   item.Verification.IndexedCommits,
		"source_branches":   item.Verification.SourceBranches,
		"imported_branches": item.Verification.ImportedBranches,
		"merge_commits":     item.Verification.MergeCommitsVerified,
		"clone_exit":        clone.ExitCode,
	}
}

func runGitPushLab(t *testing.T, gitBin, dir string, extra map[string]string, args ...string) {
	t.Helper()
	cmd := exec.Command(gitBin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Push Lab", "GIT_AUTHOR_EMAIL=push@example.com",
		"GIT_COMMITTER_NAME=Push Lab", "GIT_COMMITTER_EMAIL=push@example.com",
	)
	for key, value := range extra {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
}

func exerciseInterruptedPush(t *testing.T, ctx context.Context, app *App, ex loreexec.Executor, root string, projectID, accountID int64) map[string]any {
	t.Helper()
	id := createImportPushRepo(t, ex, root, "interrupted-push")
	mod, err := project.CreateModule(ctx, app.DB, "test", project.Module{
		ProjectID: projectID, Name: "interrupted-push", RepositoryID: id,
		RepositoryURL: importPushBase + "/" + id, MountPath: "interrupted-push",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := project.SetModulePermission(ctx, app.DB, "test", accountID, mod.ID, project.PermWrite); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "work-interrupted-push")
	if res := runLore(t, ex, root, "clone", importPushBase+"/"+id, dir); res.ExitCode != 0 {
		t.Fatal(trimResult(res))
	}
	_ = commitOffline(t, ex, dir, "seed", "seed")
	if res := runLore(t, ex, dir, "branch", "push", "--repository", dir, "main"); res.ExitCode != 0 {
		t.Fatal(trimResult(res))
	}
	var tip string
	for i := 0; i < 80; i++ {
		body := strings.Repeat(fmt.Sprintf("%04d", i), 32<<10)
		tip = commitOffline(t, ex, dir, body, fmt.Sprintf("bulk-%d", i))
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(ex.Config.Binary, "--non-interactive", "branch", "push", "--repository", dir, "main")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"LORE_AUTH_STORE="+ex.Config.Env["LORE_AUTH_STORE"],
		"LORE_AUTH_PATH="+ex.Config.Env["LORE_AUTH_PATH"],
		"SSL_CERT_FILE="+ex.Config.Env["SSL_CERT_FILE"],
	)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	retry := runLore(t, ex, dir, "branch", "push", "--repository", dir, "main")
	client := loreadapter.Client{Exec: ex, Env: ex.Config.Env}
	remoteBranches, listErr := client.ListBranchesAt(ctx, dir, true)
	retryAfterList := runLore(t, ex, dir, "branch", "push", "--repository", dir, "main")
	pushAfterList := runLore(t, ex, dir, "push", "--repository", dir, "main")
	return map[string]any{
		"repository_id": id, "tip": tip,
		"interrupted_stdout":      redactText(stdout.String()),
		"interrupted_stderr":      redactText(stderr.String()),
		"retry_exit":              retry.ExitCode,
		"retry_stdout":            redactText(retry.Stdout),
		"retry_stderr":            redactText(retry.Stderr),
		"remote_list_error":       fmt.Sprint(listErr),
		"remote_branches":         fmt.Sprintf("%+v", remoteBranches),
		"retry_after_list_exit":   retryAfterList.ExitCode,
		"retry_after_list_stdout": redactText(retryAfterList.Stdout),
		"retry_after_list_stderr": redactText(retryAfterList.Stderr),
		"push_after_list_exit":    pushAfterList.ExitCode,
		"push_after_list_stdout":  redactText(pushAfterList.Stdout),
		"push_after_list_stderr":  redactText(pushAfterList.Stderr),
	}
}

func exerciseSharedDAG(t *testing.T, ctx context.Context, app *App, ex loreexec.Executor, root string, projectID, accountID int64) map[string]any {
	t.Helper()
	id := createImportPushRepo(t, ex, root, "shared-dag")
	mod, err := project.CreateModule(ctx, app.DB, "test", project.Module{
		ProjectID: projectID, Name: "shared-dag", RepositoryID: id,
		RepositoryURL: importPushBase + "/" + id, MountPath: "shared-dag",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := project.SetModulePermission(ctx, app.DB, "test", accountID, mod.ID, project.PermWrite); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "work-shared-dag")
	if res := runLore(t, ex, root, "clone", importPushBase+"/"+id, dir); res.ExitCode != 0 {
		t.Fatal(trimResult(res))
	}
	client := loreadapter.Client{Exec: ex, Env: ex.Config.Env}
	c1 := commitOffline(t, ex, dir, "root", "c1")
	if err := client.PushBranch(ctx, dir, "main"); err != nil {
		t.Fatal(err)
	}
	if err := client.CreateBranchSlash(ctx, dir, "feature", true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "feature.txt"), []byte("feature"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := client.StageScan(ctx, dir, true); err != nil {
		t.Fatal(err)
	}
	feature, err := client.CommitFull(ctx, dir, "feature", false, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SwitchBranchRevision(ctx, dir, "main", c1, true, true); err != nil {
		t.Fatal(err)
	}
	main2 := commitOffline(t, ex, dir, "main-two", "main2")
	if err := client.PushBranch(ctx, dir, "feature"); err != nil {
		t.Fatalf("push feature: %v", err)
	}
	if err := client.PushBranch(ctx, dir, "main"); err != nil {
		t.Fatalf("push main: %v", err)
	}
	if _, err := client.MergeStartNoCommit(ctx, dir, "feature", true); err != nil {
		t.Fatal(err)
	}
	if err := client.StageScan(ctx, dir, true); err != nil {
		t.Fatal(err)
	}
	merge, err := client.CommitFull(ctx, dir, "merge feature", true, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.PushBranch(ctx, dir, "main"); err != nil {
		t.Fatalf("push merge: %v", err)
	}
	check := filepath.Join(root, "check-shared-dag")
	clone := runLore(t, ex, root, "clone", importPushBase+"/"+id, check)
	if clone.ExitCode != 0 {
		t.Fatal(trimResult(clone))
	}
	branches := runLore(t, ex, check, "branch", "list", "--repository", check)
	if branches.ExitCode != 0 || !strings.Contains(branches.Stdout, "feature") {
		t.Fatalf("remote branches: %s", trimResult(branches))
	}
	return map[string]any{
		"repository_id": id, "root": c1, "feature": feature,
		"main2": main2, "merge": merge, "clone_exit": clone.ExitCode,
		"branches": redactText(branches.Stdout + branches.Stderr),
	}
}

func startImportPushManager(t *testing.T, ctx context.Context, root string) *App {
	t.Helper()
	cfg := config.Config{
		Listen: importPushManager, ShutdownTimeout: 5 * time.Second,
		DatabasePath: filepath.Join(root, "manager.db"), LoreBinary: os.Getenv("LORE_BIN"),
		CommandTimeout: 2 * time.Minute, LogLevel: "info", LogFormat: "json",
		Auth: config.Auth{
			Issuer: "http://" + importPushAuth, Audience: []string{"127.0.0.1"},
			GRPCListen: importPushAuth, IdentityTTL: 12 * time.Hour, AccessTTL: 5 * time.Minute,
			PrivateKey: filepath.Join(root, "keys", "identity-active.pem"),
			PublicKey:  filepath.Join(root, "keys", "identity-active.pub.pem"),
			JWKS:       filepath.Join(root, "keys", "jwks.json"),
		},
	}
	app, err := New(cfg, logging.New(io.Discard, logging.Info, "manager"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = app.Serve(ctx, ln) }()
	waitPort(t, importPushAuth)
	return app
}

func startImportPushLore(t *testing.T, bin, root, cert, key string) *exec.Cmd {
	t.Helper()
	dir := filepath.Join(root, "server-config")
	store := filepath.Join(root, "store")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store, 0o755); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`[environment.endpoint]
auth_url = "http://%s"
[server.auth]
jwt_issuer = "http://%s"
jwt_audience = ["127.0.0.1"]
[server.auth.jwk]
endpoint = "file://%s"
[server.quic]
enabled = false
[server.grpc]
enabled = true
host = "127.0.0.1"
port = 53737
verify_client_certs = false
[server.grpc.certificate]
cert_file = "%s"
pkey_file = "%s"
[server.http]
enabled = true
host = "127.0.0.1"
port = 53739
[immutable_store.local]
path = "%s"
[mutable_store.local]
path = "%s"
[topology]
provider = "none"
`, importPushAuth, importPushAuth, filepath.ToSlash(filepath.Join(root, "keys", "jwks.json")),
		filepath.ToSlash(cert), filepath.ToSlash(key), filepath.ToSlash(store), filepath.ToSlash(store))
	if err := os.WriteFile(filepath.Join(dir, "local.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("stdbuf", "-oL", "-eL", bin, "--config", dir)
	cmd.Env = append(os.Environ(), "RUST_LOG=info", "SSL_CERT_FILE="+cert)
	logFile, err := os.Create(filepath.Join(root, "loreserver.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = cmd.Wait() }()
	return cmd
}

func createImportPushRepo(t *testing.T, ex loreexec.Executor, root, name string) string {
	t.Helper()
	dir := filepath.Join(root, "seed-"+name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	res := runLore(t, ex, dir, "--json", "repository", "create", importPushBase+"/"+name)
	if res.ExitCode != 0 {
		t.Fatalf("%s create: %s", name, trimResult(res))
	}
	id := findRepoID(res.Stdout + res.Stderr)
	if id == "" {
		t.Fatalf("%s: repository id missing", name)
	}
	return id
}

func commitOffline(t *testing.T, ex loreexec.Executor, dir, body, message string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "marker.txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	client := loreadapter.Client{Exec: ex, Env: ex.Config.Env}
	if err := client.StageScan(context.Background(), dir, true); err != nil {
		t.Fatal(err)
	}
	id, err := client.CommitFull(context.Background(), dir, message, false, true)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
