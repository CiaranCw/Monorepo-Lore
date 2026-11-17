package manager

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lore-monorepo/internal/client"
	"lore-monorepo/internal/config"
	"lore-monorepo/internal/logging"
	"lore-monorepo/internal/loreadapter"
	"lore-monorepo/internal/loreexec"
	"lore-monorepo/internal/project"
	"lore-monorepo/internal/user"
)

// TestBackgroundServiceSyncAndPersistentLoginLive exercises:
//  1. Service account credential expiry recovery during background history sync
//  2. Disabled service account blocking sync until re-enabled
//  3. User persistent session surviving expired Lore token and Manager restart
func TestBackgroundServiceSyncAndPersistentLoginLive(t *testing.T) {
	loreBin := os.Getenv("LORE_BIN")
	serverBin := os.Getenv("LORE_SERVER")
	if loreBin == "" || serverBin == "" {
		t.Skip("requires LORE_BIN and LORE_SERVER")
	}

	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start isolated Manager + AuthBridge + Lore Server on 537xx ports.
	app := startImportPushManager(t, ctx, root)
	ca, cert, key := writeSnapshotCerts(t, root)
	srv := startImportPushLore(t, serverBin, root, cert, key)
	defer srv.Process.Kill()
	if !waitLog(filepath.Join(root, "loreserver.log"), "Registered public gRPC", 40*time.Second) {
		t.Fatal("isolated lore server did not become ready")
	}

	adminID, err := user.Create(ctx, app.DB, "test", "admin", "pw", "user")
	if err != nil {
		t.Fatal(err)
	}
	aliceID, err := user.Create(ctx, app.DB, "test", "alice", "pw", "user")
	if err != nil {
		t.Fatal(err)
	}
	pubID, err := user.Create(ctx, app.DB, "test", "kubee-publisher", "pub-pw", "service")
	if err != nil {
		t.Fatal(err)
	}

	pubAuth := filepath.Join(root, "auth-pub")
	pubExec := loreexec.Executor{Config: loreexec.Config{
		Binary:  loreBin,
		Timeout: time.Minute,
		Env: map[string]string{
			"LORE_AUTH_STORE": "fallback",
			"LORE_AUTH_PATH":  pubAuth,
			"SSL_CERT_FILE":   ca,
		},
	}}
	// Simulate an expired publisher Lore token on disk.
	app.Tokens.SetClock(func() time.Time { return time.Now().Add(-24 * time.Hour) })
	if err := client.Login(ctx, client.Config{
		ManagerURL: "http://" + importPushManager, LoreBinary: loreBin,
		AuthURL: "http://" + importPushAuth, AuthStore: "fallback", AuthPath: pubAuth, CAFile: ca,
	}, "kubee-publisher", []byte("pub-pw"), pubExec); err != nil {
		t.Fatal(err)
	}
	app.Tokens.SetClock(time.Now)

	app.PublishLore = &loreadapter.Client{Exec: pubExec, Env: pubExec.Config.Env}
	app.PublishRoot = filepath.Join(root, "pub-work")
	app.Config.Publish.ServiceUser = "kubee-publisher"

	// Create repository and module using a live alice token, then grant publisher too.
	aliceAuth := filepath.Join(root, "auth-alice")
	aliceExec := loreexec.Executor{Config: loreexec.Config{
		Binary: loreBin, Timeout: time.Minute,
		Env: map[string]string{"LORE_AUTH_STORE": "fallback", "LORE_AUTH_PATH": aliceAuth, "SSL_CERT_FILE": ca},
	}}
	aliceCfg := client.Config{
		ManagerURL: "http://" + importPushManager, LoreBinary: loreBin,
		AuthURL: "http://" + importPushAuth, AuthStore: "fallback", AuthPath: aliceAuth, CAFile: ca,
	}
	if err := client.Login(ctx, aliceCfg, "alice", []byte("pw"), aliceExec); err != nil {
		t.Fatal(err)
	}
	// Ensure PublishLore passes the same AuthURL if needed, and verify isolated login succeeds.
	app.PublishLore = &loreadapter.Client{Exec: pubExec, Env: pubExec.Config.Env}
	repoID := createImportPushRepo(t, aliceExec, root, "eng")
	proj, err := project.CreateProject(ctx, app.DB, "admin", project.Project{
		Name: "Alpha", ParentRepositoryID: "00112233445566778899aabbccddeeff",
		ParentRepositoryURL: importPushBase + "/00112233445566778899aabbccddeeff", CreatedBy: adminID,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = project.AddMember(ctx, app.DB, "admin", proj.ID, adminID, project.RoleAdmin)
	_ = project.AddMember(ctx, app.DB, "admin", proj.ID, aliceID, project.RoleMember)
	mod, err := project.CreateModule(ctx, app.DB, "admin", project.Module{
		ProjectID: proj.ID, Name: "Engine", RepositoryID: repoID,
		RepositoryURL: importPushBase + "/" + repoID, MountPath: "Engine",
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = project.SetModulePermission(ctx, app.DB, "admin", aliceID, mod.ID, project.PermWrite)
	_ = project.SetModulePermission(ctx, app.DB, "admin", pubID, mod.ID, project.PermWrite)

	// Push 1 commit as alice into Engine.
	workAlice := filepath.Join(root, "work-alice")
	if res := runLore(t, aliceExec, root, "clone", importPushBase+"/"+repoID, workAlice); res.ExitCode != 0 {
		t.Fatalf("alice clone: %s", trimResult(res))
	}
	rev1 := commitOffline(t, aliceExec, workAlice, "v1\n", "c1")
	if res := runLore(t, aliceExec, workAlice, "push", "--repository", workAlice, "main"); res.ExitCode != 0 {
		t.Fatalf("alice push: %s", trimResult(res))
	}

	// 1. Background history sync succeeds despite expired on-disk publisher token.
	stats, err := app.syncModuleHistoryOnServer(ctx, mod, "")
	if err != nil || stats.CommitsUpserted < 1 {
		t.Fatalf("expected dynamic service token sync to succeed: stats=%+v err=%v", stats, err)
	}
	var indexed int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM module_commits WHERE module_id=? AND lore_revision=?`, mod.ID, rev1).Scan(&indexed); err != nil || indexed != 1 {
		t.Fatalf("rev1 not indexed after sync: %d %v", indexed, err)
	}

	// 2. Disable service account -> background sync must fail closed.
	if err := user.SetStatus(ctx, app.DB, "admin", "kubee-publisher", "disabled"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.syncModuleHistoryOnServer(ctx, mod, ""); err == nil {
		t.Fatal("disabled service account must fail background sync")
	}
	// Re-enable -> background sync recovers.
	if err := user.SetStatus(ctx, app.DB, "admin", "kubee-publisher", "active"); err != nil {
		t.Fatal(err)
	}
	rev2 := commitOffline(t, aliceExec, workAlice, "v2\n", "c2")
	if res := runLore(t, aliceExec, workAlice, "push", "--repository", workAlice, "main"); res.ExitCode != 0 {
		t.Fatalf("alice push 2: %s", trimResult(res))
	}
	stats2, err := app.syncModuleHistoryOnServer(ctx, mod, "")
	if err != nil || stats2.CommitsUpserted < 1 {
		t.Fatalf("sync after re-enable failed: %+v %v", stats2, err)
	}
	var indexed2 int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM module_commits WHERE module_id=? AND lore_revision=?`, mod.ID, rev2).Scan(&indexed2); err != nil || indexed2 != 1 {
		t.Fatalf("rev2 not indexed: %d %v", indexed2, err)
	}

	// 3. User persistent session survives expired Lore token AND Manager restart.
	if err := client.EnsureLoreCredential(ctx, aliceCfg, aliceExec); err != nil {
		t.Fatalf("EnsureLoreCredential: %v", err)
	}
	// Overwrite Lore tokenstore with an expired token while keeping lore-mono-session.tok intact,
	// then restart Manager (new App instance reading same DB and keys).
	app.Tokens.SetClock(func() time.Time { return time.Now().Add(-24 * time.Hour) })
	expiredTok, _ := app.Tokens.IssueIdentity("2", "alice", 1)
	app.Tokens.SetClock(time.Now)
	if res := runLore(t, aliceExec, root, "login", "--token-type", "lore", "--token", expiredTok, "--auth-url", "http://"+importPushAuth, importPushBase+"/"+repoID); res.ExitCode != 0 {
		t.Fatalf("overwrite expired lore token: %s", trimResult(res))
	}

	cancel()
	waitPortGone(t, importPushAuth)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	app2 := startImportPushManager(t, ctx2, root)
	_ = app2

	if err := client.EnsureLoreCredential(ctx2, aliceCfg, aliceExec); err != nil {
		t.Fatalf("silent refresh after Manager restart failed: %v", err)
	}
	if res := runLore(t, aliceExec, workAlice, "sync", "--repository", workAlice); res.ExitCode != 0 {
		t.Fatalf("real lore sync after silent refresh failed: %s", trimResult(res))
	}
}

func TestServiceSyncFailsClosedWithoutActiveServiceUser(t *testing.T) {
	app := testApp(t, fakeLore(t))
	ctx := context.Background()
	adminID, _ := user.Create(ctx, app.DB, "test", "admin", "pw", "user")
	pubID, _ := user.Create(ctx, app.DB, "test", "kubee-publisher", "pw", "service")
	proj, _ := project.CreateProject(ctx, app.DB, "admin", project.Project{
		Name: "Alpha", ParentRepositoryID: "00112233445566778899aabbccddeeff",
		ParentRepositoryURL: "grpc://127.0.0.1:53547/parent", CreatedBy: adminID,
	})
	mod, _ := project.CreateModule(ctx, app.DB, "admin", project.Module{
		ProjectID: proj.ID, Name: "Engine", RepositoryID: "0123456789abcdef0123456789abcdef",
		RepositoryURL: "grpc://127.0.0.1:53547/engine", MountPath: "Engine",
	})
	_ = user.SetStatus(ctx, app.DB, "admin", "kubee-publisher", "disabled")
	_ = pubID
	app.Config.Publish.ServiceUser = "kubee-publisher"
	app.PublishLore = &loreadapter.Client{Exec: loreexec.Executor{Config: loreexec.Config{Binary: app.Config.LoreBinary}}}

	if _, err := app.syncModuleHistoryOnServer(ctx, mod, ""); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected disabled service account error, got %v", err)
	}

	// Silence unused imports if helper evolves.
	_ = config.Auth{}
	_ = http.StatusOK
	_ = httptest.NewServer
	_ = logging.Info
}
