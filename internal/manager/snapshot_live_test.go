package manager

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"lore-monorepo/internal/client"
	"lore-monorepo/internal/config"
	"lore-monorepo/internal/logging"
	"lore-monorepo/internal/loreadapter"
	"lore-monorepo/internal/loreexec"
	"lore-monorepo/internal/project"
	"lore-monorepo/internal/publish"
	"lore-monorepo/internal/token"
	"lore-monorepo/internal/user"
	"strconv"
)

// TestRealSnapshotLive is the B2.5 isolated Lore experiment.
// It is skipped unless LORE_BIN, LORE_SERVER, LORE_GATEWAY_JS and B25_REPORT are set.
func TestRealSnapshotLive(t *testing.T) {
	if os.Getenv("B25_CHILD") == "crash" {
		childCrashPublish(t)
		return
	}
	loreBin := os.Getenv("LORE_BIN")
	serverBin := os.Getenv("LORE_SERVER")
	gatewayJS := os.Getenv("LORE_GATEWAY_JS")
	report := os.Getenv("B25_REPORT")
	if loreBin == "" || serverBin == "" || gatewayJS == "" || report == "" {
		t.Skip("real snapshot test requires LORE_BIN, LORE_SERVER, LORE_GATEWAY_JS, B25_REPORT")
	}
	node := os.Getenv("NODE_BIN")
	if node == "" {
		node = "/opt/codev/nodejs/bin/node"
	}
	root := filepath.Join(report, "run")
	_ = os.RemoveAll(root)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	notes := []string{}
	note := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		notes = append(notes, line)
		t.Log(line)
		_ = os.WriteFile(filepath.Join(root, "notes.txt"), []byte(joinLines(notes)), 0o644)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgrCtx, stopMgr := context.WithCancel(ctx)
	defer stopMgr()
	app := startSnapshotManager(t, mgrCtx, root)
	ca, cert, key := writeSnapshotCerts(t, root)
	srv := startSnapshotLore(t, serverBin, root, cert, key)
	defer srv.Process.Kill()
	if !waitLog(filepath.Join(root, "loreserver.log"), "Registered public gRPC", 40*time.Second) {
		t.Fatal("loreserver did not register gRPC")
	}
	gw := startSnapshotGateway(t, node, gatewayJS, ca, filepath.Join(root, "gateway.jsonl"))
	defer gw.Process.Kill()
	waitPort(t, "127.0.0.1:53647")

	carolID, err := user.Create(context.Background(), app.DB, "test", "carol", "correct-horse", "user")
	if err != nil {
		t.Fatal(err)
	}
	aliceID, err := user.Create(context.Background(), app.DB, "test", "alice", "correct-horse", "user")
	if err != nil {
		t.Fatal(err)
	}
	carol := newLoreExec(loreBin, filepath.Join(root, "auth-carol"))
	if err := loginUser(t, loreBin, app, "carol", carol); err != nil {
		t.Fatal(err)
	}
	base := "grpc://127.0.0.1:53647"
	parentID := createRepo536(t, carol, root, "alpha")
	engineID := createRepo536(t, carol, root, "engine")
	clientID := createRepo536(t, carol, root, "gameclient")
	docsID := createRepo536(t, carol, root, "docs")
	note("repos parent=%s engine=%s gameclient=%s docs=%s", parentID, engineID, clientID, docsID)

	proj, err := project.CreateProject(context.Background(), app.DB, "carol", project.Project{
		Name: "Alpha", ParentRepositoryID: parentID, ParentRepositoryURL: base + "/alpha", CreatedBy: carolID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := project.AddMember(context.Background(), app.DB, "carol", proj.ID, carolID, project.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := project.AddMember(context.Background(), app.DB, "carol", proj.ID, aliceID, project.RoleMember); err != nil {
		t.Fatal(err)
	}
	engine := mustLiveModule(t, app, proj.ID, "Engine", engineID, "Engine")
	game := mustLiveModule(t, app, proj.ID, "GameClient", clientID, "GameClient")
	docs := mustLiveModule(t, app, proj.ID, "Docs", docsID, "Docs")
	for _, id := range []int64{engine.ID, game.ID, docs.ID} {
		if err := project.SetModulePermission(context.Background(), app.DB, "carol", carolID, id, project.PermWrite); err != nil {
			t.Fatal(err)
		}
	}
	if err := project.SetModulePermission(context.Background(), app.DB, "carol", aliceID, engine.ID, project.PermWrite); err != nil {
		t.Fatal(err)
	}
	if err := loginUser(t, loreBin, app, "carol", carol); err != nil {
		t.Fatal(err)
	}

	dirs := map[string]string{"Engine": filepath.Join(root, "mod-engine"), "GameClient": filepath.Join(root, "mod-game"), "Docs": filepath.Join(root, "mod-docs")}
	revs := map[string][]string{}
	for name, dir := range dirs {
		revs[name] = commitSeries(t, carol, dir, base+"/"+slug(name), []string{"v1\n"})
		note("%s revisions %s", name, stringsShort(revs[name]))
	}
	if _, err := user.Create(context.Background(), app.DB, "test", "publisher", "correct-horse", "service"); err != nil {
		t.Fatal(err)
	}
	pubAuth := filepath.Join(root, "auth-publisher")
	pubExec := newLoreExec(loreBin, pubAuth)
	if err := loginUser(t, loreBin, app, "publisher", pubExec); err != nil {
		t.Fatal(err)
	}
	parentDir := filepath.Join(root, "parent")
	if err := os.MkdirAll(parentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cloned := runLore(t, pubExec, parentDir, "clone", base+"/alpha", ".")
	if cloned.ExitCode != 0 {
		t.Fatalf("parent clone %s", trimResult(cloned))
	}
	driver := publish.LoreDriver{Client: &loreadapter.Client{Exec: pubExec, Env: map[string]string{"LORE_AUTH_STORE": "fallback", "LORE_AUTH_PATH": pubAuth}}, ParentURL: base + "/alpha"}
	publisher := publish.Publisher{DB: app.DB, Driver: driver}
	req := publish.Request{ProjectID: proj.ID, ParentDir: parentDir, ModuleDirs: dirs, Actor: "carol", Message: "snapshot"}

	s1 := mustPublish(t, publisher, req)
	note("S1 parent=%s pins=%s", s1.ParentRevision, pinText(s1.Pins))
	if !pinIs(s1.Pins, "Engine", revs["Engine"][0]) || !pinIs(s1.Pins, "GameClient", revs["GameClient"][0]) || !pinIs(s1.Pins, "Docs", revs["Docs"][0]) {
		t.Fatalf("S1 pins %+v", s1.Pins)
	}
	verifyParentClone(t, note, pubExec, root, base+"/alpha", s1)

	refreshParent(t, pubExec, parentDir, base+"/alpha")
	revs["Engine"] = append(revs["Engine"], commitOne(t, carol, dirs["Engine"], "v2\n"))
	s2 := mustPublish(t, publisher, req)
	note("S2 pins=%s", pinText(s2.Pins))
	if !pinIs(s2.Pins, "Engine", revs["Engine"][1]) || !pinIs(s2.Pins, "GameClient", revs["GameClient"][0]) || !pinIs(s2.Pins, "Docs", revs["Docs"][0]) {
		t.Fatalf("S2 %+v", s2.Pins)
	}

	refreshParent(t, pubExec, parentDir, base+"/alpha")
	revs["Engine"] = append(revs["Engine"], commitOne(t, carol, dirs["Engine"], "v3\n"))
	revs["GameClient"] = append(revs["GameClient"], commitOne(t, carol, dirs["GameClient"], "v2\n"))
	revs["Docs"] = append(revs["Docs"], commitOne(t, carol, dirs["Docs"], "v2\n"))
	s3 := mustPublish(t, publisher, req)
	note("S3 pins=%s", pinText(s3.Pins))

	refreshParent(t, pubExec, parentDir, base+"/alpha")
	e3 := revs["Engine"][len(revs["Engine"])-1]
	publisher.AfterCapture = func(context.Context) error {
		revs["Engine"] = append(revs["Engine"], commitOne(t, carol, dirs["Engine"], "v6\n"))
		return nil
	}
	s4 := mustPublish(t, publisher, req)
	publisher.AfterCapture = nil
	note("S4 captured engine=%s later head=%s", pinOf(s4.Pins, "Engine"), revs["Engine"][len(revs["Engine"])-1])
	if pinOf(s4.Pins, "Engine") != e3 {
		t.Fatalf("capture moved with HEAD: pin=%s e3=%s", pinOf(s4.Pins, "Engine"), e3)
	}
	verifyRevisionFile(t, note, pubExec, root, base+"/engine", e3, "v3\n")

	stopProcess(srv)
	srv = startSnapshotLore(t, serverBin, root, cert, key)
	defer srv.Process.Kill()
	if !waitLog(filepath.Join(root, "loreserver.log"), "Registered public gRPC", 40*time.Second) {
		t.Fatal("loreserver did not restart")
	}
	time.Sleep(time.Second)
	info := runLore(t, pubExec, root, "repository", "info", base+"/engine")
	note("after restart repository info exit=%d %s", info.ExitCode, trimResult(info))
	verifyRevisionFile(t, note, pubExec, root, base+"/engine", e3, "v3\n")
	note("historical engine revision still clones after lore restart")

	refreshParent(t, pubExec, parentDir, base+"/alpha")
	publisher.AfterCapture = func(ctx context.Context) error {
		return project.ArchiveModule(ctx, app.DB, "carol", docs.ID)
	}
	held, err := publisher.Publish(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	publisher.AfterCapture = nil
	note("archive during publish kept docs pin=%s", pinOf(held.Pins, "Docs")[:12])
	if pinOf(held.Pins, "Docs") == "" {
		t.Fatal("archive during publish dropped a captured docs pin")
	}
	refreshParent(t, pubExec, parentDir, base+"/alpha")
	s5 := mustPublish(t, publisher, req)
	note("S5 pins=%s", pinText(s5.Pins))
	if pinOf(s5.Pins, "Docs") != "" {
		t.Fatal("archived docs still in new snapshot")
	}
	oldDocs := pinOf(s3.Pins, "Docs")
	if oldDocs == "" {
		t.Fatal("old snapshot lost docs")
	}
	verifyRevisionFile(t, note, pubExec, root, base+"/docs", oldDocs, "v2\n")
	note("archived docs revision still clones from the older snapshot")

	alice := newLoreExec(loreBin, filepath.Join(root, "auth-alice"))
	if err := loginUser(t, loreBin, app, "alice", alice); err != nil {
		t.Fatal(err)
	}
	aliceEngine := runLore(t, alice, root, "clone", base+"/engine", "alice-engine")
	note("alice clone engine exit=%d", aliceEngine.ExitCode)
	if aliceEngine.ExitCode != 0 {
		t.Fatal(trimResult(aliceEngine))
	}
	denied := runLore(t, alice, root, "clone", base+"/gameclient", "alice-game")
	note("alice clone gameclient exit=%d", denied.ExitCode)
	if denied.ExitCode == 0 {
		t.Fatal("alice cloned gameclient")
	}
	aliceAccount, err := user.GetByID(context.Background(), app.DB, aliceID)
	if err != nil {
		t.Fatal(err)
	}
	sample, err := app.Tokens.IssueAccess(strconv.FormatInt(aliceID, 10), aliceAccount.AuthVersion, []token.Resource{{
		ResourceID: "urc-" + engine.RepositoryID, Permission: []string{"access"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	sampleClaims, err := app.Tokens.VerifyAccess(sample)
	sample = ""
	if err != nil {
		t.Fatal(err)
	}
	note("access token expires=%s remaining=%s configured_ttl=5m0s", sampleClaims.Expires.UTC().Format(time.RFC3339), time.Until(sampleClaims.Expires).Round(time.Second))
	if err := project.RevokeModulePermission(context.Background(), app.DB, "carol", aliceID, engine.ID); err != nil {
		t.Fatal(err)
	}
	var still int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM module_permissions mp
		JOIN modules m ON m.module_id=mp.module_id
		WHERE mp.user_id=? AND m.repository_id=? AND m.archived_at IS NULL`, aliceID, engine.RepositoryID).Scan(&still); err != nil {
		t.Fatal(err)
	}
	note("alice engine grants after revoke=%d", still)
	if still != 0 {
		t.Fatal("revoke still lists engine")
	}
	callsBefore := len(app.Bridge.Calls())
	old := runLore(t, alice, root, "clone", base+"/engine", "alice-engine-old")
	exchanges := 0
	for _, call := range app.Bridge.Calls()[callsBefore:] {
		if call.RPC == "ExchangeUserTokenForMultiresourceToken" || call.RPC == "Exchange" {
			exchanges++
		}
	}
	note("alice old credential after revoke exit=%d new_exchanges=%d", old.ExitCode, exchanges)
	fresh := filepath.Join(root, "auth-alice-fresh")
	freshExec := newLoreExec(loreBin, fresh)
	if err := loginUser(t, loreBin, app, "alice", freshExec); err != nil {
		t.Fatal(err)
	}
	after := runLore(t, freshExec, root, "clone", base+"/engine", "alice-engine-2")
	note("alice fresh credential after revoke exit=%d", after.ExitCode)
	if after.ExitCode == 0 {
		t.Fatal("revoked alice cloned engine")
	}
	if err := user.SetStatus(context.Background(), app.DB, "carol", "alice", "disabled"); err != nil {
		t.Fatal(err)
	}
	disabled := newLoreExec(loreBin, filepath.Join(root, "auth-alice-disabled"))
	if err := loginUser(t, loreBin, app, "alice", disabled); err == nil {
		t.Fatal("disabled alice logged in")
	}
	note("alice login after disable rejected")
	oldDisabled := runLore(t, alice, root, "clone", base+"/engine", "alice-engine-disabled")
	note("alice old credential after disable exit=%d", oldDisabled.ExitCode)

	liveConcurrent(t, note, publisher, req, carol, dirs["Engine"])
	liveCrashes(t, note, publisher, req, root, loreBin, pubAuth, base+"/alpha", parentDir, pubExec, carol, dirs["Engine"])

	stopMgr()
	waitPortGone(t, "127.0.0.1:53600")
	waitPortGone(t, "127.0.0.1:53610")
	down := newLoreExec(loreBin, filepath.Join(root, "auth-carol-down"))
	if err := loginUser(t, loreBin, app, "carol", down); err == nil {
		t.Fatal("login succeeded while manager was down")
	}
	note("login while manager down rejected")
	cached := runLore(t, alice, root, "status", "--repository", filepath.Join(root, "alice-engine"))
	note("existing checkout while manager down exit=%d", cached.ExitCode)
	restoredCtx, stopRestored := context.WithCancel(ctx)
	defer stopRestored()
	app = startSnapshotManager(t, restoredCtx, root)
	if err := loginUser(t, loreBin, app, "carol", newLoreExec(loreBin, filepath.Join(root, "auth-carol-back"))); err != nil {
		t.Fatal(err)
	}
	note("login after manager restart succeeded")
	_ = s2
	_ = s4
}

func childCrashPublish(t *testing.T) {
	t.Helper()
	reqPath := os.Getenv("B25_REQ")
	raw, err := os.ReadFile(reqPath)
	if err != nil {
		t.Fatal(err)
	}
	var env childEnv
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	app := openExisting(t, env.Root)
	execer := newLoreExec(env.LoreBin, env.AuthPath)
	driver := publish.LoreDriver{Client: &loreadapter.Client{Exec: execer, Env: map[string]string{"LORE_AUTH_STORE": "fallback", "LORE_AUTH_PATH": env.AuthPath}}, ParentURL: env.ParentURL}
	pub := publish.Publisher{DB: app.DB, Driver: driver, Halt: func(step string) {
		if step == env.Halt {
			os.Exit(75)
		}
	}}
	_, _ = pub.Publish(context.Background(), env.Request)
	os.Exit(76)
}

type childEnv struct {
	Root      string
	LoreBin   string
	AuthPath  string
	ParentURL string
	Halt      string
	Request   publish.Request
}

func liveConcurrent(t *testing.T, note func(string, ...any), pub publish.Publisher, req publish.Request, ex loreexec.Executor, engineDir string) {
	t.Helper()
	commitOne(t, ex, engineDir, "concurrent\n")
	started := make(chan struct{})
	release := make(chan struct{})
	pub.AfterCapture = func(context.Context) error {
		close(started)
		<-release
		return nil
	}
	errCh := make(chan error, 1)
	go func() {
		_, err := pub.Publish(context.Background(), req)
		errCh <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Minute):
		t.Fatal("concurrent publish did not reach capture")
	}
	_, err := pub.Publish(context.Background(), req)
	close(release)
	if !errors.Is(err, publish.ErrBusy) {
		t.Fatalf("second publish %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	pub.AfterCapture = nil
	note("concurrent second publish returned busy; first publish completed")
}

func liveCrashes(t *testing.T, note func(string, ...any), pub publish.Publisher, req publish.Request, root, loreBin, authPath, parentURL, parentDir string, parentEx, moduleEx loreexec.Executor, engineDir string) {
	t.Helper()
	expect := map[string]string{
		"created":   "failed interrupted before capture",
		"captured":  "failed interrupted before push",
		"links":     "failed publish needs human review",
		"committed": "failed publish needs human review",
		"pushed":    "succeeded",
		"verified":  "succeeded",
	}
	for _, step := range []string{"created", "captured", "links", "committed", "pushed", "verified"} {
		if step == "links" || step == "committed" || step == "pushed" || step == "verified" {
			commitOne(t, moduleEx, engineDir, step+"\n")
			refreshParent(t, parentEx, parentDir, parentURL)
		}
		code := crashChild(t, root, loreBin, authPath, parentURL, step, req)
		note("crash %s child_exit=%d", step, code)
		if code != 75 {
			t.Fatalf("crash %s exit %d", step, code)
		}
		if err := pub.Recover(context.Background(), func(int64) (string, error) { return parentDir, nil }); err != nil {
			t.Fatal(err)
		}
		var status string
		var reason sql.NullString
		if err := pub.DB.QueryRow(`SELECT status, error FROM operations WHERE operation_type='snapshot_publish' ORDER BY operation_id DESC LIMIT 1`).Scan(&status, &reason); err != nil {
			t.Fatal(err)
		}
		got := status
		if reason.String != "" {
			got += " " + reason.String
		}
		note("crash %s recovered=%s", step, got)
		if !strings.HasPrefix(got, expect[step]) {
			t.Fatalf("crash %s recovered %s", step, got)
		}
		if err := pub.Recover(context.Background(), func(int64) (string, error) { return parentDir, nil }); err != nil {
			t.Fatal(err)
		}
		refreshParent(t, parentEx, parentDir, parentURL)
	}
}

func crashChild(t *testing.T, root, loreBin, authPath, parentURL, step string, req publish.Request) int {
	t.Helper()
	raw, err := json.Marshal(childEnv{Root: root, LoreBin: loreBin, AuthPath: authPath, ParentURL: parentURL, Halt: step, Request: req})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "crash-"+step+".json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRealSnapshotLive$", "-test.count=1")
	cmd.Env = append(os.Environ(), "B25_CHILD=crash", "B25_REQ="+path)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	_ = os.WriteFile(filepath.Join(root, "crash-"+step+".log"), out, 0o644)
	if cmd.ProcessState == nil {
		t.Fatal(err)
	}
	return cmd.ProcessState.ExitCode()
}

func credentialExpiry(dir string) (issued, expires, ttl string) {
	var latest time.Time
	var iat time.Time
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() || info.Size() > 1<<20 {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for _, field := range strings.Fields(string(body)) {
			parts := strings.Split(field, ".")
			if len(parts) != 3 || !strings.HasPrefix(parts[0], "eyJ") {
				continue
			}
			raw, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				continue
			}
			var payload map[string]any
			if json.Unmarshal(raw, &payload) != nil {
				continue
			}
			exp, _ := payload["exp"].(float64)
			issuedAt, _ := payload["iat"].(float64)
			if exp == 0 {
				continue
			}
			when := time.Unix(int64(exp), 0).UTC()
			if when.After(latest) {
				latest = when
				iat = time.Unix(int64(issuedAt), 0).UTC()
			}
		}
		return nil
	})
	if latest.IsZero() {
		return "unknown", "unknown", "unknown"
	}
	return iat.Format(time.RFC3339), latest.Format(time.RFC3339), latest.Sub(iat).String()
}

func joinLines(lines []string) string { return strings.Join(lines, "\n") }

func stringsShort(in []string) string {
	out := ""
	for _, s := range in {
		if len(s) > 12 {
			s = s[:12]
		}
		out += s + " "
	}
	return out
}

func pinText(pins []publish.Pin) string {
	out := ""
	for _, p := range pins {
		out += p.Name + "=" + p.Revision[:12] + " "
	}
	return out
}

func pinIs(pins []publish.Pin, name, rev string) bool { return pinOf(pins, name) == rev }

func pinOf(pins []publish.Pin, name string) string {
	for _, p := range pins {
		if p.Name == name {
			return p.Revision
		}
	}
	return ""
}

func slug(name string) string {
	switch name {
	case "Engine":
		return "engine"
	case "GameClient":
		return "gameclient"
	case "Docs":
		return "docs"
	default:
		return name
	}
}

func stopProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
}

func refreshParent(t *testing.T, ex loreexec.Executor, dir, url string) {
	t.Helper()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	res := runLore(t, ex, dir, "clone", url, ".")
	if res.ExitCode != 0 {
		t.Fatalf("refresh parent %s", trimResult(res))
	}
}

func mustPublish(t *testing.T, pub publish.Publisher, req publish.Request) publish.Result {
	t.Helper()
	got, err := pub.Publish(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func mustLiveModule(t *testing.T, app *App, projectID int64, name, repo, mount string) *project.Module {
	t.Helper()
	m, err := project.CreateModule(context.Background(), app.DB, "carol", project.Module{
		ProjectID: projectID, Name: name, RepositoryID: repo, RepositoryURL: "grpc://127.0.0.1:53647/" + slug(name), MountPath: mount,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func loginUser(t *testing.T, loreBin string, app *App, name string, ex loreexec.Executor) error {
	t.Helper()
	return client.Login(context.Background(), client.Config{
		ManagerURL: "http://127.0.0.1:53600", LoreBinary: loreBin, AuthURL: "http://127.0.0.1:53610",
		AuthStore: "fallback", AuthPath: ex.Config.Env["LORE_AUTH_PATH"],
	}, name, []byte("correct-horse"), ex)
}

func createRepo536(t *testing.T, ex loreexec.Executor, root, name string) string {
	t.Helper()
	dir := filepath.Join(root, "seed-"+name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	res := runLore(t, ex, dir, "--debug", "--non-interactive", "--json", "repository", "create", "grpc://127.0.0.1:53647/"+name)
	if res.ExitCode != 0 {
		t.Fatalf("create %s %s", name, trimResult(res))
	}
	id := findRepoID(res.Stdout + res.Stderr)
	if id == "" {
		t.Fatalf("create %s returned no id", name)
	}
	return id
}

func storePublisherCredential(t *testing.T, app *App, loreBin, authPath string, userID int64, repos []string) error {
	t.Helper()
	account, err := user.GetByID(context.Background(), app.DB, userID)
	if err != nil {
		return err
	}
	identity, err := app.Tokens.IssueIdentity(itoa(userID), account.Username, account.AuthVersion)
	if err != nil {
		return err
	}
	resources := make([]token.Resource, 0, len(repos))
	for _, id := range repos {
		resources = append(resources, token.Resource{ResourceID: "urc-" + id, Permission: []string{"access"}})
	}
	access, err := app.Tokens.IssueAccess(itoa(userID), account.AuthVersion, resources)
	if err != nil {
		return err
	}
	ex := newLoreExec(loreBin, authPath)
	if res := runLore(t, ex, authPath, "login", "--token-type", "lore", "--auth-url", "http://127.0.0.1:53610", "--token", identity); res.ExitCode != 0 {
		return fmt.Errorf("identity login %s", trimResult(res))
	}
	for _, id := range repos {
		if res := runLore(t, ex, authPath, "login", "--token-type", "lore", "--auth-url", "http://127.0.0.1:53610/"+id, "--token", access); res.ExitCode != 0 {
			return fmt.Errorf("access login %s", trimResult(res))
		}
	}
	return nil
}

func openExisting(t *testing.T, root string) *App {
	t.Helper()
	cfg := snapshotConfig(root)
	app, err := New(cfg, logging.New(io.Discard, logging.Info, "manager"))
	if err != nil {
		t.Fatal(err)
	}
	return app
}

func startSnapshotManager(t *testing.T, ctx context.Context, root string) *App {
	t.Helper()
	cfg := snapshotConfig(root)
	app, err := New(cfg, logging.New(io.Discard, logging.Info, "manager"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = app.Serve(ctx, ln) }()
	waitPort(t, "127.0.0.1:53610")
	return app
}

func writeSnapshotCerts(t *testing.T, root string) (string, string, string) {
	t.Helper()
	return writeGatewayCerts(t, root)
}

func startSnapshotLore(t *testing.T, bin, root, cert, key string) *exec.Cmd {
	t.Helper()
	dir := filepath.Join(root, "server-config")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(root, "store")
	if err := os.MkdirAll(store, 0o755); err != nil {
		t.Fatal(err)
	}
	jwks := filepath.ToSlash(filepath.Join(root, "keys", "jwks.json"))
	body := fmt.Sprintf(`# isolated B2.5 server
[environment.endpoint]
auth_url = "http://127.0.0.1:53610"
[server.auth]
jwt_issuer = "http://127.0.0.1:53610"
jwt_audience = ["127.0.0.1"]
identity_claim = "sub"
baseline_access = "denied"
repository_catalog = "auth_service"
[server.auth.jwk]
endpoint = "file://%s"
[server.quic]
enabled = false
[server.grpc]
enabled = true
host = "127.0.0.1"
port = 53637
verify_client_certs = false
[server.grpc.certificate]
cert_file = "%s"
pkey_file = "%s"
[server.http]
enabled = true
host = "127.0.0.1"
port = 53639
[immutable_store.local]
path = "%s"
[mutable_store.local]
path = "%s"
[topology]
provider = "none"
`, jwks, filepath.ToSlash(cert), filepath.ToSlash(key), filepath.ToSlash(store), filepath.ToSlash(store))
	if err := os.WriteFile(filepath.Join(dir, "local.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("stdbuf", "-oL", "-eL", bin, "--config", dir)
	cmd.Env = append(os.Environ(), "RUST_LOG=info")
	logf, err := os.Create(filepath.Join(root, "loreserver.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = logf
	cmd.Stderr = logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = cmd.Wait() }()
	return cmd
}

func startSnapshotGateway(t *testing.T, node, js, ca, logPath string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(node, js)
	cmd.Env = append(os.Environ(),
		"GATEWAY_HOST=127.0.0.1",
		"GATEWAY_PORT=53647",
		"UPSTREAM_ORIGIN=https://127.0.0.1:53637",
		"UPSTREAM_CA="+ca,
		"GATEWAY_LOG="+logPath,
	)
	out, err := os.Create(filepath.Join(filepath.Dir(logPath), "gateway.err"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = cmd.Wait() }()
	return cmd
}

func snapshotConfig(root string) config.Config {
	return config.Config{
		Listen: "127.0.0.1:53600", ShutdownTimeout: 5 * time.Second,
		DatabasePath: filepath.Join(root, "manager.db"), LoreBinary: os.Getenv("LORE_BIN"),
		CommandTimeout: 2 * time.Minute, LogLevel: "info", LogFormat: "json",
		Auth: config.Auth{
			Issuer: "http://127.0.0.1:53610", Audience: []string{"127.0.0.1"},
			GRPCListen: "127.0.0.1:53610", IdentityTTL: 12 * time.Hour, AccessTTL: 5 * time.Minute,
			PrivateKey: filepath.Join(root, "keys", "identity-active.pem"),
			PublicKey:  filepath.Join(root, "keys", "identity-active.pub.pem"),
			JWKS:       filepath.Join(root, "keys", "jwks.json"),
		},
	}
}

func commitSeries(t *testing.T, ex loreexec.Executor, dir, url string, bodies []string) []string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	res := runLore(t, ex, dir, "clone", url, ".")
	if res.ExitCode != 0 {
		t.Fatalf("clone %s %s", url, trimResult(res))
	}
	var out []string
	for i, body := range bodies {
		out = append(out, commitBody(t, ex, dir, body, fmt.Sprintf("c%d", i+1)))
	}
	return out
}

func commitOne(t *testing.T, ex loreexec.Executor, dir, body string) string {
	t.Helper()
	return commitBody(t, ex, dir, body, "next")
}

func commitBody(t *testing.T, ex loreexec.Executor, dir, body, message string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "marker.txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if res := runLore(t, ex, dir, "stage", "marker.txt"); res.ExitCode != 0 {
		t.Fatal(trimResult(res))
	}
	if res := runLore(t, ex, dir, "commit", message); res.ExitCode != 0 {
		t.Fatal(trimResult(res))
	}
	if res := runLore(t, ex, dir, "push"); res.ExitCode != 0 {
		t.Fatal(trimResult(res))
	}
	st := runLore(t, ex, dir, "status")
	id := findLongHash(st.Stdout + st.Stderr)
	if id == "" {
		t.Fatalf("no revision in %s", trimResult(st))
	}
	return id
}

func findLongHash(s string) string {
	best := ""
	cur := ""
	flush := func() {
		if len(cur) == 64 && (best == "" || cur != best) {
			best = cur
		}
		cur = ""
	}
	for _, c := range s {
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' {
			cur += string(c)
			continue
		}
		flush()
	}
	flush()
	return best
}

func verifyParentClone(t *testing.T, note func(string, ...any), ex loreexec.Executor, root, url string, result publish.Result) {
	t.Helper()
	dir := filepath.Join(root, "check-"+result.ParentRevision[:8])
	_ = os.MkdirAll(dir, 0o755)
	res := runLore(t, ex, dir, "clone", url, ".")
	if res.ExitCode != 0 {
		t.Fatal(trimResult(res))
	}
	links := runLore(t, ex, dir, "link", "list")
	note("link list %s", trimResult(links))
	for _, pin := range result.Pins {
		if !containsAll(links.Stdout+links.Stderr, pin.MountPath, pin.Revision) {
			t.Fatalf("missing pin %s %s", pin.MountPath, pin.Revision)
		}
	}
}

func verifyRevisionFile(t *testing.T, note func(string, ...any), ex loreexec.Executor, root, url, rev, want string) {
	t.Helper()
	dir := filepath.Join(root, "rev-"+rev[:8])
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	res := runLore(t, ex, root, "clone", "--revision", rev, url, dir)
	if res.ExitCode != 0 {
		note("historical clone failed rev=%s %s", rev, trimResult(res))
		t.Fatal(trimResult(res))
	}
	body, err := os.ReadFile(filepath.Join(dir, "marker.txt"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	note("rev %s sha256=%s match=%v", rev[:12], hex.EncodeToString(sum[:8]), string(body) == want)
	if string(body) != want {
		t.Fatalf("content %q want %q", body, want)
	}
}

func containsAll(text string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(text, p) {
			return false
		}
	}
	return true
}
