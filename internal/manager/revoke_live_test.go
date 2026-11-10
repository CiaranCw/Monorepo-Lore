package manager

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"lore-monorepo/internal/project"
	"lore-monorepo/internal/token"
	"lore-monorepo/internal/user"
)

// TestRevokeWithoutNewExchange uses the original Lore credential after a
// grant is removed. It does not log in again and does not ask for a new
// access token. Clone, push, and sync are recorded separately from a later
// fresh login.
func TestRevokeWithoutNewExchange(t *testing.T) {
	loreBin := os.Getenv("LORE_BIN")
	serverBin := os.Getenv("LORE_SERVER")
	gatewayJS := os.Getenv("LORE_GATEWAY_JS")
	report := os.Getenv("B25_REPORT")
	if loreBin == "" || serverBin == "" || gatewayJS == "" || report == "" {
		t.Skip("revoke test requires LORE_BIN, LORE_SERVER, LORE_GATEWAY_JS, B25_REPORT")
	}
	node := os.Getenv("NODE_BIN")
	if node == "" {
		node = "/opt/codev/nodejs/bin/node"
	}
	root := filepath.Join(report, "revoke")
	_ = os.RemoveAll(root)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app := startSnapshotManager(t, ctx, root)
	ca, cert, key := writeSnapshotCerts(t, root)
	srv := startSnapshotLore(t, serverBin, root, cert, key)
	defer srv.Process.Kill()
	if !waitLog(filepath.Join(root, "loreserver.log"), "Registered public gRPC", 40*time.Second) {
		t.Fatal("loreserver did not register")
	}
	gw := startSnapshotGateway(t, node, gatewayJS, ca, filepath.Join(root, "gateway.jsonl"))
	defer gw.Process.Kill()
	waitPort(t, "127.0.0.1:53647")

	carol := newLoreExec(loreBin, filepath.Join(root, "auth-carol"))
	carolID, err := user.Create(context.Background(), app.DB, "test", "carol", "correct-horse", "user")
	if err != nil {
		t.Fatal(err)
	}
	aliceID, err := user.Create(context.Background(), app.DB, "test", "alice", "correct-horse", "user")
	if err != nil {
		t.Fatal(err)
	}
	if err := loginUser(t, loreBin, app, "carol", carol); err != nil {
		t.Fatal(err)
	}
	base := "grpc://127.0.0.1:53647"
	engineID := createRepo536(t, carol, root, "engine")
	proj, err := project.CreateProject(context.Background(), app.DB, "carol", project.Project{
		Name: "Alpha", ParentRepositoryID: createRepo536(t, carol, root, "alpha"), ParentRepositoryURL: base + "/alpha", CreatedBy: carolID,
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
	engine, err := project.CreateModule(context.Background(), app.DB, "carol", project.Module{
		ProjectID: proj.ID, Name: "Engine", RepositoryID: engineID, RepositoryURL: base + "/engine", MountPath: "Engine",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := project.SetModulePermission(context.Background(), app.DB, "carol", aliceID, engine.ID, project.PermWrite); err != nil {
		t.Fatal(err)
	}
	alice := newLoreExec(loreBin, filepath.Join(root, "auth-alice"))
	if err := loginUser(t, loreBin, app, "alice", alice); err != nil {
		t.Fatal(err)
	}
	if res := runLore(t, alice, root, "clone", base+"/engine", "engine-work"); res.ExitCode != 0 {
		t.Fatal(trimResult(res))
	}
	work := filepath.Join(root, "engine-work")
	commitOne(t, alice, work, "v1\n")
	account, err := user.GetByID(context.Background(), app.DB, aliceID)
	if err != nil {
		t.Fatal(err)
	}
	sample, err := app.Tokens.IssueAccess(itoa(aliceID), account.AuthVersion, []token.Resource{{
		ResourceID: "urc-" + engineID, Permission: []string{"access"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := app.Tokens.VerifyAccess(sample)
	sample = ""
	if err != nil {
		t.Fatal(err)
	}
	remaining := time.Until(claims.Expires).Round(time.Second)
	t.Logf("access expires=%s remaining=%s", claims.Expires.UTC().Format(time.RFC3339), remaining)
	if remaining <= 0 {
		t.Fatal("token already expired")
	}
	if err := project.RevokeModulePermission(context.Background(), app.DB, "carol", aliceID, engine.ID); err != nil {
		t.Fatal(err)
	}
	before := len(app.Bridge.Calls())
	cloned := runLore(t, alice, root, "clone", base+"/engine", "engine-old")
	synced := runLore(t, alice, work, "sync")
	_ = os.WriteFile(filepath.Join(work, "marker.txt"), []byte("after-revoke\n"), 0o644)
	staged := runLore(t, alice, work, "stage", "marker.txt")
	committed := runLore(t, alice, work, "commit", "after")
	pushed := runLore(t, alice, work, "push")
	exchanges := 0
	for _, call := range app.Bridge.Calls()[before:] {
		if call.RPC == "ExchangeUserTokenForMultiresourceToken" {
			exchanges++
		}
	}
	t.Logf("old credential remaining=%s clone=%d sync=%d stage=%d commit=%d push=%d exchanges=%d",
		time.Until(claims.Expires).Round(time.Second), cloned.ExitCode, synced.ExitCode, staged.ExitCode, committed.ExitCode, pushed.ExitCode, exchanges)
	if exchanges != 0 {
		t.Fatal("old credential triggered a new token exchange")
	}
	fresh := newLoreExec(loreBin, filepath.Join(root, "auth-alice-new"))
	if err := loginUser(t, loreBin, app, "alice", fresh); err != nil {
		t.Fatal(err)
	}
	again := runLore(t, fresh, root, "clone", base+"/engine", "engine-new")
	t.Logf("fresh credential clone=%d", again.ExitCode)
	if again.ExitCode == 0 {
		t.Fatal("new token still cloned engine")
	}
}
