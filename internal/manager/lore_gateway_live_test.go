package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lore-monorepo/internal/authbridge"
	"lore-monorepo/internal/client"
	"lore-monorepo/internal/config"
	"lore-monorepo/internal/logging"
	"lore-monorepo/internal/loreexec"
	"lore-monorepo/internal/project"
	"lore-monorepo/internal/user"
)

const (
	gwHTTP   = "127.0.0.1:53500"
	gwAuth   = "127.0.0.1:53510"
	gwLore   = "127.0.0.1:53537"
	gwLoreH  = "127.0.0.1:53539"
	gwListen = "127.0.0.1:53547"
	gwBase   = "grpc://127.0.0.1:53547"
)

// TestLoreGatewayLive is the B2.3.1 isolated path:
// Lore CLI --plaintext grpc--> loopback gateway --TLS--> Lore Server --auth_url--> AuthBridge.
func TestLoreGatewayLive(t *testing.T) {
	loreBin := os.Getenv("LORE_BIN")
	serverBin := os.Getenv("LORE_SERVER")
	if loreBin == "" || serverBin == "" {
		t.Skip("LORE_BIN and LORE_SERVER are required")
	}
	nodeBin := os.Getenv("NODE_BIN")
	if nodeBin == "" {
		nodeBin = "/opt/codev/nodejs/bin/node"
	}
	gatewayJS := os.Getenv("LORE_GATEWAY_JS")
	if gatewayJS == "" {
		t.Fatal("LORE_GATEWAY_JS is required")
	}
	root := t.TempDir()
	reportDir := os.Getenv("B231_REPORT")
	if reportDir != "" {
		if err := os.MkdirAll(reportDir, 0o755); err != nil {
			t.Fatal(err)
		}
		root = filepath.Join(reportDir, "run")
		_ = os.RemoveAll(root)
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var steps []map[string]any
	record := func(name string, exit int, ok bool, detail string) {
		steps = append(steps, map[string]any{
			"at": time.Now().UTC().Format(time.RFC3339Nano), "name": name,
			"exit": exit, "ok": ok, "detail": redactText(detail),
		})
		raw, _ := json.Marshal(steps[len(steps)-1])
		_ = os.MkdirAll(root, 0o755)
		f, err := os.OpenFile(filepath.Join(root, "steps.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err == nil {
			_, _ = f.Write(append(raw, '\n'))
			f.Close()
		}
		t.Logf("%s ok=%v exit=%d", name, ok, exit)
	}
	var app *App
	t.Cleanup(func() {
		calls := []authbridge.CallRecord{}
		exchanges := int64(0)
		if app != nil && app.Bridge != nil {
			calls = app.Bridge.Calls()
			exchanges = app.Bridge.Exchanges()
		}
		writeReport(firstNonEmpty(reportDir, root), map[string]any{
			"steps_in_memory": len(steps), "exchanges": exchanges, "calls": calls,
		})
		raw, _ := json.MarshalIndent(calls, "", "  ")
		_ = os.WriteFile(filepath.Join(root, "authbridge-calls.json"), raw, 0o644)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app = startGatewayManager(t, ctx, root)
	provisionerID, err := user.Create(context.Background(), app.DB, "test", "provisioner", "provision-pass-1", "user")
	if err != nil {
		t.Fatal(err)
	}
	aliceID, err := user.Create(context.Background(), app.DB, "test", "alice", "correct-horse", "user")
	if err != nil {
		t.Fatal(err)
	}
	ca, cert, key := writeGatewayCerts(t, root)
	srv := startGatewayLore(t, serverBin, root, cert, key)
	defer srv.Process.Kill()
	if !waitLog(filepath.Join(root, "loreserver.log"), "Registered public gRPC", 40*time.Second) {
		tail, _ := os.ReadFile(filepath.Join(root, "loreserver.log"))
		t.Fatalf("loreserver did not register gRPC: %s", redactText(string(tail)))
	}
	record("lore_tcp", 0, dialOK(gwLore), "loreserver accepted TCP")
	gwLog := filepath.Join(root, "gateway.jsonl")
	gw := startGateway(t, nodeBin, gatewayJS, ca, gwLog)
	defer gw.Process.Kill()
	waitPort(t, gwListen)
	if !waitLog(gwLog, "upstream_probe", 15*time.Second) {
		t.Fatal("gateway did not record the upstream TLS probe")
	}
	h2ok, h2detail := probeH2C(gwListen)
	record("cli_http2_preface", exitOf(h2ok), h2ok, h2detail)
	if !h2ok {
		t.Fatal("gateway did not answer the HTTP/2 preface")
	}
	probe := readGatewayEvents(gwLog)
	record("gateway_upstream_tls", 0, probe.authorized, probe.tlsDetail)

	provDir := filepath.Join(root, "auth-provisioner")
	aliceDir := filepath.Join(root, "auth-alice")
	prov := newLoreExec(loreBin, provDir)
	alice := newLoreExec(loreBin, aliceDir)
	if err := client.Login(context.Background(), client.Config{
		ManagerURL: "http://" + gwHTTP, LoreBinary: loreBin, AuthURL: "http://" + gwAuth,
		AuthStore: "fallback", AuthPath: provDir,
	}, "provisioner", []byte("provision-pass-1"), prov); err != nil {
		record("provisioner_login", 1, false, err.Error())
		t.Fatal(err)
	}
	record("provisioner_login", 0, true, "identity stored")

	engineName, clientName := "engine", "gameclient"
	engineID := createNamedRepo(t, record, prov, root, engineName)
	clientID := createNamedRepo(t, record, prov, root, clientName)
	infoEngine := runLore(t, prov, root, "repository", "info", gwBase+"/"+engineName)
	record("resolve_engine_name", infoEngine.ExitCode, infoEngine.ExitCode == 0 && strings.Contains(infoEngine.Stdout+infoEngine.Stderr, engineID), trimResult(infoEngine))
	infoClient := runLore(t, prov, root, "repository", "info", gwBase+"/"+clientName)
	record("resolve_client_name", infoClient.ExitCode, infoClient.ExitCode == 0 && strings.Contains(infoClient.Stdout+infoClient.Stderr, clientID), trimResult(infoClient))
	engineModule := registerGatewayGrant(t, app, aliceID, engineID, clientID)
	record("grant_engine_only", 0, true, "alice granted "+engineID+" only")

	if err := client.Login(context.Background(), client.Config{
		ManagerURL: "http://" + gwHTTP, LoreBinary: loreBin, AuthURL: "http://" + gwAuth,
		AuthStore: "fallback", AuthPath: aliceDir,
	}, "alice", []byte("correct-horse"), alice); err != nil {
		record("alice_login", 1, false, err.Error())
		t.Fatal(err)
	}
	record("alice_login", 0, true, "identity stored")
	before := snapshotCalls(app)
	engineURL, engineNameOK, engineIDOK := observeResolve(t, record, alice, root, "alice_engine", engineName, engineID)
	if !engineNameOK && !engineIDOK {
		t.Fatal("engine resolved neither by name nor by id")
	}
	_, clientNameOK, clientIDOK := observeResolve(t, record, alice, root, "alice_client", clientName, clientID)
	record("ungranted_resolve", 0, !clientNameOK && !clientIDOK, fmt.Sprintf("name=%v id=%v", clientNameOK, clientIDOK))

	engineWork := filepath.Join(root, "work-engine")
	if err := os.MkdirAll(engineWork, 0o755); err != nil {
		t.Fatal(err)
	}
	clone := runLore(t, alice, engineWork, "clone", engineURL, ".")
	record("clone_engine", clone.ExitCode, clone.ExitCode == 0, trimResult(clone))
	if clone.ExitCode != 0 {
		t.Fatalf("authorized clone failed: %s", trimResult(clone))
	}
	denied := runLore(t, alice, root, "clone", gwBase+"/"+clientID, "work-client")
	record("clone_client_denied", denied.ExitCode, denied.ExitCode != 0, trimResult(denied))
	if denied.ExitCode == 0 {
		t.Fatal("unauthorized clone succeeded")
	}
	writeFile(t, filepath.Join(engineWork, "note.txt"))
	staged := runLore(t, alice, engineWork, "stage", "note.txt")
	record("stage_engine", staged.ExitCode, staged.ExitCode == 0, trimResult(staged))
	committed := runLore(t, alice, engineWork, "commit", "note")
	record("commit_engine", committed.ExitCode, committed.ExitCode == 0, trimResult(committed))
	pushed := runLore(t, alice, engineWork, "push")
	record("push_engine", pushed.ExitCode, pushed.ExitCode == 0, trimResult(pushed))
	if staged.ExitCode != 0 || committed.ExitCode != 0 || pushed.ExitCode != 0 {
		t.Fatalf("stage/commit/push failed: %s | %s | %s", trimResult(staged), trimResult(committed), trimResult(pushed))
	}
	synced := runLore(t, alice, filepath.Join(root, "work-engine"), "sync")
	record("sync_engine", synced.ExitCode, synced.ExitCode == 0, trimResult(synced))
	if synced.ExitCode != 0 {
		t.Fatalf("sync failed: %s", trimResult(synced))
	}
	deniedAgain := runLore(t, alice, root, "clone", gwBase+"/"+clientID, "work-client-2")
	record("clone_client_still_denied", deniedAgain.ExitCode, deniedAgain.ExitCode != 0, trimResult(deniedAgain))
	if deniedAgain.ExitCode == 0 {
		t.Fatal("unauthorized clone succeeded after push")
	}
	listedOK := runLore(t, alice, root, "repository", "list", gwBase)
	record("repository_list", listedOK.ExitCode, listedOK.ExitCode == 0, trimResult(listedOK))
	branch := runLore(t, alice, filepath.Join(root, "work-engine"), "branch", "info")
	record("branch_info", branch.ExitCode, branch.ExitCode == 0, trimResult(branch))
	who := runLore(t, alice, filepath.Join(root, "work-engine"), "auth", "info", "1")
	record("auth_info_local", who.ExitCode, who.ExitCode == 0, trimResult(who))
	if err := project.GrantModule(context.Background(), app.DB, "test", provisionerID, engineModule); err != nil {
		t.Fatal(err)
	}
	provWork := filepath.Join(root, "work-provisioner")
	if err := os.MkdirAll(provWork, 0o755); err != nil {
		t.Fatal(err)
	}
	provClone := runLore(t, prov, provWork, "clone", engineURL, ".")
	record("provisioner_clone_engine", provClone.ExitCode, provClone.ExitCode == 0, trimResult(provClone))
	view := runLore(t, prov, provWork, "branch", "info")
	record("provisioner_views_alice", view.ExitCode, view.ExitCode == 0, trimResult(view))
	writeFile(t, filepath.Join(provWork, "other.txt"))
	provStage := runLore(t, prov, provWork, "stage", "other.txt")
	provCommit := runLore(t, prov, provWork, "commit", "other")
	provPush := runLore(t, prov, provWork, "push")
	record("provisioner_push", provPush.ExitCode, provStage.ExitCode == 0 && provCommit.ExitCode == 0 && provPush.ExitCode == 0, trimResult(provPush))
	_ = runLore(t, alice, engineWork, "sync")
	hist := runLore(t, alice, engineWork, "revision", "history")
	_ = os.WriteFile(filepath.Join(root, "history.txt"), []byte(redactTokens(hist.Stdout+"\n"+hist.Stderr)), 0o644)
	record("revision_history", hist.ExitCode, hist.ExitCode == 0, trimResult(hist))
	recordCalls(t, record, "after_business", callsSince(app, before))
	streamOK, streamDetail := storageStreamSeen(gwLog)
	record("storage_streaming", exitOf(streamOK), streamOK, streamDetail)
	if !streamOK {
		t.Fatal("push did not exercise a Storage streaming RPC")
	}

	cached := runLore(t, alice, filepath.Join(root, "work-engine"), "status")
	record("status_before_disable", cached.ExitCode, cached.ExitCode == 0, trimResult(cached))
	if err := user.SetStatus(context.Background(), app.DB, "test", "alice", "disabled"); err != nil {
		t.Fatal(err)
	}
	loginCode := loginStatus("alice", "correct-horse")
	record("login_while_disabled", loginCode, loginCode == http.StatusForbidden, fmt.Sprintf("http %d", loginCode))
	cachedAfter := runLore(t, alice, filepath.Join(root, "work-engine"), "status")
	record("cached_access_after_disable", cachedAfter.ExitCode, true, trimResult(cachedAfter))
	listed := runLore(t, alice, root, "repository", "list", gwBase)
	record("identity_list_while_disabled", listed.ExitCode, listed.ExitCode != 0, trimResult(listed))
	_ = runLore(t, alice, filepath.Join(root, "work-engine"), "auth", "logout", "--resource", engineID)
	freshDenied := runLore(t, alice, root, "clone", gwBase+"/"+engineName, "work-engine-disabled")
	record("new_exchange_while_disabled", freshDenied.ExitCode, freshDenied.ExitCode != 0, trimResult(freshDenied))
	if freshDenied.ExitCode == 0 {
		t.Fatal("disabled user completed a new clone")
	}
	if err := user.SetStatus(context.Background(), app.DB, "test", "alice", "active"); err != nil {
		t.Fatal(err)
	}
	if err := client.Login(context.Background(), client.Config{
		ManagerURL: "http://" + gwHTTP, LoreBinary: loreBin, AuthURL: "http://" + gwAuth,
		AuthStore: "fallback", AuthPath: aliceDir,
	}, "alice", []byte("correct-horse"), alice); err != nil {
		record("alice_relogin", 1, false, err.Error())
		t.Fatal(err)
	}
	record("alice_relogin", 0, true, "new identity after re-enable")
	restored := runLore(t, alice, root, "clone", gwBase+"/"+engineName, "work-engine-restored")
	record("clone_after_reenable", restored.ExitCode, restored.ExitCode == 0, trimResult(restored))
	if restored.ExitCode != 0 {
		t.Fatalf("clone after re-enable failed: %s", trimResult(restored))
	}

	cancel()
	waitPortGone(t, gwAuth)
	waitPortGone(t, gwHTTP)
	record("manager_ports_closed", 0, !dialOK(gwHTTP) && !dialOK(gwAuth) && dialOK(gwLore) && dialOK(gwListen), "http down, auth grpc down, lore and gateway still up")
	stoppedList := runLore(t, alice, root, "repository", "list", gwBase)
	record("identity_during_manager_outage", stoppedList.ExitCode, stoppedList.ExitCode != 0, trimResult(stoppedList))
	cachedOutage := runLore(t, alice, filepath.Join(root, "work-engine"), "status")
	record("cached_access_during_outage", cachedOutage.ExitCode, true, trimResult(cachedOutage))
	_ = runLore(t, alice, filepath.Join(root, "work-engine-restored"), "auth", "logout", "--resource", engineID)
	exchangeOutage := runLore(t, alice, root, "clone", gwBase+"/"+engineName, "work-engine-outage")
	record("new_exchange_during_outage", exchangeOutage.ExitCode, exchangeOutage.ExitCode != 0, trimResult(exchangeOutage))

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	app = startGatewayManager(t, ctx2, root)
	waitPort(t, gwAuth)
	loginBack := loginStatus("alice", "correct-horse")
	record("login_after_manager_restore", loginBack, loginBack == http.StatusOK, fmt.Sprintf("http %d", loginBack))
	if err := client.Login(context.Background(), client.Config{
		ManagerURL: "http://" + gwHTTP, LoreBinary: loreBin, AuthURL: "http://" + gwAuth,
		AuthStore: "fallback", AuthPath: aliceDir,
	}, "alice", []byte("correct-horse"), alice); err != nil {
		record("cli_login_after_restore", 1, false, err.Error())
		t.Fatal(err)
	}
	listedBack := runLore(t, alice, root, "repository", "list", gwBase)
	record("identity_after_manager_restore", listedBack.ExitCode, listedBack.ExitCode == 0, trimResult(listedBack))

	_ = srv.Process.Kill()
	time.Sleep(time.Second)
	loreDown := runLore(t, alice, root, "repository", "info", gwBase+"/"+engineName)
	record("lore_server_down", loreDown.ExitCode, loreDown.ExitCode != 0 && dialOK(gwHTTP), trimResult(loreDown))
	health := getStatus("http://" + gwHTTP + "/health/live")
	record("manager_live_while_lore_down", health, health == http.StatusOK, fmt.Sprintf("http %d", health))
	if health != http.StatusOK || loreDown.ExitCode == 0 {
		t.Fatal("lore outage was not distinct from manager health")
	}
	if !forwardedDenials(gwLog) {
		t.Fatal("gateway log has no forwarded upstream denial")
	}
	record("gateway_forwards_denials", 0, true, "denied RPCs were forwarded upstream")
}

func startGatewayManager(t *testing.T, ctx context.Context, root string) *App {
	t.Helper()
	cfg := config.Config{
		Listen: gwHTTP, ShutdownTimeout: 5 * time.Second,
		DatabasePath: filepath.Join(root, "manager.db"), LoreBinary: os.Getenv("LORE_BIN"),
		CommandTimeout: 2 * time.Minute, LogLevel: "info", LogFormat: "json",
		Auth: config.Auth{
			Issuer: "http://" + gwAuth, Audience: []string{"127.0.0.1"},
			GRPCListen: gwAuth, IdentityTTL: 12 * time.Hour, AccessTTL: 5 * time.Minute,
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
	waitPort(t, gwAuth)
	return app
}

func startGatewayLore(t *testing.T, bin, root, cert, key string) *exec.Cmd {
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
	body := fmt.Sprintf(`# isolated B2.3.1 server
[environment.endpoint]
auth_url = "http://%s"
[server.auth]
jwt_issuer = "http://%s"
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
port = 53537
verify_client_certs = false
[server.grpc.certificate]
cert_file = "%s"
pkey_file = "%s"
[server.http]
enabled = true
host = "127.0.0.1"
port = 53539
[immutable_store.local]
path = "%s"
[mutable_store.local]
path = "%s"
[topology]
provider = "none"
`, gwAuth, gwAuth, jwks, filepath.ToSlash(cert), filepath.ToSlash(key), filepath.ToSlash(store), filepath.ToSlash(store))
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

func startGateway(t *testing.T, node, js, ca, logPath string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(node, js)
	cmd.Env = append(os.Environ(),
		"GATEWAY_HOST=127.0.0.1",
		"GATEWAY_PORT=53547",
		"UPSTREAM_ORIGIN=https://"+gwLore,
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

func writeGatewayCerts(t *testing.T, root string) (string, string, string) {
	t.Helper()
	dir := filepath.Join(root, "certs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(dir, "ca.pem")
	caKey := filepath.Join(dir, "ca.key")
	cert := filepath.Join(dir, "server.pem")
	key := filepath.Join(dir, "server.key")
	csr := filepath.Join(dir, "server.csr")
	ext := filepath.Join(dir, "server.ext")
	if err := os.WriteFile(ext, []byte("subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		out, err := exec.Command("openssl", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("openssl %s: %v %s", args[0], err, out)
		}
	}
	run("req", "-x509", "-newkey", "rsa:2048", "-keyout", caKey, "-out", ca, "-days", "2", "-nodes", "-subj", "/CN=B231-Test-CA")
	run("req", "-newkey", "rsa:2048", "-keyout", key, "-out", csr, "-nodes", "-subj", "/CN=localhost")
	run("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", caKey, "-CAcreateserial", "-out", cert, "-days", "2", "-extfile", ext)
	text, err := exec.Command("openssl", "verify", "-CAfile", ca, cert).CombinedOutput()
	if err != nil {
		t.Fatalf("cert verify: %v %s", err, text)
	}
	_ = os.WriteFile(filepath.Join(dir, "verify.txt"), text, 0o644)
	return ca, cert, key
}

func observeResolve(t *testing.T, record func(string, int, bool, string), ex loreexec.Executor, root, label, name, id string) (string, bool, bool) {
	t.Helper()
	byName := runLore(t, ex, root, "repository", "info", gwBase+"/"+name)
	nameOK := byName.ExitCode == 0 && strings.Contains(byName.Stdout+byName.Stderr, id)
	record("resolve_name_"+label, byName.ExitCode, nameOK, trimResult(byName))
	byID := runLore(t, ex, root, "repository", "info", gwBase+"/"+id)
	idOK := byID.ExitCode == 0 && strings.Contains(byID.Stdout+byID.Stderr, id)
	record("resolve_id_"+label, byID.ExitCode, idOK, trimResult(byID))
	if nameOK {
		return gwBase + "/" + name, nameOK, idOK
	}
	return gwBase + "/" + id, nameOK, idOK
}

func createNamedRepo(t *testing.T, record func(string, int, bool, string), ex loreexec.Executor, root, name string) string {
	t.Helper()
	dir := filepath.Join(root, "seed-"+name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	res := runLore(t, ex, dir, "--debug", "--non-interactive", "--json", "repository", "create", gwBase+"/"+name)
	record("create_"+name, res.ExitCode, res.ExitCode == 0, trimResult(res))
	if res.ExitCode != 0 {
		t.Fatalf("repository create %s failed: %s", name, trimResult(res))
	}
	id := findRepoID(res.Stdout + "\n" + res.Stderr)
	if id == "" {
		t.Fatalf("repository create %s did not report an id", name)
	}
	return id
}

func registerGatewayGrant(t *testing.T, app *App, aliceID int64, allowed, denied string) int64 {
	t.Helper()
	ctx := context.Background()
	parent := "00112233445566778899aabbccddeeff"
	p, err := project.CreateProject(ctx, app.DB, "test", project.Project{
		Name: "Alpha", ParentRepositoryID: parent, ParentRepositoryURL: gwBase + "/alpha-root", CreatedBy: aliceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := project.CreateModule(ctx, app.DB, "test", project.Module{
		ProjectID: p.ID, Name: "Engine", RepositoryID: allowed, RepositoryURL: gwBase + "/engine", MountPath: "Engine",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := project.CreateModule(ctx, app.DB, "test", project.Module{
		ProjectID: p.ID, Name: "Client", RepositoryID: denied, RepositoryURL: gwBase + "/gameclient", MountPath: "Client",
	}); err != nil {
		t.Fatal(err)
	}
	if err := project.GrantModule(ctx, app.DB, "test", aliceID, engine.ID); err != nil {
		t.Fatal(err)
	}
	return engine.ID
}

func newLoreExec(bin, authPath string) loreexec.Executor {
	_ = os.MkdirAll(authPath, 0o700)
	return loreexec.Executor{Config: loreexec.Config{
		Binary: bin, Timeout: 2 * time.Minute,
		Env: map[string]string{"LORE_AUTH_STORE": "fallback", "LORE_AUTH_PATH": authPath},
	}}
}

func probeH2C(addr string) (bool, string) {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false, err.Error()
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		return false, err.Error()
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 9)
	n, err := io.ReadFull(conn, buf)
	if err != nil {
		return false, fmt.Sprintf("read %d %v %x", n, err, buf[:n])
	}
	if len(buf) >= 4 && buf[3] == 0x04 {
		return true, fmt.Sprintf("settings frame %x", buf)
	}
	return false, fmt.Sprintf("not settings %x", buf)
}

type gwProbe struct {
	authorized bool
	tlsDetail  string
}

func readGatewayEvents(path string) gwProbe {
	raw, err := os.ReadFile(path)
	if err != nil {
		return gwProbe{tlsDetail: err.Error()}
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.Contains(line, "upstream_probe") && !strings.Contains(line, "upstream_tls") {
			continue
		}
		var ev struct {
			Event      string `json:"event"`
			Authorized bool   `json:"authorized"`
			Protocol   string `json:"protocol"`
			ALPN       string `json:"alpn"`
		}
		if json.Unmarshal([]byte(line), &ev) == nil && ev.Authorized {
			return gwProbe{true, ev.Event + " " + ev.Protocol + " " + ev.ALPN}
		}
	}
	return gwProbe{tlsDetail: "no authorized upstream event"}
}

func storageStreamSeen(path string) (bool, string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, err.Error()
	}
	var hits []string
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.Contains(line, "Storage") {
			continue
		}
		var ev struct {
			Event         string `json:"event"`
			RPC           string `json:"rpc"`
			Forwarded     bool   `json:"forwarded"`
			UpstreamBytes int    `json:"upstream_bytes"`
			ClientBytes   int    `json:"client_bytes"`
			FramesUp      int    `json:"frames_up"`
			FramesDown    int    `json:"frames_down"`
			Status        string `json:"grpc_status"`
		}
		if json.Unmarshal([]byte(line), &ev) != nil || ev.Event != "stream_end" {
			continue
		}
		if strings.Contains(ev.RPC, "Put") && ev.Forwarded && (ev.ClientBytes > 0 || ev.FramesUp > 0) {
			hits = append(hits, fmt.Sprintf("%s status=%s up=%d down=%d frames=%d/%d", ev.RPC, ev.Status, ev.ClientBytes, ev.UpstreamBytes, ev.FramesUp, ev.FramesDown))
		}
	}
	if len(hits) == 0 {
		return false, "no forwarded Storage Put"
	}
	return true, strings.Join(hits, "; ")
}

func forwardedDenials(path string) bool {
	raw, _ := os.ReadFile(path)
	for _, line := range strings.Split(string(raw), "\n") {
		var ev struct {
			Event     string `json:"event"`
			Forwarded bool   `json:"forwarded"`
			Status    string `json:"grpc_status"`
		}
		if json.Unmarshal([]byte(line), &ev) != nil || ev.Event != "stream_end" {
			continue
		}
		if ev.Forwarded && ev.Status != "" && ev.Status != "0" {
			return true
		}
	}
	return false
}

func snapshotCalls(app *App) int {
	if app == nil || app.Bridge == nil {
		return 0
	}
	return len(app.Bridge.Calls())
}

func callsSince(app *App, start int) []authbridge.CallRecord {
	all := app.Bridge.Calls()
	if start > len(all) {
		return all
	}
	return all[start:]
}

func recordCalls(t *testing.T, record func(string, int, bool, string), name string, calls []authbridge.CallRecord) {
	t.Helper()
	need := []string{"CheckUserPermission", "LookupUserPermissions", "GetUserInfo", "ExchangeUserTokenForMultiresourceToken"}
	seen := map[string]int{}
	var parts []string
	for _, call := range calls {
		seen[call.RPC]++
		parts = append(parts, fmt.Sprintf("%s ok=%v code=%s req=%d resp=%d", call.RPC, call.OK, call.Code, call.RequestN, call.ResponseN))
	}
	missing := []string{}
	for _, rpc := range need {
		if seen[rpc] == 0 {
			missing = append(missing, rpc)
		}
	}
	record(name, len(missing), len(missing) == 0, strings.Join(parts, "; "))
	if len(missing) != 0 {
		t.Fatalf("missing authbridge rpcs: %s", strings.Join(missing, ","))
	}
}

func loginStatus(username, password string) int {
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req, err := http.NewRequest(http.MethodPost, "http://"+gwHTTP+"/api/v1/auth/login", bytes.NewReader(body))
	if err != nil {
		return 0
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
	return res.StatusCode
}

func getStatus(url string) int {
	res, err := http.Get(url)
	if err != nil {
		return 0
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	return res.StatusCode
}

func dialOK(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func exitOf(ok bool) int {
	if ok {
		return 0
	}
	return 1
}

func redactTokens(s string) string {
	var b strings.Builder
	for _, field := range strings.Fields(s) {
		if strings.Contains(field, "eyJ") {
			b.WriteString("<redacted-jwt> ")
			continue
		}
		b.WriteString(field)
		b.WriteByte(' ')
	}
	return b.String()
}

func trimResult(res loreexec.CommandResult) string {
	text := res.Stdout + "\n" + res.Stderr
	if len(text) > 800 {
		text = text[:800]
	}
	return text
}

func waitLog(path, needle string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(path)
		if err == nil && strings.Contains(string(raw), needle) {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}
