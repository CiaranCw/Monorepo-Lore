package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lore-monorepo/internal/client"
	"lore-monorepo/internal/loreexec"
)

func TestModuleCloneSkipsParent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token-value" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"modules":[{"ProjectName":"Alpha","Name":"Engine","MountPath":"Engine","RepositoryURL":"grpc://127.0.0.1:53547/engine","Permission":"write"}]}`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "client.toml")
	if err := client.Save(client.Config{Path: cfgPath, ManagerURL: srv.URL, LoreBinary: "lore", Project: "Alpha"}); err != nil {
		t.Fatal(err)
	}
	var cloned []string
	prev := execRun
	execRun = func(_ context.Context, _ string, req loreexec.Request) (loreexec.CommandResult, error) {
		if len(req.Argv) > 0 && req.Argv[0] == "auth" {
			return loreexec.CommandResult{ExitCode: 0, Stdout: "Token: token-value\n"}, nil
		}
		cloned = append(cloned, strings.Join(req.Argv, " "))
		return loreexec.CommandResult{ExitCode: 0}, nil
	}
	defer func() { execRun = prev }()
	if err := cloneCmd([]string{"Engine", "--config", cfgPath, "--dest", filepath.Join(dir, "Engine")}); err != nil {
		t.Fatal(err)
	}
	if len(cloned) != 1 || !strings.Contains(cloned[0], "grpc://127.0.0.1:53547/engine") || strings.Contains(cloned[0], "/alpha") {
		t.Fatalf("cloned %v", cloned)
	}
}

func TestCloneAllSkipsUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/me/batch" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Modules []string `json:"modules"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"results":[{"ProjectName":"Alpha","Name":"Engine","MountPath":"Engine","RepositoryURL":"grpc://127.0.0.1:53547/engine"},{"ProjectName":"Alpha","Name":"GameClient","MountPath":"GameClient","RepositoryURL":"grpc://127.0.0.1:53547/gameclient"}]}`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "client.toml")
	if err := client.Save(client.Config{Path: cfgPath, ManagerURL: srv.URL, LoreBinary: "lore", Project: "Alpha"}); err != nil {
		t.Fatal(err)
	}
	var cloned []string
	prev := execRun
	execRun = func(_ context.Context, _ string, req loreexec.Request) (loreexec.CommandResult, error) {
		if len(req.Argv) > 0 && req.Argv[0] == "auth" {
			return loreexec.CommandResult{ExitCode: 0, Stdout: "Token: token-value\n"}, nil
		}
		cloned = append(cloned, strings.Join(req.Argv, " "))
		return loreexec.CommandResult{ExitCode: 0}, nil
	}
	defer func() { execRun = prev }()
	prevOut := stdout
	stdout = &bytes.Buffer{}
	defer func() { stdout = prevOut }()
	if err := cloneCmd([]string{"--all-authorized", "--config", cfgPath, "--root", dir}); err != nil {
		t.Fatal(err)
	}
	if len(cloned) != 2 || strings.Contains(strings.Join(cloned, "\n"), "docs") || strings.Contains(strings.Join(cloned, "\n"), "beta") {
		t.Fatalf("cloned %v", cloned)
	}
}

func TestBatchCommitRunsIndependentRepositoryCommitsAndPreservesMixedResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/me/batch" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Action string `json:"action"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Action != "commit" {
			http.Error(w, "wrong action", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"results":[` +
			`{"ProjectName":"Alpha","Name":"Engine","MountPath":"Engine","RepositoryURL":"grpc://127.0.0.1:53547/engine"},` +
			`{"ProjectName":"Alpha","Name":"GameClient","MountPath":"GameClient","RepositoryURL":"grpc://127.0.0.1:53547/gameclient"}` +
			`]}`))
	}))
	defer srv.Close()

	root := t.TempDir()
	cfgPath := filepath.Join(root, "client.toml")
	if err := client.Save(client.Config{Path: cfgPath, ManagerURL: srv.URL, LoreBinary: "lore", Project: "Alpha"}); err != nil {
		t.Fatal(err)
	}

	var commitCalls []string
	prevExec := execRun
	execRun = func(_ context.Context, _ string, req loreexec.Request) (loreexec.CommandResult, error) {
		if len(req.Argv) > 0 && req.Argv[0] == "auth" {
			return loreexec.CommandResult{ExitCode: 0, Stdout: "Token: token-value\n"}, nil
		}
		call := strings.Join(req.Argv, " ")
		commitCalls = append(commitCalls, call)
		if strings.Contains(call, filepath.Join(root, "GameClient")) {
			return loreexec.CommandResult{ExitCode: 40}, nil // independent failure
		}
		return loreexec.CommandResult{ExitCode: 0}, nil
	}
	defer func() { execRun = prevExec }()

	prevOut := stdout
	var out bytes.Buffer
	stdout = &out
	defer func() { stdout = prevOut }()

	err := batchAction("commit", []string{"--all", "--message", "independent commit", "--config", cfgPath, "--root", root})
	if err == nil {
		t.Fatal("mixed per-module result must return summary error")
	}
	if len(commitCalls) != 2 {
		t.Fatalf("batch commit invoked %d Lore processes, want 2: %v", len(commitCalls), commitCalls)
	}
	if !strings.Contains(commitCalls[0], filepath.Join(root, "Engine")) ||
		!strings.Contains(commitCalls[1], filepath.Join(root, "GameClient")) {
		t.Fatalf("batch commit did not target independent repository directories: %v", commitCalls)
	}
	if strings.Contains(commitCalls[0], "GameClient") || strings.Contains(commitCalls[1], "Engine") {
		t.Fatalf("one Lore commit command referenced multiple modules: %v", commitCalls)
	}
	got := out.String()
	if !strings.Contains(got, "Engine\tok") ||
		!strings.Contains(got, "GameClient\tfailed") ||
		!strings.Contains(got, "summary ok=1 failed=1") {
		t.Fatalf("mixed per-module results were overwritten or missing:\n%s", got)
	}
}

func TestLoreEnvKeepsCAOutOfProcess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, []byte("not-used-by-env-check"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := os.Getenv("SSL_CERT_FILE")
	env := loreEnv(client.Config{CAFile: path, AuthStore: "fallback"})
	if env["SSL_CERT_FILE"] != path {
		t.Fatalf("child env %v", env)
	}
	if os.Getenv("SSL_CERT_FILE") != before {
		t.Fatal("process environment changed")
	}
}

func TestPublishNeverSendsCallerControlledServerPaths(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/projects/Alpha/publish" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"operation_id":1}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "client.toml")
	if err := client.Save(client.Config{Path: cfgPath, ManagerURL: srv.URL, LoreBinary: "lore", Project: "Alpha"}); err != nil {
		t.Fatal(err)
	}
	prevExec := execRun
	execRun = func(_ context.Context, _ string, req loreexec.Request) (loreexec.CommandResult, error) {
		if len(req.Argv) > 0 && req.Argv[0] == "auth" {
			return loreexec.CommandResult{ExitCode: 0, Stdout: "Token: token-value\n"}, nil
		}
		return loreexec.CommandResult{ExitCode: 0}, nil
	}
	defer func() { execRun = prevExec }()
	prevOut := stdout
	stdout = &bytes.Buffer{}
	defer func() { stdout = prevOut }()

	if err := publishCmd([]string{"--parent", "other-project", "--config", cfgPath}); err == nil {
		t.Fatal("legacy caller-controlled --parent path must be rejected")
	}
	if err := publishCmd([]string{"--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["parent_dir"]; ok {
		t.Fatalf("publish request leaked parent_dir: %v", body)
	}
	if _, ok := body["module_dirs"]; ok {
		t.Fatalf("publish request leaked module_dirs: %v", body)
	}
}

func TestCloneFailureRemovesWorkspace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"modules":[{"ProjectName":"Alpha","Name":"Engine","MountPath":"Engine","RepositoryURL":"grpc://127.0.0.1:53547/engine","Permission":"write"}]}`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "client.toml")
	if err := client.Save(client.Config{Path: cfgPath, ManagerURL: srv.URL, LoreBinary: "lore", Project: "Alpha"}); err != nil {
		t.Fatal(err)
	}
	prev := execRun
	execRun = func(_ context.Context, _ string, req loreexec.Request) (loreexec.CommandResult, error) {
		if len(req.Argv) > 0 && req.Argv[0] == "clone" {
			return loreexec.CommandResult{ExitCode: 79}, nil
		}
		return loreexec.CommandResult{ExitCode: 0, Stdout: "Token: token-value\n"}, nil
	}
	defer func() { execRun = prev }()
	dest := filepath.Join(dir, "work")
	if err := cloneCmd([]string{"Missing", "--config", cfgPath, "--dest", dest}); err == nil {
		t.Fatal("missing module cloned")
	}
	if err := cloneCmd([]string{"Engine", "--config", cfgPath, "--dest", dest}); err == nil {
		t.Fatal("failed clone reported success")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("failed clone left a directory")
	}
}

func TestBatchCloneSwitchesToRecordedDefaultBranch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/me" {
			_, _ = w.Write([]byte("Token: token-value\n"))
			return
		}
		_, _ = w.Write([]byte(`{"results":[{"ProjectName":"Alpha","Name":"Engine","MountPath":"Engine","RepositoryURL":"grpc://127.0.0.1:53547/engine","DefaultBranch":"master"}]}`))
	}))
	defer srv.Close()
	root := t.TempDir()
	cfgPath := filepath.Join(root, "client.toml")
	if err := client.Save(client.Config{Path: cfgPath, ManagerURL: srv.URL, LoreBinary: "lore", Project: "Alpha", AuthPath: filepath.Join(root, "auth"), AuthStore: "fallback"}); err != nil {
		t.Fatal(err)
	}
	var calls []string
	prev := execRun
	execRun = func(_ context.Context, _ string, req loreexec.Request) (loreexec.CommandResult, error) {
		if len(req.Argv) > 0 && req.Argv[0] == "auth" {
			return loreexec.CommandResult{ExitCode: 0, Stdout: "Token: token-value\n"}, nil
		}
		calls = append(calls, strings.Join(req.Argv, " "))
		return loreexec.CommandResult{ExitCode: 0}, nil
	}
	defer func() { execRun = prev }()
	prevOut := stdout
	stdout = &bytes.Buffer{}
	defer func() { stdout = prevOut }()
	if err := batchAction("clone", []string{"--all-authorized", "--config", cfgPath, "--root", root}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || !strings.HasPrefix(calls[0], "clone ") || !strings.Contains(calls[1], "branch switch") || !strings.Contains(calls[1], "master") {
		t.Fatalf("clone calls %v", calls)
	}
}

func TestBatchStageScansClonedAuthorizedReposOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/me/batch" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Action string `json:"action"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Action != "stage" {
			http.Error(w, "wrong action", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"results":[` +
			`{"ProjectName":"Alpha","Name":"Engine","MountPath":"Engine","RepositoryURL":"grpc://127.0.0.1:53547/engine"},` +
			`{"ProjectName":"Alpha","Name":"GameClient","MountPath":"GameClient","RepositoryURL":"grpc://127.0.0.1:53547/gameclient"},` +
			`{"ProjectName":"Alpha","Name":"NotCloned","MountPath":"NotCloned","RepositoryURL":"grpc://127.0.0.1:53547/notcloned"}` +
			`]}`))
	}))
	defer srv.Close()

	root := t.TempDir()
	// Create Engine & GameClient cloned workdirs, plus a revoked/unauthorized local dir that must NOT be staged.
	for _, name := range []string{"Engine", "GameClient", "RevokedOld"} {
		if err := os.MkdirAll(filepath.Join(root, name, ".lore"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfgPath := filepath.Join(root, "client.toml")
	if err := client.Save(client.Config{Path: cfgPath, ManagerURL: srv.URL, LoreBinary: "lore", Project: "Alpha"}); err != nil {
		t.Fatal(err)
	}

	var stagedDirs []string
	var stageArgs []string
	prevExec := execRun
	execRun = func(_ context.Context, _ string, req loreexec.Request) (loreexec.CommandResult, error) {
		if len(req.Argv) > 0 && req.Argv[0] == "auth" {
			return loreexec.CommandResult{ExitCode: 0, Stdout: "Token: token-value\n"}, nil
		}
		stagedDirs = append(stagedDirs, req.Dir)
		stageArgs = append(stageArgs, strings.Join(req.Argv, " "))
		if filepath.Base(req.Dir) == "GameClient" {
			return loreexec.CommandResult{ExitCode: 1}, nil
		}
		return loreexec.CommandResult{ExitCode: 0}, nil
	}
	defer func() { execRun = prevExec }()

	prevOut := stdout
	var out bytes.Buffer
	stdout = &out
	defer func() { stdout = prevOut }()

	err := batchAction("stage", []string{"--all", "--config", cfgPath, "--root", root})
	if err == nil {
		t.Fatal("expected partial failure error when GameClient failed")
	}
	if len(stagedDirs) != 2 {
		t.Fatalf("expected 2 stage invocations (skipping NotCloned & RevokedOld), got %d: %v", len(stagedDirs), stagedDirs)
	}
	if stagedDirs[0] != filepath.Join(root, "Engine") || stagedDirs[1] != filepath.Join(root, "GameClient") {
		t.Fatalf("unexpected staged dirs: %v", stagedDirs)
	}
	for _, arg := range stageArgs {
		if !strings.Contains(arg, "stage --scan --repository ") || strings.Contains(arg, "RevokedOld") || strings.Contains(arg, "NotCloned") {
			t.Fatalf("unexpected stage args: %s", arg)
		}
	}
	got := out.String()
	if !strings.Contains(got, "[OK] Engine") || !strings.Contains(got, "[FAIL] GameClient") || !strings.Contains(got, "[SKIP] NotCloned (not cloned)") || !strings.Contains(got, "summary ok=1 skipped=1 failed=1") {
		t.Fatalf("unexpected stage output:\n%s", got)
	}
}

func TestBatchStageRealLoreSemantics(t *testing.T) {
	loreBin := `C:\Program Files\lore\lore.exe`
	if _, err := os.Stat(loreBin); err != nil {
		loreBin = `/data/lore/bin/lore`
		if _, err := os.Stat(loreBin); err != nil {
			t.Skip("real lore binary not present")
		}
	}

	root := t.TempDir()
	outsideFile := filepath.Join(root, "outside.txt")
	if err := os.WriteFile(outsideFile, []byte("outside\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	repoA := filepath.Join(root, "ModA")
	repoB := filepath.Join(root, "ModB")
	repoRevoked := filepath.Join(root, "ModRevoked")
	for _, dir := range []string{repoA, repoB, repoRevoked} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		res, err := loreexec.Executor{Config: loreexec.Config{Binary: loreBin}}.Run(context.Background(), loreexec.Request{
			Argv: []string{"--non-interactive", "--offline", "repository", "create", "--repository", dir, filepath.Base(dir)},
			Dir:  dir,
		})
		if err != nil || res.ExitCode != 0 {
			t.Fatalf("create %s: %v %+v", dir, err, res)
		}
	}
	// Seed initial commits in ModA & ModB including .loreignore & a file to delete.
	seed := func(dir, file, content string) {
		_ = os.WriteFile(filepath.Join(dir, ".loreignore"), []byte("*.ignored\n"), 0o644)
		_ = os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644)
		_ = os.WriteFile(filepath.Join(dir, "remove.txt"), []byte("bye\n"), 0o644)
		ex := loreexec.Executor{Config: loreexec.Config{Binary: loreBin}}
		if res, err := ex.Run(context.Background(), loreexec.Request{Argv: []string{"--non-interactive", "--offline", "stage", "--scan", "--repository", dir, "."}, Dir: dir}); err != nil || res.ExitCode != 0 {
			t.Fatalf("seed stage %s: %v %+v", dir, err, res)
		}
		if res, err := ex.Run(context.Background(), loreexec.Request{Argv: []string{"--non-interactive", "--offline", "commit", "--repository", dir, "init"}, Dir: dir}); err != nil || res.ExitCode != 0 {
			t.Fatalf("seed commit %s: %v %+v", dir, err, res)
		}
	}
	seed(repoA, "a.txt", "a1\n")
	seed(repoB, "b.txt", "b1\n")
	seed(repoRevoked, "r.txt", "r1\n")

	// Modify a.txt, add new_a.txt, delete remove.txt, write ignored file in ModA.
	_ = os.WriteFile(filepath.Join(repoA, "a.txt"), []byte("a2\n"), 0o644)
	_ = os.WriteFile(filepath.Join(repoA, "new_a.txt"), []byte("new\n"), 0o644)
	_ = os.Remove(filepath.Join(repoA, "remove.txt"))
	_ = os.WriteFile(filepath.Join(repoA, "skip.ignored"), []byte("ignore\n"), 0o644)
	// ModB left clean (empty changes). ModRevoked modified locally but omitted by Manager.
	_ = os.WriteFile(filepath.Join(repoRevoked, "r.txt"), []byte("r2\n"), 0o644)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/lore-token" {
			_, _ = w.Write([]byte(`{"lore_token":"` + fakeValidJWT() + `","expires_in":43200,"username":"alice"}`))
			return
		}
		_, _ = w.Write([]byte(`{"results":[` +
			`{"ProjectName":"Alpha","Name":"ModA","MountPath":"ModA","RepositoryURL":"lore://local/a"},` +
			`{"ProjectName":"Alpha","Name":"ModB","MountPath":"ModB","RepositoryURL":"lore://local/b"},` +
			`{"ProjectName":"Alpha","Name":"ModMissing","MountPath":"ModMissing","RepositoryURL":"lore://local/missing"}` +
			`]}`))
	}))
	defer srv.Close()

	cfgPath := filepath.Join(root, "client.toml")
	if err := client.Save(client.Config{Path: cfgPath, ManagerURL: srv.URL, LoreBinary: loreBin, Project: "Alpha", AuthPath: filepath.Join(root, "auth"), AuthStore: "fallback"}); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(root, "auth"), 0o700)
	// Ensure stage never refreshes or contacts Lore auth when running offline; auth is stubbed,
	// and EnsureLoreCredential must see the valid JWT above without calling lore login.
	if err := client.SaveSession(client.Config{AuthPath: filepath.Join(root, "auth"), ManagerURL: srv.URL}, []byte("session-tok")); err != nil {
		t.Fatal(err)
	}

	if !isClonedLoreDir(filepath.Join(root, "ModA")) {
		t.Fatal("ModA missing .lore")
	}
	prevExec := execRun
	execRun = func(ctx context.Context, binary string, req loreexec.Request) (loreexec.CommandResult, error) {
		if len(req.Argv) > 0 && req.Argv[0] == "auth" {
			if len(req.Argv) > 2 && req.Argv[2] == "--with-token" {
				return loreexec.CommandResult{ExitCode: 0, Stdout: "Token: " + fakeValidJWT() + "\n"}, nil
			}
			return loreexec.CommandResult{ExitCode: 0, Stdout: "User: alice (1)\n"}, nil
		}
		argv := append([]string{"--non-interactive", "--offline"}, req.Argv...)
		return loreexec.Executor{Config: loreexec.Config{Binary: binary}}.Run(ctx, loreexec.Request{Argv: argv, Dir: req.Dir, Env: req.Env})
	}
	defer func() { execRun = prevExec }()

	prevOut := stdout
	var out bytes.Buffer
	stdout = &out
	defer func() { stdout = prevOut }()

	// Run stage --all twice (idempotent re-stage of already staged changes + clean repo + uncloned skip).
	for pass := 0; pass < 2; pass++ {
		out.Reset()
		if err := batchAction("stage", []string{"--all", "--config", cfgPath, "--root", root}); err != nil {
			t.Fatalf("pass %d failed: %v\n%s", pass, err, out.String())
		}
		got := out.String()
		if !strings.Contains(got, "[OK] ModA") || !strings.Contains(got, "[OK] ModB") || !strings.Contains(got, "[SKIP] ModMissing (not cloned)") {
			t.Fatalf("pass %d output:\n%s", pass, got)
		}
	}

	// Verify ModA staged state contains a.txt, new_a.txt, remove.txt; excludes skip.ignored, .lore, outside.txt.
	stA, err := loreexec.Executor{Config: loreexec.Config{Binary: loreBin}}.Run(context.Background(), loreexec.Request{
		Argv: []string{"--non-interactive", "--offline", "status", "--repository", repoA}, Dir: repoA,
	})
	if err != nil || stA.ExitCode != 0 {
		t.Fatalf("status ModA: %v %+v", err, stA)
	}
	for _, want := range []string{"a.txt", "new_a.txt", "remove.txt"} {
		if !strings.Contains(stA.Stdout, want) {
			t.Fatalf("ModA missing staged %s:\n%s", want, stA.Stdout)
		}
	}
	for _, forbid := range []string{"skip.ignored", "outside.txt", ".lore/", "r.txt"} {
		if strings.Contains(stA.Stdout, forbid) {
			t.Fatalf("ModA staged forbidden %s:\n%s", forbid, stA.Stdout)
		}
	}
	// Verify ModRevoked remained untouched (nothing staged).
	stRev, err := loreexec.Executor{Config: loreexec.Config{Binary: loreBin}}.Run(context.Background(), loreexec.Request{
		Argv: []string{"--non-interactive", "--offline", "status", "--repository", repoRevoked}, Dir: repoRevoked,
	})
	if err != nil || strings.Contains(stRev.Stdout, "Changes staged") {
		t.Fatalf("unauthorized ModRevoked was modified:\n%s", stRev.Stdout)
	}
}

func fakeValidJWT() string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	p := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1","exp":4102444800}`))
	return h + "." + p + ".sig"
}
