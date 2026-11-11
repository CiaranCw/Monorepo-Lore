package main

import (
	"bytes"
	"context"
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
