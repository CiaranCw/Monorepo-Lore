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

func TestHistoryShowRefsAndImportCLI(t *testing.T) {
	var seenPaths []string
	var seenImportBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPaths = append(seenPaths, r.Method+" "+r.URL.RequestURI())
		switch {
		case r.URL.Path == "/api/v1/projects/Alpha/history":
			cur := r.URL.Query().Get("cursor")
			if cur == "" {
				_, _ = w.Write([]byte(`{"scope":"project_aggregated","project_id":1,"project_name":"Alpha","total_matching":2,"has_more":true,"next_cursor":"cur-2","commits":[{"project_id":1,"project_name":"Alpha","module_id":10,"module_name":"Engine","canonical_id":"1111111111111111111111111111111111111111","lore_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_commit_id":"1111111111111111111111111111111111111111","author_name":"Alice","committed_at":"2025-03-01T08:00:00Z","subject":"feat: engine c1"}]}`))
			} else {
				_, _ = w.Write([]byte(`{"scope":"project_aggregated","project_id":1,"project_name":"Alpha","total_matching":2,"has_more":false,"commits":[{"project_id":1,"project_name":"Alpha","module_id":11,"module_name":"Client","canonical_id":"2222222222222222222222222222222222222222","lore_revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","source_commit_id":"2222222222222222222222222222222222222222","author_name":"Bob","committed_at":"2025-03-01T07:00:00Z","subject":"feat: client c1"}]}`))
			}
		case r.URL.Path == "/api/v1/me/modules":
			_, _ = w.Write([]byte(`{"modules":[{"ModuleID":10,"ProjectName":"Alpha","Name":"Engine","MountPath":"Engine"}]}`))
		case r.URL.Path == "/api/v1/modules/10/refs":
			_, _ = w.Write([]byte(`{"refs":[{"module_id":10,"module_name":"Engine","type":"tag","name":"v1.0.0","lore_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_commit_id":"1111111111111111111111111111111111111111"}]}`))
		case r.URL.Path == "/api/v1/modules/10/commits/111111111111":
			_, _ = w.Write([]byte(`{"project_name":"Alpha","module_name":"Engine","origin_kind":"git_import","lore_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_commit_id":"1111111111111111111111111111111111111111","author_name":"Alice","author_email":"alice@example.com","authored_at":"2025-03-01T08:00:00Z","committer_name":"CI","committer_email":"ci@example.com","committed_at":"2025-03-01T08:00:00Z","message":"feat: engine c1\n\ndetails"}`))
		case r.URL.Path == "/api/v1/projects/Alpha/imports" && r.Method == http.MethodPost:
			_ = json.NewDecoder(r.Body).Decode(&seenImportBody)
			_, _ = w.Write([]byte(`{"job_id":7,"mode":"dry_run","status":"succeeded","succeeded_items":1,"items":[{"module_name":"Engine","platform":"gongfeng","status":"planned","verification":{"indexed_commits":0,"imported_branches":0,"imported_tags":0}}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "client.toml")
	if err := client.Save(client.Config{Path: cfgPath, ManagerURL: srv.URL, LoreBinary: "lore", Project: "Alpha"}); err != nil {
		t.Fatal(err)
	}

	prevExec := execRun
	execRun = func(_ context.Context, _ string, _ loreexec.Request) (loreexec.CommandResult, error) {
		return loreexec.CommandResult{ExitCode: 0, Stdout: "Token: token-value\n"}, nil
	}
	defer func() { execRun = prevExec }()

	var buf bytes.Buffer
	prevOut := stdout
	stdout = &buf
	defer func() { stdout = prevOut }()

	// 1. `lore-mono history --all --all-pages` traverses both pages!
	if err := historyCmd([]string{"--all", "--all-pages", "--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	outStr := buf.String()
	if !strings.Contains(outStr, "Alpha/Engine") || !strings.Contains(outStr, "Alpha/Client") || !strings.Contains(outStr, "total=2") {
		t.Fatalf("unexpected history output:\n%s", outStr)
	}

	// 2. `lore-mono refs Engine` and `lore-mono show Engine 111111111111`
	buf.Reset()
	if err := refsCmd([]string{"Engine", "--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "v1.0.0") {
		t.Fatalf("refs output:\n%s", buf.String())
	}

	buf.Reset()
	if err := showCmd([]string{"Engine", "111111111111", "--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "GitCommit: 1111111111111111111111111111111111111111") {
		t.Fatalf("show output:\n%s", buf.String())
	}

	// 3. Reject `--token` on argv!
	if err := importCmd([]string{"--source", "https://git.woa.com/org/engine.git", "--module", "Engine", "--token", "secret"}); err == nil {
		t.Fatal("import --token on argv must be rejected")
	}

	// 4. `lore-mono import --manifest ... --dry-run` resolves TokenEnv in-memory without writing secrets to manifest!
	t.Setenv("TEST_GONGFENG_PAT", "pat-ephemeral-xyz")
	manifestFile := filepath.Join(dir, "import.toml")
	_ = os.WriteFile(manifestFile, []byte(`
project = "Alpha"
[[repositories]]
source_url = "https://git.woa.com/org/engine.git"
module_name = "Engine"
mount_path = "Engine"
[repositories.auth]
auth_method = "https_token"
token_env = "TEST_GONGFENG_PAT"
`), 0o644)

	buf.Reset()
	if err := importCmd([]string{"--manifest", manifestFile, "--dry-run", "--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	rtMap, _ := seenImportBody["runtime_tokens"].(map[string]any)
	if rtMap["Engine"] != "pat-ephemeral-xyz" {
		t.Fatalf("expected runtime_tokens[Engine] resolved from env, got %v", seenImportBody)
	}
	_ = seenPaths
}
