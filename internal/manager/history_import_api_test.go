package manager

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"lore-monorepo/internal/history"
	"lore-monorepo/internal/loreadapter"
	"lore-monorepo/internal/loreexec"
)

func TestHistoryAndImportAPIWithPermissionIsolation(t *testing.T) {
	app := testApp(t, fakeLore(t))
	ctx := context.Background()

	carol := makeAcct(t, app, "carol")
	alice := makeAcct(t, app, "alice")
	bob := makeAcct(t, app, "bob")
	dave := makeAcct(t, app, "dave")
	srv := httptestServer(t, app)

	issue := func(id int64, name string) string {
		tok, err := app.Tokens.IssueIdentity(itoa(id), name, 1)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	carolTok := issue(carol, "carol")
	aliceTok := issue(alice, "alice")
	bobTok := issue(bob, "bob")
	daveTok := issue(dave, "dave")

	status, pBody := apiJSON(t, http.MethodPost, srv+"/api/v1/projects", carolTok, map[string]string{
		"name": "Alpha", "parent_repository_id": "00112233445566778899aabbccddeeff",
		"parent_repository_url": "grpc://127.0.0.1:53547/alpha",
	})
	if status != http.StatusCreated {
		t.Fatalf("create project %d %v", status, pBody)
	}
	pid := int64(pBody["ID"].(float64))

	status, engBody := apiJSON(t, http.MethodPost, srv+"/api/v1/projects/"+itoa(pid)+"/modules", carolTok, map[string]string{
		"name": "Engine", "repository_id": "11111111111111111111111111111111",
		"repository_url": "grpc://127.0.0.1:53547/engine", "mount_path": "Engine",
	})
	if status != http.StatusCreated {
		t.Fatal(status)
	}
	engID := int64(engBody["ID"].(float64))

	status, secBody := apiJSON(t, http.MethodPost, srv+"/api/v1/projects/"+itoa(pid)+"/modules", carolTok, map[string]string{
		"name": "SecretServer", "repository_id": "22222222222222222222222222222222",
		"repository_url": "grpc://127.0.0.1:53547/secret", "mount_path": "SecretServer",
	})
	if status != http.StatusCreated {
		t.Fatal(status)
	}
	secID := int64(secBody["ID"].(float64))

	_, _ = apiJSON(t, http.MethodPost, srv+"/api/v1/projects/"+itoa(pid)+"/members", carolTok, map[string]any{"username": "alice", "role": "project_member"})
	_, _ = apiJSON(t, http.MethodPost, srv+"/api/v1/projects/"+itoa(pid)+"/members", carolTok, map[string]any{"username": "bob", "role": "project_member"})
	_, _ = apiJSON(t, http.MethodPost, srv+"/api/v1/modules/"+itoa(engID)+"/permissions", carolTok, map[string]string{"username": "alice", "permission": "write"})
	_, _ = apiJSON(t, http.MethodPost, srv+"/api/v1/modules/"+itoa(engID)+"/permissions", carolTok, map[string]string{"username": "bob", "permission": "read"})
	_, _ = apiJSON(t, http.MethodPost, srv+"/api/v1/modules/"+itoa(secID)+"/permissions", carolTok, map[string]string{"username": "bob", "permission": "read"})

	// Seed history commits for Engine and SecretServer.
	tx, err := app.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = history.UpsertCommit(ctx, tx, history.CommitInput{
		ModuleID: engID, LoreRevision: fmt.Sprintf("%064x", 101), SourceCommitID: fmt.Sprintf("%040x", 101),
		OriginKind: history.OriginGitImport, AuthorName: "Alice", AuthorEmail: "alice@example.com",
		CommittedUnixMS: 1740000001000, AuthoredUnixMS: 1740000001000, Message: "engine commit 1",
	})
	_ = history.UpsertCommit(ctx, tx, history.CommitInput{
		ModuleID: secID, LoreRevision: fmt.Sprintf("%064x", 202), SourceCommitID: fmt.Sprintf("%040x", 202),
		OriginKind: history.OriginGitImport, AuthorName: "Bob", AuthorEmail: "bob@example.com",
		CommittedUnixMS: 1740000002000, AuthoredUnixMS: 1740000002000, Message: "top-secret server logic",
	})
	_ = history.UpsertRef(ctx, tx, history.RefDetail{
		ModuleID: engID, Type: "tag", Name: "v1.0.0", LoreRevision: fmt.Sprintf("%064x", 101),
		SourceCommitID: fmt.Sprintf("%040x", 101), IsAnnotated: true, TagMessage: "release 1.0",
	})
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// 1. Alice aggregated project history ONLY contains Engine, NEVER SecretServer!
	status, aliceHist := apiJSON(t, http.MethodGet, srv+"/api/v1/projects/Alpha/history", aliceTok, nil)
	rawAlice := mustJSON(aliceHist)
	if status != http.StatusOK || strings.Contains(rawAlice, "SecretServer") || strings.Contains(rawAlice, "top-secret") {
		t.Fatalf("alice history %d %s", status, rawAlice)
	}
	if int(aliceHist["total_matching"].(float64)) != 1 {
		t.Fatalf("alice total_matching=%v, want 1", aliceHist["total_matching"])
	}

	// 2. Bob sees both Engine and SecretServer (2 commits).
	status, bobHist := apiJSON(t, http.MethodGet, srv+"/api/v1/projects/Alpha/history", bobTok, nil)
	if status != http.StatusOK || int(bobHist["total_matching"].(float64)) != 2 {
		t.Fatalf("bob history %d %v", status, bobHist)
	}

	// 3. Alice probing SecretServer module history, commits, or refs returns exact same 404 as unknown module!
	for _, path := range []string{
		"/api/v1/modules/" + itoa(secID) + "/history",
		"/api/v1/modules/" + itoa(secID) + "/commits/" + fmt.Sprintf("%040x", 202),
		"/api/v1/modules/" + itoa(secID) + "/refs",
		"/api/v1/modules/999999/history",
	} {
		st, body := apiJSON(t, http.MethodGet, srv+path, aliceTok, nil)
		if st != http.StatusNotFound || body["error"] != "not found" {
			t.Fatalf("expected uniform 404 not found for %s, got %d %v", path, st, body)
		}
	}

	// 4. Dave (non-member) probing project history returns 404.
	if st, _ := apiJSON(t, http.MethodGet, srv+"/api/v1/projects/Alpha/history", daveTok, nil); st != http.StatusNotFound {
		t.Fatalf("dave project history got %d", st)
	}

	// 5. Alice can read Engine commit detail by original Git SHA AND list Engine tags!
	st, cDetail := apiJSON(t, http.MethodGet, srv+"/api/v1/modules/"+itoa(engID)+"/commits/"+fmt.Sprintf("%040x", 101), aliceTok, nil)
	if st != http.StatusOK || cDetail["lore_revision"] != fmt.Sprintf("%064x", 101) {
		t.Fatalf("commit detail %d %v", st, cDetail)
	}
	st, refsBody := apiJSON(t, http.MethodGet, srv+"/api/v1/modules/"+itoa(engID)+"/refs?type=tag", aliceTok, nil)
	if st != http.StatusOK || !strings.Contains(mustJSON(refsBody), "v1.0.0") {
		t.Fatalf("refs %d %v", st, refsBody)
	}

	// 6. Ordinary member Alice cannot trigger or read project import jobs (403 Forbidden)!
	st, _ = apiJSON(t, http.MethodPost, srv+"/api/v1/projects/Alpha/imports", aliceTok, map[string]any{
		"dry_run":      true,
		"repositories": []map[string]any{{"source_url": "https://github.com/org/tools.git", "module_name": "Tools", "mount_path": "Tools"}},
	})
	if st != http.StatusForbidden {
		t.Fatalf("member import expected 403, got %d", st)
	}
	if st, _ = apiJSON(t, http.MethodGet, srv+"/api/v1/projects/Alpha/imports", aliceTok, nil); st != http.StatusForbidden {
		t.Fatalf("member list import jobs expected 403, got %d", st)
	}

	// 7. History sync=1 MUST fail closed (HTTP 502) and NEVER return stale cached commits as fresh when Lore sync fails!
	//    Here `Engine` points to unreachable `grpc://127.0.0.1:53547/engine` and `fakeLore` fails clone/sync!
	st, staleModBody := apiJSON(t, http.MethodGet, srv+"/api/v1/modules/"+itoa(engID)+"/history?sync=1", aliceTok, nil)
	if st == http.StatusOK {
		t.Fatalf("module history?sync=1 MUST fail when sync fails, but returned 200 stale data: %v", staleModBody)
	}
	st, staleProjBody := apiJSON(t, http.MethodGet, srv+"/api/v1/projects/Alpha/history?sync=1", aliceTok, nil)
	if st == http.StatusOK {
		t.Fatalf("project history?sync=1 MUST fail when sync fails, but returned 200 stale data: %v", staleProjBody)
	}

	// 8. Security check on API: Carol (project_admin) CANNOT read arbitrary Manager server environment variables
	//    by posting `token_env` without `runtime_tokens` or posting `ssh_key_env`!
	t.Setenv("MANAGER_HOST_PRIVATE_SECRET", "do-not-read-from-server")
	st, envStealBody := apiJSON(t, http.MethodPost, srv+"/api/v1/projects/Alpha/imports", carolTok, map[string]any{
		"dry_run": true,
		"repositories": []map[string]any{{
			"source_url":  "https://github.com/org/tools.git",
			"module_name": "StealEnv",
			"mount_path":  "StealEnv",
			"auth": map[string]any{
				"auth_method": "https_token",
				"token_env":   "MANAGER_HOST_PRIVATE_SECRET",
			},
		}},
	})
	if st != http.StatusBadRequest {
		t.Fatalf("server-side token_env probing MUST return 400, got %d %v", st, envStealBody)
	}
	st, sshStealBody := apiJSON(t, http.MethodPost, srv+"/api/v1/projects/Alpha/imports", carolTok, map[string]any{
		"dry_run": true,
		"repositories": []map[string]any{{
			"source_url":  "ssh://git@github.com/org/tools.git",
			"module_name": "StealSSH",
			"mount_path":  "StealSSH",
			"auth": map[string]any{
				"auth_method": "ssh_key",
				"ssh_key_env": "MANAGER_HOST_PRIVATE_SECRET",
			},
		}},
	})
	if st != http.StatusBadRequest {
		t.Fatalf("server-side ssh_key_env probing MUST return 400, got %d %v", st, sshStealBody)
	}

	// If git & real lore exist, verify:
	//  (a) local path outside AllowedLocalDirs fails closed under RestrictLocalSources=true, and
	//  (b) local path inside AllowedLocalDirs succeeds!
	if gitPath, gErr := exec.LookPath("git"); gErr == nil {
		loreCand := `C:\Program Files\lore\lore.exe`
		if _, sErr := os.Stat(loreCand); sErr != nil {
			loreCand = `/data/lore/bin/lore`
		}
		if _, sErr := os.Stat(loreCand); sErr == nil {
			realExec := loreexec.Executor{Config: loreexec.Config{Binary: loreCand}}
			app.Importer.Lore = &loreadapter.Client{Exec: realExec}
			app.Importer.GitBinary = gitPath

			baseDir := t.TempDir()
			allowedDir := filepath.Join(baseDir, "allowed")
			forbiddenDir := filepath.Join(baseDir, "forbidden")
			_ = os.MkdirAll(allowedDir, 0o755)
			_ = os.MkdirAll(forbiddenDir, 0o755)
			app.Importer.AllowedLocalDirs = []string{allowedDir}

			initGit := func(dir string) {
				_ = os.MkdirAll(dir, 0o755)
				runCmd := func(args ...string) {
					c := exec.Command(gitPath, args...)
					c.Dir = dir
					c.Env = append(os.Environ(),
						"GIT_AUTHOR_NAME=Carol", "GIT_AUTHOR_EMAIL=carol@example.com",
						"GIT_COMMITTER_NAME=Carol", "GIT_COMMITTER_EMAIL=carol@example.com",
					)
					if out, err := c.CombinedOutput(); err != nil {
						t.Fatalf("git %v: %v %s", args, err, out)
					}
				}
				runCmd("init", "-b", "main")
				_ = os.WriteFile(filepath.Join(dir, "tool.go"), []byte("package tool\n"), 0o644)
				runCmd("add", "tool.go")
				runCmd("commit", "-m", "init tools")
			}

			outsideRepo := filepath.Join(forbiddenDir, "secret-git")
			initGit(outsideRepo)
			st, denyBody := apiJSON(t, http.MethodPost, srv+"/api/v1/projects/Alpha/imports", carolTok, map[string]any{
				"repositories": []map[string]any{
					{"source_url": outsideRepo, "module_name": "ForbiddenTools", "mount_path": "ForbiddenTools"},
				},
			})
			if st != http.StatusOK || denyBody["status"] != "failed" {
				t.Fatalf("local path outside AllowedLocalDirs MUST fail item, got %d %v", st, denyBody)
			}

			srcGit := filepath.Join(allowedDir, "tools-git")
			initGit(srcGit)
			st, impBody := apiJSON(t, http.MethodPost, srv+"/api/v1/projects/Alpha/imports", carolTok, map[string]any{
				"repositories": []map[string]any{
					{"source_url": srcGit, "module_name": "Tools", "mount_path": "Tools"},
				},
			})
			if st != http.StatusOK || impBody["status"] != "succeeded" {
				t.Fatalf("HTTP live import inside AllowedLocalDirs failed: %d %v", st, impBody)
			}
		}
	}
}
