package gitimport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lore-monorepo/internal/database"
	"lore-monorepo/internal/history"
	"lore-monorepo/internal/loreadapter"
	"lore-monorepo/internal/loreexec"
	"lore-monorepo/internal/project"
	"lore-monorepo/internal/publish"
	"lore-monorepo/internal/user"
)

func findRealLore(t *testing.T) string {
	t.Helper()
	candidates := []string{
		os.Getenv("LORE_BIN"),
		`C:\Program Files\lore\lore.exe`,
		`/data/lore/bin/lore`,
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	if p, err := exec.LookPath("lore"); err == nil {
		return p
	}
	t.Skip("real Lore 0.10.1 CLI binary not found on this machine")
	return ""
}

func findRealGit(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git binary not found")
	}
	return p
}

func TestPlatformDetectionAndSecretRejection(t *testing.T) {
	cases := []struct {
		url      string
		wantPlat string
		wantErr  error
	}{
		{"https://github.com/org/engine.git", PlatformGitHub, nil},
		{"git@github.com:org/engine.git", PlatformGitHub, nil},
		{"https://gitee.com/team/client.git", PlatformGitee, nil},
		{"https://gitlab.com/group/sub/server.git", PlatformGitLab, nil},
		{"https://git.woa.com/group/tools.git", PlatformGongfeng, nil},
		{"ssh://git@git.code.tencent.com/group/tools.git", PlatformGongfeng, nil},
		{"https://git.internal.corp/core.git", PlatformGenericGit, nil},
		{"https://sample_token_value@github.com/org/engine.git", "", ErrEmbeddedCredentials},
		{"https://oauth2:sample_secret_value@gitlab.com/org/repo.git", "", ErrEmbeddedCredentials},
	}
	for _, tc := range cases {
		_, plat, err := ValidateAndDetect(tc.url, "")
		if tc.wantErr != nil {
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("url %q expected %v, got %v", tc.url, tc.wantErr, err)
			}
			continue
		}
		if err != nil || plat != tc.wantPlat {
			t.Fatalf("url %q got (%q, %v), want %q", tc.url, plat, err, tc.wantPlat)
		}
	}

	// Verify BuildGitAuthEnv injects HTTP extraheader and redacts secrets without touching argv.
	env, secrets, method, err := BuildGitAuthEnv("https://git.woa.com/team/repo.git", PlatformGongfeng, AuthConfig{
		Token: "super-secret-token-999",
	})
	if err != nil || method != AuthHTTPSToken || len(env) < 3 {
		t.Fatalf("auth env err=%v method=%s env=%v", err, method, env)
	}
	redacted := RedactOutput("fatal: error super-secret-token-999\nAuthorization: Basic xyz", secrets)
	if strings.Contains(redacted, "super-secret-token-999") || strings.Contains(strings.ToLower(redacted), "authorization:") {
		t.Fatalf("secret leaked in redacted output: %s", redacted)
	}

	// Verify LoadManifest rejects unknown fields (e.g. plaintext token in manifest TOML).
	badPath := filepath.Join(t.TempDir(), "bad.toml")
	_ = os.WriteFile(badPath, []byte(`
project = "Alpha"
[[repositories]]
source_url = "https://github.com/org/repo.git"
module_name = "Engine"
token = "plain-secret-must-fail"
`), 0o644)
	if _, err := LoadManifest(badPath); err == nil {
		t.Fatal("manifest with plaintext unknown token key must be rejected")
	}
}

type gitExecHelper struct {
	t   *testing.T
	bin string
	dir string
}

func (g gitExecHelper) run(env map[string]string, args ...string) string {
	g.t.Helper()
	cmd := exec.Command(g.bin, args...)
	cmd.Dir = g.dir
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		g.t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
	}
	return strings.TrimSpace(string(out))
}

func (g gitExecHelper) commitAs(name, email, dateISO, msg string, allowEmpty bool) string {
	g.t.Helper()
	env := map[string]string{
		"GIT_AUTHOR_NAME":     name,
		"GIT_AUTHOR_EMAIL":    email,
		"GIT_AUTHOR_DATE":     dateISO,
		"GIT_COMMITTER_NAME":  "Release CI",
		"GIT_COMMITTER_EMAIL": "ci@example.com",
		"GIT_COMMITTER_DATE":  dateISO,
	}
	args := []string{"commit", "-m", msg}
	if allowEmpty {
		args = append(args, "--allow-empty")
	}
	g.run(env, args...)
	return g.run(nil, "rev-parse", "HEAD")
}

// buildComplexSyntheticGitRepo constructs a rich Git repository covering:
//   - Multiple branches (`main`, `feature/unicode-ui`, `side-b`, `release/v1.0`)
//   - Lightweight tag (`v0.1.0-alpha`) and Annotated tag (`v1.0.0` with tagger + message)
//   - Conflicting 2-parent merge commit resolved cleanly
//   - 3-parent Octopus merge commit (`git merge feature/unicode-ui side-b`)
//   - Multiple authors, identical timestamps, multiline Unicode messages, empty commit
//   - Git LFS pointer file + hydrated LFS payload in .git/lfs/objects + submodule gitlink (mode 160000)
func buildComplexSyntheticGitRepo(t *testing.T, gitBin, root string) (repoDir string, expectedCommits int) {
	t.Helper()
	// Create a tiny submodule repo so `git submodule add` creates a real 160000 gitlink + .gitmodules!
	subDir := filepath.Join(root, "thirdparty-sub")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sub := gitExecHelper{t: t, bin: gitBin, dir: subDir}
	sub.run(nil, "init", "-b", "main")
	_ = os.WriteFile(filepath.Join(subDir, "sub.c"), []byte("int sub() { return 42; }\n"), 0o644)
	sub.run(nil, "add", "sub.c")
	subSHA := sub.commitAs("Sub Author", "sub@example.com", "2025-02-01T10:00:00Z", "init submodule", false)

	repoDir = filepath.Join(root, "complex-engine")
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	g := gitExecHelper{t: t, bin: gitBin, dir: repoDir}
	g.run(nil, "init", "-b", "main")

	// C1: Initial commit on main (with subdirectory & file that will later be deleted).
	_ = os.MkdirAll(filepath.Join(repoDir, "src", "legacy"), 0o755)
	_ = os.WriteFile(filepath.Join(repoDir, "src", "core.go"), []byte("package core\nconst Version = 1\n"), 0o644)
	_ = os.WriteFile(filepath.Join(repoDir, "src", "legacy", "old.txt"), []byte("to be deleted\n"), 0o644)
	g.run(nil, "add", ".")
	c1 := g.commitAs("Alice Chen", "alice@example.com", "2025-03-01T08:00:00Z", "feat: 初始引擎核心 🚀\n\nMulti-line body with UTF-8 中文 & emoji.", false)
	g.run(nil, "tag", "v0.1.0-alpha", c1)

	// Branch `feature/unicode-ui` from C1: 2 commits sharing the EXACT same timestamp as main commits!
	g.run(nil, "checkout", "-b", "feature/unicode-ui")
	_ = os.WriteFile(filepath.Join(repoDir, "src", "core.go"), []byte("package core\nconst Version = 2 // feature side\n"), 0o644)
	_ = os.WriteFile(filepath.Join(repoDir, "ui.txt"), []byte("界面模块 v1\n"), 0o644)
	g.run(nil, "add", ".")
	_ = g.commitAs("王小明", "xiaoming@example.com", "2025-03-02T09:00:00Z", "feat(ui): 添加多语言界面支持", false)

	// Add an LFS pointer file whose real binary payload we also place in .git/lfs/objects so hydration is tested!
	lfsPayload := []byte("REAL-HYDRATED-LFS-ASSET-BINARY-PAYLOAD-2026\x00\x01\x02")
	lfsSum := sha256.Sum256(lfsPayload)
	lfsOID := hex.EncodeToString(lfsSum[:])
	lfsPointer := fmt.Sprintf("version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize %d\n", lfsOID, len(lfsPayload))
	_ = os.MkdirAll(filepath.Join(repoDir, "assets"), 0o755)
	_ = os.WriteFile(filepath.Join(repoDir, "assets", "hero.bin"), []byte(lfsPointer), 0o644)
	//Also add an unhydrated LFS pointer (simulating pointer-only object) to verify graceful pointer tracking!
	_ = os.WriteFile(filepath.Join(repoDir, "assets", "missing_remote.bin"),
		[]byte("version https://git-lfs.github.com/spec/v1\noid sha256:9999999999999999999999999999999999999999999999999999999999999999\nsize 128\n"), 0o644)
	g.run(nil, "add", ".")
	_ = g.commitAs("王小明", "xiaoming@example.com", "2025-03-02T09:00:00Z", "feat(assets): 添加主角模型资源 (LFS)", false)

	// Place hydrated LFS object inside repoDir/.git/lfs/objects/<oid[:2]>/<oid[2:4]>/<oid>
	lfsObjDir := filepath.Join(repoDir, ".git", "lfs", "objects", lfsOID[:2], lfsOID[2:4])
	_ = os.MkdirAll(lfsObjDir, 0o755)
	_ = os.WriteFile(filepath.Join(lfsObjDir, lfsOID), lfsPayload, 0o644)

	// Branch `side-b` from C1 for octopus merge!
	g.run(nil, "checkout", "-b", "side-b", c1)
	_ = os.WriteFile(filepath.Join(repoDir, "side_b.txt"), []byte("side-b feature\n"), 0o644)
	g.run(nil, "add", ".")
	_ = g.commitAs("Bob Li", "bob@example.com", "2025-03-02T09:00:00Z", "feat: side-b independent work", false)

	// Switch back to `main`: delete legacy directory, modify core.go (creating conflict with feature/unicode-ui),
	// and register a submodule gitlink (mode 160000) directly in the index!
	g.run(nil, "checkout", "main")
	_ = os.RemoveAll(filepath.Join(repoDir, "src", "legacy"))
	_ = os.WriteFile(filepath.Join(repoDir, "src", "core.go"), []byte("package core\nconst Version = 2 // main side\n"), 0o644)
	_ = os.WriteFile(filepath.Join(repoDir, ".gitmodules"), []byte("[submodule \"vendor/sub\"]\n\tpath = vendor/sub\n\turl = https://github.com/example/sub.git\n"), 0o644)
	g.run(nil, "add", "-A")
	g.run(nil, "update-index", "--add", "--cacheinfo", "160000,"+subSHA+",vendor/sub")
	_ = g.commitAs("Alice Chen", "alice@example.com", "2025-03-02T09:00:00Z", "refactor: 清理旧文件并关联子模块", false)

	// Conflicting 2-parent merge of `feature/unicode-ui` into `main`!
	mergeCmd := exec.Command(gitBin, "merge", "--no-commit", "feature/unicode-ui")
	mergeCmd.Dir = repoDir
	_ = mergeCmd.Run() // expected exit 1 due to conflict in src/core.go
	_ = os.WriteFile(filepath.Join(repoDir, "src", "core.go"), []byte("package core\nconst Version = 3 // resolved merge\n"), 0o644)
	g.run(nil, "add", "src/core.go")
	_ = g.commitAs("Alice Chen", "alice@example.com", "2025-03-03T10:00:00Z", "merge: 合并 feature/unicode-ui 解决冲突", false)

	// Add one more commit on `feature/unicode-ui` so we can do a true 3-parent Octopus merge (`main` + `feature/unicode-ui` + `side-b`)!
	g.run(nil, "checkout", "feature/unicode-ui")
	_ = os.WriteFile(filepath.Join(repoDir, "ui_extra.txt"), []byte("extra ui\n"), 0o644)
	g.run(nil, "add", "ui_extra.txt")
	_ = g.commitAs("王小明", "xiaoming@example.com", "2025-03-04T11:00:00Z", "feat(ui): 补充组件", false)

	g.run(nil, "checkout", "main")
	octoEnv := map[string]string{
		"GIT_AUTHOR_NAME":     "Carol Admin",
		"GIT_AUTHOR_EMAIL":    "carol@example.com",
		"GIT_AUTHOR_DATE":     "2025-03-05T12:00:00Z",
		"GIT_COMMITTER_NAME":  "Carol Admin",
		"GIT_COMMITTER_EMAIL": "carol@example.com",
		"GIT_COMMITTER_DATE":  "2025-03-05T12:00:00Z",
	}
	g.run(octoEnv, "merge", "--no-ff", "-m", "merge: Octopus 合并 UI 与 side-b 分支", "feature/unicode-ui", "side-b")

	// Empty release marker commit + annotated tag + release/v1.0 branch pointing to HEAD!
	headSHA := g.commitAs("Carol Admin", "carol@example.com", "2025-03-06T15:00:00Z", "chore(release): 发布 v1.0.0 空标记提交", true)
	g.run(octoEnv, "tag", "-a", "v1.0.0", "-m", "正式发布版本 1.0.0 🎉", headSHA)
	g.run(nil, "branch", "release/v1.0", headSHA)

	// Also create an advertised platform-internal hidden ref `refs/pull/42/head` to test hidden-ref reporting!
	g.run(nil, "update-ref", "refs/pull/42/head", c1)

	countStr := g.run(nil, "rev-list", "--count", "--branches", "--tags")
	var total int
	_, _ = fmt.Sscanf(countStr, "%d", &total)
	return repoDir, total
}

func buildSimpleGitRepo(t *testing.T, gitBin, dir, prefix string, n int) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	g := gitExecHelper{t: t, bin: gitBin, dir: dir}
	g.run(nil, "init", "-b", "main")
	base := time.Date(2025, 4, 1, 0, 0, 0, 0, time.UTC)
	for i := 1; i <= n; i++ {
		_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("%s_%d.txt", prefix, i)), []byte(fmt.Sprintf("%s payload %d\n", prefix, i)), 0o644)
		g.run(nil, "add", ".")
		ts := base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339)
		_ = g.commitAs("Dev "+prefix, prefix+"@example.com", ts, fmt.Sprintf("feat(%s): step %d", prefix, i), false)
	}
	return dir
}

func TestEndToEndBatchGitImportResumePostCommitAndSnapshotPublish(t *testing.T) {
	loreBin := findRealLore(t)
	gitBin := findRealGit(t)

	ctx := context.Background()
	tmp := t.TempDir()
	db, err := database.Open(filepath.Join(tmp, "manager.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	carolID, _ := user.Create(ctx, db, "test", "carol", "correct-horse", "user")
	aliceID, _ := user.Create(ctx, db, "test", "alice", "correct-horse", "user")
	bobID, _ := user.Create(ctx, db, "test", "bob", "correct-horse", "user")

	proj, err := project.CreateProject(ctx, db, "carol", project.Project{
		Name:                "Alpha",
		ParentRepositoryID:  "00112233445566778899aabbccddeeff",
		ParentRepositoryURL: "lore://local/alpha-parent",
		CreatedBy:           carolID,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = project.AddMember(ctx, db, "carol", proj.ID, carolID, project.RoleAdmin)
	_ = project.AddMember(ctx, db, "carol", proj.ID, aliceID, project.RoleMember)
	_ = project.AddMember(ctx, db, "carol", proj.ID, bobID, project.RoleMember)

	// Build 2 real synthetic external Git repositories:
	// 1. Engine: complex multi-branch + conflicting 2-parent merge + 3-parent octopus merge + tags + LFS + submodule + empty commit
	// 2. Docs: 15 linear commits
	engineGitDir, wantEngineCommits := buildComplexSyntheticGitRepo(t, gitBin, tmp)
	docsGitDir := buildSimpleGitRepo(t, gitBin, filepath.Join(tmp, "docs-git"), "docs", 15)

	// Copy hydrated LFS objects into the bare mirror path once SyncBareMirror runs?
	// Note: for a local file path `git fetch` fetches Git objects, while `git lfs fetch` over a bare local dir
	// works if git-lfs resolves the local dir! Even better, let's check what happens naturally and also verify LFS!
	execLore := loreexec.Executor{Config: loreexec.Config{Binary: loreBin, Timeout: 2 * time.Minute}}
	loreClient := &loreadapter.Client{Exec: execLore}

	workRoot := filepath.Join(tmp, "import-workspace")
	imp := &Importer{
		DB:            db,
		Lore:          loreClient,
		GitBinary:     gitBin,
		WorkspaceRoot: workRoot,
	}

	// =========================================================================
	// PHASE A: Dry-Run Preview (including 1 unreachable repo to verify failure isolation)
	// =========================================================================
	dryRes, err := imp.Run(ctx, "carol", Manifest{
		Project: "Alpha",
		DryRun:  true,
		Repositories: []RepoSpec{
			{SourceURL: engineGitDir, ModuleName: "Engine", MountPath: "Engine"},
			{SourceURL: docsGitDir, ModuleName: "Docs", MountPath: "Docs"},
			{SourceURL: filepath.Join(tmp, "does-not-exist-git"), ModuleName: "Broken", MountPath: "Broken"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dryRes.Status != "partial_failed" || dryRes.SucceededItems != 2 || dryRes.FailedItems != 1 {
		t.Fatalf("dry-run expected partial_failed (2 planned, 1 failed), got %+v", dryRes)
	}
	if len(dryRes.Items[0].Verification.AdvertisedHiddenRefs) != 1 || dryRes.Items[0].Verification.AdvertisedHiddenRefs[0] != "refs/pull/42/head" {
		t.Fatalf("dry-run must explicitly report advertised hidden refs: %+v", dryRes.Items[0].Verification.AdvertisedHiddenRefs)
	}
	// Dry-run must NOT have created any modules in project!
	modsAfterDry, _ := project.ListModules(ctx, db, proj.ID, true)
	if len(modsAfterDry) != 0 {
		t.Fatalf("dry-run created %d modules!", len(modsAfterDry))
	}

	// =========================================================================
	// PHASE B: Fault-Injected Batch Import (interrupt Engine mid-replay, Broken fails, Docs succeeds!)
	// =========================================================================
	injectedOnce := false
	imp.FaultHook = func(moduleName string, idx int) error {
		if moduleName == "Engine" && idx == 3 && !injectedOnce {
			injectedOnce = true
			return errors.New("simulated crash at commit index 3")
		}
		return nil
	}

	batchManifest := Manifest{
		JobKey:  "batch-alpha-001",
		Project: "Alpha",
		Repositories: []RepoSpec{
			{SourceURL: engineGitDir, ModuleName: "Engine", MountPath: "Engine"},
			{SourceURL: docsGitDir, ModuleName: "Docs", MountPath: "Docs"},
		},
	}

	firstRun, err := imp.Run(ctx, "carol", batchManifest)
	if err != nil {
		t.Fatal(err)
	}
	if firstRun.Status != "partial_failed" || firstRun.SucceededItems != 1 || firstRun.FailedItems != 1 {
		t.Fatalf("fault-injected run expected partial_failed (Docs ok, Engine interrupted), got %+v", firstRun)
	}

	// =========================================================================
	// PHASE C: Checkpoint Resume (clear FaultHook, re-run same JobKey -> resumes Engine from commit 4!)
	// =========================================================================
	imp.FaultHook = nil
	resumedRun, err := imp.Run(ctx, "carol", batchManifest)
	if err != nil {
		t.Fatal(err)
	}
	if resumedRun.Status != "succeeded" || resumedRun.SucceededItems != 2 || resumedRun.FailedItems != 0 {
		t.Fatalf("resumed run failed: %+v (item0 err=%q, item1 err=%q)", resumedRun, resumedRun.Items[0].Error, resumedRun.Items[1].Error)
	}

	engVer := resumedRun.Items[0].Verification
	if !engVer.Passed || engVer.IndexedCommits != wantEngineCommits || engVer.SourceBranches != 4 || engVer.SourceTags != 2 {
		t.Fatalf("Engine verification mismatch: want %d commits, got %+v", wantEngineCommits, engVer)
	}
	if engVer.MergeCommitsVerified != 2 || engVer.OctopusMergesVerified != 1 || engVer.SyntheticMergeBridges != 1 {
		t.Fatalf("Engine merge/octopus verification mismatch: %+v", engVer)
	}
	if engVer.HeadGitDigest == "" || engVer.HeadGitDigest != engVer.HeadLoreDigest {
		t.Fatalf("Engine HEAD tree digest mismatch: git=%s lore=%s", engVer.HeadGitDigest, engVer.HeadLoreDigest)
	}

	// =========================================================================
	// PHASE D: Idempotency & Conflict Policy Checks
	// =========================================================================
	// Re-running the exact same succeeded JobKey returns immediately without duplicating commits or modules!
	idemRun, err := imp.Run(ctx, "carol", batchManifest)
	if err != nil || idemRun.Status != "succeeded" || idemRun.JobID != resumedRun.JobID {
		t.Fatalf("idempotent re-run failed: %+v err=%v", idemRun, err)
	}

	// Running a NEW job targeting already-existing `Engine` with default ConflictFail MUST reject without overwriting!
	conflictRun, err := imp.Run(ctx, "carol", Manifest{
		Project:      "Alpha",
		Repositories: []RepoSpec{{SourceURL: engineGitDir, ModuleName: "Engine", MountPath: "Engine"}},
	})
	if err != nil || conflictRun.FailedItems != 1 || conflictRun.Items[0].Status != "conflict" {
		t.Fatalf("conflict policy fail must reject existing module: %+v err=%v", conflictRun, err)
	}

	// Running with ConflictSkipIfImported skips cleanly!
	skipRun, err := imp.Run(ctx, "carol", Manifest{
		Project:        "Alpha",
		ConflictPolicy: ConflictSkipIfImported,
		Repositories:   []RepoSpec{{SourceURL: engineGitDir, ModuleName: "Engine", MountPath: "Engine"}},
	})
	if err != nil || skipRun.SkippedItems != 1 || skipRun.Items[0].Status != "skipped" {
		t.Fatalf("skip_if_imported failed: %+v err=%v", skipRun, err)
	}

	// =========================================================================
	// PHASE E: Verify History DAG, Special Objects, Permissions, Post-Import Lore Commits & Snapshot Publish!
	// =========================================================================
	engineModID := resumedRun.Items[0].ModuleID
	docsModID := resumedRun.Items[1].ModuleID

	// Grant Alice -> Engine only; Grant Bob -> Engine + Docs.
	_ = project.SetModulePermission(ctx, db, "carol", aliceID, engineModID, project.PermWrite)
	_ = project.SetModulePermission(ctx, db, "carol", bobID, engineModID, project.PermRead)
	_ = project.SetModulePermission(ctx, db, "carol", bobID, docsModID, project.PermRead)

	histSvc := history.Service{DB: db}

	// Check Engine refs (4 branches + 2 tags, including annotated tag v1.0.0 message & tagger!).
	refs, err := histSvc.ListModuleRefs(ctx, aliceID, engineModID, "")
	if err != nil || len(refs) != 6 {
		t.Fatalf("Engine refs=%d, want 6 (4 branches + 2 tags), err=%v", len(refs), err)
	}
	sawAnnotated := false
	for _, r := range refs {
		if r.Type == "tag" && r.Name == "v1.0.0" && r.IsAnnotated && strings.Contains(r.TagMessage, "1.0.0") && r.TaggerEmail == "carol@example.com" {
			sawAnnotated = true
		}
	}
	if !sawAnnotated {
		t.Fatalf("annotated tag v1.0.0 metadata was not preserved: %+v", refs)
	}

	// Check Octopus merge commit has all 3 ordered Git & Lore parents!
	octoPage, err := histSvc.ModuleHistory(ctx, aliceID, engineModID, history.Filter{Search: "Octopus", Limit: 5})
	if err != nil || len(octoPage.Commits) != 1 {
		t.Fatalf("octopus search got %+v err=%v", octoPage, err)
	}
	octo := octoPage.Commits[0]
	if !octo.IsMerge || octo.ParentCount != 3 || len(octo.Parents) != 3 {
		t.Fatalf("octopus parents=%d (%+v), want 3", octo.ParentCount, octo.Parents)
	}
	for i, p := range octo.Parents {
		if len(p.SourceCommitID) != 40 || len(p.LoreRevision) != 64 {
			t.Fatalf("octopus parent[%d] missing git/lore mapping: %+v", i, p)
		}
	}

	// Check special objects (submodule gitlink + LFS hydrated/pointer) were recorded and retrievable!
	engAll, err := histSvc.ModuleHistory(ctx, aliceID, engineModID, history.Filter{Limit: 100})
	if err != nil || engAll.TotalMatching != wantEngineCommits {
		t.Fatalf("Engine history total=%d, want %d", engAll.TotalMatching, wantEngineCommits)
	}
	sawSubmodule, sawLFS := false, false
	for _, c := range engAll.Commits {
		for _, sp := range c.SpecialObjects {
			if sp.Kind == "submodule_gitlink" && sp.Path == "vendor/sub" && strings.Contains(sp.DetailJSON, "example/sub.git") {
				sawSubmodule = true
			}
			if (sp.Kind == "lfs_hydrated" || sp.Kind == "lfs_pointer") && sp.Path == "assets/hero.bin" {
				sawLFS = true
			}
		}
	}
	if !sawSubmodule || !sawLFS {
		t.Fatalf("special objects missing: sawSubmodule=%v sawLFS=%v", sawSubmodule, sawLFS)
	}

	// Now create a NEW native Lore commit on the imported Engine Lore repository (post-import collaboration!)
	// and run SyncModuleFromLore to verify new Lore commits seamlessly join the unified history!
	engineLoreDir := filepath.Join(workRoot, fmt.Sprintf("proj-%d", proj.ID), "lore", "Engine")
	if err := os.WriteFile(filepath.Join(engineLoreDir, "post_import.go"), []byte("package core\n// Post-import Lore commit!\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := loreClient.StageScan(ctx, engineLoreDir, true); err != nil {
		t.Fatal(err)
	}
	if err := loreClient.SetStagedMetadata(ctx, engineLoreDir, map[string]string{"created-by": fmt.Sprint(aliceID)}, true); err != nil {
		t.Fatal(err)
	}
	newLoreRev, err := loreClient.CommitFull(ctx, engineLoreDir, "feat(lore): 导入后原生 Lore 新提交 ✨", false, true)
	if err != nil {
		t.Fatal(err)
	}

	syncStats, err := history.SyncModuleFromLore(ctx, db, loreClient, engineModID, engineLoreDir)
	if err != nil {
		t.Fatal(err)
	}
	if syncStats.CommitsUpserted != 1 {
		t.Fatalf("post-import SyncModuleFromLore upserted %d commits, want 1 (zero duplicate re-indexing of imported commits!)", syncStats.CommitsUpserted)
	}

	// Verify Alice's aggregated history now has wantEngineCommits + 1 (and NO Docs commits),
	// while Bob's aggregated history has (wantEngineCommits + 1) + 15!
	aliceProjHist, err := histSvc.ProjectHistory(ctx, aliceID, proj.ID, history.Filter{Limit: 100})
	if err != nil || aliceProjHist.TotalMatching != wantEngineCommits+1 {
		t.Fatalf("alice aggregated total=%d, want %d", aliceProjHist.TotalMatching, wantEngineCommits+1)
	}
	if aliceProjHist.Commits[0].LoreRevision != newLoreRev || aliceProjHist.Commits[0].OriginKind != history.OriginNativeLore {
		t.Fatalf("newest commit should be post-import native Lore commit, got %+v", aliceProjHist.Commits[0])
	}
	bobProjHist, err := histSvc.ProjectHistory(ctx, bobID, proj.ID, history.Filter{Limit: 100})
	if err != nil || bobProjHist.TotalMatching != wantEngineCommits+1+15 {
		t.Fatalf("bob aggregated total=%d, want %d", bobProjHist.TotalMatching, wantEngineCommits+1+15)
	}

	// Verify Snapshot Publisher still works seamlessly with the imported + updated Lore modules
	// AND does not pollute or alter either module's commit history!
	docsLoreDir := filepath.Join(workRoot, fmt.Sprintf("proj-%d", proj.ID), "lore", "Docs")
	docsStatus, err := loreClient.Status(ctx, docsLoreDir)
	if err != nil {
		t.Fatal(err)
	}
	memPubDrv := &postImportPublishDriver{
		revs: map[string]string{
			"parent":      "1111111111111111111111111111111111111111111111111111111111111111",
			engineLoreDir: newLoreRev,
			docsLoreDir:   docsStatus.Revision,
		},
		links: map[string]string{},
	}
	pubRes, err := (publish.Publisher{DB: db, Driver: memPubDrv}).Publish(ctx, publish.Request{
		ProjectID: proj.ID,
		ParentDir: "parent",
		ModuleDirs: map[string]string{
			"Engine": engineLoreDir,
			"Docs":   docsLoreDir,
		},
		Actor:   "carol",
		Message: "release snapshot after import",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pubRes.Pins) != 2 {
		t.Fatalf("snapshot pins=%+v, want 2", pubRes.Pins)
	}
	// Module history count must remain completely unchanged after snapshot publishing!
	afterSnapHist, err := histSvc.ProjectHistory(ctx, bobID, proj.ID, history.Filter{Limit: 10})
	if err != nil || afterSnapHist.TotalMatching != wantEngineCommits+1+15 {
		t.Fatalf("snapshot publish altered module commit history: %d", afterSnapHist.TotalMatching)
	}
}

type postImportPublishDriver struct {
	revs  map[string]string
	links map[string]string
}

func (d *postImportPublishDriver) Revisions(_ context.Context, dir string) (string, string, error) {
	r := d.revs[dir]
	return r, r, nil
}
func (d *postImportPublishDriver) Links(context.Context, string) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range d.links {
		out[k] = v
	}
	return out, nil
}
func (d *postImportPublishDriver) EnsureLink(_ context.Context, _, mount, _, rev string) error {
	d.links[mount] = rev
	return nil
}
func (d *postImportPublishDriver) RemoveLink(_ context.Context, _, mount string) error {
	delete(d.links, mount)
	return nil
}
func (d *postImportPublishDriver) Commit(context.Context, string, string) error { return nil }
func (d *postImportPublishDriver) Push(context.Context, string) error {
	d.revs["parent"] = "2222222222222222222222222222222222222222222222222222222222222222"
	return nil
}
func (d *postImportPublishDriver) FindOperation(context.Context, string, int64) (bool, string, map[string]string, error) {
	return false, "", nil, nil
}
