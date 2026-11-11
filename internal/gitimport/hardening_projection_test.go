package gitimport

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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

func TestHardeningCredentialsURLSSHAndLocalAllowlist(t *testing.T) {
	gitBin := findRealGit(t)
	ctx := context.Background()

	// 1. Plaintext HTTP + Token MUST be rejected with ErrInsecureHTTPAuth!
	if _, _, _, err := BuildGitAuthEnv("http://github.com/org/repo.git", PlatformGitHub, AuthConfig{
		Token: "tok-123456",
	}, AuthPolicy{DisallowProcessEnv: true}); !errors.Is(err, ErrInsecureHTTPAuth) {
		t.Fatalf("http + token expected ErrInsecureHTTPAuth, got %v", err)
	}

	// 2. Server-side DisallowProcessEnv MUST block reading arbitrary server env vars via TokenEnv or SSHKeyEnv!
	t.Setenv("SERVER_INTERNAL_MASTER_SECRET", "top-secret-server-env-val")
	if _, _, _, err := BuildGitAuthEnv("https://github.com/org/repo.git", PlatformGitHub, AuthConfig{
		Method:   AuthHTTPSToken,
		TokenEnv: "SERVER_INTERNAL_MASTER_SECRET",
	}, AuthPolicy{DisallowProcessEnv: true}); !errors.Is(err, ErrServerEnvAccessDenied) {
		t.Fatalf("server TokenEnv expected ErrServerEnvAccessDenied, got %v", err)
	}
	if _, _, _, err := BuildGitAuthEnv("ssh://git@github.com/org/repo.git", PlatformGitHub, AuthConfig{
		Method:    AuthSSHKey,
		SSHKeyEnv: "SERVER_INTERNAL_MASTER_SECRET",
	}, AuthPolicy{DisallowProcessEnv: true}); !errors.Is(err, ErrServerEnvAccessDenied) {
		t.Fatalf("server SSHKeyEnv expected ErrServerEnvAccessDenied, got %v", err)
	}

	// 3. Query & Fragment secrets in SourceURL MUST be rejected BEFORE ever entering SQLite!
	for _, badURL := range []string{
		"https://github.com/org/repo.git?access_token=sec999",
		"https://gitlab.com/org/repo.git?private_token=sec999",
		"https://git.woa.com/org/repo.git#secret_fragment",
		"git@github.com:org/repo.git?token=abc",
		`\\evil-smb-server\share\repo.git`,
	} {
		if _, _, err := ValidateAndDetect(badURL, ""); err == nil {
			t.Fatalf("bad URL %q should have been rejected", badURL)
		} else if strings.Contains(err.Error(), "sec999") || strings.Contains(err.Error(), "secret_fragment") {
			t.Fatalf("error message leaked URL query/fragment secret: %v", err)
		}
	}

	// Verify rejected query URL never creates any row in import_jobs / import_job_items!
	tmp := t.TempDir()
	db, err := database.Open(filepath.Join(tmp, "sec.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	uid, _ := user.Create(ctx, db, "test", "carol", "correct-horse", "user")
	proj, _ := project.CreateProject(ctx, db, "carol", project.Project{
		Name: "SecProj", ParentRepositoryID: "00112233445566778899aabbccddeeff",
		ParentRepositoryURL: "lore://local/sec", CreatedBy: uid,
	})
	_ = project.AddMember(ctx, db, "carol", proj.ID, uid, project.RoleAdmin)

	imp := &Importer{
		DB:                   db,
		GitBinary:            gitBin,
		WorkspaceRoot:        filepath.Join(tmp, "ws"),
		RestrictLocalSources: true,
		AllowedLocalDirs:     []string{filepath.Join(tmp, "allowed-repos")},
	}
	if _, err := imp.Run(ctx, "carol", Manifest{
		Project: "SecProj",
		DryRun:  true,
		Repositories: []RepoSpec{{
			SourceURL:  "https://github.com/org/repo.git?token=never_persist_me",
			ModuleName: "LeakTest",
			MountPath:  "LeakTest",
		}},
	}); err == nil {
		t.Fatal("URL with query token must fail")
	}
	var itemCount int
	_ = db.QueryRow(`SELECT COUNT(*) FROM import_job_items WHERE source_url LIKE '%never_persist_me%'`).Scan(&itemCount)
	if itemCount != 0 {
		t.Fatal("sensitive query URL entered database!")
	}

	// 4. SSH Key & KnownHosts Shell Metacharacter Injection Execution Test!
	// Create a directory/filename containing `$()`, backticks, single quotes, spaces, and semicolons
	// (using characters valid on the current OS) and actually invoke `git ls-remote` via `InspectRemoteRefs`
	// to prove that `sh -c "$GIT_SSH_COMMAND ..."` NEVER executes injected shell commands!
	sshAllowedDir := filepath.Join(tmp, "allowed-ssh")
	_ = os.MkdirAll(sshAllowedDir, 0o755)
	pwnMarker := filepath.Join(sshAllowedDir, "pwned_marker_file")

	subName := "key dir $(touch pwned_marker_file) 'single' ; touch pwned_marker_file"
	if runtime.GOOS != "windows" {
		subName += " `touch pwned_marker_file`"
	}
	weirdDir := filepath.Join(sshAllowedDir, subName)
	if err := os.MkdirAll(weirdDir, 0o755); err != nil {
		t.Fatalf("mkdir weird ssh dir: %v", err)
	}
	keyFile := filepath.Join(weirdDir, "id_ed25519 space")
	khFile := filepath.Join(weirdDir, "known_hosts space")
	_ = os.WriteFile(keyFile, []byte("not-a-valid-private-key\n"), 0o600)
	_ = os.WriteFile(khFile, []byte(""), 0o600)

	sshEnv, sshSecrets, _, err := BuildGitAuthEnv("ssh://git@127.0.0.1:1/org/repo.git", PlatformGenericGit, AuthConfig{
		Method:     AuthSSHKey,
		SSHKeyPath: keyFile,
		KnownHosts: khFile,
	}, AuthPolicy{
		DisallowProcessEnv: true,
		RestrictSSHPaths:   true,
		AllowedSSHKeyDirs:  []string{sshAllowedDir},
	})
	if err != nil {
		t.Fatalf("BuildGitAuthEnv with special chars failed: %v", err)
	}
	// Verify GIT_SSH_COMMAND is static and does NOT contain the raw path characters!
	for _, kv := range sshEnv {
		if strings.HasPrefix(kv, "GIT_SSH_COMMAND=") && strings.Contains(kv, "pwned_marker_file") {
			t.Fatalf("GIT_SSH_COMMAND interpolated raw path unsafely: %s", kv)
		}
	}
	// Actually run Git with this SSH env (with cwd = sshAllowedDir) against closed port 127.0.0.1:1
	// so if `sh -c "$GIT_SSH_COMMAND ..."` evaluated `$()` or backticks or `;`, `pwned_marker_file` would be created!
	_, _ = runGit(ctx, gitBin, sshAllowedDir, sshEnv, sshSecrets, "-c", "protocol.file.allow=never", "ls-remote", "--", "ssh://git@127.0.0.1:1/org/repo.git")
	if _, statErr := os.Stat(pwnMarker); !os.IsNotExist(statErr) {
		t.Fatalf("COMMAND INJECTION EXECUTED via GIT_SSH_COMMAND: %s exists!", pwnMarker)
	}

	// Also verify `minimalGitEnv` strips arbitrary Manager server environment variables from `git` subprocesses!
	if gotEnv := strings.Join(minimalGitEnv(nil), "\n"); strings.Contains(gotEnv, "SERVER_INTERNAL_MASTER_SECRET") {
		t.Fatal("minimalGitEnv leaked server secret environment variable to git child process!")
	}

	// 5. Local Filesystem Allowlist + Path Traversal + Symlink Escape Tests!
	allowedRoot := filepath.Join(tmp, "allowed-repos")
	outsideRoot := filepath.Join(tmp, "outside-secret-repos")
	_ = os.MkdirAll(allowedRoot, 0o755)
	outsideRepo := buildSimpleGitRepo(t, gitBin, filepath.Join(outsideRoot, "secret-repo"), "sec", 2)
	insideRepo := buildSimpleGitRepo(t, gitBin, filepath.Join(allowedRoot, "good-repo"), "good", 2)

	// 5a: Direct outside path -> rejected!
	if _, err := ValidateLocalSourceAccess(outsideRepo, true, []string{allowedRoot}); !errors.Is(err, ErrLocalSourceNotAllowed) {
		t.Fatalf("outside local path must fail with ErrLocalSourceNotAllowed, got %v", err)
	}
	// 5b: `..` traversal from inside allowedRoot -> rejected!
	traversal := filepath.Join(allowedRoot, "..", "outside-secret-repos", "secret-repo")
	if _, err := ValidateLocalSourceAccess(traversal, true, []string{allowedRoot}); !errors.Is(err, ErrLocalSourceNotAllowed) {
		t.Fatalf("traversal path must fail, got %v", err)
	}
	// 5c: `file://` URL pointing outside allowedRoot -> rejected by Importer.Run!
	fileURLOutside := "file:///" + strings.TrimLeft(filepath.ToSlash(outsideRepo), "/")
	dryOutside, err := imp.Run(ctx, "carol", Manifest{
		Project:      "SecProj",
		DryRun:       true,
		Repositories: []RepoSpec{{SourceURL: fileURLOutside, ModuleName: "OutsideMod", MountPath: "OutsideMod"}},
	})
	if err != nil || dryOutside.FailedItems != 1 || !strings.Contains(dryOutside.Items[0].Error, ErrLocalSourceNotAllowed.Error()) {
		t.Fatalf("file:// outside allowed root must fail item: %+v err=%v", dryOutside, err)
	}
	// 5d: Symlink inside allowedRoot pointing to outsideRepo -> rejected after EvalSymlinks!
	symlinkPath := filepath.Join(allowedRoot, "escaped-link")
	if symErr := os.Symlink(outsideRepo, symlinkPath); symErr == nil {
		if _, err := ValidateLocalSourceAccess(symlinkPath, true, []string{allowedRoot}); !errors.Is(err, ErrLocalSourceNotAllowed) {
			t.Fatalf("symlink escaping allowedRoot must be rejected, got %v", err)
		}
	}
	// 5e: Legitimate repo inside allowedRoot -> permitted!
	if cleanIn, err := ValidateLocalSourceAccess(insideRepo, true, []string{allowedRoot}); err != nil || cleanIn == "" {
		t.Fatalf("valid inside repo rejected: %v", err)
	}
}

func TestSkipIfImportedFourStatesShallowAndTamperedDAGVerification(t *testing.T) {
	loreBin := findRealLore(t)
	gitBin := findRealGit(t)
	ctx := context.Background()
	tmp := t.TempDir()

	db, err := database.Open(filepath.Join(tmp, "fourstate.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	carolID, _ := user.Create(ctx, db, "test", "carol", "correct-horse", "user")
	proj, _ := project.CreateProject(ctx, db, "carol", project.Project{
		Name: "FourState", ParentRepositoryID: "00112233445566778899aabbccddeeff",
		ParentRepositoryURL: "lore://local/fourstate", CreatedBy: carolID,
	})
	_ = project.AddMember(ctx, db, "carol", proj.ID, carolID, project.RoleAdmin)

	execLore := loreexec.Executor{Config: loreexec.Config{Binary: loreBin, Timeout: 2 * time.Minute}}
	loreClient := &loreadapter.Client{Exec: execLore}
	imp := &Importer{
		DB:            db,
		Lore:          loreClient,
		GitBinary:     gitBin,
		WorkspaceRoot: filepath.Join(tmp, "ws"),
	}

	srcRepo := buildSimpleGitRepo(t, gitBin, filepath.Join(tmp, "src-four"), "app", 5)

	// -------------------------------------------------------------------------
	// Case 1: Ordinary manually-created module ("OrdinaryMod") MUST NOT be skipped by skip_if_imported!
	// Both DryRun and Live Import must report `conflict`!
	// -------------------------------------------------------------------------
	_, err = project.CreateModule(ctx, db, "carol", project.Module{
		ProjectID: proj.ID, Name: "OrdinaryMod", RepositoryID: "11111111111111111111111111111111",
		RepositoryURL: "grpc://127.0.0.1:53547/ordinary", MountPath: "OrdinaryMod",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, dry := range []bool{true, false} {
		res, rErr := imp.Run(ctx, "carol", Manifest{
			Project:        "FourState",
			DryRun:         dry,
			ConflictPolicy: ConflictSkipIfImported,
			Repositories:   []RepoSpec{{SourceURL: srcRepo, ModuleName: "OrdinaryMod", MountPath: "OrdinaryMod"}},
		})
		if rErr != nil || res.Items[0].Status != "conflict" || res.SkippedItems != 0 {
			t.Fatalf("ordinary module (dry=%v) MUST conflict under skip_if_imported, got %+v err=%v", dry, res.Items[0], rErr)
		}
	}

	// -------------------------------------------------------------------------
	// Case 2: Partial interrupted import + new job with skip_if_imported MUST RESUME (not skip!),
	// and AFTER completion a subsequent job with skip_if_imported MUST SKIP!
	// -------------------------------------------------------------------------
	stoppedOnce := false
	imp.FaultHook = func(mod string, idx int) error {
		if mod == "ResumableMod" && idx == 1 && !stoppedOnce {
			stoppedOnce = true
			return errors.New("interrupt at commit 1")
		}
		return nil
	}
	partRes, err := imp.Run(ctx, "carol", Manifest{
		JobKey:       "job-partial-1",
		Project:      "FourState",
		Repositories: []RepoSpec{{SourceURL: srcRepo, ModuleName: "ResumableMod", MountPath: "ResumableMod"}},
	})
	if err != nil || partRes.Items[0].Status != "failed" {
		t.Fatalf("expected partial failure, got %+v err=%v", partRes, err)
	}
	imp.FaultHook = nil

	// Dry-run with skip_if_imported on partial module previews `planned` (resume), NOT `skipped`!
	dryPartial, err := imp.Run(ctx, "carol", Manifest{
		Project:        "FourState",
		DryRun:         true,
		ConflictPolicy: ConflictSkipIfImported,
		Repositories:   []RepoSpec{{SourceURL: srcRepo, ModuleName: "ResumableMod", MountPath: "ResumableMod"}},
	})
	if err != nil || dryPartial.Items[0].Status != "planned" {
		t.Fatalf("dry-run on partial module with skip_if_imported must plan resume, got %+v", dryPartial.Items[0])
	}

	// Live import with a NEW job_key and skip_if_imported resumes and completes all 5 commits!
	resumedNewJob, err := imp.Run(ctx, "carol", Manifest{
		JobKey:         "job-partial-2",
		Project:        "FourState",
		ConflictPolicy: ConflictSkipIfImported,
		Repositories:   []RepoSpec{{SourceURL: srcRepo, ModuleName: "ResumableMod", MountPath: "ResumableMod"}},
	})
	if err != nil || resumedNewJob.Status != "succeeded" || resumedNewJob.Items[0].Verification.IndexedCommits != 5 {
		t.Fatalf("skip_if_imported on partial module should resume & finish 5 commits, got %+v err=%v", resumedNewJob, err)
	}

	// Now that `ResumableMod` is completely imported and verified, a 3rd job with `skip_if_imported` skips cleanly!
	skipComplete, err := imp.Run(ctx, "carol", Manifest{
		JobKey:         "job-partial-3",
		Project:        "FourState",
		ConflictPolicy: ConflictSkipIfImported,
		Repositories:   []RepoSpec{{SourceURL: srcRepo, ModuleName: "ResumableMod", MountPath: "ResumableMod"}},
	})
	if err != nil || skipComplete.SkippedItems != 1 || skipComplete.Items[0].Status != "skipped" {
		t.Fatalf("completed module should skip cleanly, got %+v err=%v", skipComplete, err)
	}

	// -------------------------------------------------------------------------
	// Case 3: Uncertain / Mismatched Source State MUST refuse silent skip (conflict)!
	// Importing a DIFFERENT source_url into `ResumableMod` with `skip_if_imported` MUST conflict!
	// -------------------------------------------------------------------------
	otherRepo := buildSimpleGitRepo(t, gitBin, filepath.Join(tmp, "src-other"), "other", 3)
	uncertainRes, err := imp.Run(ctx, "carol", Manifest{
		JobKey:         "job-uncertain-source",
		Project:        "FourState",
		ConflictPolicy: ConflictSkipIfImported,
		Repositories:   []RepoSpec{{SourceURL: otherRepo, ModuleName: "ResumableMod", MountPath: "ResumableMod"}},
	})
	if err != nil || uncertainRes.Items[0].Status != "conflict" {
		t.Fatalf("mismatched source_url under skip_if_imported MUST conflict, got %+v err=%v", uncertainRes, err)
	}

	// -------------------------------------------------------------------------
	// Case 4: Shallow Git Repository (`--depth 1`) MUST FAIL Import (never report complete PASS)!
	// -------------------------------------------------------------------------
	shallowDir := filepath.Join(tmp, "shallow-clone")
	gShallow := gitExecHelper{t: t, bin: gitBin, dir: tmp}
	gShallow.run(nil, "clone", "--depth", "1", "file:///"+strings.TrimLeft(filepath.ToSlash(srcRepo), "/"), shallowDir)

	shallowImport, err := imp.Run(ctx, "carol", Manifest{
		JobKey:       "job-shallow-must-fail",
		Project:      "FourState",
		Repositories: []RepoSpec{{SourceURL: shallowDir, ModuleName: "ShallowMod", MountPath: "ShallowMod"}},
	})
	if err != nil || shallowImport.Status != "failed" || shallowImport.Items[0].Verification.Passed {
		t.Fatalf("shallow git repository MUST fail import verification, got %+v err=%v", shallowImport, err)
	}

	// -------------------------------------------------------------------------
	// Case 5: DAG Parent Identity & Octopus Parent Order Tampering Detection!
	// Build a repo with a 3-parent Octopus merge, import it, then tamper with SQLite parent order
	// (same count = 3, swapped P1 and P2 identities!) and prove `verifyImportedModule` catches it!
	// -------------------------------------------------------------------------
	octoSrc, _ := buildComplexSyntheticGitRepo(t, gitBin, filepath.Join(tmp, "octo-check"))
	octoJob, err := imp.Run(ctx, "carol", Manifest{
		JobKey:       "job-octo-verify",
		Project:      "FourState",
		Repositories: []RepoSpec{{SourceURL: octoSrc, ModuleName: "OctoMod", MountPath: "OctoMod"}},
	})
	if err != nil || octoJob.Status != "succeeded" {
		t.Fatalf("octo import failed: %+v err=%v", octoJob, err)
	}
	octoModID := octoJob.Items[0].ModuleID

	// Locate the 3-parent Octopus merge in `module_commits` and swap `parent_ord=1` and `parent_ord=2`!
	var octoLoreRev, p1Lore, p1Git, p2Lore, p2Git string
	if err := db.QueryRow(`SELECT lore_revision FROM module_commits WHERE module_id=? AND parent_count=3`, octoModID).Scan(&octoLoreRev); err != nil {
		t.Fatal(err)
	}
	_ = db.QueryRow(`SELECT parent_lore_revision, parent_source_commit_id FROM module_commit_parents WHERE module_id=? AND lore_revision=? AND parent_ord=1`, octoModID, octoLoreRev).Scan(&p1Lore, &p1Git)
	_ = db.QueryRow(`SELECT parent_lore_revision, parent_source_commit_id FROM module_commit_parents WHERE module_id=? AND lore_revision=? AND parent_ord=2`, octoModID, octoLoreRev).Scan(&p2Lore, &p2Git)

	// Swap ord 1 and ord 2 (parent count is still 3, but Octopus parent order & identity at each ord are wrong!).
	_, _ = db.Exec(`UPDATE module_commit_parents SET parent_lore_revision=?, parent_source_commit_id=? WHERE module_id=? AND lore_revision=? AND parent_ord=1`, p2Lore, p2Git, octoModID, octoLoreRev)
	_, _ = db.Exec(`UPDATE module_commit_parents SET parent_lore_revision=?, parent_source_commit_id=? WHERE module_id=? AND lore_revision=? AND parent_ord=2`, p1Lore, p1Git, octoModID, octoLoreRev)

	mirrorDir := sharedMirrorDir(imp.WorkspaceRoot, proj.ID, octoSrc)
	loreDir := filepath.Join(imp.WorkspaceRoot, fmt.Sprintf("proj-%d", proj.ID), "lore", "OctoMod")
	refs, _ := InspectRemoteRefs(ctx, gitBin, octoSrc, nil, nil)
	rawG, _ := ReadMirrorGraph(ctx, gitBin, mirrorDir, refs.DefaultBranch)
	tc := NewTreeCache()
	projG, _ := ProjectMirrorGraph(ctx, gitBin, mirrorDir, rawG, "", nil, tc)
	_, gitMap, _ := loadExistingGitCommits(ctx, db, octoModID)

	tamperedVer, err := imp.verifyImportedModule(ctx, octoModID, mirrorDir, loreDir, RepoSpec{
		SourceURL: octoSrc, ModuleName: "OctoMod", MountPath: "OctoMod", LFSMode: LFSModeAuto,
	}, refs, rawG, projG, itemCheckpoint{ModuleID: octoModID, CommitMap: gitMap, SyntheticCount: 1}, tc)
	if err != nil {
		t.Fatal(err)
	}
	if tamperedVer.Passed || len(tamperedVer.Mismatches) == 0 {
		t.Fatalf("swapped Octopus parent order MUST fail verification, got %+v", tamperedVer)
	}

	// -------------------------------------------------------------------------
	// Case 6: Concurrent submission of the SAME `job_key` MUST return `ErrJobBusy` (never double-execute),
	// and `RecoverInterruptedJobs` cleans up crashed `running` jobs cleanly!
	// -------------------------------------------------------------------------
	enterCh := make(chan struct{})
	releaseCh := make(chan struct{})
	var entered atomic.Bool
	imp.FaultHook = func(mod string, idx int) error {
		if mod == "ConcMod" && !entered.Swap(true) {
			close(enterCh)
			<-releaseCh
		}
		return nil
	}
	concManifest := Manifest{
		JobKey:       "concurrent-job-key-1",
		Project:      "FourState",
		Repositories: []RepoSpec{{SourceURL: otherRepo, ModuleName: "ConcMod", MountPath: "ConcMod"}},
	}
	var wg sync.WaitGroup
	var firstErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, firstErr = imp.Run(ctx, "carol", concManifest)
	}()
	<-enterCh
	_, secondErr := imp.Run(ctx, "carol", concManifest)
	close(releaseCh)
	wg.Wait()
	imp.FaultHook = nil

	if firstErr != nil {
		t.Fatalf("first concurrent job failed: %v", firstErr)
	}
	if !errors.Is(secondErr, ErrJobBusy) {
		t.Fatalf("second concurrent submission with same job_key expected ErrJobBusy, got %v", secondErr)
	}
}

// TestTeamGamesMonorepoSplitProjectionAndIsolation implements ALL P0 mandatory
// acceptance scenarios (Tests A through I) on `TeamGames/Games`:
//
//	TeamGames/Games/
//	├── Chess/
//	├── Mahjong/
//	├── Poker/
//	└── .github/ + README.md
func TestTeamGamesMonorepoSplitProjectionAndIsolation(t *testing.T) {
	loreBin := findRealLore(t)
	gitBin := findRealGit(t)
	ctx := context.Background()
	tmp := t.TempDir()

	// Build external Git Monorepo `TeamGames/Games` with `master` as default branch (also testing master default branch preservation!):
	gamesGitDir := filepath.Join(tmp, "TeamGames-Games")
	_ = os.MkdirAll(gamesGitDir, 0o755)
	g := gitExecHelper{t: t, bin: gitBin, dir: gamesGitDir}
	g.run(nil, "init", "-b", "master")

	// Test H + Test A (Commit G1): Simultaneous initial creation of Chess, Mahjong, Poker + root README.md + .github/workflows/ci.yml!
	_ = os.MkdirAll(filepath.Join(gamesGitDir, ".github", "workflows"), 0o755)
	_ = os.MkdirAll(filepath.Join(gamesGitDir, "Chess"), 0o755)
	_ = os.MkdirAll(filepath.Join(gamesGitDir, "Mahjong"), 0o755)
	_ = os.MkdirAll(filepath.Join(gamesGitDir, "Poker"), 0o755)
	_ = os.WriteFile(filepath.Join(gamesGitDir, "README.md"), []byte("# TeamGames Monorepo\n"), 0o644)
	_ = os.WriteFile(filepath.Join(gamesGitDir, ".github", "workflows", "ci.yml"), []byte("name: ci\n"), 0o644)
	_ = os.WriteFile(filepath.Join(gamesGitDir, "Chess", "board.go"), []byte("package chess // v1\n"), 0o644)
	_ = os.WriteFile(filepath.Join(gamesGitDir, "Chess", "shared_card.txt"), []byte("moving asset v1\n"), 0o644)
	_ = os.WriteFile(filepath.Join(gamesGitDir, "Mahjong", "tiles.go"), []byte("package mahjong // v1\n"), 0o644)
	_ = os.WriteFile(filepath.Join(gamesGitDir, "Poker", "deck.go"), []byte("package poker // v1\n"), 0o644)
	g.run(nil, "add", "-A")
	shaInitAll := g.commitAs("Lead Dev", "lead@teamgames.example", "2025-05-01T09:00:00Z", "[Init] Initialize Chess, Mahjong, Poker and CI", false)

	// Test H (Commit G_GlobalOnly): Modify ONLY `.github/workflows/ci.yml` and `README.md` -> ZERO game modules should get a commit!
	_ = os.WriteFile(filepath.Join(gamesGitDir, "README.md"), []byte("# TeamGames Monorepo v2\n"), 0o644)
	_ = os.WriteFile(filepath.Join(gamesGitDir, ".github", "workflows", "ci.yml"), []byte("name: ci-v2\n"), 0o644)
	g.run(nil, "add", "-A")
	shaGlobalOnly := g.commitAs("CI Bot", "ci@teamgames.example", "2025-05-01T10:00:00Z", "ci: update global workflow only", false)

	// Test B + Test C (Interleaved commits C1 -> Chess, C2 -> Mahjong, C3 -> Chess; Poker untouched!):
	_ = os.WriteFile(filepath.Join(gamesGitDir, "Chess", "board.go"), []byte("package chess // C1\n"), 0o644)
	g.run(nil, "add", "-A")
	shaC1Chess := g.commitAs("Chess Dev", "chess@teamgames.example", "2025-05-02T09:00:00Z", "[Chess] C1 add opening book", false)

	_ = os.WriteFile(filepath.Join(gamesGitDir, "Mahjong", "tiles.go"), []byte("package mahjong // C2\n"), 0o644)
	g.run(nil, "add", "-A")
	shaC2Mahjong := g.commitAs("Mahjong Dev", "mj@teamgames.example", "2025-05-02T10:00:00Z", "[Mahjong] C2 scoring rules", false)

	_ = os.WriteFile(filepath.Join(gamesGitDir, "Chess", "board.go"), []byte("package chess // C3\n"), 0o644)
	g.run(nil, "add", "-A")
	shaC3Chess := g.commitAs("Chess Dev", "chess@teamgames.example", "2025-05-02T11:00:00Z", "[Chess] C3 endgame solver", false)

	// Test D (Cross-Module File Move: `git mv Chess/shared_card.txt Poker/shared_card.txt`):
	// Chess must get a delete commit, Poker must get an add commit, Mahjong untouched!
	g.run(nil, "mv", "Chess/shared_card.txt", "Poker/shared_card.txt")
	shaCrossMove := g.commitAs("Refactor Dev", "ref@teamgames.example", "2025-05-03T09:00:00Z", "[Move] Move shared_card from Chess to Poker", false)

	// Test E (Multi-Module Branch & Merge involving Chess and Mahjong, NOT Poker!):
	branchBase := shaCrossMove
	g.run(nil, "checkout", "-b", "feature/tournament", branchBase)
	_ = os.WriteFile(filepath.Join(gamesGitDir, "Chess", "tourney.go"), []byte("package chess // tournament\n"), 0o644)
	_ = os.WriteFile(filepath.Join(gamesGitDir, "Mahjong", "tourney.go"), []byte("package mahjong // tournament\n"), 0o644)
	g.run(nil, "add", "-A")
	shaFeatBranch := g.commitAs("Tourney Dev", "tourney@teamgames.example", "2025-05-04T09:00:00Z", "[Tournament] Branch work for Chess & Mahjong", false)

	g.run(nil, "checkout", "master")
	_ = os.WriteFile(filepath.Join(gamesGitDir, "Chess", "master_note.txt"), []byte("chess master\n"), 0o644)
	_ = os.WriteFile(filepath.Join(gamesGitDir, "Mahjong", "master_note.txt"), []byte("mahjong master\n"), 0o644)
	g.run(nil, "add", "-A")
	shaMasterAdvance := g.commitAs("Lead Dev", "lead@teamgames.example", "2025-05-04T10:00:00Z", "[Master] Advance Chess & Mahjong on master", false)

	mergeEnv := map[string]string{
		"GIT_AUTHOR_NAME": "Lead Dev", "GIT_AUTHOR_EMAIL": "lead@teamgames.example", "GIT_AUTHOR_DATE": "2025-05-05T12:00:00Z",
		"GIT_COMMITTER_NAME": "Lead Dev", "GIT_COMMITTER_EMAIL": "lead@teamgames.example", "GIT_COMMITTER_DATE": "2025-05-05T12:00:00Z",
	}
	g.run(mergeEnv, "merge", "--no-ff", "-m", "[Merge] Merge feature/tournament into master", "feature/tournament")
	shaMultiMerge := g.run(nil, "rev-parse", "HEAD")

	// Test A again (Commit `[Support] Language` modifying all 3 games simultaneously + tag `v1.0-lang`!):
	_ = os.WriteFile(filepath.Join(gamesGitDir, "Chess", "lang.json"), []byte(`{"lang":"zh-CN"}`), 0o644)
	_ = os.WriteFile(filepath.Join(gamesGitDir, "Mahjong", "lang.json"), []byte(`{"lang":"zh-CN"}`), 0o644)
	_ = os.WriteFile(filepath.Join(gamesGitDir, "Poker", "lang.json"), []byte(`{"lang":"zh-CN"}`), 0o644)
	g.run(nil, "add", "-A")
	shaSupportLang := g.commitAs("I18N Team", "i18n@teamgames.example", "2025-05-06T12:00:00Z", "[Support] Language", false)
	g.run(mergeEnv, "tag", "-a", "v1.0-lang", "-m", "Language pack release", shaSupportLang)

	// Open SQLite & create project `GamesPlatform` + users Carol (admin), Alice (Chess only), Bob (all 3 games).
	db, err := database.Open(filepath.Join(tmp, "games.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	carolID, _ := user.Create(ctx, db, "test", "carol", "correct-horse", "user")
	aliceID, _ := user.Create(ctx, db, "test", "alice", "correct-horse", "user")
	bobID, _ := user.Create(ctx, db, "test", "bob", "correct-horse", "user")

	proj, err := project.CreateProject(ctx, db, "carol", project.Project{
		Name: "GamesPlatform", ParentRepositoryID: "fedcba9876543210fedcba9876543210",
		ParentRepositoryURL: "lore://local/games-parent", CreatedBy: carolID,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = project.AddMember(ctx, db, "carol", proj.ID, carolID, project.RoleAdmin)
	_ = project.AddMember(ctx, db, "carol", proj.ID, aliceID, project.RoleMember)
	_ = project.AddMember(ctx, db, "carol", proj.ID, bobID, project.RoleMember)

	execLore := loreexec.Executor{Config: loreexec.Config{Binary: loreBin, Timeout: 2 * time.Minute}}
	loreClient := &loreadapter.Client{Exec: execLore}
	imp := &Importer{
		DB:                   db,
		Lore:                 loreClient,
		GitBinary:            gitBin,
		WorkspaceRoot:        filepath.Join(tmp, "ws"),
		RestrictLocalSources: true,
		AllowedLocalDirs:     []string{tmp},
	}

	// Test I (Interrupt Chess mid-import, then resume; verify single shared bare mirror is used for all 3 modules!):
	interruptedChess := false
	imp.FaultHook = func(mod string, idx int) error {
		if mod == "Chess" && idx == 2 && !interruptedChess {
			interruptedChess = true
			return errors.New("simulated crash during Chess split replay")
		}
		return nil
	}

	splitManifest := Manifest{
		JobKey:      "split-teamgames-001",
		Project:     "GamesPlatform",
		Concurrency: 2,
		Repositories: []RepoSpec{
			{SourceURL: gamesGitDir, SourceSubdir: "Chess", ModuleName: "Chess", MountPath: "Chess"},
			{SourceURL: gamesGitDir, SourceSubdir: "Mahjong", ModuleName: "Mahjong", MountPath: "Mahjong"},
			{SourceURL: gamesGitDir, SourceSubdir: "Poker", ModuleName: "Poker", MountPath: "Poker"},
		},
	}

	run1, err := imp.Run(ctx, "carol", splitManifest)
	if err != nil || run1.Status != "partial_failed" {
		t.Fatalf("expected partial_failed on fault injection, got %+v err=%v", run1, err)
	}

	// Resume and complete!
	imp.FaultHook = nil
	run2, err := imp.Run(ctx, "carol", splitManifest)
	if err != nil || run2.Status != "succeeded" || run2.SucceededItems != 3 {
		t.Fatalf("resumed monorepo split failed: %+v (items: %+v) err=%v", run2, run2.Items, err)
	}

	// Verify only ONE shared bare Git mirror directory was created for `TeamGames/Games`!
	mirrorsDir := filepath.Join(imp.WorkspaceRoot, fmt.Sprintf("proj-%d", proj.ID), "mirrors")
	mirrorEntries, _ := os.ReadDir(mirrorsDir)
	if len(mirrorEntries) != 1 {
		t.Fatalf("expected 1 shared bare mirror for TeamGames/Games, got %d", len(mirrorEntries))
	}

	chessModID := run2.Items[0].ModuleID
	mahjongModID := run2.Items[1].ModuleID
	pokerModID := run2.Items[2].ModuleID

	// Grant Alice -> Chess ONLY; Grant Bob -> Chess, Mahjong, Poker!
	_ = project.SetModulePermission(ctx, db, "carol", aliceID, chessModID, project.PermRead)
	for _, mid := range []int64{chessModID, mahjongModID, pokerModID} {
		_ = project.SetModulePermission(ctx, db, "carol", bobID, mid, project.PermRead)
	}

	histSvc := history.Service{DB: db}

	// =========================================================================
	// Assert Test A, B, C, D, E, G, H on Each Module's Independent Projected History!
	// =========================================================================
	// Expected Chess commits (8):
	//   1. shaInitAll, 2. shaC1Chess, 3. shaC3Chess (NOT shaC2Mahjong, NOT shaGlobalOnly!),
	//   4. shaCrossMove (deleted shared_card.txt), 5. shaFeatBranch, 6. shaMasterAdvance,
	//   7. shaMultiMerge (2-parent merge!), 8. shaSupportLang
	chessHist, err := histSvc.ModuleHistory(ctx, bobID, chessModID, history.Filter{Order: history.OrderAsc, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	wantChessSHAs := []string{shaInitAll, shaC1Chess, shaC3Chess, shaCrossMove, shaFeatBranch, shaMasterAdvance, shaMultiMerge, shaSupportLang}
	assertExactSourceSHAs(t, "Chess", chessHist.Commits, wantChessSHAs)

	// Expected Mahjong commits (6):
	//   1. shaInitAll, 2. shaC2Mahjong (NOT shaC1Chess, NOT shaC3Chess, NOT shaCrossMove!),
	//   3. shaFeatBranch, 4. shaMasterAdvance, 5. shaMultiMerge (2-parent merge!), 6. shaSupportLang
	mahjongHist, err := histSvc.ModuleHistory(ctx, bobID, mahjongModID, history.Filter{Order: history.OrderAsc, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	wantMahjongSHAs := []string{shaInitAll, shaC2Mahjong, shaFeatBranch, shaMasterAdvance, shaMultiMerge, shaSupportLang}
	assertExactSourceSHAs(t, "Mahjong", mahjongHist.Commits, wantMahjongSHAs)

	// Expected Poker commits (3):
	//   1. shaInitAll, 2. shaCrossMove (added shared_card.txt), 3. shaSupportLang
	//   (Zero commits from C1/C2/C3 or feature/tournament merge!)
	pokerHist, err := histSvc.ModuleHistory(ctx, bobID, pokerModID, history.Filter{Order: history.OrderAsc, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	wantPokerSHAs := []string{shaInitAll, shaCrossMove, shaSupportLang}
	assertExactSourceSHAs(t, "Poker", pokerHist.Commits, wantPokerSHAs)

	// Assert Test A: `[Support] Language` generated 3 DIFFERENT Lore Revisions across Chess, Mahjong, Poker!
	chessLang, _ := histSvc.GetCommit(ctx, bobID, chessModID, shaSupportLang)
	mahjongLang, _ := histSvc.GetCommit(ctx, bobID, mahjongModID, shaSupportLang)
	pokerLang, _ := histSvc.GetCommit(ctx, bobID, pokerModID, shaSupportLang)
	if chessLang.LoreRevision == mahjongLang.LoreRevision || chessLang.LoreRevision == pokerLang.LoreRevision || mahjongLang.LoreRevision == pokerLang.LoreRevision {
		t.Fatalf("Lore revisions for [Support] Language must be distinct per module: %s / %s / %s",
			chessLang.LoreRevision, mahjongLang.LoreRevision, pokerLang.LoreRevision)
	}
	if chessLang.SourceSubdir != "Chess" || mahjongLang.SourceSubdir != "Mahjong" || pokerLang.SourceSubdir != "Poker" {
		t.Fatalf("source_subdir not preserved on commits: %q %q %q", chessLang.SourceSubdir, mahjongLang.SourceSubdir, pokerLang.SourceSubdir)
	}

	// Assert Test D: Cross-module move `Chess/shared_card.txt -> Poker/shared_card.txt`
	// is a pure `delete` in Chess and a pure `add` in Poker (NO cross-module rename!).
	chessMove, _ := histSvc.GetCommit(ctx, bobID, chessModID, shaCrossMove)
	pokerMove, _ := histSvc.GetCommit(ctx, bobID, pokerModID, shaCrossMove)
	chessMoveDelta, err := loreClient.RevisionDetail(ctx, filepath.Join(imp.WorkspaceRoot, fmt.Sprintf("proj-%d", proj.ID), "lore", "Chess"), chessMove.LoreRevision, true)
	if err != nil {
		t.Fatal(err)
	}
	pokerMoveDelta, err := loreClient.RevisionDetail(ctx, filepath.Join(imp.WorkspaceRoot, fmt.Sprintf("proj-%d", proj.ID), "lore", "Poker"), pokerMove.LoreRevision, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(chessMoveDelta.Deltas) != 1 || chessMoveDelta.Deltas[0].Path != "shared_card.txt" || chessMoveDelta.Deltas[0].Action != "delete" {
		t.Fatalf("Chess cross-module move delta expected single delete of shared_card.txt, got %+v", chessMoveDelta.Deltas)
	}
	if len(pokerMoveDelta.Deltas) != 1 || pokerMoveDelta.Deltas[0].Path != "shared_card.txt" || pokerMoveDelta.Deltas[0].Action != "add" || pokerMoveDelta.Deltas[0].FromPath != "" {
		t.Fatalf("Poker cross-module move delta expected single add of shared_card.txt with empty FromPath, got %+v", pokerMoveDelta.Deltas)
	}

	// Assert Test E: Multi-module merge `shaMultiMerge` has 2 projected parents in Chess (pointing to Chess's own revisions!)
	// and 2 projected parents in Mahjong (pointing to Mahjong's own revisions!).
	chessMerge, _ := histSvc.GetCommit(ctx, bobID, chessModID, shaMultiMerge)
	mahjongMerge, _ := histSvc.GetCommit(ctx, bobID, mahjongModID, shaMultiMerge)
	if !chessMerge.IsMerge || len(chessMerge.Parents) != 2 || chessMerge.Parents[0].SourceCommitID != shaMasterAdvance || chessMerge.Parents[1].SourceCommitID != shaFeatBranch {
		t.Fatalf("Chess merge parents wrong: %+v", chessMerge.Parents)
	}
	if !mahjongMerge.IsMerge || len(mahjongMerge.Parents) != 2 || mahjongMerge.Parents[0].SourceCommitID != shaMasterAdvance || mahjongMerge.Parents[1].SourceCommitID != shaFeatBranch {
		t.Fatalf("Mahjong merge parents wrong: %+v", mahjongMerge.Parents)
	}
	if chessMerge.Parents[0].LoreRevision == mahjongMerge.Parents[0].LoreRevision || chessMerge.Parents[1].LoreRevision == mahjongMerge.Parents[1].LoreRevision {
		t.Fatal("cross-module parent Lore revision leak!")
	}

	// Assert Test H: Global files (`README.md`, `.github/workflows/ci.yml`) were explicitly reported in `UnmappedPaths`
	// AND never polluted ANY game repository's working tree or `shaGlobalOnly` commit!
	for idx, modName := range []string{"Chess", "Mahjong", "Poker"} {
		ver := run2.Items[idx].Verification
		if ver.UnmappedPathsCount != 2 {
			t.Fatalf("%s expected 2 unmapped global paths (.github/workflows/ci.yml, README.md), got %d (%v)", modName, ver.UnmappedPathsCount, ver.UnmappedPaths)
		}
		workDir := filepath.Join(imp.WorkspaceRoot, fmt.Sprintf("proj-%d", proj.ID), "lore", modName)
		for _, forbidden := range []string{"README.md", ".github", "Chess", "Mahjong", "Poker"} {
			if _, sErr := os.Stat(filepath.Join(workDir, forbidden)); !os.IsNotExist(sErr) {
				t.Fatalf("ISOLATION BREACH: %s contains forbidden path %q!", modName, forbidden)
			}
		}
	}
	_ = shaGlobalOnly

	// Verify `master` default branch was preserved (NOT overwritten with `main`), even after running `SyncModuleFromLore`!
	for _, mid := range []int64{chessModID, mahjongModID, pokerModID} {
		mRow, _ := project.GetModuleByID(ctx, db, mid)
		wDir := filepath.Join(imp.WorkspaceRoot, fmt.Sprintf("proj-%d", proj.ID), "lore", mRow.Name)
		if _, sErr := history.SyncModuleFromLore(ctx, db, loreClient, mid, wDir); sErr != nil {
			t.Fatalf("SyncModuleFromLore on %s failed: %v", mRow.Name, sErr)
		}
		bRefs, _ := histSvc.ListModuleRefs(ctx, bobID, mid, "branch")
		defName := ""
		for _, br := range bRefs {
			if br.Name == "main" {
				t.Fatalf("bootstrap main branch leaked into module_refs for %s: %+v", mRow.Name, bRefs)
			}
			if br.IsDefault {
				defName = br.Name
			}
		}
		if defName != "master" {
			t.Fatalf("module %s default branch got %q, want master", mRow.Name, defName)
		}
	}

	// Assert Test F (Aggregated History + Permission Isolation):
	// For `[Support] Language`, Bob (all 3 modules) sees 3 independent commits; Alice (Chess only) sees ONLY 1 (Chess)!
	bobLangPage, err := histSvc.ProjectHistory(ctx, bobID, proj.ID, history.Filter{Search: "[Support] Language", Limit: 20})
	if err != nil || bobLangPage.TotalMatching != 3 || len(bobLangPage.Commits) != 3 {
		t.Fatalf("Bob expected 3 independent [Support] Language records, got %+v err=%v", bobLangPage, err)
	}
	aliceLangPage, err := histSvc.ProjectHistory(ctx, aliceID, proj.ID, history.Filter{Search: "[Support] Language", Limit: 20})
	if err != nil || aliceLangPage.TotalMatching != 1 || aliceLangPage.Commits[0].ModuleName != "Chess" {
		t.Fatalf("Alice expected ONLY Chess [Support] Language record, got %+v err=%v", aliceLangPage, err)
	}
	if _, err := histSvc.GetCommit(ctx, aliceID, mahjongModID, shaSupportLang); !errors.Is(err, history.ErrNotFound) {
		t.Fatalf("Alice probing Mahjong commit by shared Git SHA must get ErrNotFound, got %v", err)
	}

	// Assert Test I: Re-running a new import job with `skip_if_imported` skips all 3 cleanly with 0 new revisions!
	skipRepos := make([]RepoSpec, len(splitManifest.Repositories))
	copy(skipRepos, splitManifest.Repositories)
	for i := range skipRepos {
		skipRepos[i].ConflictPolicy = ConflictSkipIfImported
	}
	rerunSkip, err := imp.Run(ctx, "carol", Manifest{
		JobKey:         "split-teamgames-002-rerun",
		Project:        "GamesPlatform",
		ConflictPolicy: ConflictSkipIfImported,
		Repositories:   skipRepos,
	})
	if err != nil || rerunSkip.SkippedItems != 3 {
		t.Fatalf("re-import with skip_if_imported expected 3 skipped, got %+v err=%v", rerunSkip, err)
	}

	// Verify Snapshot Publisher pins each of the 3 independent module revisions cleanly without merging module commits!
	memPub := &postImportPublishDriver{
		revs: map[string]string{
			"parent": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"chess":  chessLang.LoreRevision,
			"mj":     mahjongLang.LoreRevision,
			"poker":  pokerLang.LoreRevision,
		},
		links: map[string]string{},
	}
	snap, err := (publish.Publisher{DB: db, Driver: memPub}).Publish(ctx, publish.Request{
		ProjectID:  proj.ID,
		ParentDir:  "parent",
		ModuleDirs: map[string]string{"Chess": "chess", "Mahjong": "mj", "Poker": "poker"},
		Actor:      "carol",
		Message:    "snapshot games v1",
	})
	if err != nil || len(snap.Pins) != 3 {
		t.Fatalf("snapshot publish failed: %+v err=%v", snap, err)
	}
}

func assertExactSourceSHAs(t *testing.T, modName string, got []history.Commit, want []string) {
	t.Helper()
	if len(got) != len(want) {
		var gotSHAs []string
		for _, c := range got {
			gotSHAs = append(gotSHAs, short12(c.SourceCommitID)+":"+c.Subject)
		}
		t.Fatalf("%s commit count=%d (%v), want %d", modName, len(got), gotSHAs, len(want))
	}
	for i := range want {
		if got[i].SourceCommitID != want[i] {
			t.Fatalf("%s commit[%d] got %s (%s), want %s", modName, i, got[i].SourceCommitID, got[i].Subject, want[i])
		}
	}
}
