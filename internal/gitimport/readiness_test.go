package gitimport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lore-monorepo/internal/database"
	"lore-monorepo/internal/history"
	"lore-monorepo/internal/loreadapter"
	"lore-monorepo/internal/loreexec"
	"lore-monorepo/internal/project"
	"lore-monorepo/internal/user"
)

func newReadinessImporter(t *testing.T, root, projectName string) (*Importer, int64) {
	t.Helper()
	ctx := context.Background()
	db, err := database.Open(filepath.Join(root, "manager.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	carol, err := user.Create(ctx, db, "test", "carol", "correct-horse", "user")
	if err != nil {
		t.Fatal(err)
	}
	proj, err := project.CreateProject(ctx, db, "carol", project.Project{
		Name: projectName, ParentRepositoryID: "00112233445566778899aabbccddeeff",
		ParentRepositoryURL: "lore://local/" + strings.ToLower(projectName), CreatedBy: carol,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := project.AddMember(ctx, db, "carol", proj.ID, carol, project.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	loreBin := findRealLore(t)
	gitBin := findRealGit(t)
	return &Importer{
		DB: db, Lore: &loreadapter.Client{Exec: loreexec.Executor{Config: loreexec.Config{
			Binary: loreBin, Timeout: 2 * time.Minute,
		}}},
		GitBinary: gitBin, WorkspaceRoot: filepath.Join(root, "workspace"),
	}, proj.ID
}

func TestSourceRefSnapshotDriftAndPinnedResume(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()
	imp, _ := newReadinessImporter(t, tmp, "RefStable")
	gitBin := imp.GitBinary

	// Case 1: mutate master after ls-remote but before fetch; import must fail,
	// and no module may be registered from a mixed branch/tag snapshot.
	src := buildSimpleGitRepo(t, gitBin, filepath.Join(tmp, "moving-source"), "moving", 2)
	var mutateOnce bool
	imp.AfterInspectRefs = func(_ string) {
		if mutateOnce {
			return
		}
		mutateOnce = true
		g := gitExecHelper{t: t, bin: gitBin, dir: src}
		_ = os.WriteFile(filepath.Join(src, "after-inspect.txt"), []byte("moved\n"), 0o644)
		g.run(nil, "add", ".")
		_ = g.commitAs("Mover", "mover@example.com", "2025-06-01T00:00:00Z", "move source after ls-remote", false)
	}
	drift, err := imp.Run(ctx, "carol", Manifest{
		JobKey: "ref-drift", Project: "RefStable",
		Repositories: []RepoSpec{{SourceURL: src, ModuleName: "Drift", MountPath: "Drift"}},
	})
	if err != nil || drift.Status != "failed" || !strings.Contains(drift.Items[0].Error, ErrSourceMovedDuringFetch.Error()) {
		t.Fatalf("moving source must fail with ErrSourceMovedDuringFetch: %+v err=%v", drift, err)
	}
	mods, _ := project.ListModules(ctx, imp.DB, drift.ProjectID, true)
	if len(mods) != 0 {
		t.Fatalf("ref-drift failure created %d module(s)", len(mods))
	}

	// Case 2: interrupt after the mirror/ref snapshot is pinned. Advance source,
	// then rerun same job key. It must resume against the pinned local mirror,
	// not silently mix in the later source commit.
	imp.AfterInspectRefs = nil
	src2 := buildSimpleGitRepo(t, gitBin, filepath.Join(tmp, "resume-source"), "resume", 4)
	oldHead := gitExecHelper{t: t, bin: gitBin, dir: src2}.run(nil, "rev-parse", "HEAD")
	faulted := false
	imp.FaultHook = func(module string, idx int) error {
		if module == "Pinned" && idx == 1 && !faulted {
			faulted = true
			return errors.New("interrupt after pinned mirror")
		}
		return nil
	}
	manifest := Manifest{
		JobKey: "pinned-resume", Project: "RefStable",
		Repositories: []RepoSpec{{SourceURL: src2, ModuleName: "Pinned", MountPath: "Pinned"}},
	}
	first, err := imp.Run(ctx, "carol", manifest)
	if err != nil || first.Status != "failed" {
		t.Fatalf("expected injected failure: %+v err=%v", first, err)
	}

	g2 := gitExecHelper{t: t, bin: gitBin, dir: src2}
	_ = os.WriteFile(filepath.Join(src2, "new-upstream.txt"), []byte("later\n"), 0o644)
	g2.run(nil, "add", ".")
	newHead := g2.commitAs("Later", "later@example.com", "2025-06-02T00:00:00Z", "later upstream commit", false)
	if newHead == oldHead {
		t.Fatal("test did not advance upstream")
	}

	imp.FaultHook = nil
	resumed, err := imp.Run(ctx, "carol", manifest)
	if err != nil || resumed.Status != "succeeded" || resumed.Items[0].Verification.SourceCommits != 4 {
		t.Fatalf("resume must use 4-commit pinned snapshot, got %+v err=%v", resumed, err)
	}
	var pinnedRaw string
	if err := imp.DB.QueryRow(`SELECT pinned_refs_json FROM import_job_items WHERE job_id=?`, resumed.JobID).Scan(&pinnedRaw); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pinnedRaw, oldHead) || strings.Contains(pinnedRaw, newHead) {
		t.Fatalf("pinned refs changed across resume: %s", pinnedRaw)
	}
}

func createLFSPointerRepo(t *testing.T, gitBin, dir string, withObject, corrupt bool) (repo, oid string, payload []byte) {
	t.Helper()
	_ = os.MkdirAll(dir, 0o755)
	g := gitExecHelper{t: t, bin: gitBin, dir: dir}
	g.run(nil, "init", "-b", "main")
	payload = []byte("FULL-LFS-BINARY-CONTENT-READY-2026\x00\x01")
	sum := sha256.Sum256(payload)
	oid = hex.EncodeToString(sum[:])
	ptr := fmt.Sprintf("version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize %d\n", oid, len(payload))
	_ = os.MkdirAll(filepath.Join(dir, "assets"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "assets", "asset.bin"), []byte(ptr), 0o644)
	g.run(nil, "add", ".")
	_ = g.commitAs("LFS Dev", "lfs@example.com", "2025-07-01T00:00:00Z", "add lfs asset", false)
	if withObject {
		objDir := filepath.Join(dir, ".git", "lfs", "objects", oid[:2], oid[2:4])
		_ = os.MkdirAll(objDir, 0o755)
		data := payload
		if corrupt {
			data = append([]byte(nil), payload...)
			data[0] ^= 0xff // same size, wrong SHA-256
		}
		_ = os.WriteFile(filepath.Join(objDir, oid), data, 0o644)
	}
	return dir, oid, payload
}

func TestLFSHydrationPointerHonestyAndIntegrity(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()
	imp, _ := newReadinessImporter(t, tmp, "LFSProject")
	gitBin := imp.GitBinary

	missingRepo, _, _ := createLFSPointerRepo(t, gitBin, filepath.Join(tmp, "lfs-missing"), false, false)
	strictMissing, err := imp.Run(ctx, "carol", Manifest{
		JobKey: "lfs-missing", Project: "LFSProject",
		Repositories: []RepoSpec{{SourceURL: missingRepo, ModuleName: "Missing", MountPath: "Missing", LFSMode: LFSModeHydrate}},
	})
	if err != nil || strictMissing.Status != "failed" || !strings.Contains(strictMissing.Items[0].Error, ErrLFSHydrationFailed.Error()) {
		t.Fatalf("strict hydrate with missing object must fail: %+v err=%v", strictMissing, err)
	}

	pointerRepo, pointerOID, _ := createLFSPointerRepo(t, gitBin, filepath.Join(tmp, "lfs-pointer"), false, false)
	pointerOnly, err := imp.Run(ctx, "carol", Manifest{
		JobKey: "lfs-pointer", Project: "LFSProject",
		Repositories: []RepoSpec{{SourceURL: pointerRepo, ModuleName: "Pointer", MountPath: "Pointer", LFSMode: LFSModePointer}},
	})
	if err != nil || pointerOnly.Status != "succeeded" {
		t.Fatalf("explicit pointer mode should succeed honestly: %+v err=%v", pointerOnly, err)
	}
	pv := pointerOnly.Items[0].Verification
	if !pv.Passed || pv.FullContentMigrated || pv.LFSHydrationStatus != "pointer_only_unhydrated" || pv.LFSUnhydratedCount == 0 {
		t.Fatalf("pointer mode honesty flags wrong: %+v", pv)
	}
	var pointerKind, pointerDBOID string
	_ = imp.DB.QueryRow(`SELECT kind, oid FROM module_special_objects WHERE module_id=?`, pointerOnly.Items[0].ModuleID).Scan(&pointerKind, &pointerDBOID)
	if pointerKind != "lfs_pointer" || pointerDBOID != pointerOID {
		t.Fatalf("pointer metadata mismatch kind=%s oid=%s", pointerKind, pointerDBOID)
	}

	hydratedRepo, hydratedOID, payload := createLFSPointerRepo(t, gitBin, filepath.Join(tmp, "lfs-hydrated"), true, false)
	hydrated, err := imp.Run(ctx, "carol", Manifest{
		JobKey: "lfs-hydrated", Project: "LFSProject",
		Repositories: []RepoSpec{{SourceURL: hydratedRepo, ModuleName: "Hydrated", MountPath: "Hydrated", LFSMode: LFSModeHydrate}},
	})
	if err != nil || hydrated.Status != "succeeded" {
		t.Fatalf("hydrated LFS import failed: %+v err=%v", hydrated, err)
	}
	hv := hydrated.Items[0].Verification
	if !hv.Passed || !hv.FullContentMigrated || hv.LFSHydrationStatus != "hydrated_verified" || hv.LFSHydratedCount == 0 {
		t.Fatalf("hydrated verification wrong: %+v", hv)
	}
	work := filepath.Join(imp.WorkspaceRoot, fmt.Sprintf("proj-%d", hydrated.ProjectID), "lore", "Hydrated", "assets", "asset.bin")
	gotPayload, readErr := os.ReadFile(work)
	if readErr != nil || string(gotPayload) != string(payload) {
		t.Fatalf("hydrated payload mismatch err=%v got=%x want=%x", readErr, gotPayload, payload)
	}
	var hydratedKind, hydratedDBOID string
	_ = imp.DB.QueryRow(`SELECT kind, oid FROM module_special_objects WHERE module_id=?`, hydrated.Items[0].ModuleID).Scan(&hydratedKind, &hydratedDBOID)
	if hydratedKind != "lfs_hydrated" || hydratedDBOID != hydratedOID {
		t.Fatalf("hydrated metadata mismatch kind=%s oid=%s", hydratedKind, hydratedDBOID)
	}

	corruptRepo, _, _ := createLFSPointerRepo(t, gitBin, filepath.Join(tmp, "lfs-corrupt"), true, true)
	corrupt, err := imp.Run(ctx, "carol", Manifest{
		JobKey: "lfs-corrupt", Project: "LFSProject",
		Repositories: []RepoSpec{{SourceURL: corruptRepo, ModuleName: "Corrupt", MountPath: "Corrupt", LFSMode: LFSModeHydrate}},
	})
	if err != nil || corrupt.Status != "failed" || !strings.Contains(corrupt.Items[0].Error, ErrLFSHydrationFailed.Error()) {
		t.Fatalf("corrupt same-size LFS object must fail SHA verification: %+v err=%v", corrupt, err)
	}
}

func TestStrictGlobalPathClassificationAndPreModuleAliasPersistence(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()
	imp, _ := newReadinessImporter(t, tmp, "CoverageProject")
	gitBin := imp.GitBinary

	src := filepath.Join(tmp, "delayed-module")
	_ = os.MkdirAll(src, 0o755)
	g := gitExecHelper{t: t, bin: gitBin, dir: src}
	g.run(nil, "init", "-b", "main")
	_ = os.WriteFile(filepath.Join(src, "README.md"), []byte("# global\n"), 0o644)
	g.run(nil, "add", ".")
	preModuleSHA := g.commitAs("Docs", "docs@example.com", "2025-08-01T00:00:00Z", "global README before module exists", false)

	_ = os.MkdirAll(filepath.Join(src, "Future"), 0o755)
	_ = os.WriteFile(filepath.Join(src, "Future", "main.go"), []byte("package future\n"), 0o644)
	g.run(nil, "add", ".")
	moduleSHA := g.commitAs("Future Dev", "future@example.com", "2025-08-02T00:00:00Z", "create Future module", false)

	// Strict policy without a classification rule must block before module creation.
	blocked, err := imp.Run(ctx, "carol", Manifest{
		JobKey: "coverage-blocked", Project: "CoverageProject", GlobalFilesPolicy: GlobalPolicyStrict,
		Repositories: []RepoSpec{{
			SourceURL: src, SourceSubdir: "Future", ModuleName: "Future", MountPath: "Future",
		}},
	})
	if err != nil || blocked.Status != "failed" || !strings.Contains(blocked.Items[0].Error, ErrUnclassifiedGlobalPaths.Error()) {
		t.Fatalf("strict unclassified global path must block: %+v err=%v", blocked, err)
	}
	mods, _ := project.ListModules(ctx, imp.DB, blocked.ProjectID, true)
	if len(mods) != 0 {
		t.Fatalf("coverage-blocked import created modules: %+v", mods)
	}

	// The reviewed rule makes coverage complete; pre-module source commit must
	// persist as `pre_module_empty`, while the first module commit is direct.
	ready, err := imp.Run(ctx, "carol", Manifest{
		JobKey: "coverage-ready", Project: "CoverageProject", GlobalFilesPolicy: GlobalPolicyStrict,
		PathRules: []PathRule{{
			Pattern: "README.md", Category: PathCategoryExcluded,
			Reason: "project-level overview retained in source mirror and migration evidence",
		}},
		Repositories: []RepoSpec{{
			SourceURL: src, SourceSubdir: "Future", ModuleName: "Future", MountPath: "Future",
		}},
	})
	if err != nil || ready.Status != "succeeded" {
		t.Fatalf("classified import failed: %+v err=%v", ready, err)
	}
	ver := ready.Items[0].Verification
	if !ver.CoverageComplete || len(ver.ClassifiedExcluded) != 1 || len(ver.UndecidedPaths) != 0 {
		t.Fatalf("coverage report incorrect: %+v", ver)
	}

	var preStatus, preEff, preRev, directStatus, directEff, directRev string
	_ = imp.DB.QueryRow(`SELECT alias_status,effective_source_commit_id,lore_revision FROM module_commit_aliases WHERE module_id=? AND source_commit_id=?`,
		ready.Items[0].ModuleID, preModuleSHA).Scan(&preStatus, &preEff, &preRev)
	_ = imp.DB.QueryRow(`SELECT alias_status,effective_source_commit_id,lore_revision FROM module_commit_aliases WHERE module_id=? AND source_commit_id=?`,
		ready.Items[0].ModuleID, moduleSHA).Scan(&directStatus, &directEff, &directRev)
	if preStatus != history.AliasPreModule || preEff != "" || preRev != "" {
		t.Fatalf("pre-module alias wrong: status=%s eff=%s rev=%s", preStatus, preEff, preRev)
	}
	if directStatus != history.AliasDirect || directEff != moduleSHA || len(directRev) != 64 {
		t.Fatalf("direct alias wrong: status=%s eff=%s rev=%s", directStatus, directEff, directRev)
	}

	// Ref precondition validation: expected master but source is main -> fail closed.
	expectedMismatch, err := imp.Run(ctx, "carol", Manifest{
		JobKey: "expected-ref-mismatch", Project: "CoverageProject", DryRun: true,
		Repositories: []RepoSpec{{
			SourceURL: src, ModuleName: "Another", MountPath: "Another",
			ExpectedDefaultBranch: "master",
		}},
	})
	if err != nil || expectedMismatch.Status != "failed" || !strings.Contains(expectedMismatch.Items[0].Error, ErrExpectedRefMismatch.Error()) {
		t.Fatalf("expected ref mismatch did not fail: %+v err=%v", expectedMismatch, err)
	}
}

func TestShippedManifestTemplatesParse(t *testing.T) {
	for _, name := range []string{
		"import.example.toml",
		"import-single.example.toml",
		"import-monorepo-split.example.toml",
		"import-platform-auth.example.toml",
	} {
		path := filepath.Join("..", "..", "configs", name)
		m, err := LoadManifest(path)
		if err != nil {
			t.Fatalf("%s is not parseable by the real loader: %v", name, err)
		}
		if m.Project == "" || len(m.Repositories) == 0 {
			t.Fatalf("%s parsed incompletely: %+v", name, m)
		}
	}
}
