package opsbackup

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lore-monorepo/internal/database"
	"lore-monorepo/internal/history"
	"lore-monorepo/internal/project"
	"lore-monorepo/internal/publish"
	"lore-monorepo/internal/user"
)

func seedBackupDB(t *testing.T, dbPath string) (projectID, moduleA, moduleB int64) {
	t.Helper()
	ctx := context.Background()
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	uid, err := user.Create(ctx, db, "test", "carol", "correct-horse", "user")
	if err != nil {
		t.Fatal(err)
	}
	p, err := project.CreateProject(ctx, db, "carol", project.Project{
		Name: "Alpha", ParentRepositoryID: "00112233445566778899aabbccddeeff",
		ParentRepositoryURL: "lore://local/alpha", CreatedBy: uid,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = project.AddMember(ctx, db, "carol", p.ID, uid, project.RoleAdmin)
	a, err := project.CreateModule(ctx, db, "carol", project.Module{
		ProjectID: p.ID, Name: "Engine", RepositoryID: "11111111111111111111111111111111",
		RepositoryURL: "lore://local/engine", MountPath: "Engine",
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := project.CreateModule(ctx, db, "carol", project.Module{
		ProjectID: p.ID, Name: "Docs", RepositoryID: "22222222222222222222222222222222",
		RepositoryURL: "lore://local/docs", MountPath: "Docs",
	})
	if err != nil {
		t.Fatal(err)
	}
	tx, _ := db.BeginTx(ctx, nil)
	_ = history.UpsertCommit(ctx, tx, history.CommitInput{
		ModuleID: a.ID, LoreRevision: strings.Repeat("a", 64), SourceCommitID: strings.Repeat("1", 40),
		OriginKind: history.OriginGitImport, AuthorName: "Alice", AuthoredUnixMS: 1, CommittedUnixMS: 1, Message: "engine",
	})
	_ = history.UpsertCommit(ctx, tx, history.CommitInput{
		ModuleID: b.ID, LoreRevision: strings.Repeat("b", 64), SourceCommitID: strings.Repeat("2", 40),
		OriginKind: history.OriginGitImport, AuthorName: "Bob", AuthoredUnixMS: 2, CommittedUnixMS: 2, Message: "docs",
	})
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return p.ID, a.ID, b.ID
}

func TestBackupVerifyRestoreAndTamperDetection(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "live", "manager.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatal(err)
	}
	_, _, _ = seedBackupDB(t, dbPath)

	store := filepath.Join(root, "live", "store")
	imports := filepath.Join(root, "live", "imports")
	keys := filepath.Join(root, "live", "keys")
	configs := filepath.Join(root, "live", "configs")
	certs := filepath.Join(root, "live", "certs")
	for _, d := range []string{store, imports, keys, configs, certs} {
		_ = os.MkdirAll(d, 0o700)
	}
	_ = os.WriteFile(filepath.Join(store, "fragment.bin"), []byte("fragment-data"), 0o600)
	_ = os.WriteFile(filepath.Join(imports, "checkpoint.json"), []byte(`{"checkpoint":1}`), 0o600)
	_ = os.WriteFile(filepath.Join(keys, "identity-active.pem"), []byte("PRIVATE-TEST-FIXTURE-NOT-REAL"), 0o600)
	_ = os.WriteFile(filepath.Join(configs, "manager.toml"), []byte("[manager]\nlisten=\"127.0.0.1:1\"\n"), 0o600)
	_ = os.WriteFile(filepath.Join(certs, "server.crt"), []byte("PUBLIC-CERT-FIXTURE"), 0o644)

	bundle := filepath.Join(root, "backup")
	man, err := CreateBackup(ctx, BackupSpec{
		DatabasePath: dbPath, StoreDir: store, ImportsDir: imports,
		KeysDir: keys, ConfigsDir: configs, CertsDir: certs, OutputDir: bundle,
	})
	if err != nil {
		t.Fatal(err)
	}
	if man.UserVersion != 5 || man.TableCounts["modules"] != 2 || len(man.Files) < 6 {
		t.Fatalf("unexpected backup manifest: %+v", man)
	}
	if err := VerifyBackup(ctx, bundle); err != nil {
		t.Fatal(err)
	}

	restore := filepath.Join(root, "restore")
	if err := RestoreBackup(ctx, bundle, restore); err != nil {
		t.Fatal(err)
	}
	restoredDB, err := database.Open(filepath.Join(restore, "db", "manager.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restoredDB.Close()
	var modules, aliases int
	_ = restoredDB.QueryRow(`SELECT COUNT(*) FROM modules`).Scan(&modules)
	_ = restoredDB.QueryRow(`SELECT COUNT(*) FROM module_commit_aliases`).Scan(&aliases)
	if modules != 2 || aliases != 2 {
		t.Fatalf("restore counts modules=%d aliases=%d", modules, aliases)
	}
	if got, _ := os.ReadFile(filepath.Join(restore, "store", "fragment.bin")); string(got) != "fragment-data" {
		t.Fatalf("restored store mismatch %q", got)
	}

	// SHA256SUMS is part of the operator evidence and must agree with the
	// machine-readable manifest.
	sumsPath := filepath.Join(bundle, "SHA256SUMS")
	originalSums, err := os.ReadFile(sumsPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(sumsPath, []byte("tampered sums\n"), 0o600)
	if err := VerifyBackup(ctx, bundle); err == nil {
		t.Fatal("tampered SHA256SUMS unexpectedly verified")
	}
	_ = os.WriteFile(sumsPath, originalSums, 0o600)

	// Tamper with one backed-up file and prove VerifyBackup fails before restore.
	_ = os.WriteFile(filepath.Join(bundle, "store", "fragment.bin"), []byte("tampered"), 0o600)
	if err := VerifyBackup(ctx, bundle); err == nil {
		t.Fatal("tampered backup unexpectedly verified")
	}
}

func TestBackupRejectsMissingSourcesAndUnsafeManifestPaths(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "manager.db")
	_, _, _ = seedBackupDB(t, dbPath)

	if _, err := CreateBackup(ctx, BackupSpec{
		DatabasePath: dbPath,
		StoreDir:     filepath.Join(root, "missing-store"),
		OutputDir:    filepath.Join(root, "missing-source-backup"),
	}); err == nil {
		t.Fatal("a configured but missing Store directory must not be silently omitted")
	}

	store := filepath.Join(root, "store")
	_ = os.MkdirAll(store, 0o700)
	if _, err := CreateBackup(ctx, BackupSpec{
		DatabasePath: dbPath,
		StoreDir:     store,
		OutputDir:    filepath.Join(store, "nested-backup"),
	}); err == nil || !strings.Contains(err.Error(), "must not be inside") {
		t.Fatalf("backup output nested inside Store must be rejected, got %v", err)
	}
	bundle := filepath.Join(root, "bundle")
	if _, err := CreateBackup(ctx, BackupSpec{
		DatabasePath: dbPath,
		StoreDir:     store,
		OutputDir:    bundle,
	}); err != nil {
		t.Fatal(err)
	}

	manifestPath := filepath.Join(bundle, "backup-manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Files = append(manifest.Files, FileHash{
		RelPath: "../outside.txt",
		Size:    0,
		SHA256:  strings.Repeat("0", 64),
		Mode:    0o600,
	})
	raw, _ = json.Marshal(manifest)
	_ = os.WriteFile(manifestPath, raw, 0o600)
	if err := VerifyBackup(ctx, bundle); err == nil || !strings.Contains(err.Error(), "unsafe bundle path") {
		t.Fatalf("unsafe manifest path must be rejected before restore, got %v", err)
	}

	// A configured source directory may itself be a symlink; the copier must
	// resolve and include its contents rather than silently omitting the tree.
	_ = os.WriteFile(filepath.Join(store, "through-link.txt"), []byte("linked source"), 0o600)
	storeLink := filepath.Join(root, "store-link")
	if err := os.Symlink(store, storeLink); err == nil {
		_ = os.WriteFile(filepath.Join(store, "actual-key"), []byte("key material fixture"), 0o600)
		if err := os.Symlink("actual-key", filepath.Join(store, "active-key")); err != nil {
			t.Fatal(err)
		}
		linkBundle := filepath.Join(root, "link-bundle")
		if _, err := CreateBackup(ctx, BackupSpec{
			DatabasePath: dbPath,
			StoreDir:     storeLink,
			OutputDir:    linkBundle,
		}); err != nil {
			t.Fatal(err)
		}
		if got, err := os.ReadFile(filepath.Join(linkBundle, "store", "through-link.txt")); err != nil || string(got) != "linked source" {
			t.Fatalf("symlinked Store source was not copied: got=%q err=%v", got, err)
		}
		if got, err := os.ReadFile(filepath.Join(linkBundle, "store", "active-key")); err != nil || string(got) != "key material fixture" {
			t.Fatalf("safe in-tree file symlink was not materialized: got=%q err=%v", got, err)
		}

		external := filepath.Join(root, "external-secret")
		_ = os.WriteFile(external, []byte("outside configured source"), 0o600)
		if err := os.Symlink(external, filepath.Join(store, "escaping-link")); err != nil {
			t.Fatal(err)
		}
		if _, err := CreateBackup(ctx, BackupSpec{
			DatabasePath: dbPath,
			StoreDir:     store,
			OutputDir:    filepath.Join(root, "escaping-link-bundle"),
		}); err == nil || !strings.Contains(err.Error(), "escapes configured directory") {
			t.Fatalf("escaping source symlink must fail backup, got %v", err)
		}
	}
}

func TestBackupAndRestoreInspectionNeverApplyMigrations(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "legacy.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE legacy_data(value TEXT); INSERT INTO legacy_data(value) VALUES('kept'); PRAGMA user_version=4;`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	bundle := filepath.Join(root, "bundle")
	manifest, err := CreateBackup(ctx, BackupSpec{DatabasePath: dbPath, OutputDir: bundle})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.UserVersion != 4 {
		t.Fatalf("backup unexpectedly migrated source schema: user_version=%d", manifest.UserVersion)
	}
	checkVersion := func(path string) int {
		t.Helper()
		check, err := OpenExistingDatabase(path)
		if err != nil {
			t.Fatal(err)
		}
		defer check.Close()
		var version int
		if err := check.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
			t.Fatal(err)
		}
		return version
	}
	if got := checkVersion(dbPath); got != 4 {
		t.Fatalf("source schema mutated during backup: user_version=%d", got)
	}
	restore := filepath.Join(root, "restore")
	if err := RestoreBackup(ctx, bundle, restore); err != nil {
		t.Fatal(err)
	}
	if got := checkVersion(filepath.Join(restore, "db", "manager.db")); got != 4 {
		t.Fatalf("restored schema mutated during validation: user_version=%d", got)
	}
}

func TestConsistencyAuditAndModuleQuarantineIsolation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "manager.db")
	pid, modA, modB := seedBackupDB(t, dbPath)
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	report, err := AuditConsistency(ctx, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Healthy || report.CrossModuleRevCollisions != 0 || report.DanglingParentEdges != 0 {
		t.Fatalf("healthy DB audit failed: %+v", report)
	}

	// Insert import job metadata/workspace for Engine, then quarantine Engine.
	engineWork := filepath.Join(root, "imports", "Engine")
	_ = os.MkdirAll(engineWork, 0o755)
	_ = os.WriteFile(filepath.Join(engineWork, "file.txt"), []byte("engine"), 0o644)
	res, _ := db.Exec(`INSERT INTO import_jobs(job_key,project_id,mode,status,manifest_hash,requested_by,total_items) VALUES('qjob',?,'import','failed','h','carol',1)`, pid)
	jobID, _ := res.LastInsertId()
	_, _ = db.Exec(`INSERT INTO import_job_items(job_id,ord,source_url,platform,module_name,mount_path,module_id,lore_repository_id,lore_repository_url,git_mirror_path,lore_work_path,status,error) VALUES(?,0,'local','local_git','Engine','Engine',?,'11111111111111111111111111111111','lore://local/engine','',?,'failed','broken')`,
		jobID, modA, engineWork)

	q, err := QuarantineModuleImport(ctx, db, "carol", pid, "Engine")
	if err != nil {
		t.Fatal(err)
	}
	if q.Action != "quarantined_and_archived" || q.CommitsRemoved != 1 || q.AliasesRemoved != 1 || q.QuarantinedWorkspaceTarget == "" {
		t.Fatalf("unexpected quarantine result: %+v", q)
	}
	var docsCommits int
	_ = db.QueryRow(`SELECT COUNT(*) FROM module_commits WHERE module_id=?`, modB).Scan(&docsCommits)
	if docsCommits != 1 {
		t.Fatalf("quarantining Engine damaged Docs history: commits=%d", docsCommits)
	}
	docs, err := project.GetModuleByID(ctx, db, modB)
	if err != nil || docs.Archived() {
		t.Fatalf("quarantining Engine archived Docs: %+v err=%v", docs, err)
	}

	// A snapshot-protected Docs module must only be archived and marked for human review.
	var carolID int64
	_ = db.QueryRow(`SELECT user_id FROM users WHERE username='carol'`).Scan(&carolID)
	pins, _ := json.Marshal([]publish.Pin{{
		Name: "Docs", MountPath: "Docs", RepositoryID: docs.RepositoryID,
		RepositoryURL: docs.RepositoryURL, Revision: strings.Repeat("b", 64),
	}})
	_, err = db.Exec(`INSERT INTO snapshots(project_id,parent_revision,pins_json,created_by) VALUES(?,?,?,?)`,
		pid, strings.Repeat("c", 64), string(pins), carolID)
	if err != nil {
		t.Fatal(err)
	}
	q2, err := QuarantineModuleImport(ctx, db, "carol", pid, "Docs")
	if err != nil {
		t.Fatal(err)
	}
	if q2.Action != "archived_protected_by_snapshot" || !q2.RequiresHumanReview || !q2.ReferencedByPublishedSnap {
		t.Fatalf("snapshot-protected quarantine wrong: %+v", q2)
	}
	var preserved int
	_ = db.QueryRow(`SELECT COUNT(*) FROM module_commits WHERE module_id=?`, modB).Scan(&preserved)
	if preserved != 1 {
		t.Fatalf("snapshot-protected Docs history was deleted: %d", preserved)
	}
}

func TestQuarantineRestoresWorkspaceWhenDatabaseTransactionFails(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "manager.db")
	projectID, moduleID, _ := seedBackupDB(t, dbPath)
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	work := filepath.Join(root, "imports", "Engine")
	_ = os.MkdirAll(work, 0o755)
	_ = os.WriteFile(filepath.Join(work, "valuable.txt"), []byte("preserve me"), 0o644)
	res, _ := db.Exec(`INSERT INTO import_jobs(job_key,project_id,mode,status,manifest_hash,requested_by,total_items) VALUES('rollback-job',?,'import','failed','h','carol',1)`, projectID)
	jobID, _ := res.LastInsertId()
	_, _ = db.Exec(`INSERT INTO import_job_items(job_id,ord,source_url,platform,module_name,mount_path,module_id,lore_repository_id,lore_repository_url,git_mirror_path,lore_work_path,status,error) VALUES(?,0,'local','local_git','Engine','Engine',?,'11111111111111111111111111111111','lore://local/engine','',?,'failed','broken')`,
		jobID, moduleID, work)
	_, err = db.Exec(fmt.Sprintf(`
		CREATE TRIGGER inject_quarantine_failure
		BEFORE DELETE ON module_commits
		WHEN OLD.module_id=%d
		BEGIN
			SELECT RAISE(ABORT, 'injected quarantine failure');
		END
	`, moduleID))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := QuarantineModuleImport(ctx, db, "carol", projectID, "Engine"); err == nil {
		t.Fatal("injected database failure did not fail quarantine")
	}
	if got, err := os.ReadFile(filepath.Join(work, "valuable.txt")); err != nil || string(got) != "preserve me" {
		t.Fatalf("workspace was not restored after transaction rollback: got=%q err=%v", got, err)
	}
	module, err := project.GetModuleByID(ctx, db, moduleID)
	if err != nil || module.Archived() {
		t.Fatalf("failed quarantine archived module: module=%+v err=%v", module, err)
	}
	var commits int
	_ = db.QueryRow(`SELECT COUNT(*) FROM module_commits WHERE module_id=?`, moduleID).Scan(&commits)
	if commits != 1 {
		t.Fatalf("failed quarantine removed module commits: %d", commits)
	}
}
