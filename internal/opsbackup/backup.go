// Package opsbackup implements WAL-consistent SQLite backups, Lore Store and
// key/config bundle snapshots, isolated-directory restoration, SQLite-to-Lore
// consistency auditing, and single-module quarantine without affecting sibling modules.
package opsbackup

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"lore-monorepo/internal/database"
	"lore-monorepo/internal/loreadapter"
	"lore-monorepo/internal/project"
)

// BackupSpec defines the source paths to include in a consistent backup bundle.
type BackupSpec struct {
	DatabasePath string
	StoreDir     string
	ImportsDir   string
	KeysDir      string
	ConfigsDir   string
	CertsDir     string
	OutputDir    string
}

// FileHash is one relative file entry inside a backup bundle.
type FileHash struct {
	RelPath string `json:"rel_path"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	Mode    uint32 `json:"mode"`
}

// Manifest is written to `backup-manifest.json` inside the bundle directory.
// It contains metadata and SHA-256 digests only — never key material or tokens.
type Manifest struct {
	CreatedAtUTC string         `json:"created_at_utc"`
	UserVersion  int            `json:"user_version"`
	TableCounts  map[string]int `json:"table_counts"`
	Files        []FileHash     `json:"files"`
}

// ConsistencyReport summarizes a live SQLite <-> Lore Store consistency audit.
type ConsistencyReport struct {
	Healthy                  bool     `json:"healthy"`
	UserVersion              int      `json:"user_version"`
	IntegrityCheck           string   `json:"integrity_check"`
	RunningOperations        int      `json:"running_operations"`
	RunningImportJobs        int      `json:"running_import_jobs"`
	CrossModuleRevCollisions int      `json:"cross_module_rev_collisions"`
	DanglingParentEdges      int      `json:"dangling_parent_edges"`
	DanglingAliases          int      `json:"dangling_aliases"`
	UnsafeSucceededImports   int      `json:"unsafe_succeeded_imports"`
	ModulesCheckedOnDisk     int      `json:"modules_checked_on_disk"`
	Issues                   []string `json:"issues,omitempty"`
}

// QuarantineResult describes the isolated cleanup/archival of a failed module import.
type QuarantineResult struct {
	ProjectID                  int64  `json:"project_id"`
	ModuleID                   int64  `json:"module_id"`
	ModuleName                 string `json:"module_name"`
	Action                     string `json:"action"` // "archived_protected_by_snapshot" or "quarantined_and_archived"
	ReferencedByPublishedSnap  bool   `json:"referenced_by_published_snapshot"`
	RequiresHumanReview        bool   `json:"requires_human_review"`
	QuarantinedWorkspaceTarget string `json:"quarantined_workspace_target,omitempty"`
	CommitsRemoved             int64  `json:"commits_removed"`
	AliasesRemoved             int64  `json:"aliases_removed"`
}

// CreateBackup produces a WAL-consistent SQLite snapshot (`VACUUM INTO`) alongside
// Lore Store, import workspaces, keys, configs, and certs, plus `SHA256SUMS` and `backup-manifest.json`.
func CreateBackup(ctx context.Context, spec BackupSpec) (Manifest, error) {
	if strings.TrimSpace(spec.DatabasePath) == "" || strings.TrimSpace(spec.OutputDir) == "" {
		return Manifest{}, errors.New("opsbackup: database path and output directory are required")
	}
	if err := validateBackupSources(spec); err != nil {
		return Manifest{}, err
	}
	if entries, err := os.ReadDir(spec.OutputDir); err == nil && len(entries) > 0 {
		return Manifest{}, fmt.Errorf("opsbackup: output directory %q already exists and is non-empty", spec.OutputDir)
	}
	if err := os.MkdirAll(filepath.Join(spec.OutputDir, "db"), 0o700); err != nil {
		return Manifest{}, err
	}

	// 1. Hot WAL-consistent SQLite backup via VACUUM INTO.
	srcDB, err := OpenExistingDatabase(spec.DatabasePath)
	if err != nil {
		return Manifest{}, fmt.Errorf("opsbackup: open source db: %w", err)
	}
	defer srcDB.Close()

	destDBPath := filepath.Join(spec.OutputDir, "db", "manager.db")
	escapedDest := strings.ReplaceAll(filepath.ToSlash(destDBPath), "'", "''")
	if _, err := srcDB.ExecContext(ctx, fmt.Sprintf("VACUUM INTO '%s'", escapedDest)); err != nil {
		return Manifest{}, fmt.Errorf("opsbackup: vacuum into failed: %w", err)
	}

	var userVer int
	_ = srcDB.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&userVer)
	counts, err := collectTableCounts(ctx, srcDB)
	if err != nil {
		return Manifest{}, err
	}

	// 2. Copy optional directories preserving permissions.
	sections := []struct {
		src  string
		name string
	}{
		{spec.StoreDir, "store"},
		{spec.ImportsDir, "imports"},
		{spec.KeysDir, "keys"},
		{spec.ConfigsDir, "configs"},
		{spec.CertsDir, "certs"},
	}
	for _, sec := range sections {
		if strings.TrimSpace(sec.src) == "" {
			continue
		}
		if err := copyDirFiltered(sec.src, filepath.Join(spec.OutputDir, sec.name)); err != nil {
			return Manifest{}, fmt.Errorf("opsbackup: copy %s: %w", sec.name, err)
		}
	}

	// 3. Hash all backed-up files and write SHA256SUMS + backup-manifest.json.
	files, err := hashBundleFiles(spec.OutputDir)
	if err != nil {
		return Manifest{}, err
	}
	if err := os.WriteFile(filepath.Join(spec.OutputDir, "SHA256SUMS"), []byte(renderSHA256SUMS(files)), 0o600); err != nil {
		return Manifest{}, err
	}

	man := Manifest{
		CreatedAtUTC: time.Now().UTC().Format(time.RFC3339),
		UserVersion:  userVer,
		TableCounts:  counts,
		Files:        files,
	}
	manBytes, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	if err := os.WriteFile(filepath.Join(spec.OutputDir, "backup-manifest.json"), manBytes, 0o600); err != nil {
		return Manifest{}, err
	}

	// 4. Verify the newly created bundle before declaring success!
	if err := VerifyBackup(ctx, spec.OutputDir); err != nil {
		return Manifest{}, err
	}
	return man, nil
}

// VerifyBackup validates `backup-manifest.json`, checks every file's SHA-256 digest,
// and runs `PRAGMA integrity_check` and `PRAGMA foreign_key_check` on the snapshot DB.
func VerifyBackup(ctx context.Context, bundleDir string) error {
	rawMan, err := os.ReadFile(filepath.Join(bundleDir, "backup-manifest.json"))
	if err != nil {
		return fmt.Errorf("opsbackup: read backup-manifest.json: %w", err)
	}
	var man Manifest
	if err := json.Unmarshal(rawMan, &man); err != nil {
		return fmt.Errorf("opsbackup: decode manifest: %w", err)
	}
	if len(man.Files) == 0 {
		return errors.New("opsbackup: manifest contains zero files")
	}

	seen := make(map[string]struct{}, len(man.Files))
	for _, f := range man.Files {
		if _, exists := seen[f.RelPath]; exists {
			return fmt.Errorf("opsbackup: duplicate manifest path %q", f.RelPath)
		}
		seen[f.RelPath] = struct{}{}
		full, err := safeBundlePath(bundleDir, f.RelPath)
		if err != nil {
			return err
		}
		st, err := os.Lstat(full)
		if err != nil {
			return fmt.Errorf("opsbackup: missing file %s: %w", f.RelPath, err)
		}
		if !st.Mode().IsRegular() {
			return fmt.Errorf("opsbackup: bundle entry %s is not a regular file", f.RelPath)
		}
		if st.Size() != f.Size {
			return fmt.Errorf("opsbackup: size mismatch on %s: got %d want %d", f.RelPath, st.Size(), f.Size)
		}
		gotHash, err := sha256File(full)
		if err != nil {
			return err
		}
		if gotHash != f.SHA256 {
			return fmt.Errorf("opsbackup: sha256 mismatch on %s", f.RelPath)
		}
	}

	wantSums := renderSHA256SUMS(man.Files)
	gotSums, err := os.ReadFile(filepath.Join(bundleDir, "SHA256SUMS"))
	if err != nil {
		return fmt.Errorf("opsbackup: read SHA256SUMS: %w", err)
	}
	if string(gotSums) != wantSums {
		return errors.New("opsbackup: SHA256SUMS does not match backup manifest")
	}

	dbPath := filepath.Join(bundleDir, "db", "manager.db")
	dsn := "file:" + filepath.ToSlash(dbPath) + "?mode=ro"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	var integrity string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil {
		return err
	}
	if integrity != "ok" {
		return fmt.Errorf("opsbackup: sqlite integrity_check failed: %s", integrity)
	}

	fkRows, err := db.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return err
	}
	defer fkRows.Close()
	if fkRows.Next() {
		return errors.New("opsbackup: sqlite foreign_key_check reported violations")
	}
	return fkRows.Err()
}

// RestoreBackup verifies bundleDir and restores it into an empty/new targetRoot directory,
// enforcing 0600 permissions on private key files and verifying post-restore DB health.
func RestoreBackup(ctx context.Context, bundleDir, targetRoot string) error {
	if err := VerifyBackup(ctx, bundleDir); err != nil {
		return fmt.Errorf("opsbackup: pre-restore verification failed: %w", err)
	}
	if entries, err := os.ReadDir(targetRoot); err == nil && len(entries) > 0 {
		return fmt.Errorf("opsbackup: restore destination %q must be empty", targetRoot)
	}
	if err := os.MkdirAll(targetRoot, 0o700); err != nil {
		return err
	}

	rawMan, err := os.ReadFile(filepath.Join(bundleDir, "backup-manifest.json"))
	if err != nil {
		return err
	}
	var man Manifest
	if err := json.Unmarshal(rawMan, &man); err != nil {
		return err
	}

	for _, f := range man.Files {
		src, err := safeBundlePath(bundleDir, f.RelPath)
		if err != nil {
			return err
		}
		dst, err := safeBundlePath(targetRoot, f.RelPath)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		perm := os.FileMode(f.Mode) & 0o777
		if perm == 0 {
			perm = 0o600
		}
		if strings.HasSuffix(f.RelPath, ".key") || strings.Contains(f.RelPath, "private") || strings.HasSuffix(f.RelPath, "-active.pem") {
			perm = 0o600
		}
		if err := copySingleFile(src, dst, perm); err != nil {
			return err
		}
	}

	// Verify restored SQLite DB opens cleanly in WAL mode with matching table counts!
	restoredDB, err := OpenExistingDatabase(filepath.Join(targetRoot, "db", "manager.db"))
	if err != nil {
		return fmt.Errorf("opsbackup: open restored database: %w", err)
	}
	defer restoredDB.Close()

	gotCounts, err := collectTableCounts(ctx, restoredDB)
	if err != nil {
		return err
	}
	for tbl, wantN := range man.TableCounts {
		if gotCounts[tbl] != wantN {
			return fmt.Errorf("opsbackup: restored table %s count %d != %d", tbl, gotCounts[tbl], wantN)
		}
	}
	return nil
}

// AuditConsistency cross-checks SQLite metadata, commit DAG tables, and physical Lore repositories on disk.
func AuditConsistency(ctx context.Context, db *sql.DB, lore *loreadapter.Client) (ConsistencyReport, error) {
	var rep ConsistencyReport
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&rep.UserVersion); err != nil {
		return rep, err
	}
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&rep.IntegrityCheck); err != nil {
		return rep, err
	}
	if rep.IntegrityCheck != "ok" {
		rep.Issues = append(rep.Issues, "sqlite integrity_check: "+rep.IntegrityCheck)
	}

	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM operations WHERE status='running'`).Scan(&rep.RunningOperations)
	if rep.RunningOperations > 0 {
		rep.Issues = append(rep.Issues, fmt.Sprintf("%d running operation(s) require recovery", rep.RunningOperations))
	}
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM import_jobs WHERE status='running'`).Scan(&rep.RunningImportJobs)
	if rep.RunningImportJobs > 0 {
		rep.Issues = append(rep.Issues, fmt.Sprintf("%d running import job(s) require recovery", rep.RunningImportJobs))
	}

	_ = db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM module_commits a
		JOIN module_commits b ON a.lore_revision = b.lore_revision AND a.module_id <> b.module_id
	`).Scan(&rep.CrossModuleRevCollisions)
	if rep.CrossModuleRevCollisions > 0 {
		rep.Issues = append(rep.Issues, fmt.Sprintf("P0 violation: %d cross-module lore_revision collision(s)", rep.CrossModuleRevCollisions))
	}

	_ = db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM module_commit_parents p
		LEFT JOIN module_commits c ON c.module_id = p.module_id AND c.lore_revision = p.parent_lore_revision
		WHERE p.parent_lore_revision <> '' AND c.lore_revision IS NULL
	`).Scan(&rep.DanglingParentEdges)
	if rep.DanglingParentEdges > 0 {
		rep.Issues = append(rep.Issues, fmt.Sprintf("%d dangling parent edge(s) in module_commit_parents", rep.DanglingParentEdges))
	}
	_ = db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM module_commit_aliases a
		LEFT JOIN module_commits c ON c.module_id=a.module_id AND c.lore_revision=a.lore_revision
		WHERE a.lore_revision <> '' AND c.lore_revision IS NULL
	`).Scan(&rep.DanglingAliases)
	if rep.DanglingAliases > 0 {
		rep.Issues = append(rep.Issues, fmt.Sprintf("%d dangling source-commit alias mapping(s)", rep.DanglingAliases))
	}

	// A succeeded import is operationally unsafe when verification did not pass,
	// strict path coverage is incomplete, or pointer-only LFS was mistaken for a
	// full-content migration.
	unsafeRows, err := db.QueryContext(ctx, `
		SELECT verification_json
		FROM import_job_items
		WHERE status='succeeded'
	`)
	if err != nil {
		return rep, err
	}
	for unsafeRows.Next() {
		var raw string
		if unsafeRows.Scan(&raw) != nil {
			continue
		}
		var v struct {
			Passed              bool   `json:"passed"`
			CoverageComplete    bool   `json:"coverage_complete"`
			FullContentMigrated bool   `json:"full_content_migrated"`
			LFSHydrationStatus  string `json:"lfs_hydration_status"`
		}
		if json.Unmarshal([]byte(raw), &v) != nil ||
			!v.Passed ||
			!v.CoverageComplete ||
			(v.LFSHydrationStatus == "pointer_only_unhydrated" && v.FullContentMigrated) {
			rep.UnsafeSucceededImports++
		}
	}
	unsafeRows.Close()
	if rep.UnsafeSucceededImports > 0 {
		rep.Issues = append(rep.Issues, fmt.Sprintf("%d succeeded import item(s) have unsafe/inconsistent verification evidence", rep.UnsafeSucceededImports))
	}

	// Cross-check active modules that have managed Lore workspaces on disk.
	rows, err := db.QueryContext(ctx, `
		SELECT m.module_id, m.name, m.repository_id, COALESCE((
			SELECT i.lore_work_path FROM import_job_items i
			WHERE i.module_id = m.module_id AND i.lore_work_path <> ''
			ORDER BY i.item_id DESC LIMIT 1
		), '')
		FROM modules m
		WHERE m.archived_at IS NULL
	`)
	if err != nil {
		return rep, err
	}
	type modCheck struct {
		id      int64
		name    string
		repoID  string
		workDir string
	}
	var checks []modCheck
	for rows.Next() {
		var mc modCheck
		if err := rows.Scan(&mc.id, &mc.name, &mc.repoID, &mc.workDir); err != nil {
			rows.Close()
			return rep, err
		}
		if mc.workDir != "" {
			checks = append(checks, mc)
		}
	}
	if err := rows.Close(); err != nil {
		return rep, err
	}

	for _, mc := range checks {
		idFile := filepath.Join(mc.workDir, ".lore", "id")
		rawID, rErr := os.ReadFile(idFile)
		if rErr != nil {
			rep.Issues = append(rep.Issues, fmt.Sprintf("module %s (%d): missing .lore/id at %s", mc.name, mc.id, mc.workDir))
			continue
		}
		rep.ModulesCheckedOnDisk++
		diskID := ""
		if len(rawID) == 16 {
			diskID = hex.EncodeToString(rawID)
		} else {
			diskID = strings.TrimSpace(strings.ToLower(string(rawID)))
		}
		if diskID != "" && diskID != mc.repoID {
			rep.Issues = append(rep.Issues, fmt.Sprintf("module %s (%d): disk .lore/id %s != SQLite repository_id %s", mc.name, mc.id, diskID, mc.repoID))
		}
		if lore != nil {
			if lbs, lErr := lore.ListBranchesAt(ctx, mc.workDir, false); lErr == nil {
				byName := map[string]string{}
				for _, b := range lbs {
					if !b.Archived {
						byName[b.Name] = b.Latest
					}
				}
				bRows, bErr := db.QueryContext(ctx, `SELECT ref_name, lore_revision FROM module_refs WHERE module_id=? AND ref_type='branch'`, mc.id)
				if bErr == nil {
					for bRows.Next() {
						var rn, rr string
						if bRows.Scan(&rn, &rr) == nil && byName[rn] != rr {
							rep.Issues = append(rep.Issues, fmt.Sprintf("module %s branch %s: SQLite rev %s != Lore rev %s", mc.name, rn, short(rr), short(byName[rn])))
						}
					}
					bRows.Close()
				}
			}
		}
	}

	rep.Healthy = len(rep.Issues) == 0
	return rep, nil
}

// QuarantineModuleImport isolates a broken or undesired module import without
// touching any sibling module's Lore repository, commits, or permissions.
// If the module is already referenced by a published parent Snapshot, destructive
// history deletion is refused (`RequiresHumanReview=true`) and the module is only archived.
func QuarantineModuleImport(ctx context.Context, db *sql.DB, actor string, projectID int64, moduleName string) (QuarantineResult, error) {
	var out QuarantineResult
	if strings.TrimSpace(actor) == "" {
		return out, errors.New("opsbackup: actor is required")
	}
	mod, err := project.GetModule(ctx, db, projectID, moduleName)
	if err != nil {
		return out, err
	}
	out.ProjectID = projectID
	out.ModuleID = mod.ID
	out.ModuleName = mod.Name

	// Check whether any published snapshot on projectID pins mod.RepositoryID!
	snapRows, err := db.QueryContext(ctx, `SELECT pins_json FROM snapshots WHERE project_id=?`, projectID)
	if err != nil {
		return out, err
	}
	referenced := false
	for snapRows.Next() {
		var raw string
		if snapRows.Scan(&raw) == nil && strings.Contains(raw, mod.RepositoryID) {
			referenced = true
			break
		}
	}
	snapRows.Close()
	out.ReferencedByPublishedSnap = referenced

	if referenced {
		// Protected by immutable published snapshot: archive only, preserve history, require human review!
		if !mod.Archived() {
			if err := project.ArchiveModule(ctx, db, actor, mod.ID); err != nil {
				return out, err
			}
		}
		out.Action = "archived_protected_by_snapshot"
		out.RequiresHumanReview = true
		return out, nil
	}

	var workDir string
	_ = db.QueryRowContext(ctx, `
		SELECT lore_work_path FROM import_job_items
		WHERE module_id=? AND lore_work_path <> ''
		ORDER BY item_id DESC LIMIT 1
	`, mod.ID).Scan(&workDir)

	var quarantineTarget string
	if workDir != "" {
		if _, statErr := os.Stat(workDir); statErr == nil {
			quarantineTarget = filepath.Join(
				filepath.Dir(filepath.Dir(workDir)),
				"quarantine",
				fmt.Sprintf("%s-%d", mod.Name, time.Now().UnixNano()),
			)
			if err := os.MkdirAll(filepath.Dir(quarantineTarget), 0o700); err != nil {
				return out, fmt.Errorf("opsbackup: prepare quarantine directory: %w", err)
			}
			if err := os.Rename(workDir, quarantineTarget); err != nil {
				return out, fmt.Errorf("opsbackup: quarantine module workspace: %w", err)
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return out, fmt.Errorf("opsbackup: inspect module workspace: %w", statErr)
		}
	}

	err = database.Tx(ctx, db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM module_special_objects WHERE module_id=?`, mod.ID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM module_refs WHERE module_id=?`, mod.ID); err != nil {
			return err
		}
		aRes, err := tx.ExecContext(ctx, `DELETE FROM module_commit_aliases WHERE module_id=?`, mod.ID)
		if err != nil {
			return err
		}
		out.AliasesRemoved, _ = aRes.RowsAffected()

		if _, err := tx.ExecContext(ctx, `DELETE FROM module_commit_parents WHERE module_id=?`, mod.ID); err != nil {
			return err
		}
		cRes, err := tx.ExecContext(ctx, `DELETE FROM module_commits WHERE module_id=?`, mod.ID)
		if err != nil {
			return err
		}
		out.CommitsRemoved, _ = cRes.RowsAffected()

		if _, err := tx.ExecContext(ctx, `DELETE FROM module_permissions WHERE module_id=?`, mod.ID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE import_job_items
			SET status='failed', error=?
			WHERE module_id=?
		`, "quarantined by "+actor, mod.ID); err != nil {
			return err
		}
		if !mod.Archived() {
			res, err := tx.ExecContext(ctx, `
				UPDATE modules
				SET archived_at=strftime('%Y-%m-%dT%H:%M:%SZ','now'), mount_path=?
				WHERE module_id=? AND archived_at IS NULL
			`, fmt.Sprintf("~archived/%d", mod.ID), mod.ID)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return fmt.Errorf("opsbackup: active module %d changed during quarantine", mod.ID)
			}
			if err := database.Audit(ctx, tx, actor, "module_archive", fmt.Sprint(mod.ID), "mount_released="+mod.MountPath); err != nil {
				return err
			}
		}
		return database.Audit(ctx, tx, actor, "module_import_quarantine", mod.Name, fmt.Sprintf("module_id=%d", mod.ID))
	})
	if err != nil {
		if quarantineTarget != "" {
			if restoreErr := os.Rename(quarantineTarget, workDir); restoreErr != nil {
				return out, fmt.Errorf("%w; additionally failed to restore quarantined workspace: %v", err, restoreErr)
			}
		}
		return out, err
	}

	out.QuarantinedWorkspaceTarget = quarantineTarget
	out.Action = "quarantined_and_archived"
	return out, nil
}

// OpenExistingDatabase opens an existing Manager SQLite database without
// applying schema migrations. Operational backup/audit/restore commands must
// not silently upgrade the schema merely by inspecting it.
func OpenExistingDatabase(path string) (*sql.DB, error) {
	if info, err := os.Stat(path); err != nil {
		return nil, err
	} else if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("opsbackup: database path %q is not a regular file", path)
	}
	dsn := "file:" + filepath.ToSlash(path) + "?mode=rw&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func collectTableCounts(ctx context.Context, db *sql.DB) (map[string]int, error) {
	rows, err := db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		names = append(names, n)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	counts := make(map[string]int, len(names))
	for _, n := range names {
		var c int
		if err := db.QueryRowContext(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, strings.ReplaceAll(n, `"`, `""`))).Scan(&c); err != nil {
			return nil, err
		}
		counts[n] = c
	}
	return counts, nil
}

func validateBackupSources(spec BackupSpec) error {
	dbInfo, err := os.Stat(spec.DatabasePath)
	if err != nil {
		return fmt.Errorf("opsbackup: database path: %w", err)
	}
	if !dbInfo.Mode().IsRegular() {
		return fmt.Errorf("opsbackup: database path %q is not a regular file", spec.DatabasePath)
	}

	outputAbs, err := resolveProspectivePath(spec.OutputDir)
	if err != nil {
		return fmt.Errorf("opsbackup: resolve output directory: %w", err)
	}
	for name, source := range map[string]string{
		"store": spec.StoreDir, "imports": spec.ImportsDir, "keys": spec.KeysDir,
		"configs": spec.ConfigsDir, "certs": spec.CertsDir,
	} {
		if strings.TrimSpace(source) == "" {
			continue
		}
		info, statErr := os.Stat(source)
		if statErr != nil {
			return fmt.Errorf("opsbackup: %s source %q: %w", name, source, statErr)
		}
		if !info.IsDir() {
			return fmt.Errorf("opsbackup: %s source %q is not a directory", name, source)
		}
		sourceAbs, absErr := filepath.EvalSymlinks(source)
		if absErr != nil {
			return fmt.Errorf("opsbackup: resolve %s source: %w", name, absErr)
		}
		sourceAbs, absErr = filepath.Abs(sourceAbs)
		if absErr != nil {
			return fmt.Errorf("opsbackup: resolve %s source absolute path: %w", name, absErr)
		}
		rel, relErr := filepath.Rel(sourceAbs, outputAbs)
		if relErr != nil {
			return fmt.Errorf("opsbackup: compare %s source and output: %w", name, relErr)
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return fmt.Errorf("opsbackup: output directory must not be inside %s source %q", name, source)
		}
	}
	return nil
}

// resolveProspectivePath resolves symlinks in the longest existing ancestor
// while preserving a not-yet-created path suffix.
func resolveProspectivePath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	cursor := abs
	var suffix []string
	for {
		if _, statErr := os.Lstat(cursor); statErr == nil {
			resolved, err := filepath.EvalSymlinks(cursor)
			if err != nil {
				return "", err
			}
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return filepath.Clean(resolved), nil
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return "", statErr
		}
		parent := filepath.Dir(cursor)
		if parent == cursor {
			return "", fmt.Errorf("opsbackup: no existing ancestor for %q", path)
		}
		suffix = append(suffix, filepath.Base(cursor))
		cursor = parent
	}
}

func safeBundlePath(root, relSlash string) (string, error) {
	if strings.TrimSpace(relSlash) == "" {
		return "", errors.New("opsbackup: empty bundle-relative path")
	}
	rel := filepath.FromSlash(relSlash)
	if filepath.IsAbs(rel) || filepath.VolumeName(rel) != "" {
		return "", fmt.Errorf("opsbackup: unsafe absolute bundle path %q", relSlash)
	}
	clean := filepath.Clean(rel)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("opsbackup: unsafe bundle path %q", relSlash)
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	full := filepath.Join(rootAbs, clean)
	contained, err := filepath.Rel(rootAbs, full)
	if err != nil || contained == ".." || strings.HasPrefix(contained, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("opsbackup: bundle path escapes root: %q", relSlash)
	}
	return full, nil
}

func copyDirFiltered(srcDir, dstDir string) error {
	resolvedSource, err := filepath.EvalSymlinks(srcDir)
	if err != nil {
		return err
	}
	return filepath.Walk(resolvedSource, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(resolvedSource, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return os.MkdirAll(dstDir, 0o700)
		}
		// Skip transient lock files during snapshot copy.
		if strings.HasSuffix(info.Name(), ".lock") {
			return nil
		}
		target := filepath.Join(dstDir, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			resolvedTarget, err := filepath.EvalSymlinks(path)
			if err != nil {
				return fmt.Errorf("opsbackup: resolve source symlink %q: %w", path, err)
			}
			contained, err := filepath.Rel(resolvedSource, resolvedTarget)
			if err != nil || contained == ".." || strings.HasPrefix(contained, ".."+string(filepath.Separator)) {
				return fmt.Errorf("opsbackup: source symlink %q escapes configured directory", path)
			}
			targetInfo, err := os.Stat(resolvedTarget)
			if err != nil {
				return err
			}
			if !targetInfo.Mode().IsRegular() {
				return fmt.Errorf("opsbackup: source symlink %q does not resolve to a regular file", path)
			}
			return copySingleFile(resolvedTarget, target, targetInfo.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("opsbackup: unsupported non-regular source entry %q", path)
		}
		perm := info.Mode().Perm()
		if strings.HasSuffix(info.Name(), ".key") || strings.Contains(info.Name(), "private") || strings.HasSuffix(info.Name(), "-active.pem") {
			perm = 0o600
		}
		return copySingleFile(path, target, perm)
	})
}

func copySingleFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func hashBundleFiles(bundleDir string) ([]FileHash, error) {
	var list []FileHash
	err := filepath.Walk(bundleDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(bundleDir, path)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(rel)
		if relSlash == "SHA256SUMS" || relSlash == "backup-manifest.json" {
			return nil
		}
		sum, err := sha256File(path)
		if err != nil {
			return err
		}
		list = append(list, FileHash{
			RelPath: relSlash,
			Size:    info.Size(),
			SHA256:  sum,
			Mode:    uint32(info.Mode().Perm()),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(list, func(i, j int) bool { return list[i].RelPath < list[j].RelPath })
	return list, nil
}

func renderSHA256SUMS(files []FileHash) string {
	var out strings.Builder
	for _, f := range files {
		fmt.Fprintf(&out, "%s  %s\n", f.SHA256, f.RelPath)
	}
	return out.String()
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
