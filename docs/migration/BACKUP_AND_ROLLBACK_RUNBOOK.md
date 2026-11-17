# Backup, Restore, Rollback, and Failure Recovery Runbook

This runbook is executable with `manager-ops`. A SQLite-only backup is insufficient: the Manager DB, Lore Store, import mirror/workspaces, configuration, signing keys, and certificates form one operational recovery unit.

## A. Pre-backup quiescence

1. Block new imports and snapshot publishes.
2. Wait for `operations.status='running'` and `import_jobs.status='running'` to reach zero.
3. Stop the isolated Manager, Gateway, and Lore Server gracefully. Store copying is not transactionally atomic while Lore writes.
4. Record process state, ports, database path, Store path, import workspace, config/key/cert paths, and expected SHA identities.

## B. Create and verify backup

```sh
manager-ops backup \
  --db <manager.db> \
  --store <lore-store> \
  --imports <import-workspace> \
  --keys <key-dir> \
  --configs <config-dir> \
  --certs <cert-dir> \
  --out <new-backup-dir>

manager-ops verify --bundle <new-backup-dir>
```

What it does:

- `VACUUM INTO` creates a WAL-consistent SQLite snapshot;
- copies Store/import/key/config/cert directories while services are quiesced;
- rejects any configured source directory that is missing instead of silently producing an incomplete bundle;
- writes `backup-manifest.json` and `SHA256SUMS`;
- resolves configured source roots, materializes safe in-tree file symlinks, rejects escaping/unsupported source links and unsafe/symlinked bundle entries, then runs SHA-256/SHA256SUMS verification, `PRAGMA integrity_check`, and `PRAGMA foreign_key_check`.
- opens operational databases without applying migrations; backup, verify, restore validation, and audit never upgrade a schema as a side effect.

Keep the backup outside the repository. Protect directories containing private keys with OS permissions and access controls.

## C. Isolated restore drill

```sh
manager-ops restore --bundle <backup-dir> --target <empty-isolated-restore-dir>
manager-ops audit --db <restore-dir>/db/manager.db
```

Then, on unused test ports only:

1. Point a copy of config at restored SQLite/Store/keys/certs.
2. Start the restored Lore Server, Manager, and Gateway.
3. Run `manager-ops audit --db ... --lore ... --auth-path ...`.
4. Clone one active module and one snapshot-pinned historical revision.
5. Verify project/module/history/snapshot counts against `backup-manifest.json`.
6. Stop restored services and confirm test ports close.

Do not consider a backup valid until an isolated restore drill succeeds.

## D. Automatic recovery capabilities

Automatically recoverable:

- stale `running` import jobs after Manager restart (`RecoverInterruptedJobs`);
- per-commit importer checkpoint recovery;
- physical Lore DAG reconciliation when Lore committed before SQLite checkpoint persisted;
- remote branch push idempotency when branch head already equals intended revision;
- F5 snapshot recovery (push succeeded before SQLite success marker).

Not automatically recoverable:

- unknown remote publish where operation id/pins cannot be proven;
- source branch/tag drift during fetch;
- shallow/missing Git parents;
- corrupt/missing LFS binaries in hydrate mode;
- uncertain existing module provenance;
- failed import mixed with later native Lore commits;
- Store corruption or a DB/Store backup from different quiescent moments.

These require human review or whole-bundle restoration.

## E. Import failure handling

### Before module creation

- Correct manifest, credentials, mapping, or source-ref stability.
- Re-run Dry-run. No cleanup is required.

### Partial import with no native commits

- Re-run the identical manifest and `job_key`.
- The importer resumes from persisted aliases/checkpoints and physical Lore reconciliation.

### One bad module in a successful batch

Do not roll back sibling modules. Quarantine only the failed module:

```sh
manager-ops quarantine-module \
  --db <manager.db> \
  --project-id <id> \
  --module <name> \
  --actor <admin>
```

The operation:

- removes only that module’s history/aliases/refs/special-object index and permissions;
- archives only that module;
- moves only that module’s managed Lore workspace to quarantine;
- restores the workspace automatically if the SQLite quarantine transaction fails;
- marks related import items failed;
- leaves sibling modules untouched.

If a published snapshot already references the module, destructive deletion is refused: it is archived, data is preserved, and exit code `3` signals required human review.

### Restore entire migration window

Use only when multiple modules, DB schema, or Lore Store integrity is compromised:

1. Stop services.
2. Move current DB/Store/import workspace aside (never delete until review).
3. Restore the verified bundle into a fresh directory.
4. Rebind copied config to the fresh restored paths.
5. Audit and start on test ports.
6. Promote only after acceptance.

## F. DB ↔ Store consistency checks

`manager-ops audit` checks:

- SQLite integrity and running operation/job state;
- cross-module Lore revision collisions;
- dangling module parent edges;
- managed `.lore/id` vs SQLite `repository_id`;
- SQLite branch refs vs physical Lore branch heads when Lore CLI is supplied.

Any issue means **FAIL** for migration readiness until resolved.
