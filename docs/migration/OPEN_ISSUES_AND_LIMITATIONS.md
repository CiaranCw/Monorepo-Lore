# Open Issues, Limitations, and Risk Register

Status values: **P0** blocks all migration; **P1** blocks the affected repository/module or formal acceptance; **P2** may proceed with documented constraints.

## P0

No known unresolved P0 defects in the B2.8 migration-readiness implementation.

P0 invariants enforced by code/tests:

- one physical Lore revision belongs to one module only;
- parent edges resolve inside the same module;
- one cross-module Git commit projects to distinct module-local Lore revisions;
- untouched module commits are aliases, not fake revisions;
- unclassified Monorepo paths block strict import;
- shallow/missing Git DAGs block import;
- unauthorized history/ref/detail/cursor access returns no data.

Any future violation of these invariants is an immediate migration stop.

## P1

### P1-1 — Real business repositories not yet Dry-run

Status: **NOT_RUN by task boundary**.

Synthetic repositories cover branches, tags, long history, Unicode metadata, conflict and Octopus merges, LFS, submodules, symlinks, interruption/resume, source ref drift, and Monorepo split projection. Real source-host peculiarities and repository-specific path ownership still require inventory and Dry-run.

### P1-2 — Independent second Linux client

Status: **NOT_RUN**.

Server-side Linux and isolated Lore Server tests pass, but a second independent team Linux workstation has not run the client workflow.

### P1-3 — Pointer-only LFS is not full content migration

`lfs_mode="pointer"` may be used only with explicit owner acceptance. It reports:

- `full_content_migrated=false`;
- `lfs_hydration_status="pointer_only_unhydrated"`;
- every pointer OID and expected size.

It does not satisfy full-file migration acceptance. Normal first migrations should use `lfs_mode="hydrate"`, which fails on missing, size-mismatched, or SHA-256-mismatched LFS objects.

### P1-4 — Submodule repositories require explicit decisions

The parent module preserves only gitlink path/SHA and `.gitmodules` metadata. Child files never enter the parent.

- `submodule_policy="require_registered"` blocks acceptance until dependencies are independently registered/imported.
- `record_gitlink` records dependencies as `unmigrated_independent_repo`; it does not claim child history migration.

### P1-5 — Store backup requires a write-quiescent window

SQLite uses hot WAL-consistent `VACUUM INTO`, but Lore Store/import workspace copying is filesystem-level. Manager and Lore writes must be stopped/quiesced for a cross-component consistent bundle. `manager-ops backup` does not freeze a running Lore Server.

## P2

### P2-1 — Tags are Manager compatibility objects

Lore 0.10.1 has no native Tag entity. Lightweight/annotated Tag metadata and exact target mapping are stored in `module_refs`; target historical Lore revisions remain cloneable. Tag queries use Manager/lore-mono.

### P2-2 — Octopus merge compatibility bridges

Lore has two physical parent slots. Git merges with three or more parents use hidden `git.synthetic=1` two-parent bridge revisions. User history filters bridges and exposes the exact ordered N-parent Git DAG from `module_commit_parents`.

### P2-3 — Non-main bootstrap branch

Lore creates an undeletable initial `main`. A `master`-only source anchors its root on physical `main`, then uses `master` as the sole indexed/default branch. `bootstrap_main_rev` prevents that implementation branch from leaking into Manager history/ref APIs.

### P2-4 — Lore read label is not read-only enforcement

Lore 0.10.1 maps Manager `read` and `write` grants to repository access. A read-labeled access token can push. Do not use the read label as a security boundary.

### P2-5 — Access token revocation delay

Access token TTL is five minutes. Grant revocation, account disable, or Manager shutdown affects new identity/token exchanges but does not instantly invalidate an already-issued token.

### P2-6 — Snapshot recovery history window

Lore recovery currently scans the latest 20 parent revisions for the operation marker. Pin comparison is exact, so an older operation is never falsely accepted, but it may be marked for human review instead of recovered automatically.

### P2-7 — Historical byte verification depth

The importer materializes every projected tree during replay and verifies metadata, ordered parents, aliases, refs, deltas, and special objects across the full history. The independent end-to-end byte digest comparison is performed for the default-branch HEAD; it is not a second full checkout-and-byte-digest pass for every historical revision.

### P2-8 — Quarantine and archived remote repositories

Snapshot protection currently detects a repository ID in stored pin JSON conservatively before destructive quarantine. Quarantine archives Manager metadata/workspace but does not delete the remote Lore repository. The publisher service identity continues to require archived repositories for historical Snapshot access.
