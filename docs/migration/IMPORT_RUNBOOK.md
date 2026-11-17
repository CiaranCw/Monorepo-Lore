# External Git Repository Migration Runbook

This runbook is the required operator sequence for the first real repository migrations. Do not skip steps or reinterpret `dry-run` as a completed migration.

## 0. Change control and environment

- Use an isolated Manager SQLite database, Lore Store, import workspace, signing keys, TLS certificates, ports, and publisher service identity.
- Do not point the importer at production until an isolated backup/restore drill and all acceptance checks pass.
- Record an operator, change ticket, source owners, target project, intended users, and rollback owner.
- Never put tokens in TOML, URLs, argv, logs, tickets, or screenshots. Export the token only in the client shell named by `token_env`; `lore-mono` resolves it locally.

## 1. Source inventory

1. Copy `REPOSITORY_INVENTORY_TEMPLATE.csv`.
2. Record source platform, URL, default branch, branch/tag/commit counts, repository size, LFS, submodules, symlinks, shallow status, and ownership.
3. For a Monorepo, copy `MONOREPO_MAPPING_TEMPLATE.csv`; list every target `source_subdir`, module, and mount path.
4. Reject overlapping subdirectories (`Games` with `Games/Chess`) and duplicate mount paths.

Recommended source commands:

```sh
git ls-remote --symref <source-url>
git clone --mirror <source-url> inventory.git
git -C inventory.git rev-list --all --count
git -C inventory.git for-each-ref refs/heads refs/tags
git -C inventory.git rev-parse --is-shallow-repository
git -C inventory.git lfs ls-files --all
git -C inventory.git ls-tree -r -z --full-tree <default-branch>
```

Only advertised/accessible refs can migrate. Record hidden advertised refs separately; do not claim unadvertised server internals.

## 2. Credentials and access preflight

- HTTPS Token: source URL **must** be `https://`; set a short-lived least-privilege token in the client environment named by `token_env`.
- SSH: key and `known_hosts` files must reside under Manager `[import].allowed_ssh_dirs`.
- Local/file URL: source must resolve under `[import].allowed_local_dirs` after symlink resolution.
- Confirm no userinfo, query string, or fragment appears in `source_url`.

## 3. Pin a coherent source ref snapshot

The importer executes:

1. `git ls-remote --symref` (pre-fetch ref snapshot).
2. Bare mirror fetch of all standard branches and tags.
3. Comparison of mirror branch/tag heads against the pre-fetch snapshot.

If any branch or tag moves between steps 1 and 3, import fails with `ErrSourceMovedDuringFetch`. Do not override it. Ask source owners for a quiet window or provide `expected_default_branch`, `expected_branches`, and `expected_tags` from an approved inventory snapshot.

On resumed jobs, `pinned_refs_json` freezes the prior coherent mirror. Later upstream commits are not mixed into that job. Start a new job after completing or abandoning the prior one to import later commits.

## 4. Dry-run

```sh
lore-mono import --manifest configs/import-real.toml --dry-run --json > dry-run.json
```

Review:

- detected platform and default branch;
- standard branches/tags and advertised hidden refs;
- full DAG traversal and any shallow/missing parents;
- module/mount conflicts and four-state status (`ordinary`, `complete`, `partial`, `uncertain`);
- Monorepo `unmapped_paths`, `classified_excluded`, `classified_separate_module`, and `undecided_paths`;
- LFS OID/size availability and submodule registration policy.

Dry-run must be `succeeded`/`planned`, `verification.passed=true`, and have zero undecided paths in strict mode. It uses an isolated disposable mirror but creates no module or Lore revision. Its report is explicitly `preflight_only=true` and `full_content_migrated=false`; only formal import can assert that content was migrated.

## 5. Path ownership review

Every source path must fall into exactly one category:

1. mapped to one module by `source_subdir`;
2. `path_rules.category = "excluded"` with a documented reason;
3. `path_rules.category = "separate_module"` and a corresponding module in the same reviewed manifest;
4. undecided — **migration blocker**.

Do not copy root README, `.github`, CI, shared config, or global docs into every module.

## 6. Special object review

### Git LFS

- `lfs_mode = "hydrate"` is the normal acceptance mode. Missing object, size mismatch, or SHA-256 mismatch fails import.
- `lfs_mode = "pointer"` is explicitly incomplete content migration: verification reports `full_content_migrated=false` and `lfs_hydration_status=pointer_only_unhydrated`. It requires written owner acceptance and cannot satisfy a “full file migration” checkbox.

### Submodules

- Parent module stores the gitlink path/SHA and `.gitmodules` metadata. It never copies child files into the parent.
- `submodule_policy = "require_registered"` blocks acceptance until every dependency is represented by an independently registered/imported module.
- `record_gitlink` records dependencies as `unmigrated_independent_repo` without pretending they were migrated.

## 7. Backup before mutation

Follow `BACKUP_AND_ROLLBACK_RUNBOOK.md`. Stop/quiesce Manager and Lore writes, create the bundle with `manager-ops backup`, run `manager-ops verify`, restore into an isolated directory, and run an audit. Record SHA256SUMS and backup location.

## 8. Formal import

```sh
lore-mono import --manifest configs/import-real.toml --json > import-result.json
lore-mono import jobs --project <project> --job <job-id> --json
```

- Use an explicit stable `job_key`.
- If interrupted, rerun the identical manifest and job key. Do not manually edit checkpoint JSON.
- Do not start a second job targeting the same module or mirror.

## 9. Three-layer integrity verification

Require every item:

- `status = "succeeded"`;
- `verification.passed = true`;
- no shallow/missing parents;
- source/projected/indexed/mapped counts match;
- aliases cover every raw source commit;
- exact ordered parent identities (including Octopus parents);
- branch/tag/default branch mappings match;
- special objects match;
- strict path coverage complete;
- `head_git_digest == head_lore_digest`;
- `full_content_migrated = true` for full migration acceptance.

Run:

```sh
manager-ops audit --db <restored-or-live-db> --lore <lore-bin> --auth-path <publisher-auth-dir>
```

## 10. Permissions and collaboration

Apply the reviewed `USER_PERMISSION_MATRIX_TEMPLATE.csv`.

- Ordinary users receive only explicit module grants.
- `project_admin` does not automatically receive module or parent repository access.
- Publisher service credentials stay server-side.
- Lore 0.10.1 `read` is a Manager label; the resulting Lore access token can push.
- Access token TTL is five minutes; revocation is effective for new tokens, not immediately for already-issued tokens.

Run single and batch clone/status/sync/commit/push. Batch commit must produce one independent Lore commit process per module.

## 11. Snapshot acceptance

1. Capture and publish a snapshot using the publisher service identity.
   The API and CLI accept no parent/module filesystem paths; the Manager always prepares project-scoped server workspaces.
2. Clone the parent as publisher.
3. Compare every Link Pin with captured module revisions.
4. Clone each pinned historical module revision and verify content.
5. Restart Manager and verify snapshot history and module history remain queryable.

Module commits must never be merged into parent history. Parent commits only update links.

## 12. Final decision

Use `IMPORT_ACCEPTANCE_CHECKLIST.md`. Any P0 or P1 failure blocks migration acceptance. Pointer-only LFS, unresolved submodules under `require_registered`, undecided paths, ref drift, or incomplete DAGs block “complete migration” status.
