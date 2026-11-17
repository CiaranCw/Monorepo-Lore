# Per-Import Acceptance Checklist

Record PASS / FAIL / NOT_RUN / UNKNOWN and attach evidence for every line. **Do not mark the migration accepted with any P0 or P1 FAIL/UNKNOWN.**

## Source snapshot and inventory

- [ ] Source owner and migration/change ticket recorded.
- [ ] Source platform, URL, default branch, branch/tag/commit counts recorded.
- [ ] `git rev-parse --is-shallow-repository` is `false`.
- [ ] All expected branch/tag heads are pinned in the reviewed manifest or Dry-run evidence.
- [ ] Import did not report `ErrSourceMovedDuringFetch` or `ErrSourceMovedDuringResume`.
- [ ] Hidden advertised refs reviewed; unavailable/unadvertised refs not claimed migrated.
- [ ] Dry-run used an isolated mirror and reports `preflight_only=true`; it was not treated as completed migration.

## Mapping and content ownership

- [ ] Target project/module/mount names approved.
- [ ] No overlapping `source_subdir` mappings.
- [ ] Every source path classified as mapped, excluded-with-reason, separate-module, or blocking undecided.
- [ ] `coverage_complete=true`; `undecided_paths=[]`.
- [ ] No root/global file leaked into an unrelated module.
- [ ] Same source commit modifying N modules produced N independent Lore revisions.
- [ ] Module parent edges reference only the same module.
- [ ] Folded commit aliases persisted for every raw source commit and resolve after Manager restart.

## DAG and metadata

- [ ] `verification.passed=true`.
- [ ] Raw/projected/indexed/mapped counts match expected values.
- [ ] Every Git SHA maps to the expected module-local Lore revision or explicit alias.
- [ ] Every Lore revision can be queried by Lore revision ID and direct Git SHA.
- [ ] Parent count, identity, and order match every source commit.
- [ ] Merge and Octopus parent order verified.
- [ ] Default branch preserved (including `master` or custom default).
- [ ] All expected branches and tags match target SHA/revision; annotated tagger/message preserved.
- [ ] Author, committer, emails, authored time, committed time, full multiline message, and Git tree SHA preserved.
- [ ] HEAD Git/Lore content SHA-256 digests match.

## LFS, submodules, symlinks

- [ ] Hydrate mode: every LFS binary exists and SHA-256 OID + size verify.
- [ ] `full_content_migrated=true` for full migration acceptance.
- [ ] Pointer mode, if explicitly accepted: `lfs_hydration_status=pointer_only_unhydrated` and incomplete-content waiver attached.
- [ ] Every submodule gitlink path, commit SHA, URL/branch metadata recorded.
- [ ] `require_registered`: every submodule dependency is an independent project module.
- [ ] No submodule child files leaked into parent module.
- [ ] Symlink metadata verified on target platform.

## Security and permissions

- [ ] No token/private key appears in URL, manifest, argv, SQLite, logs, or report.
- [ ] Local source and SSH files are within approved allowlists after symlink resolution.
- [ ] Ordinary users see only explicit module grants.
- [ ] Repository ID/name/URL/history/ref/search/batch probes return uniform not-found for unauthorized modules.
- [ ] Old history cursor rechecks permissions after revocation.
- [ ] `project_admin` has no automatic parent/module Lore access.
- [ ] Service account cannot use human HTTP API.
- [ ] Lore `read` limitation recorded: access token can push.
- [ ] Five-minute old-token revocation boundary recorded.

## Operations, backup, and collaboration

- [ ] Verified pre-migration backup created with SHA256SUMS.
- [ ] Isolated restore drill PASS.
- [ ] `manager-ops audit` PASS on restored and target environments.
- [ ] Single and batch clone/status/sync PASS.
- [ ] Batch commit generated independent commits per module.
- [ ] Concurrent same-module conflict resolved through Lore sync/merge without data loss.
- [ ] Snapshot publish PASS; parent links equal captured pins.
- [ ] Historical pinned revisions clone successfully after Manager/Lore restart.
- [ ] Import workspace, Store, SQLite, Gateway, Manager, and Lore ports cleaned up or transferred to operations.

## Decision

- [ ] ACCEPTED — all mandatory checks PASS.
- [ ] CONDITIONALLY ACCEPTED — only documented P2 items remain.
- [ ] REJECTED — P0/P1 failure or incomplete/unknown evidence remains.
