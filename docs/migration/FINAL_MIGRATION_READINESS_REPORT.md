# B2.8 Final Migration Readiness Report

## Executive decision

**Readiness status: READY FOR FIRST REAL-REPOSITORY DRY-RUN, CONDITIONALLY READY FOR FORMAL IMPORT.**

The importer, per-module Git Monorepo projection, history index, permissions, Snapshot Publisher, credentials boundary, source-ref consistency checks, persistent alias mapping, LFS/submodule honesty, backup/restore tooling, and rollback isolation have been audited in code and exercised with synthetic repositories and real Lore 0.10.1.

Formal import is allowed only after the repository-specific inventory, strict path classification, LFS/submodule decision, pinned source ref snapshot, verified backup, and isolated restore drill pass. No real business repository or production Store was accessed in B2.8.

## Baseline and change safety

Checked local and remote refs before work:

- `main`: `46e31c09ef00efffa2cf9a45e1b9471e63900a68`
- `v0.1.0-b2.6.6`: same SHA
- PR #1 branch `chore/repository-hygiene`: `bb564105100c8ffb28ced48d8687ea6bb8072357`
- `feat/history-and-git-import`: `ac32d268406d2fd2ff5a6997bd9b9c2ce6a6efd9`
- `fix/history-import-hardening`: `649bf8c9dafd192ea1782f4d6d78b0980af5b803`
- PR #1 and PR #2 remain unmerged.

B2.8 is implemented on `feat/b28-migration-readiness`; no existing commit, tag, or branch history was rewritten.

## Direct architecture/code audit

### P0 module commit isolation

Verified in `internal/gitimport/projection.go`, `replay.go`, `verify.go`, migrations, and tests:

- each physical Lore revision is indexed under one `module_id`;
- the verifier rejects cross-module revision collisions;
- every parent edge must resolve to a commit in the same module;
- one source commit changing N mapped subdirectories produces N distinct Lore revisions;
- unchanged module projections create aliases, not commits;
- cross-module moves project to a source-module delete and destination-module add;
- batch commit runs one Lore process per module/repository;
- Snapshot Publisher only commits parent link updates and never combines module file changes.

### Persistent folded aliases (P0 finding fixed)

B2.7.1 kept `ProjectedGraph.EffectiveCommitOf` in memory/checkpoint JSON. This was sufficient for one running job but was not a durable, queryable module-level alias index after Manager restart.

Migration `0005_migration_readiness.sql` adds `module_commit_aliases`:

- key: `(module_id, source_commit_id)`;
- status: `direct`, `unchanged_alias`, `pre_module_empty`;
- effective source commit;
- effective module-local Lore revision;
- source subdirectory.

Aliases are transactionally rewritten with authoritative refs at import completion and are verified against every raw source commit. `history.Service.GetCommit` and `/aliases/{source_sha}` resolve aliases after Manager restart. Branch/tag records retain both projected target and `original_source_commit_id`.

### History completeness

Three layers are checked for every projected commit:

1. Bare Git Mirror: raw commit SHA/tree/parents and branch/tag refs.
2. Physical Lore repository: revision metadata, parent topology/Octopus bridge chain, branches, deltas, content.
3. SQLite: commit metadata, ordered parent rows, aliases, refs, special objects.

Verification covers all commits, not only HEAD:

- original and Lore IDs;
- exact ordered parent identities;
- full author/committer names/emails/timestamps;
- complete multiline message;
- tree SHA;
- lightweight/annotated tags;
- default and non-default branches;
- LFS, submodule, and symlink records;
- per-revision path isolation;
- HEAD content digest.

Shallow or missing-parent source history fails before module mutation.

### Source ref coherence (P1 finding fixed)

The importer now:

1. records a pre-fetch `ls-remote --symref` snapshot;
2. fetches the mirror;
3. compares every branch/tag head with that snapshot;
4. stores the coherent snapshot in `import_job_items.pinned_refs_json`.

Ref movement during fetch fails with `ErrSourceMovedDuringFetch`. Resume reuses the pinned local mirror; it does not mix later upstream commits into the job. Optional expected branch/tag hashes in the manifest provide operator-approved preconditions.

### LFS and submodules

LFS:

- `hydrate`: default; missing object, wrong size, or wrong SHA-256 OID fails import.
- `pointer`: explicit incomplete-content policy; reports `full_content_migrated=false` and `pointer_only_unhydrated`.

Submodules:

- parent stores gitlink path/commit and `.gitmodules` URL/branch metadata;
- child files never enter parent module;
- `require_registered` blocks acceptance until an independent project module exists;
- `record_gitlink` records `unmigrated_independent_repo` without claiming migration.

### Global/unmapped path classification (P1 finding fixed)

Strict Monorepo import now requires every path outside mapped `source_subdir` prefixes to match a reviewed `path_rules` decision:

- `excluded` with reason;
- `separate_module` with target module present in the reviewed manifest;
- otherwise `undecided` and import fails before module creation.

### Permissions and repository isolation

Reviewed API dispatch and permission service:

- project/module/search/repository lookup/history/commit detail/ref/alias/batch operations are server-filtered;
- unauthorized/unknown module probes return uniform not-found;
- project aggregated history recomputes accessible modules on every cursor page;
- import jobs are `project_admin` only;
- ordinary members cannot create modules;
- project admin receives no automatic module or parent Lore resource;
- service identities receive not-found on human API;
- Snapshot history filters pins by module grant;
- user-status API cannot target service accounts, requires target membership, and refuses a global status change unless the actor administers every project the target belongs to.
- publish callers cannot submit parent/module filesystem paths; only Manager-prepared project-scoped workspaces execute with the publisher service credential.

Known limitation retained: Lore 0.10.1 read labels map to actual repository access and can push. Access tokens last five minutes; already-issued tokens are not instantly revoked.

### Snapshot and service reliability

Real Lore tests revalidated:

- historical pin clone before/after Lore restart;
- module HEAD movement after capture;
- archive during publish;
- per-project publish serialization;
- F1–F6 process-exit recovery;
- F5 push-success/SQLite-running recovery without duplicate push;
- Manager outage/restart;
- permission revocation with no new token exchange.

## B2.8 P0/P1 fixes

| Severity | Finding | Resolution |
|---|---|---|
| P0 | Folded per-module aliases were not durable/queryable after restart | Schema v5 `module_commit_aliases`, alias APIs, ref original target provenance, full alias verification |
| P1 | No coherent source branch/tag snapshot across `ls-remote` and fetch | Pre/post snapshot comparison plus persisted pinned refs and resume freeze |
| P1 | LFS pointer fallback could be interpreted as complete migration | Strict `hydrate` mode with SHA/size verification; explicit incomplete pointer mode flags |
| P1 | Global files were reported but not forced through a complete ownership decision | Strict path rules and undecided-path import blocker |
| P1 | Submodule dependency state was recorded but acceptance policy was not explicit | `record_gitlink` vs `require_registered`, dependency report, no child-file materialization |
| P1 | Operational backup/restore and module isolation rollback were documentation-only | `manager-ops` executable backup/verify/restore/audit/quarantine; non-mutating schema inspection plus missing-source, traversal, tamper, restore, transaction-rollback, and sibling-isolation tests |
| P1 | Project admin user-status endpoint could target unrelated/service users or globally disable a user in another administrator's project | uniform not-found, human-kind/target-membership checks, and all-memberships administration guard |
| P0 | Publish API accepted caller-supplied server paths while using the global publisher credential | removed path fields from API/CLI; Manager always creates project-ID-scoped server workspaces and request-scopes the Lore driver parent URL |
| P1 | Lore history sync replaced a folded imported branch's raw source-tip provenance | sync reloads and preserves `original_source_commit_id`; regression covers publish/history-sync paths |
| P1 | A pinned retry could reuse a partial LFS mirror without retrying fetch; mixed pointer/hydrate siblings raced on first mode | pinned resume always refreshes LFS, all referenced objects remain OID/size gates, and a shared source uses hydrate when any mapped module requires it |
| P1 | Dry-run reported verification success after `ls-remote` only | isolated disposable mirror now performs ref pinning, full DAG/shallow checks, module projection, global-path classification, LFS verification, and submodule policy checks; result is explicitly preflight-only |
| P1 | Parallel sibling-module registration could surface SQLite `BUSY` and partially fail an otherwise valid batch | project registration is serialized and retries transient writer contention; mixed-mode shared-Mirror stress regression runs repeatedly |
| P2 | Recovery accepted extra parent links and active modules with no revision were omitted | recovery requires exact pin equality; an active module without a capturable revision blocks publication |
| P2 | Lore has no native Tag entity | Manager compatibility Tag index; historical Lore target remains cloneable |
| P2 | Lore has two physical parent slots | hidden synthetic bridges plus exact ordered N-parent Manager DAG |

## Test evidence

### Windows

Environment:

- Go 1.20.4
- Lore 0.10.1
- Git 2.45.2

Results:

- `go test -mod=readonly -count=1 ./...`: **PASS**
- `go vet -mod=readonly ./...`: **PASS**
- `go build -mod=readonly ./...`: **PASS**
- real local Lore CLI import/projection/history/LFS/backup tests: **PASS**
- full isolated Lore Server integration: **NOT_RUN** locally (no local `loreserver`)

### Linux isolated environment

- Go 1.20.4
- Lore 0.10.1
- isolated Store, SQLite, Gateway, AuthBridge, ports, keys

Results:

- `go test -mod=readonly -count=1 ./...`: **PASS**
- `go vet -mod=readonly ./...`: **PASS**
- `go build -mod=readonly ./...`: **PASS**
- `TestRealSnapshotLive`: **PASS**
- `TestRevokeWithoutNewExchange`: **PASS**
- test ports closed afterward: **PASS**

### Synthetic coverage

**PASS**:

- >200 commits and side-branch merge discovery;
- same-timestamp stable pagination;
- permission revocation between cursor pages;
- conflicting two-parent and Octopus merges;
- branch/tag/default-branch fidelity;
- Unicode/multiline metadata;
- empty commits;
- LFS hydrate/missing/corrupt/pointer semantics;
- pinned LFS retry and mixed pointer/hydrate modules sharing one mirror;
- submodule gitlinks and dependency reporting;
- Monorepo split A–I;
- alias restart persistence;
- folded branch provenance across Lore history sync/Snapshot preparation;
- source ref drift and pinned resume;
- full Dry-run preflight for shallow DAGs, unclassified paths, and missing LFS objects;
- interruption/checkpoint recovery;
- concurrent job lock;
- Snapshot Publisher path-injection, exact-pin recovery, and empty-active-module regressions;
- backup tamper detection, isolated restore, consistency audit, module-local quarantine.

**NOT_RUN by design**:

- real business repository Dry-run/import;
- formal team users;
- independent second Linux workstation.

## Risk decision

No unresolved known P0 defect remains. P1 repository-specific checks remain intentionally open until source inventory:

- source access and refs;
- LFS object availability;
- submodule migration mapping;
- global/shared path classification;
- verified backup/restore drill in the target environment.

## Final answers

1. **Can the first real business repositories be imported safely?**
   **Yes for Dry-run now. Formal import is conditional** on per-repository inventory, strict classification, LFS/submodule review, coherent pinned refs, backup verification, and isolated restore drill.

2. **What blockers remain?**
   No generic code P0 blocker. Repository-specific P1 blockers may be shallow history, unavailable LFS objects, unresolved submodules, undecided global paths, inaccessible refs, or missing target backup drill.

3. **Which capabilities have real Lore verification?**
   Snapshot capture/publish/reclone, historical pins, concurrent serialization, archive/head-change behavior, F1–F6 recovery, Manager restart, revocation boundary; local/import replay uses real Lore 0.10.1 CLI on both Windows and Linux.

4. **Which capabilities only have automated synthetic support?**
   Real hosted business source behavior, source-host rate limits, real enterprise LFS endpoints, and repository-specific path/submodule classification.

5. **What repository information is needed next?**
   Completed repository inventory CSV, source URLs/platforms, default branch, branch/tag/commit counts, LFS/submodule/symlink details, sizes, shallow status, Monorepo subdirectory mapping, root/global file classification, expected ref hashes, owners, and credential method.

6. **What user/permission information is needed?**
   Users, account status, project membership/role, per-module read/write labels, publisher/import service identities, revocation test participants, and expected batch-visible module sets.

7. **How should the first round run after receiving repositories?**
   Inventory → source-access/ref snapshot → backup + restore drill → strict manifest/path review → Dry-run → owner review → formal import of a low-risk pilot module → three-layer verification → permissions → multi-user clone/history/push/sync → snapshot publish/reclone → acceptance checklist.
