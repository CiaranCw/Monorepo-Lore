# Lore Git Import Recovery — 2026-11-12

## Scope and safety boundary

This change fixes remote publication and interrupted merge replay without
changing the authentication, permission, project, parent-link, or aggregate
history models. It adds no database table or column. Existing
`import_job_items.checkpoint_json` rows remain readable.

The production Kubee Store, SQLite database, Job 3, ten failed repositories,
42 original repositories, 814 original revisions, and Snapshot pins were not
modified by development or testing.

## Root cause

### Remote publication failures

Observed facts:

- A clean Lore 0.10.1 `branch push` uploads a linear history.
- A clean `push` does the same for the current branch.
- `branch push` also succeeds for a new branch, branches sharing ancestors,
  and a two-parent merge. A fresh clone can read the published history.
- Killing a client during a long push can leave a remote branch at a durable
  prefix. A clean synthetic repository resumed successfully.
- A copy of the real `Ball` local repository and server Store reproduced the
  production failure exactly. The immediate next revision failed with exit 80:

  ```text
  Address not found:
  1c528a8b...-01a1ce98...
  pushing branch to remote, missing fragment
  ```

- `repository store immutable query` proved that fragment had a local payload
  but was absent remotely. `repository verify fragment --remote --heal` did not
  upload it. `--force` did not change the result.

Conclusion: `branch push` is not merely a ref-update command and was not the
wrong API. The failed workspaces contain locally present immutable fragments
that Lore 0.10.1 no longer attempts to transfer, while the remote branch
references a partial durable prefix. A later ref update therefore fails at the
first missing fragment. A single long push made this failure window large, and
the importer incorrectly treated remote HEAD equality as sufficient evidence
of completeness.

### NightWardenProject merge failure

The copied production workspace showed an open merge on `_import_lane_16`:

- HEAD `84a65898aa45…`
- merged parent `c15ae870ed1c…`
- staged revision `9bfebfef7553…`
- 659 staged paths
- unresolved `.gitignore`

The source Git merge commit is `6838c624cb08…`. Its committed `.gitignore`
tree intentionally contains conflict-marker text. The working file exactly
matched the Git blob. Lore correctly refused to commit while the path remained
in conflict. A retry did not recognize the already-open merge and called
`merge start` again.

The recovery must explicitly clear Lore's conflict state, commit a synthetic
two-parent bridge, restore the exact source tree (including intentional marker
text), then create the real mapped Lore revision. This preserves the Git tree
and exact logical parent list without inventing a second Git commit.

## Implementation

Changed files:

- `internal/gitimport/importer.go`: backward-compatible checkpoint fields and
  operation-level fault hook.
- `internal/gitimport/replay.go`: merge resume, conflict-marker bridge,
  incremental remote publication, remote DAG/clone verification.
- `internal/gitimport/verify.go`: physical-parent verification through the
  conflict-marker merge bridge.
- `internal/loreadapter/decode.go`: staged and merged revision status fields.
- `internal/loreadapter/history_ops.go`: remote revision inspection, unresolved
  conflict listing, and forced conflict-state resolution.
- `internal/gitimport/importer_test.go`,
  `internal/loreadapter/adapter_test.go`: recovery regressions.
- `internal/manager/import_push_live_test.go`: opt-in real Lore 0.10.1 lab.
- `internal/project/project.go`, `internal/loreadapter/validate.go`: retain the
  previously requested leading-digit name support and tests.

### Checkpoint

`itemCheckpoint` now stores:

- `pending`: source commit, lane, parent step, expected parents/tree, operation
  kind, phase, and committed Lore revision.
- `synthetic_bridges`: source/step to physical helper revision.
- `published_revisions`: last verified remote revision per branch.

These are optional JSON fields. No migration is required.

Physical Lore metadata remains authoritative. Startup reconciliation rebuilds
`git.commit` mappings and synthetic bridge mappings. If a Lore commit exists
but SQLite/checkpoint persistence was interrupted, resume indexes it instead of
committing again.

### Merge replay

Before starting a merge, replay verifies:

- current lane;
- current HEAD equals Parent 1;
- merge source equals Parent 2;
- no unrelated staged merge exists.

If the matching merge is already open, replay continues it. Conflicts are
enumerated from Lore status and cleared with forced `merge resolve mine`; the
exact Git tree is then reapplied. Source trees that intentionally contain
conflict markers use a synthetic merge bridge followed by the mapped commit.

Every merge-start and commit boundary is checkpointed. Test hooks cover
interruption before/after merge start and after Lore commit but before SQLite.

### Remote publication

Branches are published in short first-parent increments. After each increment:

1. remote HEAD must equal the intended revision;
2. the revision must be readable remotely;
3. its physical parent list must equal the local Lore DAG;
4. checkpoint progress is persisted.

After all branches, each branch tip is cloned by revision into a disposable
bare worktree. This catches missing immutable fragments that a HEAD-only check
cannot detect. The default branch is restored locally afterwards.

No force push is used. A remote head that is not a first-parent ancestor of the
local target is treated as divergence and stops recovery.

## Tests

### Automated

- linear history and ordinary checkpoint resume;
- shared-ancestor branches;
- two-parent merge;
- consecutive/multi-lane merges through the complex fixture;
- octopus merge and synthetic bridge;
- interruption after merge start;
- interruption after Lore commit before SQLite;
- duplicate-revision prevention after retry;
- committed conflict-marker merge;
- leading-digit project/module/Lore names;
- cross-module projection, no shared revision IDs, module-local parents, and
  permission-filtered aggregate history through the existing full suite.

Windows Go 1.20.4: `go test -count=1 ./...`, `go vet ./...`, and
`go build ./...` all PASS.

Linux Go 1.20.4 in the isolated lab: the same three commands all PASS.

### Real Lore 0.10.1 isolation

An isolated loopback Manager/AuthBridge/Lore Store on 537xx verified:

- `push` and `branch push` clean behavior;
- shared ancestors and merge publication;
- interrupted client publication;
- fixed importer publication;
- per-branch remote DAG verification;
- clone-by-revision after publication;
- idempotent job rerun.

Status: PASS.

A copy of the real NightWarden workspace, mirror, and SQLite database resumed
from 132 indexed commits to:

```text
status=succeeded
passed=true
source=298
indexed=298
merges=58
synthetic=1
mismatches=0
```

Running the copied recovery a second time returned the same 298/298 result and
created no duplicate revision. Status: PASS.

## Production recovery plan

Before any production action:

1. make a new cold backup of Store, SQLite, workspaces, keys, and configuration;
2. verify SQLite integrity and retain the current Job 3/checkpoints;
3. deploy only after review and rerun the real isolation suite;
4. recover one module at a time; stop on the first mismatch;
5. verify source count, indexed count, parent order, branches/tags, LFS,
   Git/Lore digest, remote clone, and permission filtering.

`NightWardenProject` can resume directly from its existing checkpoint and open
merge after the reviewed fix is deployed. The copied recovery proves no reset,
repository recreation, or duplicate revision is needed.

The nine push failures require special care. The fixed publisher prevents this
failure for clean/future imports, but the existing workspaces already contain
local/remote fragment-state disagreement. Lore 0.10.1 exposes no successful
CLI repair for uploading those missing fragment addresses. Do not rerun,
recreate, force-push, or edit SQLite. Recovery requires a separately reviewed
fragment-transfer procedure or Lore provider support, followed by the normal
checkpoint resume. Until that procedure exists, those nine modules remain
manual-review items.

## Risk

- Original 42 modules and 814 revisions: unchanged.
- Database schema: unchanged.
- Existing checkpoint compatibility: preserved.
- Authentication and permissions: unchanged.
- Parent Snapshot and pins: unchanged.
- Production deployment/recovery: not run.
