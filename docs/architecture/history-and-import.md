# Commit History & External Git Import

Monorepo-Lore keeps three distinct history concepts strictly separate:

1. **Module commit history (`module_commits`, `module_commit_parents`, `module_refs`, `module_special_objects`)**: Every real commit inside each child module repository, whether imported from an external Git repository or committed natively in Lore afterwards.
2. **Monorepo aggregated history (`GET /api/v1/projects/{ref}/history`)**: A permission-filtered, chronological union across the caller's currently authorized modules in a project. It never fabricates a cross-repository Git commit chain.
3. **Parent snapshot history (`snapshots`)**: Published immutable module-pin manifests on the parent repository. Snapshot publishing never rewrites or truncates child module commit history.

## Lore 0.10.1 Native Model vs. Git Commit DAG

| Capability | Lore 0.10.1 Native Storage | Monorepo-Lore Compatibility & Index Layer |
|---|---|---|
| Commit / Revision ID | 64-hex Lore signature | Bidirectional 1-to-1 mapping (`source_commit_id` <-> `lore_revision`) stamped in Lore revision metadata (`git.commit`) and indexed in `module_commits` |
| Commit DAG Parents | Fixed 2-parent array `[parent_self, parent_other]` | 1-parent and 2-parent merges stored natively in Lore; >=3-parent Octopus merges bridged via `git.synthetic=1` Lore merges while `module_commit_parents` preserves the exact ordered N-parent DAG |
| Multiple Root (Orphan) Commits | Non-`main` branches require an existing anchor revision |Anchored in Lore with explicit `lore.orphan_anchor` metadata while `git.parents=""` and `module_commit_parents` preserve 0-parent root topology |
| Author vs. Committer Timestamps | `prepare_commit_metadata` stamps `timestamp` with `now()` and `committed-by` with current Lore user | Original author & committer names, emails, ISO-8601 timestamps, and millisecond epochs preserved in `git.author.*` / `git.committer.*` revision metadata and `module_commits` |
| Branches | Native branches (including slash names like `feature/ui`) | Created as real Lore branches at exact mapped revisions and indexed in `module_refs` |
| Lightweight & Annotated Tags | No native `lore tag` entity in Lore 0.10.1 | Indexed losslessly in `module_refs` (`ref_type='tag'`), preserving tag object SHA, tagger, timestamp, and annotation message |
| Empty Commits | Rejected unless `-f` is passed | Committed with `-f` after metadata staging so every Git commit maps 1-to-1 to a real Lore revision |
| Git LFS / Submodules / Symlinks | Regular file store | LFS hydrated when available (or pointer tracked as `lfs_pointer`), submodule `160000` gitlinks + `.gitmodules` recorded as `submodule_gitlink`, symlinks recorded as `symlink` in `module_special_objects` |

## Deterministic Ordering & Live-Permission Cursor Pagination

All module and project-aggregated timeline queries order commits by:

```text
(committed_unix_ms DESC/ASC, authored_unix_ms DESC/ASC, module_id ASC, lore_revision ASC)
```

Keyset cursors encode `(committed_unix_ms, authored_unix_ms, module_id, lore_revision, order)`. They never encode an authorized module list. Every page request re-evaluates `permission.Service` against SQLite so revoking a module grant immediately excludes that module from subsequent cursor pages.

## External Git Batch Import

### Supported Platforms & Authentication

- **Platforms**: `github`, `gitee`, `gitlab`, `gongfeng` (`git.woa.com` / `*.code.tencent.com`), `generic_git`, and `local_git`.
- **Authentication**:
  - `https_token`: Reads token from `token_env` (resolved in-memory by `lore-mono` or Manager) and passes `http.<origin>.extraheader = Authorization: Basic ...` via `GIT_CONFIG_COUNT` in the `git` child process environment. Tokens are rejected on CLI argv and rejected inside `source_url`.
  - `ssh_key`: Passes `GIT_SSH_COMMAND` with `IdentitiesOnly=yes` and optional `known_hosts` to the `git` child process.
  - `git_credential_helper` / `none`.

### Engineering Guarantees

- **Dry-run (`--dry-run`)**: Runs `git ls-remote --symref`, checks module/mount conflicts, reports advertised branches, tags, and platform-hidden refs (`refs/pull/*`, `refs/merge-requests/*`), and makes zero Lore or module mutations.
- **Idempotency & Checkpointing**: Every replayed Git commit checkpoints `commit_map` in `import_job_items`. Re-running an interrupted job resumes from the exact next commit without duplicating Lore revisions or modules.
- **Failure Isolation**: Each repository in a batch manifest runs independently; one failing repository marks the job `partial_failed` without rolling back sibling modules.
- **Post-Import Verification**: Compares non-synthetic commit count, 1-to-1 SHA mappings, merge/octopus parent counts, branch/tag counts, and the byte-for-byte SHA-256 content digest of the HEAD working tree.

## HTTP API Reference

- `GET /api/v1/projects/{project}/history` — Permission-filtered monorepo aggregated commit timeline (`module`, `author`, `q`, `since`, `until`, `merges_only`, `no_merges`, `order`, `limit`, `cursor`, `sync`).
- `GET /api/v1/modules/{id}/history` — Complete single-module commit history (`branch`, `tag`, `from_revision`, `first_parent`, plus all timeline filters).
- `POST /api/v1/modules/{id}/history/sync` — Crawl all Lore branches & merge parents into SQLite without truncation.
- `GET /api/v1/modules/{id}/commits/{sha_or_rev}` — Full commit detail by original Git SHA or 64-hex Lore revision.
- `GET /api/v1/modules/{id}/refs?type=branch|tag` — Module branches and tags (including annotated tag metadata).
- `POST /api/v1/projects/{project}/imports` — Execute single/batch dry-run or live Git import (`project_admin` only).
- `GET /api/v1/projects/{project}/imports` & `GET /api/v1/projects/{project}/imports/{job_id}` — Inspect import job status and verification reports.

## CLI Reference

```sh
# Aggregated monorepo history across all modules authorized for the current user
lore-mono history --all [--project Alpha] [--author name] [--search text] [--limit 50] [--cursor tok] [--all-pages]

# Single-module full DAG history (all branches/tags, or reachable from a specific branch/tag)
lore-mono history Engine [--branch feature/ui] [--first-parent] [--all-pages]

# Inspect branches, tags, and individual commit mappings
lore-mono refs Engine [--type branch|tag]
lore-mono show Engine <git-sha-or-lore-revision>

# Single or batch external Git import (dry-run first, then live import)
lore-mono import --manifest configs/import.example.toml --dry-run
lore-mono import --manifest configs/import.example.toml
lore-mono import --source https://github.com/org/engine.git --module Engine --token-env GITHUB_TOKEN --dry-run
```
