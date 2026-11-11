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
  - `https_token`: Requires `https://` (`http://` plaintext is strictly rejected). `token_env` is resolved **exclusively on the client (`lore-mono`)** and sent in-memory via `runtime_tokens`; the Manager server never reads `os.Getenv(token_env)`. Inside `git` child processes, the token is injected via `GIT_CONFIG_COUNT=1` + `http.<origin>.extraheader = Authorization: Basic ...` in a sanitized environment. Tokens, query parameters (`?...`), and URL fragments (`#...`) are strictly rejected inside `source_url` and on CLI argv.
  - `ssh_key`: Key and `known_hosts` paths are passed in dedicated environment variables (`LORE_GIT_SSH_KEY`, `LORE_GIT_SSH_KH`) referenced by a static `GIT_SSH_COMMAND` string (preventing shell metacharacter command injection) and validated against `import.allowed_ssh_dirs` after symlink resolution.
  - `local_git`: Local repository paths and `file://` URLs are restricted to administrator-configured `import.allowed_local_dirs` after `EvalSymlinks` resolution.
  - `git_credential_helper` / `none`.

### Per-Module Subdirectory Projection (`source_subdir`)

- A single external Git Monorepo (e.g. `TeamGames/Games` containing `Chess/`, `Mahjong/`, `Poker/`) can be split into multiple independent Lore modules in one manifest using `source_subdir`.
- All modules sharing the same `source_url` reuse one Bare Git Mirror under mutex protection while projecting an independent per-module commit DAG:
  - Commits touching $N$ module subdirectories produce $N$ distinct Lore revisions in their respective module repositories, each containing strictly that module's stripped relative paths and module-local parent pointers.
  - Commits not modifying a module's subdirectory are folded without creating empty revisions. Every raw source commit receives a persistent `(module_id, source_commit_id)` row in `module_commit_aliases` with `direct`, `unchanged_alias`, or `pre_module_empty` status, effective module commit, and module-local Lore revision. This survives Manager restart and resolves branch/tag heads and history queries correctly.
  - Unmapped global files outside declared subdirectories (e.g. root `README.md`, `.github/`) are excluded from child modules and reported in `unmapped_paths`. Under `global_files_policy="strict"`, every such path must match a documented `path_rules` decision (`excluded` or `separate_module`); undecided paths block import before module creation.

### Engineering Guarantees

- **Dry-run (`--dry-run`)**: Runs `git ls-remote --symref`, validates optional `expected_default_branch` / `expected_branches` / `expected_tags`, classifies existing module collisions (`ordinary`, `complete`, `partial`, `uncertain`), reports advertised branches, tags, and platform-hidden refs (`refs/pull/*`, `refs/merge-requests/*`), and makes zero Lore or module mutations.
- **4-State `skip_if_imported` & Concurrency Locks**: Only verified `complete` imports matching `(source_url, source_subdir)` are skipped; `ordinary` pre-existing modules and `uncertain` states conflict; `partial` interrupted imports automatically resume. Concurrent submissions of the same `job_key` or same target module are serialized/rejected cleanly, and Manager startup recovers interrupted `running` jobs.
- **Coherent source ref snapshot**: Captures `ls-remote` before fetch and compares the fetched mirror against that exact branch/tag set. Ref movement fails the job. Resume reuses `pinned_refs_json` from the coherent local mirror instead of silently mixing later upstream commits.
- **Strict LFS honesty**: `lfs_mode="hydrate"` requires and cryptographically verifies each object’s SHA-256 OID and size; missing/corrupt objects fail import. Explicit `pointer` mode reports `full_content_migrated=false` and `pointer_only_unhydrated`.
- **Submodule honesty**: Parent modules preserve gitlink path/SHA and `.gitmodules` metadata only. `require_registered` blocks acceptance until each dependency is an independent project module; `record_gitlink` reports it as `unmigrated_independent_repo`.
- **3-Layer Post-Import Verification**: Rejects shallow/missing-parent graphs and verifies bijection across the Bare Git Mirror, physical Lore revisions/branches/deltas, and SQLite (`module_commits`, persistent `module_commit_aliases`, exact ordered `module_commit_parents` for 2-parent & Octopus merges, `module_refs` including original folded branch/tag targets and non-`main` defaults, `module_special_objects`, per-revision content isolation, and HEAD SHA-256 tree digest).

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
