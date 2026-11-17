-- Schema v3: complete module commit history, multi-parent DAG, branches/tags,
-- special Git objects (LFS / submodule / symlink), and external Git batch import jobs.
-- Forward-compatible with v1 and v2 databases; existing tables are untouched.

CREATE TABLE module_commits (
  commit_row_id          INTEGER PRIMARY KEY,
  module_id              INTEGER NOT NULL REFERENCES modules(module_id),
  lore_revision          TEXT NOT NULL,
  lore_revision_number   INTEGER NOT NULL DEFAULT 0,
  source_commit_id       TEXT,
  canonical_id           TEXT NOT NULL,
  origin_kind            TEXT NOT NULL CHECK (origin_kind IN ('native_lore','git_import')),
  is_synthetic           INTEGER NOT NULL DEFAULT 0 CHECK (is_synthetic IN (0,1)),
  is_merge               INTEGER NOT NULL DEFAULT 0 CHECK (is_merge IN (0,1)),
  parent_count           INTEGER NOT NULL DEFAULT 0,
  author_name            TEXT NOT NULL DEFAULT '',
  author_email           TEXT NOT NULL DEFAULT '',
  authored_at            TEXT NOT NULL,
  authored_unix_ms       INTEGER NOT NULL,
  committer_name         TEXT NOT NULL DEFAULT '',
  committer_email        TEXT NOT NULL DEFAULT '',
  committed_at           TEXT NOT NULL,
  committed_unix_ms      INTEGER NOT NULL,
  lore_committed_unix_ms INTEGER NOT NULL DEFAULT 0,
  subject                TEXT NOT NULL DEFAULT '',
  message                TEXT NOT NULL DEFAULT '',
  git_tree_id            TEXT,
  lore_branch_id         TEXT,
  extra_metadata_json    TEXT NOT NULL DEFAULT '{}',
  indexed_at             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  UNIQUE (module_id, lore_revision)
);

CREATE UNIQUE INDEX module_commits_source_idx
  ON module_commits(module_id, source_commit_id)
  WHERE source_commit_id IS NOT NULL AND is_synthetic = 0;

CREATE INDEX module_commits_timeline_idx
  ON module_commits(module_id, is_synthetic, committed_unix_ms DESC, authored_unix_ms DESC, lore_revision ASC);

CREATE INDEX module_commits_global_timeline_idx
  ON module_commits(is_synthetic, committed_unix_ms DESC, authored_unix_ms DESC, module_id ASC, lore_revision ASC);

CREATE INDEX module_commits_author_idx
  ON module_commits(module_id, author_email, author_name);

CREATE TABLE module_commit_parents (
  module_id               INTEGER NOT NULL REFERENCES modules(module_id),
  lore_revision           TEXT NOT NULL,
  parent_ord              INTEGER NOT NULL,
  parent_lore_revision    TEXT NOT NULL DEFAULT '',
  parent_source_commit_id TEXT,
  PRIMARY KEY (module_id, lore_revision, parent_ord)
);

CREATE INDEX module_commit_parents_parent_idx
  ON module_commit_parents(module_id, parent_lore_revision);

CREATE INDEX module_commit_parents_git_idx
  ON module_commit_parents(module_id, parent_source_commit_id)
  WHERE parent_source_commit_id IS NOT NULL;

CREATE TABLE module_refs (
  module_id            INTEGER NOT NULL REFERENCES modules(module_id),
  ref_type             TEXT NOT NULL CHECK (ref_type IN ('branch','tag')),
  ref_name             TEXT NOT NULL,
  lore_revision        TEXT NOT NULL,
  source_commit_id     TEXT,
  source_tag_object_id TEXT,
  lore_branch_id       TEXT,
  is_default           INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0,1)),
  is_annotated         INTEGER NOT NULL DEFAULT 0 CHECK (is_annotated IN (0,1)),
  tagger_name          TEXT NOT NULL DEFAULT '',
  tagger_email         TEXT NOT NULL DEFAULT '',
  tagged_at            TEXT NOT NULL DEFAULT '',
  tag_message          TEXT NOT NULL DEFAULT '',
  updated_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  PRIMARY KEY (module_id, ref_type, ref_name)
);

CREATE INDEX module_refs_rev_idx
  ON module_refs(module_id, lore_revision);

CREATE TABLE module_special_objects (
  object_id        INTEGER PRIMARY KEY,
  module_id        INTEGER NOT NULL REFERENCES modules(module_id),
  lore_revision    TEXT NOT NULL,
  source_commit_id TEXT,
  kind             TEXT NOT NULL CHECK (kind IN ('lfs_hydrated','lfs_pointer','submodule_gitlink','symlink')),
  path             TEXT NOT NULL,
  oid              TEXT NOT NULL DEFAULT '',
  size_bytes       INTEGER NOT NULL DEFAULT 0,
  detail_json      TEXT NOT NULL DEFAULT '{}',
  UNIQUE (module_id, lore_revision, kind, path)
);

CREATE INDEX module_special_objects_rev_idx
  ON module_special_objects(module_id, lore_revision);

CREATE TABLE import_jobs (
  job_id          INTEGER PRIMARY KEY,
  job_key         TEXT NOT NULL UNIQUE,
  project_id      INTEGER NOT NULL REFERENCES projects(project_id),
  mode            TEXT NOT NULL CHECK (mode IN ('dry_run','import')),
  status          TEXT NOT NULL CHECK (status IN ('pending','running','succeeded','partial_failed','failed')),
  manifest_hash   TEXT NOT NULL,
  requested_by    TEXT NOT NULL,
  total_items     INTEGER NOT NULL DEFAULT 0,
  succeeded_items INTEGER NOT NULL DEFAULT 0,
  failed_items    INTEGER NOT NULL DEFAULT 0,
  skipped_items   INTEGER NOT NULL DEFAULT 0,
  summary_json    TEXT NOT NULL DEFAULT '{}',
  created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  finished_at     TEXT
);

CREATE TABLE import_job_items (
  item_id             INTEGER PRIMARY KEY,
  job_id              INTEGER NOT NULL REFERENCES import_jobs(job_id),
  ord                 INTEGER NOT NULL,
  source_url          TEXT NOT NULL,
  platform            TEXT NOT NULL,
  auth_method         TEXT NOT NULL DEFAULT 'none',
  module_name         TEXT NOT NULL,
  mount_path          TEXT NOT NULL,
  conflict_policy     TEXT NOT NULL DEFAULT 'fail' CHECK (conflict_policy IN ('fail','skip_if_imported','resume')),
  module_id           INTEGER REFERENCES modules(module_id),
  lore_repository_id  TEXT NOT NULL DEFAULT '',
  lore_repository_url TEXT NOT NULL DEFAULT '',
  git_mirror_path     TEXT NOT NULL DEFAULT '',
  lore_work_path      TEXT NOT NULL DEFAULT '',
  status              TEXT NOT NULL CHECK (status IN ('pending','planned','cloning','replaying','pushing','verifying','succeeded','skipped','conflict','failed')),
  checkpoint_json     TEXT NOT NULL DEFAULT '{}',
  verification_json   TEXT NOT NULL DEFAULT '{}',
  error               TEXT NOT NULL DEFAULT '',
  started_at          TEXT,
  finished_at         TEXT,
  UNIQUE (job_id, ord),
  UNIQUE (job_id, module_name)
);
