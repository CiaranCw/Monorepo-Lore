-- Schema v4: per-module monorepo subdirectory projection metadata, bootstrap branch tracking,
-- and import job worker lease / target locking support.
-- Forward-compatible with v1, v2, and v3 databases.

ALTER TABLE module_commits ADD COLUMN source_subdir TEXT NOT NULL DEFAULT '';

ALTER TABLE import_jobs ADD COLUMN worker_token TEXT NOT NULL DEFAULT '';

ALTER TABLE import_job_items ADD COLUMN source_subdir TEXT NOT NULL DEFAULT '';
ALTER TABLE import_job_items ADD COLUMN bootstrap_main_rev TEXT NOT NULL DEFAULT '';

CREATE INDEX import_job_items_module_idx
  ON import_job_items(module_id, item_id DESC);
