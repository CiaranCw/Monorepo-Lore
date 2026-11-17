-- Schema v5: persistent per-module source commit alias mapping, original ref provenance,
-- and pinned upstream ref snapshots for resume consistency.
-- Forward-compatible with v1..v4 databases.

CREATE TABLE module_commit_aliases (
  module_id                  INTEGER NOT NULL REFERENCES modules(module_id),
  source_commit_id           TEXT NOT NULL,
  alias_status               TEXT NOT NULL CHECK (alias_status IN ('direct','unchanged_alias','pre_module_empty')),
  effective_source_commit_id TEXT NOT NULL DEFAULT '',
  lore_revision              TEXT NOT NULL DEFAULT '',
  source_subdir              TEXT NOT NULL DEFAULT '',
  updated_at                 TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  PRIMARY KEY (module_id, source_commit_id)
);

CREATE INDEX module_commit_aliases_rev_idx
  ON module_commit_aliases(module_id, lore_revision)
  WHERE lore_revision <> '';

ALTER TABLE module_refs ADD COLUMN original_source_commit_id TEXT NOT NULL DEFAULT '';

ALTER TABLE import_job_items ADD COLUMN pinned_refs_json TEXT NOT NULL DEFAULT '{}';
