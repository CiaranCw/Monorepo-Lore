-- Schema v6: per-revision source path to module path audit rows.
-- Forward-compatible with v1..v5 databases.

CREATE TABLE module_path_projections (
  module_id        INTEGER NOT NULL REFERENCES modules(module_id),
  source_commit_id TEXT NOT NULL,
  lore_revision    TEXT NOT NULL DEFAULT '',
  source_path      TEXT NOT NULL,
  mapped_path      TEXT NOT NULL,
  path_rule_id     TEXT NOT NULL DEFAULT '',
  projection_type  TEXT NOT NULL DEFAULT 'normal',
  PRIMARY KEY (module_id, source_commit_id, source_path)
);

CREATE INDEX module_path_projections_rev_idx
  ON module_path_projections(module_id, lore_revision);
