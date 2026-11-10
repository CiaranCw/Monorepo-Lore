-- Lore Monorepo Lite Manager schema v1 (9 tables). Applied inside one transaction.
-- Version tracking uses PRAGMA user_version (no extra table).

CREATE TABLE users (
  user_id       INTEGER PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,                       -- Argon2id PHC string; never plaintext
  kind          TEXT NOT NULL DEFAULT 'user' CHECK (kind IN ('user','service')),
  status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  auth_version  INTEGER NOT NULL DEFAULT 1,          -- bumped on password change / disable; embedded in identity tokens
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE projects (
  project_id            INTEGER PRIMARY KEY,
  name                  TEXT NOT NULL UNIQUE,
  parent_repository_id  TEXT NOT NULL UNIQUE,         -- 32 hex
  parent_repository_url TEXT NOT NULL,
  created_by            INTEGER NOT NULL REFERENCES users(user_id),
  created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE modules (
  module_id      INTEGER PRIMARY KEY,
  project_id     INTEGER NOT NULL REFERENCES projects(project_id),
  name           TEXT NOT NULL,
  repository_id  TEXT NOT NULL UNIQUE,
  repository_url TEXT NOT NULL,
  mount_path     TEXT NOT NULL,
  archived_at    TEXT,
  created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  UNIQUE (project_id, name),
  UNIQUE (project_id, mount_path)
);

CREATE TABLE module_permissions (
  user_id    INTEGER NOT NULL REFERENCES users(user_id),
  module_id  INTEGER NOT NULL REFERENCES modules(module_id),
  granted_by TEXT NOT NULL,
  granted_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  PRIMARY KEY (user_id, module_id)
);

CREATE TABLE project_publishers (
  user_id    INTEGER NOT NULL REFERENCES users(user_id),
  project_id INTEGER NOT NULL REFERENCES projects(project_id),
  PRIMARY KEY (user_id, project_id)
);

-- Reserved for P3-B3 (Snapshot Manager). Created now so the schema is complete.
CREATE TABLE snapshots (
  snapshot_id     INTEGER PRIMARY KEY,
  project_id      INTEGER NOT NULL REFERENCES projects(project_id),
  parent_revision TEXT NOT NULL,
  parent_rev_no   INTEGER,
  pins_json       TEXT NOT NULL,
  description     TEXT,
  operation_id    INTEGER REFERENCES operations(operation_id),
  protected       INTEGER NOT NULL DEFAULT 1,
  created_by      INTEGER NOT NULL REFERENCES users(user_id),
  created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  UNIQUE (project_id, parent_revision)
);

CREATE TABLE operations (
  operation_id   INTEGER PRIMARY KEY,
  project_id     INTEGER REFERENCES projects(project_id),
  operation_type TEXT NOT NULL CHECK (operation_type IN
                   ('project_create','module_add','snapshot_publish','snapshot_verify','key_rotate','emergency_revoke')),
  status         TEXT NOT NULL CHECK (status IN ('running','succeeded','failed','noop')),
  request_json   TEXT NOT NULL,
  progress       TEXT,
  attempts       INTEGER NOT NULL DEFAULT 0,
  error          TEXT,
  requested_by   TEXT NOT NULL,
  started_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  finished_at    TEXT
);
CREATE UNIQUE INDEX one_running_publish ON operations(project_id)
  WHERE operation_type = 'snapshot_publish' AND status = 'running';

-- Signing keys. Private key material lives in 0600 files, never in the DB.
-- purpose=identity: one shared active key for identity tokens (always verified online by the Manager).
-- purpose=access:   one key per (user, module) grant, or per service account (module_id NULL),
--                   so that an emergency revocation can retire exactly one grant.
CREATE TABLE signing_keys (
  kid          TEXT PRIMARY KEY,
  purpose      TEXT NOT NULL CHECK (purpose IN ('identity','access')),
  user_id      INTEGER REFERENCES users(user_id),
  module_id    INTEGER REFERENCES modules(module_id),
  key_path     TEXT NOT NULL,
  status       TEXT NOT NULL CHECK (status IN ('active','draining','retired')),
  created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  published_at TEXT,                                 -- first time it appeared in the published JWKS
  retire_after TEXT,                                 -- draining keys are retired after this time
  retired_at   TEXT
);
CREATE INDEX signing_keys_grant ON signing_keys(user_id, module_id, status);

CREATE TABLE audit_log (
  audit_id INTEGER PRIMARY KEY,
  at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  actor    TEXT NOT NULL,
  action   TEXT NOT NULL,
  target   TEXT,
  detail   TEXT
);
CREATE INDEX audit_log_at ON audit_log(at);
