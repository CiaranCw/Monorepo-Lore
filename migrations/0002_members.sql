-- Forward-compatible membership and module permission levels.
-- Existing module_permissions rows default to write, which is what Lore 0.10.1
-- can actually enforce. read is a Manager-level label, not a Lore ACL.

CREATE TABLE project_members (
  project_id INTEGER NOT NULL REFERENCES projects(project_id),
  user_id    INTEGER NOT NULL REFERENCES users(user_id),
  role       TEXT NOT NULL CHECK (role IN ('project_admin','project_member')),
  added_by   TEXT NOT NULL,
  added_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  PRIMARY KEY (project_id, user_id)
);

ALTER TABLE module_permissions ADD COLUMN permission TEXT NOT NULL DEFAULT 'write';

CREATE TRIGGER module_permissions_permission_insert
BEFORE INSERT ON module_permissions
FOR EACH ROW
WHEN NEW.permission NOT IN ('read','write')
BEGIN
  SELECT RAISE(ABORT, 'invalid module permission');
END;

CREATE TRIGGER module_permissions_permission_update
BEFORE UPDATE OF permission ON module_permissions
FOR EACH ROW
WHEN NEW.permission NOT IN ('read','write')
BEGIN
  SELECT RAISE(ABORT, 'invalid module permission');
END;
