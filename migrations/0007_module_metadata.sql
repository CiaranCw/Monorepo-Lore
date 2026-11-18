-- Schema v7: human-readable display names and descriptions for modules.
-- Forward-compatible with v1..v6 databases; existing tables and rows remain intact.

ALTER TABLE modules ADD COLUMN display_name TEXT NOT NULL DEFAULT '';
ALTER TABLE modules ADD COLUMN description  TEXT NOT NULL DEFAULT '';
