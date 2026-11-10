// Package migrations embeds the ordered SQLite migration files.
package migrations

import "embed"

// FS holds NNNN_*.sql files; file N is applied when PRAGMA user_version < N.
//
//go:embed *.sql
var FS embed.FS
