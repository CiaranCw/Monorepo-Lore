package project

import (
	"context"
	"database/sql"

	"lore-monorepo/internal/database"
)

// GrantModule records that userID may reach the module repository.
// An archived module still keeps the row, but listing skips archived modules.
func GrantModule(ctx context.Context, db *sql.DB, actor string, userID, moduleID int64) error {
	if actor == "" {
		return invalid("actor is required")
	}
	return database.Tx(ctx, db, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO module_permissions(user_id, module_id, granted_by)
			VALUES (?,?,?)`, userID, moduleID, actor)
		if err != nil {
			return mapConstraint(err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrConflict
		}
		return database.Audit(ctx, tx, actor, "module_grant", itoa(moduleID), "user="+itoa(userID))
	})
}

// AccessibleRepositories returns repository ids the user may reach.
// Archived modules are omitted. This is the database record AuthBridge reads.
func AccessibleRepositories(ctx context.Context, db *sql.DB, userID int64) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT m.repository_id
		FROM module_permissions p
		JOIN modules m ON m.module_id = p.module_id
		WHERE p.user_id = ? AND m.archived_at IS NULL
		ORDER BY m.repository_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
