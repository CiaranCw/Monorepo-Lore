package database

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func TestMigrationIdempotentAndWAL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "w.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	db, err = Open(path) // second open must not re-apply
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var v, tables, fk int
	var mode string
	db.QueryRow(`PRAGMA user_version`).Scan(&v)
	db.QueryRow(`PRAGMA journal_mode`).Scan(&mode)
	db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk)
	db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table'`).Scan(&tables)
	if v != 5 || mode != "wal" || tables != 17 || fk != 1 {
		t.Fatalf("user_version=%d journal_mode=%s tables=%d foreign_keys=%d (want 5, wal, 17, 1)", v, mode, tables, fk)
	}
}

func TestTxRollback(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	boom := errors.New("boom")
	err = Tx(ctx, db, func(tx *sql.Tx) error {
		if err := Audit(ctx, tx, "a", "x", "", ""); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&n)
	if n != 0 {
		t.Fatal("rolled back write is visible")
	}
	// foreign keys enforced
	if _, err := db.Exec(`INSERT INTO module_permissions(user_id, module_id, granted_by) VALUES (1, 1, 'x')`); err == nil {
		t.Fatal("foreign key not enforced")
	}
}
