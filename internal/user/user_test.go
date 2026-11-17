package user

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"lore-monorepo/internal/database"
)

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "u.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestHashAndVerify(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") || strings.Contains(h, "correct horse") {
		t.Fatalf("unexpected hash format: %s", h)
	}
	if !VerifyPassword(h, "correct horse battery") || VerifyPassword(h, "correct horse batterY") {
		t.Fatal("verify wrong")
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Fatal("salt not random")
	}
	for _, bad := range []string{"", "$argon2i$v=19$m=65536,t=3,p=2$AAAA$AAAA", "$argon2id$v=18$m=65536,t=3,p=2$AAAA$AAAA", "garbage"} {
		if VerifyPassword(bad, "x") {
			t.Fatalf("malformed hash accepted: %q", bad)
		}
	}
	if _, err := HashPassword("short"); err != nil {
		t.Fatal(err)
	}
	if _, err := HashPassword(""); err == nil {
		t.Fatal("empty password accepted")
	}
}

func TestLifecycle(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	if _, err := Create(ctx, db, "admin", "UserA", "password-1234", "user"); err == nil {
		t.Fatal("uppercase username accepted")
	}
	if _, err := Create(ctx, db, "admin", "usera", "password-1234", "user"); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(ctx, db, "admin", "usera", "password-1234", "user"); err == nil {
		t.Fatal("duplicate username accepted")
	}
	u, err := Authenticate(ctx, db, "usera", "password-1234")
	if err != nil || u.AuthVersion != 1 || u.Status != "active" {
		t.Fatalf("auth: %v %+v", err, u)
	}
	if _, err := Authenticate(ctx, db, "usera", "wrong-password"); !errors.Is(err, ErrBadPassword) {
		t.Fatalf("wrong pw: %v", err)
	}
	if _, err := Authenticate(ctx, db, "nobody", "password-1234"); !errors.Is(err, ErrBadPassword) {
		t.Fatalf("unknown user must look like bad password: %v", err)
	}
	if err := SetPassword(ctx, db, "admin", "usera", "new-password-5678"); err != nil {
		t.Fatal(err)
	}
	if _, err := Authenticate(ctx, db, "usera", "password-1234"); !errors.Is(err, ErrBadPassword) {
		t.Fatal("old password still works")
	}
	if u, err = Authenticate(ctx, db, "usera", "new-password-5678"); err != nil || u.AuthVersion != 2 {
		t.Fatalf("password change must bump auth_version: %v %+v", err, u)
	}
	if err := SetStatus(ctx, db, "admin", "usera", "disabled"); err != nil {
		t.Fatal(err)
	}
	if _, err := Authenticate(ctx, db, "usera", "new-password-5678"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled: %v", err)
	}
	if err := SetStatus(ctx, db, "admin", "usera", "active"); err != nil {
		t.Fatal(err)
	}
	if u, err = Authenticate(ctx, db, "usera", "new-password-5678"); err != nil || u.AuthVersion != 3 {
		t.Fatalf("disable must bump auth_version, enable must not: %v %+v", err, u)
	}
	if err := SetStatus(ctx, db, "admin", "nobody", "disabled"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user: %v", err)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action IN ('user_create','user_password_change','user_status')`).Scan(&n)
	if n != 4 {
		t.Fatalf("expected 4 audit rows, got %d", n)
	}
	var leaked int
	db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE detail LIKE '%password-1234%' OR detail LIKE '%new-password%'`).Scan(&leaked)
	if leaked != 0 {
		t.Fatal("password leaked into audit_log")
	}
	list, err := List(ctx, db)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %d", err, len(list))
	}
}
