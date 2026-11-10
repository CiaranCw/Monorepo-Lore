// Package user manages Manager accounts: Argon2id password hashes, status and auth_version.
package user

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/argon2"

	"lore-monorepo/internal/database"
)

// Argon2id parameters (OWASP baseline: m=64MiB, t=3, p=2).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
	minPassword  = 10
)

var (
	ErrNotFound    = errors.New("user not found")
	ErrBadPassword = errors.New("invalid username or password")
	ErrDisabled    = errors.New("account disabled")
	usernameRe     = regexp.MustCompile(`^[a-z][a-z0-9._-]{1,62}$`)
)

// User is one account row (password hash excluded from String output).
type User struct {
	ID          int64
	Username    string
	Kind        string
	Status      string
	AuthVersion int64
}

// HashPassword returns an Argon2id PHC string.
func HashPassword(password string) (string, error) {
	if len(password) < minPassword {
		return "", fmt.Errorf("password must be at least %d characters", minPassword)
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime,
		argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword checks password against a PHC string in constant time.
func VerifyPassword(phc, password string) bool {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var v int
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	b64 := base64.RawStdEncoding
	salt, err1 := b64.DecodeString(parts[4])
	want, err2 := b64.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash is verified when the user does not exist, so timing does not reveal account existence.
var dummyHash, _ = HashPassword("dummy-password-for-timing")

// Create adds an account. kind is "user" or "service".
func Create(ctx context.Context, db *sql.DB, actor, username, password, kind string) (int64, error) {
	if !usernameRe.MatchString(username) {
		return 0, fmt.Errorf("invalid username %q (lowercase, 2-63 chars, [a-z0-9._-])", username)
	}
	hash, err := HashPassword(password)
	if err != nil {
		return 0, err
	}
	var id int64
	err = database.Tx(ctx, db, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO users(username, password_hash, kind) VALUES (?,?,?)`, username, hash, kind)
		if err != nil {
			return err
		}
		id, _ = res.LastInsertId()
		return database.Audit(ctx, tx, actor, "user_create", username, "kind="+kind)
	})
	return id, err
}

// GetByID loads an account without its password hash.
func GetByID(ctx context.Context, db *sql.DB, id int64) (*User, error) {
	u := &User{}
	err := db.QueryRowContext(ctx, `SELECT user_id, username, kind, status, auth_version FROM users WHERE user_id=?`, id).
		Scan(&u.ID, &u.Username, &u.Kind, &u.Status, &u.AuthVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

// Get loads a user by name.
func Get(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}, username string) (*User, string, error) {
	u := &User{}
	var hash string
	err := q.QueryRowContext(ctx, `SELECT user_id, username, kind, status, auth_version, password_hash FROM users WHERE username=?`,
		username).Scan(&u.ID, &u.Username, &u.Kind, &u.Status, &u.AuthVersion, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", ErrNotFound
	}
	return u, hash, err
}

// Authenticate verifies username/password and returns the active account.
func Authenticate(ctx context.Context, db *sql.DB, username, password string) (*User, error) {
	u, hash, err := Get(ctx, db, username)
	if errors.Is(err, ErrNotFound) {
		VerifyPassword(dummyHash, password)
		return nil, ErrBadPassword
	}
	if err != nil {
		return nil, err
	}
	if !VerifyPassword(hash, password) {
		return nil, ErrBadPassword
	}
	if u.Status != "active" {
		return nil, ErrDisabled
	}
	return u, nil
}

// SetPassword replaces the hash and bumps auth_version (old identity tokens stop working).
func SetPassword(ctx context.Context, db *sql.DB, actor, username, password string) error {
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	return database.Tx(ctx, db, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE users SET password_hash=?, auth_version=auth_version+1,
			updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE username=?`, hash, username)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		return database.Audit(ctx, tx, actor, "user_password_change", username, "auth_version bumped")
	})
}

// SetStatus enables/disables an account; disabling also bumps auth_version.
func SetStatus(ctx context.Context, db *sql.DB, actor, username, status string) error {
	if status != "active" && status != "disabled" {
		return fmt.Errorf("bad status %q", status)
	}
	return database.Tx(ctx, db, func(tx *sql.Tx) error {
		bump := 0
		if status == "disabled" {
			bump = 1
		}
		res, err := tx.ExecContext(ctx, `UPDATE users SET status=?, auth_version=auth_version+?,
			updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE username=?`, status, bump, username)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		return database.Audit(ctx, tx, actor, "user_status", username, "status="+status)
	})
}

// List returns all accounts.
func List(ctx context.Context, db *sql.DB) ([]User, error) {
	rows, err := db.QueryContext(ctx, `SELECT user_id, username, kind, status, auth_version FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Kind, &u.Status, &u.AuthVersion); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
