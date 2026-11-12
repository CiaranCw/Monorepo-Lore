package manager

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"lore-monorepo/internal/authbridge"
	"lore-monorepo/internal/database"
	"lore-monorepo/internal/user"
)

const maxLoginBody = 4096

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	IdentityToken string `json:"identity_token"`
	TokenType     string `json:"token_type"`
	ExpiresIn     int    `json:"expires_in"`
	Username      string `json:"username"`
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxLoginBody))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	defer wipe(body)
	var req loginRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	password := []byte(req.Password)
	req.Password = ""
	defer wipe(password)

	account, err := user.Authenticate(r.Context(), a.DB, req.Username, string(password))
	if err != nil {
		_ = a.auditLogin(r.Context(), req.Username, false, err)
		if errors.Is(err, user.ErrDisabled) {
			writeError(w, http.StatusForbidden, "account disabled")
			return
		}
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	token, err := a.Tokens.IssueIdentity(strconv.FormatInt(account.ID, 10), account.Username, account.AuthVersion)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}
	if err := a.auditLogin(r.Context(), account.Username, true, nil); err != nil {
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}
	writeJSON(w, http.StatusOK, loginResponse{
		IdentityToken: token,
		TokenType:     "Bearer",
		ExpiresIn:     int(a.Config.Auth.IdentityTTL.Seconds()),
		Username:      account.Username,
	})
}

func (a *App) changePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	raw := bearerToken(r)
	session, err := authbridge.AuthenticateIdentity(r.Context(), a.Tokens, authbridge.UserDirectory{Get: a.userByID}, raw)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	password := body.Password
	body.Password = ""
	defer func() {
		password = ""
	}()
	if err := user.SetPassword(r.Context(), a.DB, session.User.Username, session.User.Username, password); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (a *App) me(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	raw := bearerToken(r)
	session, err := authbridge.AuthenticateIdentity(r.Context(), a.Tokens, authbridge.UserDirectory{Get: a.userByID}, raw)
	if err != nil {
		if raw != "" {
			if _, verifyErr := a.Tokens.VerifyIdentity(raw); verifyErr != nil && strings.Contains(verifyErr.Error(), "expired") {
				writeError(w, http.StatusUnauthorized, "expired token")
				return
			}
		}
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username":     session.User.Username,
		"user_id":      strconv.FormatInt(session.User.ID, 10),
		"auth_version": session.User.AuthVersion,
		"status":       session.User.Status,
	})
}

func (a *App) userByID(ctx context.Context, id int64) (*user.User, error) {
	if a.DB == nil {
		return nil, user.ErrNotFound
	}
	return user.GetByID(ctx, a.DB, id)
}

func (a *App) auditLogin(ctx context.Context, username string, ok bool, cause error) error {
	if len(username) > 64 {
		username = username[:64]
	}
	action := "login_failure"
	detail := "rejected"
	if ok {
		action = "login_success"
		detail = "identity token issued"
	} else if errors.Is(cause, user.ErrDisabled) {
		detail = "disabled"
	}
	return database.Tx(ctx, a.DB, func(tx *sql.Tx) error {
		return database.Audit(ctx, tx, "login", action, username, detail)
	})
}

func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
