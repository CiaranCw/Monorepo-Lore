package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"lore-monorepo/internal/logging"
	"lore-monorepo/internal/user"
)

func TestLoginAndMe(t *testing.T) {
	var logs bytes.Buffer
	app := testApp(t, fakeLore(t))
	app.Log = logging.New(&logs, logging.Info, "manager")
	ctx := context.Background()
	if _, err := user.Create(ctx, app.DB, "test", "alice", "correct-horse", "user"); err != nil {
		t.Fatal(err)
	}
	if _, err := user.Create(ctx, app.DB, "test", "bob", "correct-horse", "user"); err != nil {
		t.Fatal(err)
	}
	srv := httptestServer(t, app)
	password := "correct-horse"

	ok := postLogin(t, srv, "alice", password)
	if ok.Username != "alice" || ok.TokenType != "Bearer" || ok.ExpiresIn != int(app.Config.Auth.IdentityTTL.Seconds()) || ok.IdentityToken == "" {
		t.Fatalf("login response missing identity fields")
	}
	if strings.Contains(ok.IdentityToken, "resources") {
		t.Fatal("identity token contains resources")
	}
	me := getMe(t, srv, ok.IdentityToken, http.StatusOK)
	if me["username"] != "alice" || me["auth_version"].(float64) != 1 {
		t.Fatalf("me %#v", me)
	}

	missing := postLoginStatus(t, srv, "nobody", password)
	wrong := postLoginStatus(t, srv, "alice", "wrong-password-1")
	if missing != http.StatusUnauthorized || wrong != http.StatusUnauthorized {
		t.Fatalf("missing %d wrong %d", missing, wrong)
	}
	missingBody := postLoginBody(t, srv, "nobody", password)
	wrongBody := postLoginBody(t, srv, "alice", "wrong-password-1")
	if missingBody != wrongBody {
		t.Fatalf("login errors differ: %s vs %s", missingBody, wrongBody)
	}

	if err := user.SetStatus(ctx, app.DB, "test", "bob", "disabled"); err != nil {
		t.Fatal(err)
	}
	if postLoginStatus(t, srv, "bob", password) != http.StatusForbidden {
		t.Fatal("disabled user was accepted")
	}

	if err := user.SetPassword(ctx, app.DB, "test", "alice", "new-password-1"); err != nil {
		t.Fatal(err)
	}
	if getMeStatus(t, srv, ok.IdentityToken) != http.StatusUnauthorized {
		t.Fatal("old token accepted after password change")
	}
	again := postLogin(t, srv, "alice", "new-password-1")
	if again.IdentityToken == ok.IdentityToken {
		t.Fatal("password change did not issue a new token")
	}
	if getMeStatus(t, srv, again.IdentityToken) != http.StatusOK {
		t.Fatal("new token rejected")
	}

	if err := user.SetStatus(ctx, app.DB, "test", "alice", "disabled"); err != nil {
		t.Fatal(err)
	}
	if getMeStatus(t, srv, again.IdentityToken) != http.StatusUnauthorized {
		t.Fatal("disabled user's old token still works")
	}
	if err := user.SetStatus(ctx, app.DB, "test", "alice", "active"); err != nil {
		t.Fatal(err)
	}
	if getMeStatus(t, srv, again.IdentityToken) != http.StatusUnauthorized {
		t.Fatal("re-enabled account accepted the pre-disable token")
	}
	fresh := postLogin(t, srv, "alice", "new-password-1")
	if getMeStatus(t, srv, fresh.IdentityToken) != http.StatusOK {
		t.Fatal("login after re-enable failed")
	}

	issued := time.Now()
	app.Tokens.SetClock(func() time.Time { return issued.Add(13 * time.Hour) })
	if getMeStatus(t, srv, fresh.IdentityToken) != http.StatusUnauthorized {
		t.Fatal("expired token accepted")
	}
	if getMeStatus(t, srv, "not-a-token") != http.StatusUnauthorized {
		t.Fatal("invalid token accepted")
	}

	logText := logs.String()
	for _, secret := range []string{password, "new-password-1", "wrong-password-1", fresh.IdentityToken, ok.IdentityToken} {
		if strings.Contains(logText, secret) {
			t.Fatal("log contains a password or token")
		}
	}
	var n int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE detail LIKE '%horse%' OR detail LIKE '%eyJ%'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("audit stored a secret: %v n=%d", err, n)
	}
}

type loginJSON struct {
	IdentityToken string `json:"identity_token"`
	TokenType     string `json:"token_type"`
	ExpiresIn     int    `json:"expires_in"`
	Username      string `json:"username"`
	Error         string `json:"error"`
}

func postLogin(t *testing.T, srv, username, password string) loginJSON {
	t.Helper()
	res, body := doLogin(t, srv, username, password)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login %s: %s", username, body)
	}
	var out loginJSON
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func postLoginStatus(t *testing.T, srv, username, password string) int {
	t.Helper()
	res, _ := doLogin(t, srv, username, password)
	return res.StatusCode
}

func postLoginBody(t *testing.T, srv, username, password string) string {
	t.Helper()
	_, body := doLogin(t, srv, username, password)
	return body
}

func doLogin(t *testing.T, srv, username, password string) (*http.Response, string) {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"username": username, "password": password})
	res, err := http.Post(srv+"/api/v1/auth/login", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	buf, _ := io.ReadAll(res.Body)
	return res, string(buf)
}

func getMe(t *testing.T, srv, token string, want int) map[string]any {
	t.Helper()
	res := meRequest(t, srv, token)
	defer res.Body.Close()
	if res.StatusCode != want {
		t.Fatalf("me status %d", res.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body
}

func getMeStatus(t *testing.T, srv, token string) int {
	t.Helper()
	res := meRequest(t, srv, token)
	defer res.Body.Close()
	return res.StatusCode
}

func meRequest(t *testing.T, srv, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv+"/api/v1/auth/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}
