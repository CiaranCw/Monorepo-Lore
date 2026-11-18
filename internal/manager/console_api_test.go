package manager

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"lore-monorepo/internal/history"
	"lore-monorepo/internal/user"
)

func TestConsoleOverviewMetadataUsersPermissionsAndIsolation(t *testing.T) {
	app := testApp(t, fakeLore(t))
	ctx := context.Background()

	carol := makeAcct(t, app, "carol")
	_ = makeAcct(t, app, "erin")
	_ = makeAcct(t, app, "bob")
	srv := httptestServer(t, app)

	// Verify root "/" serves embedded Web Console while "/health/live" and "/api/v1/*" still work.
	uiRes, err := http.Get(srv + "/")
	if err != nil {
		t.Fatal(err)
	}
	uiRes.Body.Close()
	if uiRes.StatusCode != http.StatusOK || !strings.Contains(uiRes.Header.Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatalf("GET / status=%d headers=%v", uiRes.StatusCode, uiRes.Header)
	}

	carolLogin := postLogin(t, srv, "carol", "correct-horse")
	erinLogin := postLogin(t, srv, "erin", "correct-horse")
	carolTok := carolLogin.IdentityToken
	erinTok := erinLogin.IdentityToken

	// Create Alpha (carol) and Gamma (erin), with bob in both projects.
	st, alphaBody := apiJSON(t, http.MethodPost, srv+"/api/v1/projects", carolTok, map[string]string{
		"name": "Alpha", "parent_repository_id": "00112233445566778899aabbccddeeff", "parent_repository_url": "grpc://127.0.0.1:53547/alpha",
	})
	if st != http.StatusCreated {
		t.Fatalf("create Alpha: %d %v", st, alphaBody)
	}
	alphaID := int64(alphaBody["ID"].(float64))

	st, gammaBody := apiJSON(t, http.MethodPost, srv+"/api/v1/projects", erinTok, map[string]string{
		"name": "Gamma", "parent_repository_id": "ffeeddccbbaa99887766554433221100", "parent_repository_url": "grpc://127.0.0.1:53547/gamma",
	})
	if st != http.StatusCreated {
		t.Fatalf("create Gamma: %d %v", st, gammaBody)
	}
	gammaID := int64(gammaBody["ID"].(float64))

	_, _ = apiJSON(t, http.MethodPost, srv+"/api/v1/projects/"+itoa(alphaID)+"/members", carolTok, map[string]string{"username": "bob", "role": "project_member"})
	_, _ = apiJSON(t, http.MethodPost, srv+"/api/v1/projects/"+itoa(gammaID)+"/members", erinTok, map[string]string{"username": "bob", "role": "project_member"})

	// Create two modules in Alpha: tide-holiday and cloudpunk-web-study.
	st, mod1Body := apiJSON(t, http.MethodPost, srv+"/api/v1/projects/Alpha/modules", carolTok, map[string]string{
		"name": "tide-holiday", "display_name": "潮汐假日", "description": "海岛垂钓",
		"repository_id": "11111111111111111111111111111111", "repository_url": "grpc://127.0.0.1:53547/tide", "mount_path": "tide-holiday",
	})
	if st != http.StatusCreated {
		t.Fatalf("create mod1: %d %v", st, mod1Body)
	}
	mod1ID := int64(mod1Body["ID"].(float64))

	st, mod2Body := apiJSON(t, http.MethodPost, srv+"/api/v1/projects/Alpha/modules", carolTok, map[string]string{
		"name":          "cloudpunk-web-study",
		"repository_id": "22222222222222222222222222222222", "repository_url": "grpc://127.0.0.1:53547/cloudpunk", "mount_path": "cloudpunk-web-study",
	})
	if st != http.StatusCreated {
		t.Fatalf("create mod2: %d %v", st, mod2Body)
	}
	mod2ID := int64(mod2Body["ID"].(float64))

	// Seed commit history on both modules; grant carol ONLY mod1 initially to test admin content isolation!
	_, _ = apiJSON(t, http.MethodPost, srv+"/api/v1/modules/"+itoa(mod1ID)+"/permissions", carolTok, map[string]string{"username": "carol", "permission": "write"})
	tx, err := app.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = history.UpsertCommit(ctx, tx, history.CommitInput{
		ModuleID: mod1ID, LoreRevision: fmt.Sprintf("%064x", 11), SourceCommitID: fmt.Sprintf("%040x", 11),
		OriginKind: history.OriginGitImport, AuthorName: "Dev1", CommittedUnixMS: 1750000001000, AuthoredUnixMS: 1750000001000, Message: "tide commit subject",
	})
	_ = history.UpsertRef(ctx, tx, history.RefDetail{
		ModuleID: mod1ID, Type: "branch", Name: "main", LoreRevision: fmt.Sprintf("%064x", 11), SourceCommitID: fmt.Sprintf("%040x", 11), IsDefault: true,
	})
	_ = history.UpsertCommit(ctx, tx, history.CommitInput{
		ModuleID: mod2ID, LoreRevision: fmt.Sprintf("%064x", 22), SourceCommitID: fmt.Sprintf("%040x", 22),
		OriginKind: history.OriginGitImport, AuthorName: "SecretDev", CommittedUnixMS: 1750000002000, AuthoredUnixMS: 1750000002000, Message: "confidential ungranted commit",
	})
	_ = history.UpsertRef(ctx, tx, history.RefDetail{
		ModuleID: mod2ID, Type: "branch", Name: "master", LoreRevision: fmt.Sprintf("%064x", 22), SourceCommitID: fmt.Sprintf("%040x", 22), IsDefault: true,
	})
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// Bulk metadata update sets display_name on cloudpunk-web-study.
	st, metaRes := apiJSON(t, http.MethodPost, srv+"/api/v1/projects/Alpha/modules/metadata", carolTok, map[string]any{
		"items": []map[string]string{
			{"module_name": "cloudpunk-web-study", "display_name": "吸就完事了"},
		},
	})
	if st != http.StatusOK || int(metaRes["updated"].(float64)) != 1 {
		t.Fatalf("bulk metadata: %d %v", st, metaRes)
	}

	// Admin overview lists BOTH modules in registry, but ONLY exposes head_commit for mod1 (where carol has a grant)!
	st, ovAdmin := apiJSON(t, http.MethodGet, srv+"/api/v1/projects/Alpha/overview", carolTok, nil)
	rawOvAdmin := mustJSON(ovAdmin)
	if st != http.StatusOK || !strings.Contains(rawOvAdmin, "潮汐假日") || !strings.Contains(rawOvAdmin, "吸就完事了") {
		t.Fatalf("admin overview missing display names: %d %s", st, rawOvAdmin)
	}
	if !strings.Contains(rawOvAdmin, "tide commit subject") || strings.Contains(rawOvAdmin, "confidential ungranted commit") {
		t.Fatalf("admin overview violated module content ACL boundary: %s", rawOvAdmin)
	}

	// Atomic user creation + grant: invalid module_id must roll back user creation completely.
	st, _ = apiJSON(t, http.MethodPost, srv+"/api/v1/projects/Alpha/users", carolTok, map[string]any{
		"username": "rollbackuser", "password": "rollbackuser", "role": "project_member",
		"grant_mode": "selected_write", "module_ids": []int64{mod1ID, 999999},
	})
	if st != http.StatusNotFound {
		t.Fatalf("expected 404 on invalid module_id, got %d", st)
	}
	if _, _, gErr := user.Get(ctx, app.DB, "rollbackuser"); gErr == nil {
		t.Fatal("failed createProjectUser leaked half-created user row")
	}

	// Atomic user creation with all_write succeeds and grants both active modules.
	st, createdUser := apiJSON(t, http.MethodPost, srv+"/api/v1/projects/Alpha/users", carolTok, map[string]any{
		"username": "evelynn", "password": "evelynn", "role": "project_member", "grant_mode": "all_write",
	})
	if st != http.StatusCreated || int(createdUser["granted_modules"].(float64)) != 2 {
		t.Fatalf("createProjectUser all_write: %d %v", st, createdUser)
	}
	evelynnUID := int64(createdUser["user_id"].(float64))

	evelynnLogin := postLogin(t, srv, "evelynn", "evelynn")
	evelynnTok := evelynnLogin.IdentityToken

	// /api/v1/auth/me exposes project roles.
	meBody := getMe(t, srv, evelynnTok, http.StatusOK)
	if !strings.Contains(mustJSON(meBody), `"role":"project_member"`) {
		t.Fatalf("me missing project role: %v", meBody)
	}

	// Member cannot access admin endpoints (403 Forbidden).
	for _, adminPath := range []string{
		"/api/v1/projects/Alpha/members",
		"/api/v1/projects/Alpha/permissions",
		"/api/v1/projects/Alpha/audit",
	} {
		code, _ := apiJSON(t, http.MethodGet, srv+adminPath, evelynnTok, nil)
		if code != http.StatusForbidden {
			t.Fatalf("member GET %s expected 403, got %d", adminPath, code)
		}
	}

	// Batch permissions: revoke mod2 from evelynn, verify evelynn overview drops mod2 immediately.
	st, batchRes := apiJSON(t, http.MethodPost, srv+"/api/v1/projects/Alpha/permissions/batch", carolTok, map[string]any{
		"changes": []map[string]any{
			{"user_id": evelynnUID, "module_id": mod2ID, "permission": "none"},
		},
	})
	if st != http.StatusOK || int(batchRes["applied"].(float64)) != 1 {
		t.Fatalf("batch revoke: %d %v", st, batchRes)
	}
	st, ovEvelynn := apiJSON(t, http.MethodGet, srv+"/api/v1/projects/Alpha/overview", evelynnTok, nil)
	rawOvEvelynn := mustJSON(ovEvelynn)
	if st != http.StatusOK || !strings.Contains(rawOvEvelynn, "潮汐假日") || strings.Contains(rawOvEvelynn, "cloudpunk-web-study") || strings.Contains(rawOvEvelynn, "member_count") {
		t.Fatalf("member overview leaked unauthorized module or admin stats: %d %s", st, rawOvEvelynn)
	}

	// Anti-lockout protections: sole admin carol cannot remove, demote, or disable herself.
	if code, _ := apiJSON(t, http.MethodDelete, srv+"/api/v1/projects/Alpha/members/"+itoa(carol), carolTok, nil); code != http.StatusConflict {
		t.Fatalf("self remove expected 409, got %d", code)
	}
	if code, _ := apiJSON(t, http.MethodPatch, srv+"/api/v1/projects/Alpha/members/"+itoa(carol), carolTok, map[string]string{"role": "project_member"}); code != http.StatusConflict {
		t.Fatalf("self demote expected 409, got %d", code)
	}
	if code, _ := apiJSON(t, http.MethodPost, srv+"/api/v1/users/carol/status", carolTok, map[string]any{"project_id": alphaID, "status": "disabled"}); code != http.StatusConflict {
		t.Fatalf("self disable expected 409, got %d", code)
	}

	// Promote evelynn to project_admin, then demote her back to project_member cleanly.
	if code, _ := apiJSON(t, http.MethodPatch, srv+"/api/v1/projects/Alpha/members/"+itoa(evelynnUID), carolTok, map[string]string{"role": "project_admin"}); code != http.StatusOK {
		t.Fatalf("promote evelynn failed: %d", code)
	}
	if code, _ := apiJSON(t, http.MethodPatch, srv+"/api/v1/projects/Alpha/members/"+itoa(evelynnUID), carolTok, map[string]string{"role": "project_member"}); code != http.StatusOK {
		t.Fatalf("demote evelynn failed: %d", code)
	}

	// Cross-project password reset isolation: carol CANNOT reset bob's password because bob also belongs to Gamma!
	codeBobPw, bodyBobPw := apiJSON(t, http.MethodPost, srv+"/api/v1/users/bob/password", carolTok, map[string]any{
		"project_id": alphaID, "password": "hacked-password",
	})
	codeUnkPw, bodyUnkPw := apiJSON(t, http.MethodPost, srv+"/api/v1/users/no-such-user/password", carolTok, map[string]any{
		"project_id": alphaID, "password": "hacked-password",
	})
	if codeBobPw != http.StatusNotFound || codeUnkPw != http.StatusNotFound || bodyBobPw["error"] != bodyUnkPw["error"] {
		t.Fatalf("cross-project password reset leaked/allowed: bob=(%d,%v) unk=(%d,%v)", codeBobPw, bodyBobPw, codeUnkPw, bodyUnkPw)
	}
	if postLoginStatus(t, srv, "bob", "correct-horse") != http.StatusOK {
		t.Fatal("bob's password was unexpectedly altered")
	}

	// Admin password reset on Alpha-only member evelynn succeeds and immediately invalidates old persistent token!
	if code, _ := apiJSON(t, http.MethodPost, srv+"/api/v1/users/evelynn/password", carolTok, map[string]any{
		"project_id": alphaID, "password": "new-secret-pw",
	}); code != http.StatusOK {
		t.Fatalf("reset evelynn password failed: %d", code)
	}
	if getMeStatus(t, srv, evelynnTok) != http.StatusUnauthorized {
		t.Fatal("old persistent token stayed valid after admin password reset")
	}
	if postLoginStatus(t, srv, "evelynn", "new-secret-pw") != http.StatusOK {
		t.Fatal("evelynn could not log in with new password")
	}

	// Audit log for Alpha shows Alpha/evelynn events, NEVER Gamma/erin/bob login events!
	_ = postLoginStatus(t, srv, "bob", "correct-horse")
	st, auditRes := apiJSON(t, http.MethodGet, srv+"/api/v1/projects/Alpha/audit?limit=100", carolTok, nil)
	rawAudit := mustJSON(auditRes)
	if st != http.StatusOK || !strings.Contains(rawAudit, "module_permission_batch") || !strings.Contains(rawAudit, "evelynn") {
		t.Fatalf("audit missing expected Alpha events: %d %s", st, rawAudit)
	}
	if strings.Contains(rawAudit, "Gamma") || strings.Contains(rawAudit, `"target":"erin"`) || strings.Contains(rawAudit, `"target":"bob"`) {
		t.Fatalf("audit leaked cross-project events: %s", rawAudit)
	}
}
