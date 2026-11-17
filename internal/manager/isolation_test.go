package manager

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"lore-monorepo/internal/permission"
	"lore-monorepo/internal/user"
)

func TestProjectAndRepositoryIsolation(t *testing.T) {
	app := testApp(t, fakeLore(t))
	ctx := context.Background()
	carol := makeAcct(t, app, "carol")
	alice := makeAcct(t, app, "alice")
	bob := makeAcct(t, app, "bob")
	dave := makeAcct(t, app, "dave")
	erin := makeAcct(t, app, "erin")
	svc, err := user.Create(ctx, app.DB, "test", "publisher", "correct-horse", "service")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptestServer(t, app)
	tok := func(id int64, name string) string {
		raw, err := app.Tokens.IssueIdentity(itoa(id), name, 1)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	carolTok, aliceTok, bobTok, daveTok, erinTok := tok(carol, "carol"), tok(alice, "alice"), tok(bob, "bob"), tok(dave, "dave"), tok(erin, "erin")
	svcTok := tok(svc, "publisher")

	status, alphaBody := apiJSON(t, http.MethodPost, srv+"/api/v1/projects", carolTok, map[string]string{
		"name": "Alpha", "parent_repository_id": "00112233445566778899aabbccddeeff", "parent_repository_url": "grpc://127.0.0.1:53547/alpha",
	})
	if status != http.StatusCreated || alphaBody["ParentRepositoryID"] != nil || alphaBody["parent_repository_id"] != nil {
		t.Fatalf("alpha create leaked parent %d %v", status, alphaBody)
	}
	alpha := int64(alphaBody["ID"].(float64))
	status, betaBody := apiJSON(t, http.MethodPost, srv+"/api/v1/projects", carolTok, map[string]string{
		"name": "Beta", "parent_repository_id": "ffeeddccbbaa99887766554433221100", "parent_repository_url": "grpc://127.0.0.1:53547/beta",
	})
	if status != http.StatusCreated {
		t.Fatalf("beta %d", status)
	}
	beta := int64(betaBody["ID"].(float64))
	status, gammaBody := apiJSON(t, http.MethodPost, srv+"/api/v1/projects", erinTok, map[string]string{
		"name": "Gamma", "parent_repository_id": "55555555555555555555555555555555", "parent_repository_url": "grpc://127.0.0.1:53547/gamma",
	})
	if status != http.StatusCreated {
		t.Fatalf("gamma %d", status)
	}
	gamma := int64(gammaBody["ID"].(float64))
	status, _ = apiJSON(t, http.MethodPost, srv+"/api/v1/projects/"+itoa(gamma)+"/members", erinTok, map[string]any{"username": "bob", "role": "project_member"})
	if status != http.StatusCreated {
		t.Fatalf("gamma member bob %d", status)
	}

	addMod := func(project int64, name, repo, mount string) int64 {
		t.Helper()
		status, body := apiJSON(t, http.MethodPost, srv+"/api/v1/projects/"+itoa(project)+"/modules", carolTok, map[string]string{
			"name": name, "repository_id": repo, "repository_url": "grpc://127.0.0.1:53547/" + mount, "mount_path": mount,
		})
		if status != http.StatusCreated {
			t.Fatalf("module %s %d %v", name, status, body)
		}
		return int64(body["ID"].(float64))
	}
	alphaEngine := addMod(alpha, "Engine", "0123456789abcdef0123456789abcdef", "Engine")
	alphaClient := addMod(alpha, "GameClient", "11111111111111111111111111111111", "GameClient")
	alphaDocs := addMod(alpha, "Docs", "22222222222222222222222222222222", "Docs")
	betaEngine := addMod(beta, "Engine", "33333333333333333333333333333333", "BetaEngine")
	betaBackend := addMod(beta, "Backend", "44444444444444444444444444444444", "Backend")

	grantMember := func(project int64, name string) {
		t.Helper()
		status, _ := apiJSON(t, http.MethodPost, srv+"/api/v1/projects/"+itoa(project)+"/members", carolTok, map[string]any{"username": name, "role": "project_member"})
		if status != http.StatusCreated {
			t.Fatalf("member %s %d", name, status)
		}
	}
	grantMember(alpha, "alice")
	grantMember(alpha, "bob")
	grantMember(beta, "bob")
	grant := func(module int64, name, perm string) {
		t.Helper()
		status, _ := apiJSON(t, http.MethodPost, srv+"/api/v1/modules/"+itoa(module)+"/permissions", carolTok, map[string]string{"username": name, "permission": perm})
		if status != http.StatusOK {
			t.Fatalf("grant %s %d", name, status)
		}
	}
	grant(alphaEngine, "alice", "write")
	grant(alphaClient, "alice", "write")
	grant(alphaDocs, "bob", "read")
	grant(betaEngine, "bob", "write")

	// User status is global: Carol must not be able to disable Bob through
	// Alpha while Bob also belongs to Gamma, which Carol does not administer.
	status, crossProjectStatus := apiJSON(t, http.MethodPost, srv+"/api/v1/users/bob/status", carolTok, map[string]any{
		"status": "disabled", "project_id": alpha,
	})
	if status != http.StatusNotFound || crossProjectStatus["error"] != "not found" {
		t.Fatalf("cross-project global status change leaked/changed Bob: %d %v", status, crossProjectStatus)
	}
	status, unknownStatus := apiJSON(t, http.MethodPost, srv+"/api/v1/users/not-a-user/status", carolTok, map[string]any{
		"status": "disabled", "project_id": alpha,
	})
	if status != http.StatusNotFound || unknownStatus["error"] != crossProjectStatus["error"] {
		t.Fatalf("unknown and cross-project status target differ: %d %v vs %v", status, unknownStatus, crossProjectStatus)
	}

	names := func(token string) string {
		t.Helper()
		status, body := apiJSON(t, http.MethodGet, srv+"/api/v1/me/modules", token, nil)
		if status != http.StatusOK {
			t.Fatalf("list %d", status)
		}
		raw, _ := jsonArray(body["modules"])
		out := ""
		for _, item := range raw {
			m := item.(map[string]any)
			out += m["ProjectName"].(string) + "/" + m["Name"].(string) + "=" + m["RepositoryID"].(string) + " "
		}
		return out
	}
	if got := names(aliceTok); got != "Alpha/Engine=0123456789abcdef0123456789abcdef Alpha/GameClient=11111111111111111111111111111111 " && got != "Alpha/GameClient=11111111111111111111111111111111 Alpha/Engine=0123456789abcdef0123456789abcdef " {
		t.Fatalf("alice %q", got)
	}
	if !strings.Contains(names(bobTok), "Alpha/Docs") || !strings.Contains(names(bobTok), "Beta/Engine=33333333333333333333333333333333") || strings.Contains(names(bobTok), "0123456789abcdef") {
		t.Fatalf("bob %q", names(bobTok))
	}
	if names(daveTok) != "" || names(carolTok) != "" {
		t.Fatalf("dave %q carol %q", names(daveTok), names(carolTok))
	}

	status, got := apiJSON(t, http.MethodGet, srv+"/api/v1/me/repositories/33333333333333333333333333333333", aliceTok, nil)
	if status != http.StatusNotFound {
		t.Fatalf("alice beta engine %d %v", status, got)
	}
	status, missing := apiJSON(t, http.MethodGet, srv+"/api/v1/me/repositories/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", aliceTok, nil)
	if status != http.StatusNotFound || missing["error"] != got["error"] {
		t.Fatalf("unknown and forbidden differ %v %v", missing, got)
	}
	status, _ = apiJSON(t, http.MethodGet, srv+"/api/v1/projects/"+itoa(beta), aliceTok, nil)
	if status != http.StatusNotFound {
		t.Fatalf("alice beta project %d", status)
	}
	status, projectView := apiJSON(t, http.MethodGet, srv+"/api/v1/projects/"+itoa(alpha), aliceTok, nil)
	if status != http.StatusOK || projectView["ParentRepositoryID"] != nil || projectView["Name"] != "Alpha" {
		t.Fatalf("alpha view %d %v", status, projectView)
	}
	status, search := apiJSON(t, http.MethodGet, srv+"/api/v1/me/search?q=Engine", aliceTok, nil)
	raw, _ := jsonArray(search["modules"])
	if status != http.StatusOK || len(raw) != 1 || raw[0].(map[string]any)["RepositoryID"] != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("search %d %v", status, search)
	}
	status, batch := apiJSON(t, http.MethodPost, srv+"/api/v1/me/batch", aliceTok, map[string]any{
		"action": "clone", "modules": []string{"Engine", "Docs", "Backend"},
	})
	raw, _ = jsonArray(batch["results"])
	blob := mustJSON(batch)
	if status != http.StatusOK || len(raw) != 1 || strings.Contains(blob, "Docs") || strings.Contains(blob, "Backend") || strings.Contains(blob, "33333333333333333333333333333333") {
		t.Fatalf("batch %d %s", status, blob)
	}
	status, denied := apiJSON(t, http.MethodGet, srv+"/api/v1/modules/"+itoa(betaBackend), aliceTok, nil)
	if status != http.StatusNotFound {
		t.Fatalf("module id %d %v", status, denied)
	}

	_, err = app.DB.Exec(`INSERT INTO snapshots(project_id, parent_revision, pins_json, created_by) VALUES (?,?,?,?)`,
		alpha, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		`[{"name":"Engine","mount_path":"Engine","repository_id":"0123456789abcdef0123456789abcdef","revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},{"name":"Docs","mount_path":"Docs","repository_id":"22222222222222222222222222222222","revision":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}]`,
		carol)
	if err != nil {
		t.Fatal(err)
	}
	status, snaps := apiJSON(t, http.MethodGet, srv+"/api/v1/projects/"+itoa(alpha)+"/snapshots", aliceTok, nil)
	snapText := mustJSON(snaps)
	if status != http.StatusOK || strings.Contains(snapText, "Docs") || strings.Contains(snapText, "22222222222222222222222222222222") || strings.Contains(snapText, "parent") {
		t.Fatalf("snapshots %d %s", status, snapText)
	}
	status, st := apiJSON(t, http.MethodGet, srv+"/api/v1/projects/"+itoa(alpha)+"/status", daveTok, nil)
	if status != http.StatusNotFound {
		t.Fatalf("dave status %d %v", status, st)
	}
	status, svcBody := apiJSON(t, http.MethodGet, srv+"/api/v1/me/modules", svcTok, nil)
	if status != http.StatusNotFound {
		t.Fatalf("service http %d %v", status, svcBody)
	}
	ids, err := (permission.Service{DB: app.DB}).RepositoryIDs(ctx, svc)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(ids, ",")
	if !strings.Contains(joined, "00112233445566778899aabbccddeeff") || !strings.Contains(joined, "ffeeddccbbaa99887766554433221100") {
		t.Fatalf("service lore resources %v", ids)
	}
	human, err := (permission.Service{DB: app.DB}).RepositoryIDs(ctx, carol)
	if err != nil {
		t.Fatal(err)
	}
	if len(human) != 0 {
		t.Fatalf("admin lore resources %v", human)
	}
	var audits int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE actor='publisher' AND action='service_repository_list'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("service audit %d %v", audits, err)
	}
}

func jsonArray(v any) ([]any, bool) {
	items, ok := v.([]any)
	return items, ok
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
