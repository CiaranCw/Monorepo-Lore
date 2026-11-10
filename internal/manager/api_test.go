package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"lore-monorepo/internal/user"
)

func TestTeamAPIAndBypass(t *testing.T) {
	app := testApp(t, fakeLore(t))
	ctx := context.Background()
	carol := makeAcct(t, app, "carol")
	alice := makeAcct(t, app, "alice")
	bob := makeAcct(t, app, "bob")
	dave := makeAcct(t, app, "dave")
	srv := httptestServer(t, app)
	token := func(id int64, name string, version int64) string {
		raw, err := app.Tokens.IssueIdentity(itoa(id), name, version)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	carolTok := token(carol, "carol", 1)
	aliceTok := token(alice, "alice", 1)
	bobTok := token(bob, "bob", 1)
	daveTok := token(dave, "dave", 1)

	status, projectBody := apiJSON(t, http.MethodPost, srv+"/api/v1/projects", carolTok, map[string]string{
		"name": "Alpha", "parent_repository_id": "00112233445566778899aabbccddeeff", "parent_repository_url": "grpc://127.0.0.1:53547/alpha",
	})
	if status != http.StatusCreated {
		t.Fatalf("create %d %v", status, projectBody)
	}
	pid := int64(projectBody["ID"].(float64))
	status, _ = apiJSON(t, http.MethodPost, srv+"/api/v1/projects/"+itoa(pid)+"/modules", aliceTok, map[string]string{
		"name": "Engine", "repository_id": "0123456789abcdef0123456789abcdef", "repository_url": "grpc://127.0.0.1:53547/engine", "mount_path": "Engine",
	})
	if status != http.StatusNotFound {
		t.Fatalf("non-member create module %d", status)
	}
	status, engineBody := apiJSON(t, http.MethodPost, srv+"/api/v1/projects/"+itoa(pid)+"/modules", carolTok, map[string]string{
		"name": "Engine", "repository_id": "0123456789abcdef0123456789abcdef", "repository_url": "grpc://127.0.0.1:53547/engine", "mount_path": "Engine",
	})
	if status != http.StatusCreated {
		t.Fatalf("engine %d %v", status, engineBody)
	}
	status, clientBody := apiJSON(t, http.MethodPost, srv+"/api/v1/projects/"+itoa(pid)+"/modules", carolTok, map[string]string{
		"name": "GameClient", "repository_id": "fedcba9876543210fedcba9876543210", "repository_url": "grpc://127.0.0.1:53547/gameclient", "mount_path": "GameClient",
	})
	if status != http.StatusCreated {
		t.Fatalf("client %d %v", status, clientBody)
	}
	engineID := int64(engineBody["ID"].(float64))
	clientID := int64(clientBody["ID"].(float64))
	for _, add := range []map[string]string{{"username": "alice", "role": "project_member"}, {"username": "bob", "role": "project_member"}, {"username": "dave", "role": "project_member"}} {
		status, body := apiJSON(t, http.MethodPost, srv+"/api/v1/projects/"+itoa(pid)+"/members", carolTok, add)
		if status != http.StatusCreated {
			t.Fatalf("member %v %d %v", add, status, body)
		}
	}
	status, _ = apiJSON(t, http.MethodPost, srv+"/api/v1/modules/"+itoa(engineID)+"/permissions", carolTok, map[string]string{"username": "alice", "permission": "write"})
	if status != http.StatusOK {
		t.Fatalf("grant alice %d", status)
	}
	status, _ = apiJSON(t, http.MethodPost, srv+"/api/v1/modules/"+itoa(clientID)+"/permissions", carolTok, map[string]string{"username": "bob", "permission": "write"})
	if status != http.StatusOK {
		t.Fatalf("grant bob %d", status)
	}
	status, _ = apiJSON(t, http.MethodPost, srv+"/api/v1/modules/"+itoa(clientID)+"/permissions", aliceTok, map[string]string{"username": "alice", "permission": "write"})
	if status != http.StatusNotFound {
		t.Fatalf("alice grant %d", status)
	}

	aliceMods := moduleIDs(t, srv, aliceTok)
	if len(aliceMods) != 1 || aliceMods[0] != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("alice %v", aliceMods)
	}
	bobMods := moduleIDs(t, srv, bobTok)
	if len(bobMods) != 1 || bobMods[0] != "fedcba9876543210fedcba9876543210" {
		t.Fatalf("bob %v", bobMods)
	}
	if len(moduleIDs(t, srv, daveTok)) != 0 {
		t.Fatal("dave saw a module")
	}
	carolMods := moduleIDs(t, srv, carolTok)
	if len(carolMods) != 0 {
		t.Fatalf("admin must not receive parent or module lore access automatically: %v", carolMods)
	}

	status, _ = apiJSON(t, http.MethodDelete, srv+"/api/v1/modules/"+itoa(engineID)+"/permissions/"+itoa(alice), carolTok, nil)
	if status != http.StatusOK {
		t.Fatalf("revoke %d", status)
	}
	if len(moduleIDs(t, srv, aliceTok)) != 0 {
		t.Fatal("revoked token source still lists engine")
	}

	drv := &apiDriver{local: map[string]string{"parent": "p1", "engine": "e1", "client": "c1"}, remote: map[string]string{"parent": "p1"}}
	app.PublishDriver = drv
	status, pubBody := apiJSON(t, http.MethodPost, srv+"/api/v1/projects/"+itoa(pid)+"/publish", aliceTok, map[string]any{
		"parent_dir": "parent", "module_dirs": map[string]string{"Engine": "engine", "GameClient": "client"},
	})
	if status != http.StatusForbidden {
		t.Fatalf("member publish %d", status)
	}
	status, pubBody = apiJSON(t, http.MethodPost, srv+"/api/v1/projects/"+itoa(pid)+"/publish", carolTok, map[string]any{
		"parent_dir": "parent", "module_dirs": map[string]string{"Engine": "engine", "GameClient": "client"},
	})
	if status != http.StatusOK {
		t.Fatalf("publish %d %v", status, pubBody)
	}
	if drv.links["Engine"] != "e1" || drv.links["GameClient"] != "c1" {
		t.Fatalf("pins %v", drv.links)
	}
	_ = ctx
}

func makeAcct(t *testing.T, app *App, name string) int64 {
	t.Helper()
	id, err := user.Create(context.Background(), app.DB, "test", name, "correct-horse", "user")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func apiJSON(t *testing.T, method, url, token string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, url, &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func moduleIDs(t *testing.T, srv, token string) []string {
	t.Helper()
	status, body := apiJSON(t, http.MethodGet, srv+"/api/v1/me/modules", token, nil)
	if status != http.StatusOK {
		t.Fatalf("modules %d %v", status, body)
	}
	raw, _ := body["modules"].([]any)
	var ids []string
	for _, item := range raw {
		m := item.(map[string]any)
		ids = append(ids, m["RepositoryID"].(string))
	}
	return ids
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

type apiDriver struct {
	local  map[string]string
	remote map[string]string
	links  map[string]string
	next   int
}

func (m *apiDriver) Revisions(_ context.Context, dir string) (string, string, error) {
	return m.local[dir], m.remote[dir], nil
}

func (m *apiDriver) Links(context.Context, string) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range m.links {
		out[k] = v
	}
	return out, nil
}

func (m *apiDriver) EnsureLink(_ context.Context, _, mount, _, revision string) error {
	if m.links == nil {
		m.links = map[string]string{}
	}
	m.links[mount] = revision
	return nil
}

func (m *apiDriver) RemoveLink(_ context.Context, _, mount string) error {
	delete(m.links, mount)
	return nil
}

func (m *apiDriver) Commit(context.Context, string, string) error { return nil }

func (m *apiDriver) FindOperation(context.Context, string, int64) (bool, string, map[string]string, error) {
	return false, "", nil, nil
}

func (m *apiDriver) Push(context.Context, string) error {
	m.next++
	rev := "p" + strconv.Itoa(m.next)
	m.local["parent"] = rev
	m.remote["parent"] = rev
	return nil
}
