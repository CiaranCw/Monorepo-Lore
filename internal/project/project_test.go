package project

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"lore-monorepo/internal/database"
)

const (
	rootID  = "01a1bfb55b9d7370963a8d96d542029e"
	alphaID = "01a1bfb55aef76a1a0502a40f6727643"
	betaID  = "01a1bfb55b3471f3b9c911d692c1be24"
	base    = "grpcs://127.0.0.1:52737/"
)

func setup(t *testing.T) (*sql.DB, int64) {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	res, err := db.Exec(`INSERT INTO users(username, password_hash, kind) VALUES ('svc-manager','x','service')`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return db, id
}

func mustProject(t *testing.T, db *sql.DB, uid int64) *Project {
	t.Helper()
	p, err := CreateProject(context.Background(), db, "test", Project{Name: "Project-A",
		ParentRepositoryID: rootID, ParentRepositoryURL: base + "project-a-root", CreatedBy: uid})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func audits(t *testing.T, db *sql.DB, action string) int {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action=?`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestProjectCRUD(t *testing.T) {
	ctx := context.Background()
	db, uid := setup(t)
	p := mustProject(t, db, uid)
	if p.ID == 0 || p.ParentRepositoryID != rootID || p.CreatedAt == "" {
		t.Fatalf("bad project %+v", p)
	}
	got, err := GetProject(ctx, db, "Project-A")
	if err != nil || got.ID != p.ID {
		t.Fatalf("get: %v %+v", err, got)
	}
	if _, err := GetProject(ctx, db, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	// duplicate name and duplicate parent repository id are conflicts
	_, err = CreateProject(ctx, db, "test", Project{Name: "Project-A", ParentRepositoryID: betaID, ParentRepositoryURL: base + "x", CreatedBy: uid})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("dup name: %v", err)
	}
	_, err = CreateProject(ctx, db, "test", Project{Name: "Project-B", ParentRepositoryID: rootID, ParentRepositoryURL: base + "x", CreatedBy: uid})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("dup root id: %v", err)
	}
	// update name + url; id immutable by API
	n, u := "Project-A2", base+"project-a-root-moved"
	up, err := UpdateProject(ctx, db, "test", p.ID, ProjectUpdate{Name: &n, ParentRepositoryURL: &u})
	if err != nil || up.Name != n || up.ParentRepositoryURL != u || up.ParentRepositoryID != rootID {
		t.Fatalf("update: %v %+v", err, up)
	}
	if _, err := UpdateProject(ctx, db, "test", p.ID, ProjectUpdate{}); err != nil {
		t.Fatalf("no-op update: %v", err)
	}
	bad := "has space"
	if _, err := UpdateProject(ctx, db, "test", p.ID, ProjectUpdate{Name: &bad}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad name: %v", err)
	}
	list, err := ListProjects(ctx, db)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %d", err, len(list))
	}
	if audits(t, db, "project_create") != 1 || audits(t, db, "project_update") != 1 {
		t.Fatal("audit records missing or duplicated")
	}
}

func TestNameAllowsLeadingDigit(t *testing.T) {
	if err := ValidateName("2199"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateName("-2199"); err == nil {
		t.Fatal("leading hyphen accepted")
	}
}

func TestProjectValidation(t *testing.T) {
	ctx := context.Background()
	db, uid := setup(t)
	cases := []Project{
		{Name: "", ParentRepositoryID: rootID, ParentRepositoryURL: base + "r"},
		{Name: "P", ParentRepositoryID: "XYZ", ParentRepositoryURL: base + "r"},
		{Name: "P", ParentRepositoryID: "01A1BFB55B9D7370963A8D96D542029E", ParentRepositoryURL: base + "r"}, // upper-case hex
		{Name: "P", ParentRepositoryID: rootID, ParentRepositoryURL: "https://127.0.0.1/r"},
		{Name: "P", ParentRepositoryID: rootID, ParentRepositoryURL: "grpcs://u:p@127.0.0.1/r"},
		{Name: "P", ParentRepositoryID: rootID, ParentRepositoryURL: "grpcs://127.0.0.1/a/b"},
		{Name: "P", ParentRepositoryID: rootID, ParentRepositoryURL: "grpcs://127.0.0.1/"},
	}
	for i, c := range cases {
		c.CreatedBy = uid
		if _, err := CreateProject(ctx, db, "test", c); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d: want ErrInvalid, got %v", i, err)
		}
	}
}

func TestMountPathRules(t *testing.T) {
	ok := map[string]string{"Alpha": "Alpha", "libs/core": "libs/core", "Beta/": "Beta"}
	for in, want := range ok {
		got, err := NormalizeMountPath(in)
		if err != nil || got != want {
			t.Errorf("%q: got %q %v", in, got, err)
		}
	}
	for _, in := range []string{"", "/abs", `win\path`, "a/../b", "./a", "a//b", ".lore", "x/.loreignore", "a/b/c/d/e", "-x", "a b"} {
		if _, err := NormalizeMountPath(in); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: want ErrInvalid, got %v", in, err)
		}
	}
	if !mountsOverlap("Alpha", "alpha") || !mountsOverlap("libs", "libs/core") || mountsOverlap("lib", "libs") {
		t.Error("overlap rules wrong")
	}
}

func TestModuleCRUDAndAssociation(t *testing.T) {
	ctx := context.Background()
	db, uid := setup(t)
	p := mustProject(t, db, uid)
	a, err := CreateModule(ctx, db, "test", Module{ProjectID: p.ID, Name: "alpha", RepositoryID: alphaID,
		RepositoryURL: base + "alpha", MountPath: "Alpha"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := CreateModule(ctx, db, "test", Module{ProjectID: p.ID, Name: "beta", RepositoryID: betaID,
		RepositoryURL: base + "beta", MountPath: "Beta/"})
	if err != nil || b.MountPath != "Beta" {
		t.Fatalf("beta: %v %+v", err, b)
	}
	// unknown project
	if _, err := CreateModule(ctx, db, "test", Module{ProjectID: 999, Name: "x", RepositoryID: "0123456789abcdef0123456789abcdef",
		RepositoryURL: base + "x", MountPath: "X"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown project: %v", err)
	}
	conflicts := []Module{
		{Name: "alpha", RepositoryID: "0123456789abcdef0123456789abcdef", MountPath: "Other"}, // dup name
		{Name: "gamma", RepositoryID: alphaID, MountPath: "Gamma"},                            // dup repo id
		{Name: "gamma", RepositoryID: rootID, MountPath: "Gamma"},                             // project root id reused as module
		{Name: "gamma", RepositoryID: "0123456789abcdef0123456789abcdef", MountPath: "alpha"}, // case-insensitive mount clash
		{Name: "gamma", RepositoryID: "0123456789abcdef0123456789abcdef", MountPath: "Alpha/sub"},
	}
	for i, c := range conflicts {
		c.ProjectID, c.RepositoryURL = p.ID, base+"gamma"
		if _, err := CreateModule(ctx, db, "test", c); !errors.Is(err, ErrConflict) {
			t.Errorf("conflict case %d: got %v", i, err)
		}
	}
	// a project root cannot reuse a module repository id either
	if _, err := CreateProject(ctx, db, "test", Project{Name: "Project-B", ParentRepositoryID: alphaID,
		ParentRepositoryURL: base + "pb", CreatedBy: uid}); !errors.Is(err, ErrConflict) {
		t.Fatalf("root reusing module id: %v", err)
	}
	got, err := GetModule(ctx, db, p.ID, "alpha")
	if err != nil || got.ID != a.ID || got.RepositoryID != alphaID {
		t.Fatalf("get: %v %+v", err, got)
	}
	mods, err := ListModules(ctx, db, p.ID, false)
	if err != nil || len(mods) != 2 || mods[0].MountPath != "Alpha" || mods[1].MountPath != "Beta" {
		t.Fatalf("list: %v %+v", err, mods)
	}
	// update mount path: overlap rejected, valid move accepted
	clash := "Beta/inner"
	if _, err := UpdateModule(ctx, db, "test", a.ID, ModuleUpdate{MountPath: &clash}); !errors.Is(err, ErrConflict) {
		t.Fatalf("mount clash on update: %v", err)
	}
	mv, url := "modules/Alpha", base+"alpha-renamed"
	up, err := UpdateModule(ctx, db, "test", a.ID, ModuleUpdate{MountPath: &mv, RepositoryURL: &url})
	if err != nil || up.MountPath != mv || up.RepositoryURL != url || up.RepositoryID != alphaID {
		t.Fatalf("update: %v %+v", err, up)
	}
	same := "Beta"
	if _, err := UpdateModule(ctx, db, "test", b.ID, ModuleUpdate{MountPath: &same}); err != nil {
		t.Fatalf("same mount must be a no-op: %v", err)
	}
	// resolve
	role, rp, rm, err := ResolveRepository(ctx, db, alphaID)
	if err != nil || role != RoleModule || rp.ID != p.ID || rm.ID != a.ID {
		t.Fatalf("resolve module: %v %v", role, err)
	}
	role, rp, _, err = ResolveRepository(ctx, db, rootID)
	if err != nil || role != RoleProjectRoot || rp.ID != p.ID {
		t.Fatalf("resolve root: %v %v", role, err)
	}
	if role, _, _, err = ResolveRepository(ctx, db, "0123456789abcdef0123456789abcdef"); err != nil || role != RoleUnknown {
		t.Fatalf("resolve unknown: %v %v", role, err)
	}
	// archive: no longer resolvable, not updatable, repo id stays reserved, mount freed
	if err := ArchiveModule(ctx, db, "test", a.ID); err != nil {
		t.Fatal(err)
	}
	if err := ArchiveModule(ctx, db, "test", a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double archive: %v", err)
	}
	if role, _, _, _ = ResolveRepository(ctx, db, alphaID); role != RoleUnknown {
		t.Fatal("archived module must not resolve")
	}
	if _, err := UpdateModule(ctx, db, "test", a.ID, ModuleUpdate{MountPath: &mv}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("update archived: %v", err)
	}
	if _, err := CreateModule(ctx, db, "test", Module{ProjectID: p.ID, Name: "alpha2", RepositoryID: alphaID,
		RepositoryURL: base + "alpha", MountPath: "Alpha"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("archived repo id must stay reserved: %v", err)
	}
	if _, err := CreateModule(ctx, db, "test", Module{ProjectID: p.ID, Name: "alpha2", RepositoryID: "0123456789abcdef0123456789abcdef",
		RepositoryURL: base + "alpha2", MountPath: "modules/Alpha"}); err != nil {
		t.Fatalf("mount of archived module must be reusable: %v", err)
	}
	if mods, _ = ListModules(ctx, db, p.ID, true); len(mods) != 3 {
		t.Fatalf("list incl archived: %d", len(mods))
	}
	if audits(t, db, "module_create") != 3 || audits(t, db, "module_update") != 1 || audits(t, db, "module_archive") != 1 {
		t.Fatal("module audit counts wrong")
	}
}

func TestReactivateArchivedModuleRestoresMount(t *testing.T) {
	ctx := context.Background()
	db, uid := setup(t)
	p := mustProject(t, db, uid)
	mod, err := CreateModule(ctx, db, "test", Module{ProjectID: p.ID, Name: "Engine", RepositoryID: alphaID, RepositoryURL: base + "alpha", MountPath: "Engine"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ArchiveModule(ctx, db, "test", mod.ID); err != nil {
		t.Fatal(err)
	}
	if err := ReactivateModule(ctx, db, "test", mod.ID, "Engine"); err != nil {
		t.Fatal(err)
	}
	got, err := GetModuleByID(ctx, db, mod.ID)
	if err != nil || got.Archived() || got.MountPath != "Engine" {
		t.Fatalf("reactivated module %+v err=%v", got, err)
	}
	if _, err := CreateModule(ctx, db, "test", Module{ProjectID: p.ID, Name: "Other", RepositoryID: betaID, RepositoryURL: base + "beta", MountPath: "Engine"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("reactivated mount must be reserved, got %v", err)
	}
}
