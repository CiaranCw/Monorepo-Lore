package permission

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"lore-monorepo/internal/database"
	"lore-monorepo/internal/project"
	"lore-monorepo/internal/user"
)

func TestPermissionMatrix(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	alice := makeUser(t, db, "alice")
	bob := makeUser(t, db, "bob")
	carol := makeUser(t, db, "carol")
	dave := makeUser(t, db, "dave")
	alpha := makeProject(t, db, carol, "Alpha", "00112233445566778899aabbccddeeff")
	beta := makeProject(t, db, carol, "Beta", "ffeeddccbbaa99887766554433221100")
	engine := makeModule(t, db, alpha, "Engine", "0123456789abcdef0123456789abcdef", "Engine")
	client := makeModule(t, db, alpha, "GameClient", "fedcba9876543210fedcba9876543210", "GameClient")
	foreign := makeModule(t, db, beta, "Foreign", "abcdef0123456789abcdef0123456789", "Foreign")
	if err := project.AddMember(ctx, db, "test", alpha, carol, project.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := project.AddMember(ctx, db, "carol", alpha, alice, project.RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := project.AddMember(ctx, db, "carol", alpha, bob, project.RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := project.SetModulePermission(ctx, db, "carol", alice, engine, project.PermWrite); err != nil {
		t.Fatal(err)
	}
	if err := project.SetModulePermission(ctx, db, "carol", bob, client, project.PermRead); err != nil {
		t.Fatal(err)
	}
	svc := Service{DB: db}
	if err := svc.CanManageProject(ctx, carol, alpha); err != nil {
		t.Fatal(err)
	}
	if err := svc.CanManageProject(ctx, alice, alpha); !errors.Is(err, ErrDenied) {
		t.Fatalf("member manage %v", err)
	}
	if err := svc.CanManageProject(ctx, dave, alpha); !errors.Is(err, ErrDenied) {
		t.Fatalf("stranger manage %v", err)
	}
	if err := svc.CanWriteModule(ctx, alice, engine); err != nil {
		t.Fatal(err)
	}
	if err := svc.CanWriteModule(ctx, alice, client); !errors.Is(err, ErrDenied) {
		t.Fatalf("alice client %v", err)
	}
	if err := svc.CanReadModule(ctx, bob, client); err != nil {
		t.Fatal(err)
	}
	if err := svc.CanWriteModule(ctx, bob, client); !errors.Is(err, ErrDenied) {
		t.Fatalf("bob write %v", err)
	}
	if err := svc.CanReadModule(ctx, dave, engine); !errors.Is(err, ErrDenied) {
		t.Fatalf("dave %v", err)
	}
	if err := svc.CanReadModule(ctx, alice, foreign); !errors.Is(err, ErrDenied) {
		t.Fatalf("cross project %v", err)
	}
	ids, err := svc.RepositoryIDs(ctx, alice)
	if err != nil || len(ids) != 1 || ids[0] != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("alice repos %v %v", ids, err)
	}
	if err := project.ArchiveModule(ctx, db, "carol", engine); err != nil {
		t.Fatal(err)
	}
	if err := svc.CanReadModule(ctx, alice, engine); !errors.Is(err, ErrDenied) {
		t.Fatalf("archived %v", err)
	}
	ids, err = svc.RepositoryIDs(ctx, alice)
	if err != nil || len(ids) != 0 {
		t.Fatalf("archived still listed %v %v", ids, err)
	}
	if err := project.SetModulePermission(ctx, db, "carol", alice, client, project.PermWrite); err != nil {
		t.Fatal(err)
	}
	if err := svc.CanWriteModule(ctx, alice, client); err != nil {
		t.Fatal(err)
	}
	if err := user.SetStatus(ctx, db, "carol", "alice", "disabled"); err != nil {
		t.Fatal(err)
	}
	if ids, err = svc.RepositoryIDs(ctx, alice); err != nil || len(ids) != 0 {
		t.Fatalf("disabled repos %v %v", ids, err)
	}
	if err := svc.CanWriteModule(ctx, alice, client); !errors.Is(err, user.ErrDisabled) {
		t.Fatalf("disabled write %v", err)
	}
	_ = bob
}

func TestServiceAccountSeesParentAndArchivedModules(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	admin := makeUser(t, db, "carol")
	svc, err := user.Create(ctx, db, "test", "publisher", "correct-horse", "service")
	if err != nil {
		t.Fatal(err)
	}
	alpha := makeProject(t, db, admin, "Alpha", "00112233445566778899aabbccddeeff")
	engine := makeModule(t, db, alpha, "Engine", "0123456789abcdef0123456789abcdef", "Engine")
	if err := project.ArchiveModule(ctx, db, "carol", engine); err != nil {
		t.Fatal(err)
	}
	s := Service{DB: db}
	human, err := s.RepositoryIDs(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(human) != 0 {
		t.Fatalf("project admin resources %v", human)
	}
	ids, err := s.RepositoryIDs(ctx, svc)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, id := range ids {
		got[id] = true
	}
	if !got["00112233445566778899aabbccddeeff"] || !got["0123456789abcdef0123456789abcdef"] {
		t.Fatalf("service resources %v", ids)
	}
}

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func makeUser(t *testing.T, db *sql.DB, name string) int64 {
	t.Helper()
	id, err := user.Create(context.Background(), db, "test", name, "correct-horse", "user")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func makeProject(t *testing.T, db *sql.DB, owner int64, name, parent string) int64 {
	t.Helper()
	p, err := project.CreateProject(context.Background(), db, "test", project.Project{
		Name: name, ParentRepositoryID: parent, ParentRepositoryURL: "grpc://127.0.0.1:53547/" + name, CreatedBy: owner,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p.ID
}

func makeModule(t *testing.T, db *sql.DB, projectID int64, name, repo, mount string) int64 {
	t.Helper()
	m, err := project.CreateModule(context.Background(), db, "test", project.Module{
		ProjectID: projectID, Name: name, RepositoryID: repo, RepositoryURL: "grpc://127.0.0.1:53547/" + name, MountPath: mount,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m.ID
}

func TestListAccessibleModulesIncludesRecordedDefaultBranch(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	carol := makeUser(t, db, "carol")
	alice := makeUser(t, db, "alice")
	proj := makeProject(t, db, carol, "Alpha", "00112233445566778899aabbccddeeff")
	if err := project.AddMember(ctx, db, "carol", proj, alice, project.RoleMember); err != nil {
		t.Fatal(err)
	}
	mod := makeModule(t, db, proj, "Engine", "0123456789abcdef0123456789abcdef", "Engine")
	if err := project.SetModulePermission(ctx, db, "carol", alice, mod, project.PermWrite); err != nil {
		t.Fatal(err)
	}
	rev := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := db.Exec(`INSERT INTO module_refs(module_id, ref_type, ref_name, lore_revision, is_default) VALUES (?, 'branch', 'master', ?, 1)`, mod, rev); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO module_refs(module_id, ref_type, ref_name, lore_revision, is_default) VALUES (?, 'branch', 'main', ?, 0)`, mod, rev); err != nil {
		t.Fatal(err)
	}
	mods, err := (Service{DB: db}).ListAccessibleModules(ctx, alice)
	if err != nil || len(mods) != 1 || mods[0].DefaultBranch != "master" {
		t.Fatalf("default branch %+v %v", mods, err)
	}
}
