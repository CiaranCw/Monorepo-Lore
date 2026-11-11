package gitimport

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestHistoricalDirectoryMergeAndConflicts(t *testing.T) {
	ctx := context.Background()
	gitBin := findRealGit(t)
	root := t.TempDir()
	repo := filepath.Join(root, "src")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	g := gitExecHelper{t: t, bin: gitBin, dir: repo}
	g.run(nil, "init", "-b", "main")
	write := func(rel, body string) {
		t.Helper()
		full := filepath.Join(repo, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("Games/OldName/README.md", "old readme\n")
	write("Games/OldName/src/main.txt", "v1\n")
	write("notes/root.txt", "outside\n")
	g.run(nil, "add", ".")
	oldSHA := g.commitAs("Ada", "ada@example.com", "2024-01-01T00:00:00Z", "create old game", false)

	if err := os.Rename(filepath.Join(repo, "Games", "OldName"), filepath.Join(repo, "Games", "NewName")); err != nil {
		t.Fatal(err)
	}
	write("Games/NewName/src/main.txt", "v2\n")
	g.run(nil, "add", "-A")
	renameSHA := g.commitAs("Ada", "ada@example.com", "2024-01-02T00:00:00Z", "rename game", false)
	write("Games/NewName/docs/guide.md", "kept inside the game\n")
	g.run(nil, "add", ".")
	_ = g.commitAs("Ada", "ada@example.com", "2024-01-03T00:00:00Z", "add game doc", false)

	bare := filepath.Join(root, "mirror.git")
	g.run(nil, "clone", "--bare", repo, bare)
	graph, err := ReadMirrorGraph(ctx, gitBin, bare, "main")
	if err != nil {
		t.Fatal(err)
	}
	rules := []PathRule{{Pattern: "notes/**", Category: PathCategoryExcluded, Reason: "repository notes are not a game"}}
	maps := []PathMapping{
		{ID: "current", SourcePrefix: "Games/NewName", Kind: MappingTree, ProjectionType: ProjectionNormal},
		{ID: "old", SourcePrefix: "Games/OldName", TargetPrefix: "", Kind: MappingTree, ProjectionType: ProjectionRename},
	}
	pg, err := ProjectMirrorGraph(ctx, gitBin, bare, graph, "Games/NewName", nil, rules, NewTreeCache(), maps, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pg.Commits) != 3 {
		t.Fatalf("rename history must stay in one module, got %d commits", len(pg.Commits))
	}
	if _, ok := pg.CommitsBySHA[oldSHA]; !ok {
		t.Fatal("pre-rename commit was dropped")
	}
	if _, ok := pg.CommitsBySHA[renameSHA]; !ok {
		t.Fatal("rename commit was dropped")
	}
	if !pg.CoverageComplete {
		t.Fatalf("notes should be excluded, undecided=%v", pg.UndecidedPaths)
	}

	// Same commit touching old and new paths with different bytes at one target is a conflict.
	conflictRepo := filepath.Join(root, "conflict")
	if err := os.MkdirAll(conflictRepo, 0o755); err != nil {
		t.Fatal(err)
	}
	cg := gitExecHelper{t: t, bin: gitBin, dir: conflictRepo}
	cg.run(nil, "init", "-b", "main")
	writeConflict := func(rel, body string) {
		full := filepath.Join(conflictRepo, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeConflict("Old/a.txt", "left\n")
	writeConflict("New/a.txt", "right\n")
	cg.run(nil, "add", ".")
	cg.commitAs("Ada", "ada@example.com", "2024-02-01T00:00:00Z", "both names", false)
	cbare := filepath.Join(root, "conflict.git")
	cg.run(nil, "clone", "--bare", conflictRepo, cbare)
	cgraph, err := ReadMirrorGraph(ctx, gitBin, cbare, "main")
	if err != nil {
		t.Fatal(err)
	}
	_, err = ProjectMirrorGraph(ctx, gitBin, cbare, cgraph, "New", nil, nil, NewTreeCache(), []PathMapping{
		{ID: "new", SourcePrefix: "New", Kind: MappingTree, ProjectionType: ProjectionNormal},
		{ID: "old", SourcePrefix: "Old", Kind: MappingTree, ProjectionType: ProjectionRename},
	}, nil)
	if err == nil {
		t.Fatal("different bytes mapped to the same path must conflict")
	}

	// Identical bytes dedupe instead of conflicting.
	sameRepo := filepath.Join(root, "same")
	if err := os.MkdirAll(sameRepo, 0o755); err != nil {
		t.Fatal(err)
	}
	sg := gitExecHelper{t: t, bin: gitBin, dir: sameRepo}
	sg.run(nil, "init", "-b", "main")
	writeSame := func(rel, body string) {
		full := filepath.Join(sameRepo, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeSame("Old/a.txt", "same\n")
	writeSame("New/a.txt", "same\n")
	sg.run(nil, "add", ".")
	sg.commitAs("Ada", "ada@example.com", "2024-03-01T00:00:00Z", "duplicate bytes", false)
	sbare := filepath.Join(root, "same.git")
	sg.run(nil, "clone", "--bare", sameRepo, sbare)
	sgraph, err := ReadMirrorGraph(ctx, gitBin, sbare, "main")
	if err != nil {
		t.Fatal(err)
	}
	spg, err := ProjectMirrorGraph(ctx, gitBin, sbare, sgraph, "New", nil, nil, NewTreeCache(), []PathMapping{
		{ID: "new", SourcePrefix: "New", Kind: MappingTree, ProjectionType: ProjectionNormal},
		{ID: "old", SourcePrefix: "Old", Kind: MappingTree, ProjectionType: ProjectionRename},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if spg.IdenticalPathMerges == 0 || len(spg.Commits) != 1 {
		t.Fatalf("identical mapped paths should dedupe into one revision, merges=%d commits=%d", spg.IdenticalPathMerges, len(spg.Commits))
	}
}

func TestFileMappingDoesNotImportWholePackage(t *testing.T) {
	ctx := context.Background()
	gitBin := findRealGit(t)
	root := t.TempDir()
	repo := filepath.Join(root, "src")
	g := gitExecHelper{t: t, bin: gitBin, dir: repo}
	if err := os.MkdirAll(filepath.Join(repo, "Game", "public", "models"), 0o755); err != nil {
		t.Fatal(err)
	}
	g.run(nil, "init", "-b", "main")
	body := []byte("model-bytes\n")
	if err := os.MkdirAll(filepath.Join(repo, "Pkg", "models"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "Pkg", "models", "face.task"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "Pkg", "bundle.js"), []byte("bundle\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "Game", "README.md"), []byte("game readme\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g.run(nil, "add", ".")
	g.commitAs("Ada", "ada@example.com", "2024-04-01T00:00:00Z", "package and game", false)
	if err := os.WriteFile(filepath.Join(repo, "Game", "public", "models", "face.task"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(repo, "Pkg")); err != nil {
		t.Fatal(err)
	}
	g.run(nil, "add", "-A")
	g.commitAs("Ada", "ada@example.com", "2024-04-02T00:00:00Z", "move model into game", false)
	bare := filepath.Join(root, "mirror.git")
	g.run(nil, "clone", "--bare", repo, bare)
	graph, err := ReadMirrorGraph(ctx, gitBin, bare, "main")
	if err != nil {
		t.Fatal(err)
	}
	rules := []PathRule{{Pattern: "Pkg/**", Category: PathCategoryExcluded, Reason: "generated package"}}
	pg, err := ProjectMirrorGraph(ctx, gitBin, bare, graph, "Game", nil, rules, NewTreeCache(), []PathMapping{
		{ID: "game", SourcePrefix: "Game", Kind: MappingTree, ProjectionType: ProjectionNormal},
		{ID: "model", SourcePrefix: "Pkg/models/face.task", TargetPrefix: "public/models/face.task", Kind: MappingFile, ProjectionType: ProjectionFileMove},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pg.Commits) != 1 {
		t.Fatalf("moving an already mapped file into its target path must not create a second revision, got %d", len(pg.Commits))
	}
	if !pg.CoverageComplete {
		t.Fatalf("package bundle should be excluded, undecided=%v", pg.UndecidedPaths)
	}
	if len(graph.Commits) < 2 {
		t.Fatal("source history should contain the move commit")
	}
}

func TestDeletedGameDoesNotCreateModuleHistory(t *testing.T) {
	ctx := context.Background()
	gitBin := findRealGit(t)
	root := t.TempDir()
	repo := filepath.Join(root, "src")
	g := gitExecHelper{t: t, bin: gitBin, dir: repo}
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	g.run(nil, "init", "-b", "main")
	if err := os.MkdirAll(filepath.Join(repo, "Gone"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "Gone", "main.txt"), []byte("gone\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "Kept"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "Kept", "main.txt"), []byte("kept\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g.run(nil, "add", ".")
	g.commitAs("Ada", "ada@example.com", "2024-05-01T00:00:00Z", "both games", false)
	if err := os.RemoveAll(filepath.Join(repo, "Gone")); err != nil {
		t.Fatal(err)
	}
	g.run(nil, "add", "-A")
	g.commitAs("Ada", "ada@example.com", "2024-05-02T00:00:00Z", "delete gone", false)
	bare := filepath.Join(root, "mirror.git")
	g.run(nil, "clone", "--bare", repo, bare)
	graph, err := ReadMirrorGraph(ctx, gitBin, bare, "main")
	if err != nil {
		t.Fatal(err)
	}
	rules := []PathRule{{Pattern: "Gone/**", Category: PathCategoryExcluded, Reason: "deleted game with no successor"}}
	pg, err := ProjectMirrorGraph(ctx, gitBin, bare, graph, "Kept", nil, rules, NewTreeCache(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pg.Commits) != 1 {
		t.Fatalf("kept game has one content revision, got %d", len(pg.Commits))
	}
	if !pg.CoverageComplete {
		t.Fatalf("deleted game paths must be excluded, undecided=%v", pg.UndecidedPaths)
	}
}
