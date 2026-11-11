package history

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"lore-monorepo/internal/loreadapter"
	"lore-monorepo/internal/loreexec"
	"lore-monorepo/internal/lorejson"
	"lore-monorepo/internal/project"
	"lore-monorepo/internal/user"
)

type flexibleLoreRunner struct {
	localBranches  string
	remoteBranches string
	failLocal      bool
	failRemote     bool
	noRemote       bool
	defaultBranch  string
	pages          map[string]string
}

func (f *flexibleLoreRunner) Run(_ context.Context, req loreexec.Request) (loreexec.CommandResult, error) {
	completeOK := `{"tagName":"complete","data":{"status":0,"error":{"errorCode":0,"message":"","traceLocations":[]}}}` + "\n"
	failErr := `{"tagName":"log","data":{"level":"error","category":0,"timestamp":1,"location":"lore","message":"Disconnected from server"}}` + "\n" +
		`{"tagName":"complete","data":{"status":28,"error":{"errorCode":28,"message":"Disconnected from server","traceLocations":[]}}}` + "\n"
	noRemoteErr := `{"tagName":"log","data":{"level":"error","category":0,"timestamp":1,"location":"lore","message":"No remote configured"}}` + "\n" +
		`{"tagName":"complete","data":{"status":111,"error":{"errorCode":111,"message":"No remote configured","traceLocations":[]}}}` + "\n"

	var out string
	exitCode := 0

	switch {
	case containsToken(req.Argv, "--local") && containsToken(req.Argv, "branch") && containsToken(req.Argv, "list"):
		if f.failLocal {
			out, exitCode = failErr, 28
		} else {
			out = f.localBranches + completeOK
		}
	case containsToken(req.Argv, "--remote") && containsToken(req.Argv, "branch") && containsToken(req.Argv, "list"):
		if f.failRemote {
			out, exitCode = failErr, 28
		} else if f.noRemote {
			out, exitCode = noRemoteErr, 111
		} else {
			out = f.remoteBranches + completeOK
		}
	case containsToken(req.Argv, "repository") && containsToken(req.Argv, "metadata") && containsToken(req.Argv, "get"):
		def := f.defaultBranch
		if def == "" {
			def = "main"
		}
		out = fmt.Sprintf(`{"tagName":"metadata","data":{"key":"default-branch-name","value":{"tagName":"string","data":%q}}}`+"\n", def) + completeOK
	case containsToken(req.Argv, "history"):
		var rev string
		for _, a := range req.Argv {
			if len(a) == 64 {
				rev = a
			}
		}
		out = f.pages[rev] + completeOK
	default:
		out = completeOK
	}

	res := loreexec.CommandResult{ExitCode: exitCode, Started: true, Stdout: out}
	res.StdoutParse = lorejson.Parse(lorejson.Stdout, out)
	res.Findings = lorejson.Classify(res.StdoutParse)
	return res, nil
}

func TestSyncModuleReliabilityBranchFailuresDefaultMasterPruningAndBoundaryMerge(t *testing.T) {
	ctx := context.Background()
	db := openHistoryTestDB(t)
	uid, _ := user.Create(ctx, db, "test", "alice", "correct-horse", "user")
	proj, _ := project.CreateProject(ctx, db, "alice", project.Project{
		Name: "RelProj", ParentRepositoryID: "00112233445566778899aabbccddeeff",
		ParentRepositoryURL: "grpc://127.0.0.1:53547/rel", CreatedBy: uid,
	})
	_ = project.AddMember(ctx, db, "alice", proj.ID, uid, project.RoleAdmin)
	mod, _ := project.CreateModule(ctx, db, "alice", project.Module{
		ProjectID: proj.ID, Name: "Engine", RepositoryID: "0123456789abcdef0123456789abcdef",
		RepositoryURL: "grpc://127.0.0.1:53547/engine", MountPath: "Engine",
	})
	_ = project.SetModulePermission(ctx, db, "alice", uid, mod.ID, project.PermWrite)

	rev1 := hex64(1)
	rev2 := hex64(2)
	revSide := hex64(3)
	revMerge := hex64(4)

	makeEntry := func(rev string, num int, p0, p1 string, ts int64, msg string) string {
		if p0 == "" {
			p0 = zeroHash64
		}
		if p1 == "" {
			p1 = zeroHash64
		}
		return fmt.Sprintf(`{"tagName":"revisionHistoryEntry","data":{"revision":%q,"revisionNumber":%d,"parent":[%q,%q]}}`+"\n"+
			`{"tagName":"metadata","data":{"key":"timestamp","value":{"tagName":"numeric","data":%d}}}`+"\n"+
			`{"tagName":"metadata","data":{"key":"created-by","value":{"tagName":"string","data":"1"}}}`+"\n"+
			`{"tagName":"metadata","data":{"key":"committed-by","value":{"tagName":"string","data":"1"}}}`+"\n"+
			`{"tagName":"metadata","data":{"key":"message","value":{"tagName":"string","data":%q}}}`+"\n",
			rev, num, p0, p1, ts, msg)
	}

	// 1. Both local & remote branch lists fail -> MUST return ErrBranchDiscovery (never silent success)!
	badRunner := &flexibleLoreRunner{failLocal: true, failRemote: true}
	if _, err := SyncModuleFromLore(ctx, db, &loreadapter.Client{Exec: badRunner}, mod.ID, t.TempDir()); !errors.Is(err, ErrBranchDiscovery) {
		t.Fatalf("expected ErrBranchDiscovery when local branch list fails, got %v", err)
	}

	// 2. Remote branch list fails with network error (NOT "No remote configured") -> MUST fail closed!
	partialFailRunner := &flexibleLoreRunner{
		localBranches: fmt.Sprintf(`{"tagName":"branchListEntry","data":{"id":"b1","name":"master","latest":%q,"isCurrent":1,"archived":false}}`+"\n", rev1),
		failRemote:    true,
	}
	if _, err := SyncModuleFromLore(ctx, db, &loreadapter.Client{Exec: partialFailRunner}, mod.ID, t.TempDir()); !errors.Is(err, ErrBranchDiscovery) {
		t.Fatalf("expected ErrBranchDiscovery when remote branch list fails with Disconnected, got %v", err)
	}

	// 3. Offline repository (`No remote configured`) with `master` default branch + `feature/old` + tag `v1.0`:
	//    - `master` MUST be preserved as `is_default=true` (not overwritten to non-default!)
	//    - Tag `v1.0` seeded in `module_refs` MUST NOT be deleted by branch sync!
	tx, _ := db.BeginTx(ctx, nil)
	_ = UpsertRef(ctx, tx, RefDetail{
		ModuleID: mod.ID, Type: "tag", Name: "v1.0", LoreRevision: rev1, IsAnnotated: true, TagMessage: "keep me",
	})
	_ = tx.Commit()

	goodRunner := &flexibleLoreRunner{
		noRemote:      true,
		defaultBranch: "master",
		localBranches: fmt.Sprintf(`{"tagName":"branchListEntry","data":{"id":"b1","name":"master","latest":%q,"isCurrent":1,"archived":false}}`+"\n"+
			`{"tagName":"branchListEntry","data":{"id":"b2","name":"feature/old","latest":%q,"isCurrent":0,"archived":false}}`+"\n", rev1, rev2),
		pages: map[string]string{
			rev1: makeEntry(rev1, 1, "", "", 1750000001000, "c1"),
			rev2: makeEntry(rev2, 2, rev1, "", 1750000002000, "c2 on old feature") + makeEntry(rev1, 1, "", "", 1750000001000, "c1"),
		},
	}

	st1, err := SyncModuleFromLore(ctx, db, &loreadapter.Client{Exec: goodRunner}, mod.ID, t.TempDir())
	if err != nil || st1.BranchSource != "local_only" || st1.BranchesIndexed != 2 {
		t.Fatalf("sync 1 got %+v err=%v", st1, err)
	}

	svc := Service{DB: db}
	refs1, _ := svc.ListModuleRefs(ctx, uid, mod.ID, "")
	sawMasterDefault, sawFeatureOld, sawTag := false, false, false
	for _, r := range refs1 {
		if r.Type == "branch" && r.Name == "master" && r.IsDefault {
			sawMasterDefault = true
		}
		if r.Type == "branch" && r.Name == "feature/old" {
			sawFeatureOld = true
		}
		if r.Type == "tag" && r.Name == "v1.0" {
			sawTag = true
		}
	}
	if !sawMasterDefault || !sawFeatureOld || !sawTag {
		t.Fatalf("refs after sync 1 wrong: masterDef=%v featOld=%v tag=%v (%+v)", sawMasterDefault, sawFeatureOld, sawTag, refs1)
	}

	// 4. Archive `feature/old`, add `feature/new`, AND simulate an already-indexed merge commit `revMerge`
	//    whose second parent `revSide` was NOT yet indexed (boundary merge side-branch test!):
	tx2, _ := db.BeginTx(ctx, nil)
	_ = UpsertCommit(ctx, tx2, CommitInput{
		ModuleID: mod.ID, LoreRevision: revMerge, LoreRevisionNumber: 4, OriginKind: OriginNativeLore,
		AuthorName: "alice", CommittedUnixMS: 1750000004000, Message: "already indexed merge",
		Parents: []ParentLink{
			{Ord: 0, LoreRevision: rev1},
			{Ord: 1, LoreRevision: revSide}, // revSide is NOT in module_commits yet!
		},
	})
	_ = tx2.Commit()

	goodRunner.localBranches = fmt.Sprintf(
		`{"tagName":"branchListEntry","data":{"id":"b1","name":"master","latest":%q,"isCurrent":1,"archived":false}}`+"\n"+
			`{"tagName":"branchListEntry","data":{"id":"b2","name":"feature/old","latest":%q,"isCurrent":0,"archived":true}}`+"\n"+
			`{"tagName":"branchListEntry","data":{"id":"b3","name":"feature/new","latest":%q,"isCurrent":0,"archived":false}}`+"\n",
		revMerge, rev2, revMerge)
	goodRunner.pages[revSide] = makeEntry(revSide, 3, rev1, "", 1750000003000, "side commit behind known merge") +
		makeEntry(rev1, 1, "", "", 1750000001000, "c1")

	st2, err := SyncModuleFromLore(ctx, db, &loreadapter.Client{Exec: goodRunner}, mod.ID, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if st2.BranchesPruned != 1 {
		t.Fatalf("expected 1 archived branch pruned (feature/old), got %+v", st2)
	}
	if st2.CommitsUpserted != 1 {
		t.Fatalf("expected unindexed side branch commit revSide to be discovered & upserted (1), got %d", st2.CommitsUpserted)
	}

	// Verify `feature/old` is gone, `feature/new` is present, `master` is STILL `is_default=true`, and tag `v1.0` is STILL intact!
	refs2, _ := svc.ListModuleRefs(ctx, uid, mod.ID, "")
	var bNames []string
	masterStillDefault, tagStillPresent := false, false
	for _, r := range refs2 {
		if r.Type == "branch" {
			bNames = append(bNames, r.Name)
			if r.Name == "master" && r.IsDefault {
				masterStillDefault = true
			}
		}
		if r.Type == "tag" && r.Name == "v1.0" {
			tagStillPresent = true
		}
	}
	joinedB := strings.Join(bNames, ",")
	if strings.Contains(joinedB, "feature/old") || !strings.Contains(joinedB, "feature/new") || !masterStillDefault || !tagStillPresent {
		t.Fatalf("after branch archive/add: branches=%q masterDef=%v tag=%v", joinedB, masterStillDefault, tagStillPresent)
	}
}
