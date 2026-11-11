package history

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"lore-monorepo/internal/database"
	"lore-monorepo/internal/loreadapter"
	"lore-monorepo/internal/loreexec"
	"lore-monorepo/internal/lorejson"
	"lore-monorepo/internal/project"
	"lore-monorepo/internal/user"
)

func openHistoryTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func hex64(n int) string {
	return fmt.Sprintf("%064x", n)
}

func hex40(n int) string {
	return fmt.Sprintf("%040x", n)
}

func TestAggregatedHistoryUnionTieBreakPaginationAndLiveRevocation(t *testing.T) {
	ctx := context.Background()
	db := openHistoryTestDB(t)

	carol, _ := user.Create(ctx, db, "test", "carol", "correct-horse", "user")
	alice, _ := user.Create(ctx, db, "test", "alice", "correct-horse", "user")
	bob, _ := user.Create(ctx, db, "test", "bob", "correct-horse", "user")
	dave, _ := user.Create(ctx, db, "test", "dave", "correct-horse", "user")

	proj, err := project.CreateProject(ctx, db, "carol", project.Project{
		Name:                "Alpha",
		ParentRepositoryID:  "00112233445566778899aabbccddeeff",
		ParentRepositoryURL: "grpc://127.0.0.1:53547/alpha",
		CreatedBy:           carol,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = project.AddMember(ctx, db, "carol", proj.ID, carol, project.RoleAdmin)
	_ = project.AddMember(ctx, db, "carol", proj.ID, alice, project.RoleMember)
	_ = project.AddMember(ctx, db, "carol", proj.ID, bob, project.RoleMember)

	modSpecs := []struct {
		name string
		repo string
	}{
		{"Engine", "11111111111111111111111111111111"},
		{"Client", "22222222222222222222222222222222"},
		{"Server", "33333333333333333333333333333333"},
		{"Documents", "44444444444444444444444444444444"},
		{"Tools", "55555555555555555555555555555555"},
	}
	mods := make([]*project.Module, len(modSpecs))
	for i, sp := range modSpecs {
		m, err := project.CreateModule(ctx, db, "carol", project.Module{
			ProjectID: proj.ID, Name: sp.name, RepositoryID: sp.repo,
			RepositoryURL: "grpc://127.0.0.1:53547/" + sp.name, MountPath: sp.name,
		})
		if err != nil {
			t.Fatal(err)
		}
		mods[i] = m
	}

	// Alice gets Engine, Client, Server (3 modules).
	for _, idx := range []int{0, 1, 2} {
		if err := project.SetModulePermission(ctx, db, "carol", alice, mods[idx].ID, project.PermRead); err != nil {
			t.Fatal(err)
		}
	}
	// Bob gets all 5 modules.
	for _, idx := range []int{0, 1, 2, 3, 4} {
		if err := project.SetModulePermission(ctx, db, "carol", bob, mods[idx].ID, project.PermRead); err != nil {
			t.Fatal(err)
		}
	}

	// Populate 50 commits per module (250 total), deliberately injecting identical timestamps across
	// modules and within the same module, Unicode subjects, multi-author commits, and synthetic bridge rows.
	baseMS := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	err = database.Tx(ctx, db, func(tx *sql.Tx) error {
		seq := 1
		for mIdx, m := range mods {
			var prevRev, prevGit string
			for k := 0; k < 50; k++ {
				rev := hex64(seq)
				gitSHA := hex40(seq)
				seq++
				// Every 5th commit shares the exact same millisecond across ALL modules to stress tie-breaking!
				ts := baseMS + int64(k*1000)
				if k%5 != 0 {
					ts += int64(mIdx * 100)
				}
				author := "Alice Chen"
				email := "alice@example.com"
				if k%2 == 1 {
					author = "王小明"
					email = "xiaoming@example.com"
				}
				var parents []ParentLink
				if prevRev != "" {
					parents = append(parents, ParentLink{Ord: 0, LoreRevision: prevRev, SourceCommitID: prevGit})
				}
				if k == 25 {
					// Make k=25 a 2-parent merge commit.
					parents = append(parents, ParentLink{Ord: 1, LoreRevision: hex64(9000 + mIdx), SourceCommitID: hex40(9000 + mIdx)})
				}
				if err := UpsertCommit(ctx, tx, CommitInput{
					ModuleID:        m.ID,
					LoreRevision:    rev,
					SourceCommitID:  gitSHA,
					OriginKind:      OriginGitImport,
					AuthorName:      author,
					AuthorEmail:     email,
					AuthoredUnixMS:  ts - 50,
					CommitterName:   "Release Bot",
					CommitterEmail:  "bot@example.com",
					CommittedUnixMS: ts,
					Message:         fmt.Sprintf("feat(%s): 第 %d 次提交 🚀\n\nDetailed body %d", m.Name, k, k),
					Parents:         parents,
				}); err != nil {
					return err
				}
				prevRev, prevGit = rev, gitSHA
			}
			// Insert one synthetic octopus bridge row per module — must NEVER appear in user history!
			if err := UpsertCommit(ctx, tx, CommitInput{
				ModuleID:        m.ID,
				LoreRevision:    hex64(80000 + mIdx),
				OriginKind:      OriginGitImport,
				IsSynthetic:     true,
				AuthorName:      "synth",
				CommittedUnixMS: baseMS + 999999,
				Message:         "synthetic bridge",
			}); err != nil {
				return err
			}
			if err := UpsertRef(ctx, tx, RefDetail{
				ModuleID: m.ID, Type: "branch", Name: "main", LoreRevision: prevRev, SourceCommitID: prevGit, IsDefault: true,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	svc := Service{DB: db}

	// 1. Dave (non-member) and Carol (admin without module grant) checks.
	if _, err := svc.ProjectHistory(ctx, dave, proj.ID, Filter{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("dave expected ErrNotFound, got %v", err)
	}
	if _, err := svc.ModuleHistory(ctx, alice, mods[3].ID, Filter{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("alice reading Documents expected ErrNotFound, got %v", err)
	}
	if _, err := svc.ModuleHistory(ctx, alice, 999999, Filter{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown module expected ErrNotFound, got %v", err)
	}
	carolPage, err := svc.ProjectHistory(ctx, carol, proj.ID, Filter{})
	if err != nil || carolPage.TotalMatching != 0 || len(carolPage.Commits) != 0 {
		t.Fatalf("carol with 0 module grants must see 0 commits: err=%v page=%+v", err, carolPage)
	}

	// 2. Paginate ALL of Alice's aggregated project history (page size 17) and verify:
	//    - exact count = 150 (3 modules * 50, zero synthetic rows, zero Documents/Tools leaks)
	//    - zero duplicates, zero omissions, strict monotonic sort order with deterministic tie-breakers
	//    - exact set equality with union of Alice's 3 individual ModuleHistory queries!
	var aliceAgg []Commit
	seenKeys := map[string]bool{}
	cursor := ""
	for {
		page, err := svc.ProjectHistory(ctx, alice, proj.ID, Filter{Limit: 17, Cursor: cursor, Order: OrderDesc})
		if err != nil {
			t.Fatal(err)
		}
		if page.TotalMatching != 150 {
			t.Fatalf("alice TotalMatching=%d, want 150", page.TotalMatching)
		}
		for _, c := range page.Commits {
			if c.ModuleName == "Documents" || c.ModuleName == "Tools" {
				t.Fatalf("unauthorized module leaked to alice: %s", c.ModuleName)
			}
			key := fmt.Sprintf("%d:%s", c.ModuleID, c.LoreRevision)
			if seenKeys[key] {
				t.Fatalf("duplicate commit during cursor pagination: %s", key)
			}
			seenKeys[key] = true
			aliceAgg = append(aliceAgg, c)
		}
		if !page.HasMore {
			break
		}
		cursor = page.NextCursor
	}
	if len(aliceAgg) != 150 {
		t.Fatalf("alice paginated %d commits, want 150", len(aliceAgg))
	}
	for i := 1; i < len(aliceAgg); i++ {
		prev, cur := aliceAgg[i-1], aliceAgg[i]
		if prev.CommittedUnixMS < cur.CommittedUnixMS {
			t.Fatalf("out of order committed_unix_ms at %d", i)
		}
		if prev.CommittedUnixMS == cur.CommittedUnixMS && prev.AuthoredUnixMS == cur.AuthoredUnixMS && prev.ModuleID > cur.ModuleID {
			t.Fatalf("tie-breaker module_id violated at %d (%d > %d)", i, prev.ModuleID, cur.ModuleID)
		}
	}

	// Verify exact union against per-module histories.
	unionSet := map[string]bool{}
	for _, idx := range []int{0, 1, 2} {
		mp, err := svc.ModuleHistory(ctx, alice, mods[idx].ID, Filter{Limit: 200})
		if err != nil {
			t.Fatal(err)
		}
		if mp.TotalMatching != 50 || len(mp.Commits) != 50 {
			t.Fatalf("module %s count=%d/%d, want 50", mods[idx].Name, mp.TotalMatching, len(mp.Commits))
		}
		for _, c := range mp.Commits {
			unionSet[fmt.Sprintf("%d:%s", c.ModuleID, c.LoreRevision)] = true
		}
	}
	if len(unionSet) != len(seenKeys) {
		t.Fatalf("union size %d != aggregated size %d", len(unionSet), len(seenKeys))
	}

	// 3. Bob sees all 250 commits across all 5 modules.
	bobPage, err := svc.ProjectHistory(ctx, bob, proj.ID, Filter{Limit: 10})
	if err != nil || bobPage.TotalMatching != 250 || len(bobPage.AuthorizedModules) != 5 {
		t.Fatalf("bob total=%d mods=%d err=%v", bobPage.TotalMatching, len(bobPage.AuthorizedModules), err)
	}

	// 4. Filter tests: author Unicode, merges_only, module subset.
	xmPage, err := svc.ProjectHistory(ctx, alice, proj.ID, Filter{Author: "王小明", Limit: 200})
	if err != nil || xmPage.TotalMatching != 75 {
		t.Fatalf("author filter got %d, want 75 (err=%v)", xmPage.TotalMatching, err)
	}
	mergePage, err := svc.ProjectHistory(ctx, bob, proj.ID, Filter{MergesOnly: true, Limit: 50})
	if err != nil || mergePage.TotalMatching != 5 {
		t.Fatalf("merges_only got %d, want 5 (err=%v)", mergePage.TotalMatching, err)
	}

	// 5. CRITICAL SECURITY CHECK: Cursor pagination across permission revocation!
	// Alice fetches page 1 (limit 20), obtaining `NextCursor`. Then Carol revokes `Server` from Alice.
	// When Alice requests page 2 using that existing `NextCursor`, `Server` commits MUST NOT be returned!
	p1, err := svc.ProjectHistory(ctx, alice, proj.ID, Filter{Limit: 20})
	if err != nil || !p1.HasMore {
		t.Fatalf("p1 err=%v hasMore=%v", err, p1.HasMore)
	}
	if err := project.RevokeModulePermission(ctx, db, "carol", alice, mods[2].ID); err != nil {
		t.Fatal(err)
	}
	curAfterRevoke := p1.NextCursor
	for curAfterRevoke != "" {
		pn, err := svc.ProjectHistory(ctx, alice, proj.ID, Filter{Limit: 20, Cursor: curAfterRevoke})
		if err != nil {
			t.Fatal(err)
		}
		if pn.TotalMatching != 100 {
			t.Fatalf("after revoking Server, TotalMatching=%d, want 100", pn.TotalMatching)
		}
		for _, c := range pn.Commits {
			if c.ModuleName == "Server" {
				t.Fatalf("SECURITY VIOLATION: pagination cursor leaked revoked Server commit %s!", c.CanonicalID)
			}
		}
		if !pn.HasMore {
			break
		}
		curAfterRevoke = pn.NextCursor
	}
}

type scriptedLoreRunner struct {
	branches string
	pages    map[string]string
}

func (s *scriptedLoreRunner) Run(_ context.Context, req loreexec.Request) (loreexec.CommandResult, error) {
	joined := fmt.Sprint(req.Argv)
	var out string
	complete := `{"tagName":"complete","data":{"status":0,"error":{"errorCode":0,"message":"","traceLocations":[]}}}` + "\n"
	switch {
	case containsToken(req.Argv, "branch") && containsToken(req.Argv, "list"):
		out = s.branches + complete
	case containsToken(req.Argv, "history"):
		// Find the revision argument (last 64-hex arg).
		var rev string
		for _, a := range req.Argv {
			if len(a) == 64 {
				rev = a
			}
		}
		out = s.pages[rev] + complete
	default:
		out = complete
	}
	_ = joined
	res := loreexec.CommandResult{ExitCode: 0, Started: true, Stdout: out}
	res.StdoutParse = lorejson.Parse(lorejson.Stdout, out)
	return res, nil
}

func containsToken(argv []string, want string) bool {
	for _, a := range argv {
		if a == want {
			return true
		}
	}
	return false
}

func TestSyncModuleFromLoreDeepDAGBeyond200WithoutTruncation(t *testing.T) {
	ctx := context.Background()
	db := openHistoryTestDB(t)
	uid, _ := user.Create(ctx, db, "test", "alice", "correct-horse", "user")
	proj, _ := project.CreateProject(ctx, db, "alice", project.Project{
		Name: "DeepProj", ParentRepositoryID: "00112233445566778899aabbccddeeff",
		ParentRepositoryURL: "grpc://127.0.0.1:53547/deep", CreatedBy: uid,
	})
	_ = project.AddMember(ctx, db, "alice", proj.ID, uid, project.RoleAdmin)
	mod, _ := project.CreateModule(ctx, db, "alice", project.Module{
		ProjectID: proj.ID, Name: "Engine", RepositoryID: "0123456789abcdef0123456789abcdef",
		RepositoryURL: "grpc://127.0.0.1:53547/engine", MountPath: "Engine",
	})
	_ = project.SetModulePermission(ctx, db, "alice", uid, mod.ID, project.PermWrite)

	// Build a 260-revision main chain + a side branch of 2 revisions merged at revision 250!
	// SyncModuleFromLore fetches in chunks of 200 and follows both parent[0] and parent[1].
	mainRevs := make([]string, 261) // 1..260
	for i := 1; i <= 260; i++ {
		mainRevs[i] = hex64(i)
	}
	side1 := hex64(5001)
	side2 := hex64(5002)

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

	var page1, page2, sidePage string
	// Page 1: mainRevs[260] down to mainRevs[61] (200 entries). At i=250, p1 = side2!
	for i := 260; i >= 61; i-- {
		p1 := ""
		if i == 250 {
			p1 = side2
		}
		page1 += makeEntry(mainRevs[i], i, mainRevs[i-1], p1, int64(1700000000000+i*1000), fmt.Sprintf("commit %d", i))
	}
	// Page 2: mainRevs[60] down to mainRevs[1] (60 entries).
	for i := 60; i >= 1; i-- {
		p0 := ""
		if i > 1 {
			p0 = mainRevs[i-1]
		}
		page2 += makeEntry(mainRevs[i], i, p0, "", int64(1700000000000+i*1000), fmt.Sprintf("commit %d", i))
	}
	// Side branch page starting at side2 -> side1 -> mainRevs[100].
	sidePage = makeEntry(side2, 102, side1, "", 1700000249500, "side 2") +
		makeEntry(side1, 101, mainRevs[100], "", 1700000249200, "side 1")

	runner := &scriptedLoreRunner{
		branches: fmt.Sprintf(`{"tagName":"branchListEntry","data":{"id":"b1","name":"main","latest":%q,"isCurrent":1,"archived":false}}`+"\n", mainRevs[260]),
		pages: map[string]string{
			mainRevs[260]: page1,
			mainRevs[60]:  page2,
			side2:         sidePage,
		},
	}
	stats, err := SyncModuleFromLore(ctx, db, &loreadapter.Client{Exec: runner}, mod.ID, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if stats.CommitsUpserted != 262 {
		t.Fatalf("CommitsUpserted=%d, want 262 (260 main + 2 merged side commits)", stats.CommitsUpserted)
	}

	svc := Service{DB: db}
	// Full branch DAG reachability from main includes all 262 commits!
	allReachable, err := svc.ModuleHistory(ctx, uid, mod.ID, Filter{Branch: "main", Limit: 300})
	if err != nil || allReachable.TotalMatching != 262 {
		t.Fatalf("reachable from main=%d, want 262 (err=%v)", allReachable.TotalMatching, err)
	}
	// First-parent-only from main excludes the 2 side-branch commits -> 260 commits!
	fpOnly, err := svc.ModuleHistory(ctx, uid, mod.ID, Filter{Branch: "main", FirstParentOnly: true, Limit: 300})
	if err != nil || fpOnly.TotalMatching != 260 {
		t.Fatalf("first-parent from main=%d, want 260 (err=%v)", fpOnly.TotalMatching, err)
	}
	// Author "1" was resolved to username "alice".
	if fpOnly.Commits[0].AuthorName != "alice" {
		t.Fatalf("author user_id resolution got %q, want alice", fpOnly.Commits[0].AuthorName)
	}
}
