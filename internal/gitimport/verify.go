package gitimport

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"lore-monorepo/internal/history"
	"lore-monorepo/internal/loreadapter"
)

const loreScanChunk = 200

// readActualLoreDAG reads all reachable revisions and local branches directly from
// the physical Lore repository on disk so recovery and verification never rely
// solely on in-memory maps or SQLite tables.
func readActualLoreDAG(
	ctx context.Context,
	lore *loreadapter.Client,
	loreWorkDir string,
	extraSeedRevs []string,
) (entries map[string]loreadapter.HistoryEntry, activeBranches map[string]loreadapter.Branch, err error) {
	entries = map[string]loreadapter.HistoryEntry{}
	activeBranches = map[string]loreadapter.Branch{}

	localBranches, err := lore.ListBranchesAt(ctx, loreWorkDir, false)
	if err != nil {
		return nil, nil, err
	}

	var queue []string
	queued := map[string]bool{}
	enqueue := func(rev string) {
		if rev == "" || rev == zeroHash64 || len(rev) != 64 || queued[rev] {
			return
		}
		queued[rev] = true
		queue = append(queue, rev)
	}

	for _, b := range localBranches {
		if !b.Archived && !strings.HasPrefix(b.Name, "_import_") {
			activeBranches[b.Name] = b
		}
		if b.Latest != "" && b.Latest != zeroHash64 {
			enqueue(b.Latest)
		}
	}
	for _, r := range extraSeedRevs {
		enqueue(r)
	}

	for len(queue) > 0 {
		start := queue[0]
		queue = queue[1:]
		if _, seen := entries[start]; seen {
			continue
		}
		chunk, hErr := lore.History(ctx, loreWorkDir, loreScanChunk, start)
		if hErr != nil {
			return nil, nil, hErr
		}
		for idx, e := range chunk {
			if e.Revision == "" || e.Revision == zeroHash64 {
				continue
			}
			alreadySeen := false
			if _, ok := entries[e.Revision]; ok {
				alreadySeen = true
			} else {
				entries[e.Revision] = e
			}
			if len(e.Parent) > 1 && e.Parent[1] != "" && e.Parent[1] != zeroHash64 {
				enqueue(e.Parent[1])
			}
			if alreadySeen {
				break
			}
			if idx == len(chunk)-1 && len(e.Parent) > 0 && e.Parent[0] != "" && e.Parent[0] != zeroHash64 {
				enqueue(e.Parent[0])
			}
		}
	}
	return entries, activeBranches, nil
}

// verifyImportedModule performs comprehensive 3-layer integrity verification across:
//   1. Source Bare Git Mirror (MirrorGraph + ProjectedGraph + Git trees/blobs)
//   2. Physical Lore Repository (Lore revisions, metadata, [parent_self, parent_other] DAG, branches, HEAD files)
//   3. Manager SQLite Index (module_commits, module_commit_parents, module_refs, module_special_objects)
func (im *Importer) verifyImportedModule(
	ctx context.Context,
	moduleID int64,
	mirrorDir, loreWorkDir string,
	spec RepoSpec,
	remoteRefs RemoteRefSummary,
	rawGraph MirrorGraph,
	projGraph ProjectedGraph,
	cp itemCheckpoint,
	treeCache *TreeCache,
) (VerificationReport, error) {
	rep := VerificationReport{
		SourceSubdir:          spec.SourceSubdir,
		RawSourceCommits:      len(rawGraph.Commits),
		SourceCommits:         len(projGraph.Commits),
		AliasedCommits:        projGraph.AliasedCommitsCount,
		MappedCommits:         len(cp.CommitMap),
		SyntheticMergeBridges: cp.SyntheticCount,
		SourceBranches:        len(projGraph.Branches),
		SourceTags:            len(projGraph.Tags),
		HeadBranch:            projGraph.DefaultBranch,
		AdvertisedHiddenRefs:  remoteRefs.AdvertisedHiddenRefs,
		ShallowMissingParents: rawGraph.ShallowMissingParents,
		SkippedEmptyBranches:  projGraph.SkippedEmptyBranches,
		SkippedEmptyTags:      projGraph.SkippedEmptyTags,
		UnmappedPathsCount:    len(projGraph.UnmappedPaths),
		LFSFetchAttempted:     rawGraph.LFSFetchAttempted,
		LFSFetchSucceeded:     rawGraph.LFSFetchSucceeded,
	}
	if len(projGraph.UnmappedPaths) > 0 {
		limit := len(projGraph.UnmappedPaths)
		if limit > 32 {
			limit = 32
		}
		rep.UnmappedPaths = append([]string{}, projGraph.UnmappedPaths[:limit]...)
	}

	// 1. Shallow / Missing Parent Gate: incomplete source history MUST fail!
	if rawGraph.IsShallow {
		rep.Mismatches = append(rep.Mismatches, "source git repository is shallow (.git/shallow present)")
	}
	if len(rawGraph.ShallowMissingParents) > 0 {
		rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("missing %d parent commit(s) in git object graph (first: %s)",
			len(rawGraph.ShallowMissingParents), rawGraph.ShallowMissingParents[0]))
	}

	// Collect tag target revisions so tag-only commits (not on any branch) are also scanned from Lore!
	var tagTargetRevs []string
	for _, t := range projGraph.Tags {
		if rev := cp.CommitMap[t.TargetSHA]; rev != "" {
			tagTargetRevs = append(tagTargetRevs, rev)
		}
	}

	// 2. Load Layer 2: physical Lore DAG & branches directly from Lore CLI.
	loreDAG, loreBranches, err := readActualLoreDAG(ctx, im.Lore, loreWorkDir, tagTargetRevs)
	if err != nil {
		return rep, fmt.Errorf("verify: read physical lore dag: %w", err)
	}

	// 3. Load Layer 3: SQLite commits, parents, refs, and special objects for moduleID.
	type sqlCommitRow struct {
		LoreRev      string
		SourceSHA    string
		SourceSubdir string
		IsSynthetic  bool
		IsMerge      bool
		ParentCount  int
	}
	sqlCommits := map[string]sqlCommitRow{}
	sqlBySourceSHA := map[string]string{}
	var sqlSyntheticCount int

	cRows, err := im.DB.QueryContext(ctx, `
		SELECT lore_revision, COALESCE(source_commit_id,''), source_subdir, is_synthetic, is_merge, parent_count
		FROM module_commits
		WHERE module_id=? AND origin_kind='git_import'
	`, moduleID)
	if err != nil {
		return rep, err
	}
	for cRows.Next() {
		var r sqlCommitRow
		var synth, merge int
		if err := cRows.Scan(&r.LoreRev, &r.SourceSHA, &r.SourceSubdir, &synth, &merge, &r.ParentCount); err != nil {
			cRows.Close()
			return rep, err
		}
		r.IsSynthetic = synth == 1
		r.IsMerge = merge == 1
		if r.IsSynthetic {
			sqlSyntheticCount++
			continue
		}
		sqlCommits[r.LoreRev] = r
		if r.SourceSHA != "" {
			if prev, dup := sqlBySourceSHA[r.SourceSHA]; dup && prev != r.LoreRev {
				rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("conflicting lore revisions for git commit %s (%s vs %s)", r.SourceSHA, prev, r.LoreRev))
			}
			sqlBySourceSHA[r.SourceSHA] = r.LoreRev
		}
	}
	if err := cRows.Close(); err != nil {
		return rep, err
	}
	rep.IndexedCommits = len(sqlCommits)

	if rep.IndexedCommits != rep.SourceCommits {
		rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("indexed commits %d != projected source commits %d", rep.IndexedCommits, rep.SourceCommits))
	}
	if len(cp.CommitMap) != rep.SourceCommits {
		rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("mapped commits %d != projected source commits %d", len(cp.CommitMap), rep.SourceCommits))
	}

	// Verify no Lore revision in `module_commits` belongs to another module (global uniqueness check across modules!).
	var crossModCount int
	if err := im.DB.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM module_commits a
		JOIN module_commits b ON a.lore_revision = b.lore_revision AND a.module_id <> b.module_id
		WHERE a.module_id = ?
	`, moduleID).Scan(&crossModCount); err == nil && crossModCount > 0 {
		rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("cross-module lore_revision collision detected (%d)", crossModCount))
	}

	// Load all SQLite parent edges for moduleID AND verify every parent revision belongs to THIS module!
	sqlParents := map[string][]history.ParentLink{}
	var totalParentEdges int
	pRows, err := im.DB.QueryContext(ctx, `
		SELECT p.lore_revision, p.parent_ord, p.parent_lore_revision, COALESCE(p.parent_source_commit_id,''),
		       CASE WHEN c.lore_revision IS NOT NULL THEN 1 ELSE 0 END
		FROM module_commit_parents p
		LEFT JOIN module_commits c ON c.module_id = p.module_id AND c.lore_revision = p.parent_lore_revision
		WHERE p.module_id = ?
		ORDER BY p.lore_revision ASC, p.parent_ord ASC
	`, moduleID)
	if err != nil {
		return rep, err
	}
	for pRows.Next() {
		var childRev string
		var edge history.ParentLink
		var parentInSameModule int
		if err := pRows.Scan(&childRev, &edge.Ord, &edge.LoreRevision, &edge.SourceCommitID, &parentInSameModule); err != nil {
			pRows.Close()
			return rep, err
		}
		totalParentEdges++
		if parentInSameModule == 0 {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("parent %s of %s does not belong to module %d", edge.LoreRevision, childRev, moduleID))
		}
		sqlParents[childRev] = append(sqlParents[childRev], edge)
	}
	if err := pRows.Close(); err != nil {
		return rep, err
	}

	// 4. Per-Commit 3-Layer Verification: Mapping Bijection, Lore Existence, Metadata, and Exact Ordered Parents!
	seenLoreRevs := map[string]string{}
	expectedTotalParentEdges := 0

	for _, c := range projGraph.Commits {
		loreRev := cp.CommitMap[c.SHA]
		if loreRev == "" {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("missing lore revision mapping for commit %s", c.SHA))
			continue
		}
		if otherSHA, dup := seenLoreRevs[loreRev]; dup && otherSHA != c.SHA {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("two git commits (%s, %s) mapped to same lore revision %s", otherSHA, c.SHA, loreRev))
			continue
		}
		seenLoreRevs[loreRev] = c.SHA

		// Layer 2 check: Lore store entry & metadata.
		le, inLore := loreDAG[loreRev]
		if !inLore {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("mapped lore revision %s for commit %s not found in physical lore store", loreRev[:12], c.SHA[:12]))
			continue
		}
		if le.Metadata["git.commit"] != c.SHA {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("lore revision %s git.commit=%q != %q", loreRev[:12], le.Metadata["git.commit"], c.SHA))
		}
		if le.Metadata["git.subdir"] != spec.SourceSubdir {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("lore revision %s git.subdir=%q != %q", loreRev[:12], le.Metadata["git.subdir"], spec.SourceSubdir))
		}

		// Layer 3 check: SQLite row.
		sc, inSQL := sqlCommits[loreRev]
		if !inSQL {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("commit %s (%s) missing from module_commits", c.SHA[:12], loreRev[:12]))
			continue
		}
		if sc.SourceSHA != c.SHA || sc.SourceSubdir != spec.SourceSubdir {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("module_commits mismatch for %s: got (%s,%q), want (%s,%q)",
				loreRev[:12], sc.SourceSHA, sc.SourceSubdir, c.SHA, spec.SourceSubdir))
		}

		// Parent Edge Identity & Exact Order Check (SQLite + Physical Lore DAG)!
		wantN := len(c.Parents)
		expectedTotalParentEdges += wantN
		gotEdges := sqlParents[loreRev]
		if sc.ParentCount != wantN || len(gotEdges) != wantN {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("commit %s parent count sql=%d/%d != expected=%d",
				c.SHA[:12], sc.ParentCount, len(gotEdges), wantN))
			continue
		}

		wantParentLoreRevs := make([]string, wantN)
		edgesMatch := true
		for ord, wantParentSHA := range c.Parents {
			wantParentRev := cp.CommitMap[wantParentSHA]
			wantParentLoreRevs[ord] = wantParentRev
			got := gotEdges[ord]
			if got.Ord != ord || got.SourceCommitID != wantParentSHA || got.LoreRevision != wantParentRev {
				rep.Mismatches = append(rep.Mismatches, fmt.Sprintf(
					"commit %s parent[%d] mismatch: got (ord=%d git=%s lore=%s), want (ord=%d git=%s lore=%s)",
					c.SHA[:12], ord, got.Ord, short12(got.SourceCommitID), short12(got.LoreRevision),
					ord, short12(wantParentSHA), short12(wantParentRev)))
				edgesMatch = false
			}
		}

		// Verify physical Lore [parent_self, parent_other] DAG topology & order!
		if !verifyPhysicalLoreParents(le, wantParentLoreRevs, loreDAG) {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("physical lore parent topology/order mismatch on commit %s (%s)", c.SHA[:12], loreRev[:12]))
			edgesMatch = false
		}

		if edgesMatch && wantN >= 2 {
			rep.MergeCommitsVerified++
			if wantN >= 3 {
				rep.OctopusMergesVerified++
			}
		}
	}

	// Ensure no extra non-synthetic Lore revisions with git.commit exist unindexed, and no extra SQLite parent rows!
	for rev, le := range loreDAG {
		if le.Metadata["git.synthetic"] == "1" {
			continue
		}
		if le.Metadata["git.commit"] != "" && seenLoreRevs[rev] == "" {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("unexplained extra lore revision %s (git.commit=%s) in repository", short12(rev), short12(le.Metadata["git.commit"])))
		}
	}
	// Subtract any synthetic bridge parent edges if synthetic commits recorded parents (synthetic commits don't write parents, so totalParentEdges == expectedTotalParentEdges).
	var nonSynthParentEdges int
	_ = im.DB.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM module_commit_parents p
		JOIN module_commits c ON c.module_id=p.module_id AND c.lore_revision=p.lore_revision
		WHERE p.module_id=? AND c.is_synthetic=0 AND c.origin_kind='git_import'
	`, moduleID).Scan(&nonSynthParentEdges)
	if nonSynthParentEdges != expectedTotalParentEdges || totalParentEdges != expectedTotalParentEdges {
		rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("unexpected parent edge rows in SQLite (%d/%d != %d)", nonSynthParentEdges, totalParentEdges, expectedTotalParentEdges))
	}
	_ = sqlSyntheticCount

	// 5. Verify ALL Standard Branches, Default Branch, and Tags!
	sqlBranches := map[string]history.RefDetail{}
	sqlTags := map[string]history.RefDetail{}
	var sqlDefaultBranches []string

	rRows, err := im.DB.QueryContext(ctx, `
		SELECT ref_type, ref_name, lore_revision, COALESCE(source_commit_id,''), COALESCE(source_tag_object_id,''),
		       is_default, is_annotated, tagger_name, tagger_email, tagged_at, tag_message
		FROM module_refs
		WHERE module_id=?
	`, moduleID)
	if err != nil {
		return rep, err
	}
	for rRows.Next() {
		var d history.RefDetail
		var isDef, isAnn int
		if err := rRows.Scan(&d.Type, &d.Name, &d.LoreRevision, &d.SourceCommitID, &d.SourceTagObjectID,
			&isDef, &isAnn, &d.TaggerName, &d.TaggerEmail, &d.TaggedAt, &d.TagMessage); err != nil {
			rRows.Close()
			return rep, err
		}
		d.IsDefault = isDef == 1
		d.IsAnnotated = isAnn == 1
		if d.Type == "branch" {
			sqlBranches[d.Name] = d
			if d.IsDefault {
				sqlDefaultBranches = append(sqlDefaultBranches, d.Name)
			}
		} else if d.Type == "tag" {
			sqlTags[d.Name] = d
		}
	}
	if err := rRows.Close(); err != nil {
		return rep, err
	}

	rep.ImportedBranches = len(sqlBranches)
	rep.ImportedTags = len(sqlTags)

	if len(sqlBranches) != len(projGraph.Branches) {
		rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("SQLite branch count %d != expected %d", len(sqlBranches), len(projGraph.Branches)))
	}
	for bName, wantSHA := range projGraph.Branches {
		wantRev := cp.CommitMap[wantSHA]
		sb, ok := sqlBranches[bName]
		if !ok {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("missing branch %q in module_refs", bName))
			continue
		}
		if sb.SourceCommitID != wantSHA || sb.LoreRevision != wantRev {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("branch %q mapping mismatch: got (%s,%s), want (%s,%s)",
				bName, short12(sb.SourceCommitID), short12(sb.LoreRevision), short12(wantSHA), short12(wantRev)))
		}
		lb, inLore := loreBranches[bName]
		if !inLore || lb.Latest != wantRev {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("physical lore branch %q mismatch: present=%v latest=%s want=%s",
				bName, inLore, short12(lb.Latest), short12(wantRev)))
		}
	}
	if len(projGraph.Branches) > 0 {
		if len(sqlDefaultBranches) != 1 || sqlDefaultBranches[0] != projGraph.DefaultBranch {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("default branch mismatch: got %v, want [%s]", sqlDefaultBranches, projGraph.DefaultBranch))
		}
	}

	// Verify no unexpected extra non-bootstrap branches exist in physical Lore repository.
	for bName, lb := range loreBranches {
		if _, wanted := projGraph.Branches[bName]; !wanted {
			if bName == "main" && cp.BootstrapMainRev != "" && lb.Latest == cp.BootstrapMainRev {
				continue // Lore's un-deletable initial bootstrap branch frozen at C1
			}
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("unexpected extra branch %q in physical lore repository", bName))
		}
	}

	if len(sqlTags) != len(projGraph.Tags) {
		rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("SQLite tag count %d != expected %d", len(sqlTags), len(projGraph.Tags)))
	}
	for _, wantTag := range projGraph.Tags {
		wantRev := cp.CommitMap[wantTag.TargetSHA]
		st, ok := sqlTags[wantTag.Name]
		if !ok {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("missing tag %q in module_refs", wantTag.Name))
			continue
		}
		if st.SourceCommitID != wantTag.TargetSHA || st.LoreRevision != wantRev || st.IsAnnotated != wantTag.IsAnnotated || st.SourceTagObjectID != wantTag.TagObjectID {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("tag %q target/metadata mismatch in module_refs", wantTag.Name))
		}
		if wantTag.IsAnnotated && (st.TaggerEmail != wantTag.TaggerEmail || st.TagMessage != wantTag.Message) {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("annotated tag %q tagger/message mismatch", wantTag.Name))
		}
	}

	// 6. Verify Special Objects (count, kind, path, OID, size, and detail JSON) across EVERY commit!
	reader, err := NewBatchBlobReader(ctx, im.GitBinary, mirrorDir)
	if err != nil {
		return rep, err
	}
	defer reader.Close()

	sqlSpecials := map[string][]history.SpecialObject{}
	var totalSQLSpecials int
	sRows, err := im.DB.QueryContext(ctx, `
		SELECT lore_revision, COALESCE(source_commit_id,''), kind, path, oid, size_bytes, detail_json
		FROM module_special_objects
		WHERE module_id=?
		ORDER BY path ASC, kind ASC
	`, moduleID)
	if err != nil {
		return rep, err
	}
	for sRows.Next() {
		var sp history.SpecialObject
		if err := sRows.Scan(&sp.LoreRevision, &sp.SourceCommitID, &sp.Kind, &sp.Path, &sp.OID, &sp.SizeBytes, &sp.DetailJSON); err != nil {
			sRows.Close()
			return rep, err
		}
		totalSQLSpecials++
		sqlSpecials[sp.LoreRevision] = append(sqlSpecials[sp.LoreRevision], sp)
	}
	if err := sRows.Close(); err != nil {
		return rep, err
	}
	rep.SpecialObjectsCount = totalSQLSpecials

	expectedSpecialTotal := 0
	for _, c := range projGraph.Commits {
		loreRev := cp.CommitMap[c.SHA]
		if loreRev == "" {
			continue
		}
		allEntries, tErr := treeCache.Entries(ctx, im.GitBinary, mirrorDir, c.TreeSHA)
		if tErr != nil {
			return rep, tErr
		}
		wantSpecs, sErr := InspectExpectedSpecialObjects(mirrorDir, spec.SourceSubdir, spec.LFSMode, allEntries, reader)
		if sErr != nil {
			return rep, sErr
		}
		expectedSpecialTotal += len(wantSpecs)
		gotSpecs := sqlSpecials[loreRev]
		if len(gotSpecs) != len(wantSpecs) {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("commit %s special objects count %d != %d", c.SHA[:12], len(gotSpecs), len(wantSpecs)))
			continue
		}
		for i := range wantSpecs {
			w, g := wantSpecs[i], gotSpecs[i]
			wDetail := w.DetailJSON
			if wDetail == "" {
				wDetail = "{}"
			}
			if g.Kind != w.Kind || g.Path != w.Path || g.OID != w.OID || g.SizeBytes != w.SizeBytes || g.DetailJSON != wDetail || g.SourceCommitID != c.SHA {
				rep.Mismatches = append(rep.Mismatches, fmt.Sprintf(
					"commit %s special object[%d] mismatch: got (%s %s oid=%s sz=%d detail=%s), want (%s %s oid=%s sz=%d detail=%s)",
					c.SHA[:12], i, g.Kind, g.Path, short12(g.OID), g.SizeBytes, g.DetailJSON,
					w.Kind, w.Path, short12(w.OID), w.SizeBytes, wDetail))
			}
		}
	}
	if totalSQLSpecials != expectedSpecialTotal {
		rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("extra special object rows in SQLite (%d != %d)", totalSQLSpecials, expectedSpecialTotal))
	}

	// 7. Verify Per-Module Content Isolation across Lore revisions when source_subdir is used,
	//    AND verify HEAD working tree SHA-256 content digest byte-for-byte!
	if spec.SourceSubdir != "" {
		// Check every Lore revision's delta paths via `lore revision info --delta <rev>` to prove
		// that NO file belonging to sibling subdirs or root unmapped files ever entered ANY Lore revision!
		forbiddenSet := map[string]bool{}
		for _, up := range projGraph.UnmappedPaths {
			forbiddenSet[up] = true
		}
		for _, c := range projGraph.Commits {
			loreRev := cp.CommitMap[c.SHA]
			if loreRev == "" {
				continue
			}
			det, dErr := im.Lore.RevisionDetail(ctx, loreWorkDir, loreRev, true)
			if dErr != nil {
				rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("failed reading lore revision delta for %s: %v", short12(loreRev), dErr))
				continue
			}
			// Verify expected valid relative paths in this commit's module subtree.
			allEntries, tErr := treeCache.Entries(ctx, im.GitBinary, mirrorDir, c.TreeSHA)
			if tErr != nil {
				return rep, tErr
			}
			scopedEntries, _ := filterEntriesForSubdir(allEntries, spec.SourceSubdir, nil)
			validAddedOrKept := map[string]bool{}
			for _, se := range scopedEntries {
				validAddedOrKept[se.Path] = true
				dir := se.Path
				for idx := strings.LastIndexByte(dir, '/'); idx > 0; idx = strings.LastIndexByte(dir, '/') {
					dir = dir[:idx]
					validAddedOrKept[dir] = true
				}
			}
			for _, d := range det.Deltas {
				if d.Action == "delete" {
					continue
				}
				if !validAddedOrKept[d.Path] {
					rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("CONTENT ISOLATION VIOLATION: revision %s contains non-module path %q", short12(loreRev), d.Path))
				}
			}
			_ = forbiddenSet
		}
	}

	if projGraph.DefaultBranch != "" && projGraph.Branches[projGraph.DefaultBranch] != "" {
		headCommit, ok := projGraph.CommitsBySHA[projGraph.Branches[projGraph.DefaultBranch]]
		if ok {
			gitFiles, gitDigest, err := ComputeGitTreeContentDigest(ctx, im.GitBinary, mirrorDir, headCommit.TreeSHA, spec.SourceSubdir, spec.LFSMode, reader)
			if err != nil {
				return rep, err
			}
			loreFiles, loreDigest, err := ComputeWorkdirDigest(loreWorkDir)
			if err != nil {
				return rep, err
			}
			rep.HeadFileCount = loreFiles
			rep.HeadGitDigest = gitDigest
			rep.HeadLoreDigest = loreDigest
			if gitFiles != loreFiles || gitDigest != loreDigest {
				rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("HEAD tree digest mismatch (git %d:%s vs lore %d:%s)",
					gitFiles, short12(gitDigest), loreFiles, short12(loreDigest)))
			}
		}
	}

	sort.Strings(rep.Mismatches)
	rep.Passed = len(rep.Mismatches) == 0
	return rep, nil
}

func verifyPhysicalLoreParents(le loreadapter.HistoryEntry, wantParentRevs []string, loreDAG map[string]loreadapter.HistoryEntry) bool {
	p0, p1 := "", ""
	if len(le.Parent) > 0 && le.Parent[0] != zeroHash64 {
		p0 = le.Parent[0]
	}
	if len(le.Parent) > 1 && le.Parent[1] != zeroHash64 {
		p1 = le.Parent[1]
	}

	switch len(wantParentRevs) {
	case 0:
		if anchor := le.Metadata["lore.orphan_anchor"]; anchor != "" {
			return p0 == anchor && p1 == ""
		}
		return p0 == "" && p1 == ""

	case 1:
		return p0 == wantParentRevs[0] && p1 == ""

	case 2:
		return p0 == wantParentRevs[0] && p1 == wantParentRevs[1]

	default:
		// N-parent Octopus merge: walk backwards down synthetic bridge chain!
		// Final commit has [bridge_{N-2}, wantParentRevs[N-1]], ..., bridge_1 has [wantParentRevs[0], wantParentRevs[1]].
		cur := le
		for idx := len(wantParentRevs) - 1; idx >= 2; idx-- {
			cp0, cp1 := "", ""
			if len(cur.Parent) > 0 && cur.Parent[0] != zeroHash64 {
				cp0 = cur.Parent[0]
			}
			if len(cur.Parent) > 1 && cur.Parent[1] != zeroHash64 {
				cp1 = cur.Parent[1]
			}
			if cp1 != wantParentRevs[idx] || cp0 == "" {
				return false
			}
			prev, ok := loreDAG[cp0]
			if !ok || prev.Metadata["git.synthetic"] != "1" {
				return false
			}
			cur = prev
		}
		bp0, bp1 := "", ""
		if len(cur.Parent) > 0 && cur.Parent[0] != zeroHash64 {
			bp0 = cur.Parent[0]
		}
		if len(cur.Parent) > 1 && cur.Parent[1] != zeroHash64 {
			bp1 = cur.Parent[1]
		}
		return bp0 == wantParentRevs[0] && bp1 == wantParentRevs[1]
	}
}

func short12(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
