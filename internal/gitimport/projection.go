package gitimport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// TreeCache caches `git ls-tree -r --full-tree` results keyed by Git tree SHA
// across commits and across sibling modules splitting the same external Monorepo.
type TreeCache struct {
	mu      sync.Mutex
	entries map[string][]treeEntry
}

func NewTreeCache() *TreeCache {
	return &TreeCache{entries: map[string][]treeEntry{}}
}

func (tc *TreeCache) Entries(ctx context.Context, gitBin, mirrorDir, treeSHA string) ([]treeEntry, error) {
	if tc != nil {
		tc.mu.Lock()
		if cached, ok := tc.entries[treeSHA]; ok {
			tc.mu.Unlock()
			return cached, nil
		}
		tc.mu.Unlock()
	}
	list, err := readGitTreeEntries(ctx, gitBin, mirrorDir, treeSHA)
	if err != nil {
		return nil, err
	}
	if tc != nil {
		tc.mu.Lock()
		tc.entries[treeSHA] = list
		tc.mu.Unlock()
	}
	return list, nil
}

// ClassifiedPath records an explicit classification decision for a path outside
// a module's subdirectory in an external Git Monorepo.
type ClassifiedPath struct {
	Path         string `json:"path"`
	Category     string `json:"category"` // "excluded" or "separate_module"
	Pattern      string `json:"pattern"`
	TargetModule string `json:"target_module,omitempty"`
	Reason       string `json:"reason"`
}

// ProjectedGraph is a single module's independent DAG projected from MirrorGraph.
// Every commit in ProjectedGraph.Commits belongs strictly to this module, and every
// parent SHA in GitCommit.Parents points strictly to an earlier commit in ProjectedGraph.Commits!
type ProjectedGraph struct {
	SourceSubdir             string
	DefaultBranch            string
	Commits                  []GitCommit
	CommitsBySHA             map[string]GitCommit
	RawGitParents            map[string][]string // projected commit sha -> original unprojected git parents
	EffectiveCommitOf        map[string]string   // any source git sha -> effective projected commit sha in this module ("" if pre-creation)
	Branches                 map[string]string   // branch name -> projected commit sha
	OriginalBranches         map[string]string   // branch name -> raw source git sha before alias folding
	Tags                     []GitTag            // tags whose target commit maps to a non-empty projected commit
	SkippedEmptyBranches     []string
	SkippedEmptyTags         []string
	UnmappedPaths            []string         // all paths outside sourceSubdir & siblingSubdirs
	ClassifiedExcluded       []ClassifiedPath // paths explicitly excluded with documented reason
	ClassifiedSeparateModule []ClassifiedPath // paths explicitly assigned to a governance/shared module
	UndecidedPaths           []string         // unclassified paths that block strict migration completeness
	CoverageComplete         bool
	AliasedCommitsCount      int
}

func ProjectMirrorGraph(
	ctx context.Context,
	gitBin, mirrorDir string,
	g MirrorGraph,
	sourceSubdir string,
	siblingSubdirs []string,
	pathRules []PathRule,
	cache *TreeCache,
) (ProjectedGraph, error) {
	sourceSubdir = strings.Trim(strings.TrimSpace(sourceSubdir), "/")
	if sourceSubdir == "" {
		eff := make(map[string]string, len(g.Commits))
		bySHA := make(map[string]GitCommit, len(g.Commits))
		rawParents := make(map[string][]string, len(g.Commits))
		commits := make([]GitCommit, len(g.Commits))
		for i, c := range g.Commits {
			cp := c
			cp.Parents = append([]string{}, c.Parents...)
			commits[i] = cp
			bySHA[c.SHA] = cp
			eff[c.SHA] = c.SHA
			rawParents[c.SHA] = append([]string{}, c.Parents...)
		}
		branches := make(map[string]string, len(g.Branches))
		origBranches := make(map[string]string, len(g.Branches))
		for k, v := range g.Branches {
			branches[k] = v
			origBranches[k] = v
		}
		tags := make([]GitTag, len(g.Tags))
		for i, t := range g.Tags {
			pt := t
			if pt.OriginalTargetSHA == "" {
				pt.OriginalTargetSHA = t.TargetSHA
			}
			tags[i] = pt
		}
		return ProjectedGraph{
			SourceSubdir:      "",
			DefaultBranch:     g.DefaultBranch,
			Commits:           commits,
			CommitsBySHA:      bySHA,
			RawGitParents:     rawParents,
			EffectiveCommitOf: eff,
			Branches:          branches,
			OriginalBranches:  origBranches,
			Tags:              tags,
			CoverageComplete:  true,
		}, nil
	}

	out := ProjectedGraph{
		SourceSubdir:      sourceSubdir,
		CommitsBySHA:      map[string]GitCommit{},
		RawGitParents:     map[string][]string{},
		EffectiveCommitOf: map[string]string{},
		Branches:          map[string]string{},
		OriginalBranches:  map[string]string{},
	}

	allDeclaredPrefixes := []string{sourceSubdir + "/"}
	for _, sib := range siblingSubdirs {
		sib = strings.Trim(strings.TrimSpace(sib), "/")
		if sib != "" && sib != sourceSubdir {
			allDeclaredPrefixes = append(allDeclaredPrefixes, sib+"/")
		}
	}

	unmappedSet := map[string]bool{}
	projSubtree := map[string]string{}
	ancestors := map[string]map[string]bool{}

	modulePrefix := sourceSubdir + "/"

	computeSubtree := func(treeSHA string) (string, error) {
		entries, err := cache.Entries(ctx, gitBin, mirrorDir, treeSHA)
		if err != nil {
			return "", err
		}
		var scoped []treeEntry
		var rootGitmodulesOID string
		for _, e := range entries {
			if e.Path == ".gitmodules" && e.Type == "blob" {
				rootGitmodulesOID = e.OID
			}
			if strings.HasPrefix(e.Path, modulePrefix) {
				rel := strings.TrimPrefix(e.Path, modulePrefix)
				if rel != "" && rel != ".lore" && !strings.HasPrefix(rel, ".lore/") {
					scoped = append(scoped, treeEntry{Mode: e.Mode, Type: e.Type, OID: e.OID, Path: rel})
				}
				continue
			}
			inSibling := false
			for _, pfx := range allDeclaredPrefixes {
				if strings.HasPrefix(e.Path, pfx) {
					inSibling = true
					break
				}
			}
			if !inSibling {
				unmappedSet[e.Path] = true
			}
		}
		if len(scoped) == 0 {
			return "", nil
		}
		sort.Slice(scoped, func(i, j int) bool { return scoped[i].Path < scoped[j].Path })
		h := sha256.New()
		hasGitlink := false
		for _, e := range scoped {
			if e.Mode == "160000" || e.Type == "commit" {
				hasGitlink = true
			}
			_, _ = fmt.Fprintf(h, "%s\t%s\t%s\t%s\n", e.Mode, e.Type, e.OID, e.Path)
		}
		if hasGitlink && rootGitmodulesOID != "" {
			_, _ = fmt.Fprintf(h, ".gitmodules_ref\t%s\n", rootGitlinkMetaRef(rootGitmodulesOID))
		}
		return hex.EncodeToString(h.Sum(nil)), nil
	}

	recordProjected := func(orig GitCommit, projParents []string, subDigest string) {
		cp := orig
		cp.Parents = append([]string{}, projParents...)
		out.Commits = append(out.Commits, cp)
		out.CommitsBySHA[cp.SHA] = cp
		out.RawGitParents[cp.SHA] = append([]string{}, orig.Parents...)
		out.EffectiveCommitOf[cp.SHA] = cp.SHA
		projSubtree[cp.SHA] = subDigest

		anc := map[string]bool{cp.SHA: true}
		for _, p := range projParents {
			anc[p] = true
			for a := range ancestors[p] {
				anc[a] = true
			}
		}
		ancestors[cp.SHA] = anc
	}

	for _, c := range g.Commits {
		subDigest, err := computeSubtree(c.TreeSHA)
		if err != nil {
			return out, err
		}

		var rawMapped []string
		seenP := map[string]bool{}
		for _, p := range c.Parents {
			eff := out.EffectiveCommitOf[p]
			if eff != "" && !seenP[eff] {
				seenP[eff] = true
				rawMapped = append(rawMapped, eff)
			}
		}

		switch len(rawMapped) {
		case 0:
			if subDigest == "" {
				out.EffectiveCommitOf[c.SHA] = ""
				out.AliasedCommitsCount++
			} else {
				recordProjected(c, nil, subDigest)
			}

		case 1:
			p0 := rawMapped[0]
			if subDigest == projSubtree[p0] {
				out.EffectiveCommitOf[c.SHA] = p0
				out.AliasedCommitsCount++
			} else {
				recordProjected(c, []string{p0}, subDigest)
			}

		default:
			kept := []string{rawMapped[0]}
			for j := 1; j < len(rawMapped); j++ {
				cand := rawMapped[j]
				redundant := false
				for _, prev := range kept {
					if ancestors[prev][cand] {
						redundant = true
						break
					}
				}
				if !redundant {
					kept = append(kept, cand)
				}
			}
			if len(kept) == 1 && subDigest == projSubtree[kept[0]] {
				out.EffectiveCommitOf[c.SHA] = kept[0]
				out.AliasedCommitsCount++
			} else {
				recordProjected(c, kept, subDigest)
			}
		}
	}

	for uPath := range unmappedSet {
		out.UnmappedPaths = append(out.UnmappedPaths, uPath)
	}
	sort.Strings(out.UnmappedPaths)

	for _, uPath := range out.UnmappedPaths {
		if rule, matched := MatchPathRule(uPath, pathRules); matched {
			cp := ClassifiedPath{
				Path:         uPath,
				Category:     rule.Category,
				Pattern:      rule.Pattern,
				TargetModule: rule.TargetModule,
				Reason:       rule.Reason,
			}
			if rule.Category == PathCategorySeparateModule {
				out.ClassifiedSeparateModule = append(out.ClassifiedSeparateModule, cp)
			} else {
				out.ClassifiedExcluded = append(out.ClassifiedExcluded, cp)
			}
		} else {
			out.UndecidedPaths = append(out.UndecidedPaths, uPath)
		}
	}
	out.CoverageComplete = len(out.UndecidedPaths) == 0

	for _, bName := range sortedKeys(g.Branches) {
		tipSHA := g.Branches[bName]
		if eff := out.EffectiveCommitOf[tipSHA]; eff != "" {
			out.Branches[bName] = eff
			out.OriginalBranches[bName] = tipSHA
		} else {
			out.SkippedEmptyBranches = append(out.SkippedEmptyBranches, bName)
		}
	}
	if g.DefaultBranch != "" && out.Branches[g.DefaultBranch] != "" {
		out.DefaultBranch = g.DefaultBranch
	} else if out.Branches["main"] != "" {
		out.DefaultBranch = "main"
	} else if out.Branches["master"] != "" {
		out.DefaultBranch = "master"
	} else {
		for _, bName := range sortedKeys(out.Branches) {
			out.DefaultBranch = bName
			break
		}
	}

	for _, t := range g.Tags {
		if eff := out.EffectiveCommitOf[t.TargetSHA]; eff != "" {
			pt := t
			pt.OriginalTargetSHA = t.TargetSHA
			pt.TargetSHA = eff
			out.Tags = append(out.Tags, pt)
		} else {
			out.SkippedEmptyTags = append(out.SkippedEmptyTags, t.Name)
		}
	}
	return out, nil
}

func rootGitlinkMetaRef(oid string) string {
	return oid
}
