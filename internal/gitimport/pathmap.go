package gitimport

import (
	"fmt"
	"sort"
	"strings"
)

const (
	MappingTree = "tree"
	MappingFile = "file"

	ProjectionNormal     = "normal"
	ProjectionRename     = "rename"
	ProjectionFileMove   = "file_move"
	ProjectionDependency = "dependency"
)

// PathMapping rewrites one source path or directory into a module-relative path.
// A tree mapping claims the directory and everything under it. A file mapping
// claims one exact path and outranks a tree mapping of the same module.
type PathMapping struct {
	ID             string `json:"id,omitempty" toml:"id"`
	SourcePrefix   string `json:"source_prefix" toml:"source_prefix"`
	TargetPrefix   string `json:"target_prefix,omitempty" toml:"target_prefix"`
	Kind           string `json:"kind" toml:"kind"`
	ProjectionType string `json:"projection_type,omitempty" toml:"projection_type"`
}

// MappedEntry is one source blob or gitlink after path rewriting.
type MappedEntry struct {
	treeEntry
	SourcePath     string
	RuleID         string
	ProjectionType string
}

// MappingsForSubdir is the historical single-prefix mapping.
func MappingsForSubdir(sourceSubdir string) []PathMapping {
	sourceSubdir = strings.Trim(strings.TrimSpace(sourceSubdir), "/")
	if sourceSubdir == "" {
		return nil
	}
	return []PathMapping{{
		ID: "source_subdir", SourcePrefix: sourceSubdir, Kind: MappingTree, ProjectionType: ProjectionNormal,
	}}
}

// EffectiveMappings returns the module's current directory plus any extra history mappings.
func (r RepoSpec) EffectiveMappings() []PathMapping {
	var out []PathMapping
	primary := strings.Trim(strings.TrimSpace(r.SourceSubdir), "/")
	if primary != "" {
		out = append(out, PathMapping{
			ID: "source_subdir", SourcePrefix: primary, Kind: MappingTree, ProjectionType: ProjectionNormal,
		})
	}
	for _, m := range r.PathMappings {
		m.SourcePrefix = strings.Trim(strings.TrimSpace(m.SourcePrefix), "/")
		m.TargetPrefix = strings.Trim(strings.TrimSpace(m.TargetPrefix), "/")
		m.Kind = strings.ToLower(strings.TrimSpace(m.Kind))
		if m.Kind == "" {
			m.Kind = MappingTree
		}
		if m.Kind == MappingTree && m.SourcePrefix == primary && m.TargetPrefix == "" {
			continue
		}
		if m.ProjectionType == "" {
			if m.Kind == MappingFile {
				m.ProjectionType = ProjectionFileMove
			} else {
				m.ProjectionType = ProjectionRename
			}
		}
		out = append(out, m)
	}
	return out
}

func validateMapping(m PathMapping) error {
	if m.Kind != MappingTree && m.Kind != MappingFile {
		return fmt.Errorf("path mapping %q: kind must be tree or file", m.ID)
	}
	switch m.ProjectionType {
	case "", ProjectionNormal, ProjectionRename, ProjectionFileMove, ProjectionDependency:
	default:
		return fmt.Errorf("path mapping %q: invalid projection_type %q", m.ID, m.ProjectionType)
	}
	if _, err := NormalizeSourceSubdir(m.SourcePrefix); err != nil || m.SourcePrefix == "" {
		return fmt.Errorf("path mapping %q: invalid source_prefix", m.ID)
	}
	if m.TargetPrefix != "" {
		if _, err := NormalizeSourceSubdir(m.TargetPrefix); err != nil {
			return fmt.Errorf("path mapping %q: invalid target_prefix", m.ID)
		}
	}
	if m.Kind == MappingFile && m.TargetPrefix == "" {
		return fmt.Errorf("path mapping %q: file mapping requires target_prefix", m.ID)
	}
	return nil
}

func mappingsClaimOverlap(a, b PathMapping) bool {
	if a.Kind == MappingFile && b.Kind == MappingFile {
		return a.SourcePrefix == b.SourcePrefix
	}
	if a.Kind == MappingFile {
		return pathUnderTree(a.SourcePrefix, b.SourcePrefix)
	}
	if b.Kind == MappingFile {
		return pathUnderTree(b.SourcePrefix, a.SourcePrefix)
	}
	return a.SourcePrefix == b.SourcePrefix ||
		strings.HasPrefix(a.SourcePrefix, b.SourcePrefix+"/") ||
		strings.HasPrefix(b.SourcePrefix, a.SourcePrefix+"/")
}

func pathUnderTree(filePath, treePrefix string) bool {
	return filePath == treePrefix || strings.HasPrefix(filePath, treePrefix+"/")
}

func matchScore(path string, m PathMapping) (int, bool) {
	switch m.Kind {
	case MappingFile:
		if path == m.SourcePrefix {
			return len(m.SourcePrefix) + 1_000_000, true
		}
	case MappingTree:
		if path == m.SourcePrefix || strings.HasPrefix(path, m.SourcePrefix+"/") {
			return len(m.SourcePrefix), true
		}
	}
	return 0, false
}

func rewriteMapped(path string, m PathMapping) (string, bool) {
	switch m.Kind {
	case MappingFile:
		if path != m.SourcePrefix {
			return "", false
		}
		return m.TargetPrefix, true
	case MappingTree:
		if !strings.HasPrefix(path, m.SourcePrefix+"/") {
			return "", false
		}
		rel := strings.TrimPrefix(path, m.SourcePrefix+"/")
		if rel == "" || rel == ".lore" || strings.HasPrefix(rel, ".lore/") {
			return "", false
		}
		if m.TargetPrefix == "" {
			return rel, true
		}
		return m.TargetPrefix + "/" + rel, true
	default:
		return "", false
	}
}

// ApplyPathMappings rewrites entries into one module tree.
// Identical mode and OID at the same target are deduplicated. Different content is an error.
// Nil mappings mean the whole repository.
func ApplyPathMappings(entries []treeEntry, mappings []PathMapping) ([]MappedEntry, int, error) {
	if len(mappings) == 0 {
		out := make([]MappedEntry, 0, len(entries))
		for _, e := range entries {
			out = append(out, MappedEntry{treeEntry: e, SourcePath: e.Path, RuleID: "", ProjectionType: ProjectionNormal})
		}
		return out, 0, nil
	}
	byTarget := map[string]MappedEntry{}
	deduped := 0
	var targets []string
	for _, e := range entries {
		var best PathMapping
		bestScore := -1
		ties := 0
		for _, m := range mappings {
			score, ok := matchScore(e.Path, m)
			if !ok {
				continue
			}
			if score > bestScore {
				best = m
				bestScore = score
				ties = 1
			} else if score == bestScore {
				ties++
			}
		}
		if ties == 0 {
			continue
		}
		if ties > 1 {
			return nil, 0, fmt.Errorf("gitimport: ambiguous path mapping for %q", e.Path)
		}
		target, ok := rewriteMapped(e.Path, best)
		if !ok || target == "" {
			continue
		}
		mapped := MappedEntry{
			treeEntry:      treeEntry{Mode: e.Mode, Type: e.Type, OID: e.OID, Path: target},
			SourcePath:     e.Path,
			RuleID:         best.ID,
			ProjectionType: best.ProjectionType,
		}
		if prev, exists := byTarget[target]; exists {
			if prev.Mode != mapped.Mode || prev.OID != mapped.OID || prev.Type != mapped.Type {
				return nil, 0, fmt.Errorf("gitimport: path conflict at %q from %q and %q", target, prev.SourcePath, mapped.SourcePath)
			}
			deduped++
			continue
		}
		byTarget[target] = mapped
		targets = append(targets, target)
	}
	sort.Strings(targets)
	out := make([]MappedEntry, 0, len(targets))
	for _, t := range targets {
		out = append(out, byTarget[t])
	}
	return out, deduped, nil
}

func claimedBy(path string, mappings []PathMapping) bool {
	for _, m := range mappings {
		if _, ok := matchScore(path, m); ok {
			if _, rewritten := rewriteMapped(path, m); rewritten {
				return true
			}
			if m.Kind == MappingTree && (path == m.SourcePrefix || strings.HasPrefix(path, m.SourcePrefix+"/")) {
				return true
			}
			if m.Kind == MappingFile && path == m.SourcePrefix {
				return true
			}
		}
	}
	return false
}
