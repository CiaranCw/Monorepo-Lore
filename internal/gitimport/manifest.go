package gitimport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"lore-monorepo/internal/project"
)

const (
	ConflictFail           = "fail"
	ConflictSkipIfImported = "skip_if_imported"
	ConflictResume         = "resume"

	// LFSModeHydrate requires every Git LFS pointer to be hydrated into its real
	// binary content and cryptographically verified (SHA-256 OID + byte size).
	// Unhydrated pointers fail import so pointer-only copies are never claimed as full migrations.
	LFSModeHydrate = "hydrate"
	// LFSModeAuto is accepted as a backward-compatible alias for LFSModeHydrate.
	LFSModeAuto = "auto"
	// LFSModePointer preserves Git LFS pointer files without binary hydration and
	// explicitly flags LFSHydrationStatus="pointer_only_unhydrated" and FullContentMigrated=false.
	LFSModePointer = "pointer"

	SubmoduleRecordGitlink     = "record_gitlink"
	SubmoduleRequireRegistered = "require_registered"

	GlobalPolicyStrict        = "strict"
	GlobalPolicyAllowUnmapped = "allow_unmapped"

	PathCategoryExcluded       = "excluded"
	PathCategorySeparateModule = "separate_module"
)

// PathRule classifies files outside mapped module subdirectories in an external Git Monorepo.
type PathRule struct {
	Pattern      string `json:"pattern" toml:"pattern"`
	Category     string `json:"category" toml:"category"` // "excluded" or "separate_module"
	TargetModule string `json:"target_module,omitempty" toml:"target_module"`
	Reason       string `json:"reason" toml:"reason"`
}

// RepoSpec describes one external Git repository (or one subdirectory of an
// external Git Monorepo) to import as an independent Monorepo-Lore module.
type RepoSpec struct {
	SourceURL             string            `json:"source_url" toml:"source_url"`
	SourceSubdir          string            `json:"source_subdir,omitempty" toml:"source_subdir"`
	ModuleName            string            `json:"module_name" toml:"module_name"`
	MountPath             string            `json:"mount_path" toml:"mount_path"`
	Platform              string            `json:"platform,omitempty" toml:"platform"`
	ConflictPolicy        string            `json:"conflict_policy,omitempty" toml:"conflict_policy"`
	LFSMode               string            `json:"lfs_mode,omitempty" toml:"lfs_mode"`
	SubmodulePolicy       string            `json:"submodule_policy,omitempty" toml:"submodule_policy"`
	GlobalFilesPolicy     string            `json:"global_files_policy,omitempty" toml:"global_files_policy"`
	ExpectedDefaultBranch string            `json:"expected_default_branch,omitempty" toml:"expected_default_branch"`
	ExpectedBranches      map[string]string `json:"expected_branches,omitempty" toml:"expected_branches"`
	ExpectedTags          map[string]string `json:"expected_tags,omitempty" toml:"expected_tags"`
	Auth                  AuthConfig        `json:"auth,omitempty" toml:"auth"`
}

// Manifest describes a single or batch import job.
type Manifest struct {
	JobKey            string     `json:"job_key,omitempty" toml:"job_key"`
	Project           string     `json:"project" toml:"project"`
	DryRun            bool       `json:"dry_run,omitempty" toml:"dry_run"`
	ConflictPolicy    string     `json:"conflict_policy,omitempty" toml:"conflict_policy"`
	GlobalFilesPolicy string     `json:"global_files_policy,omitempty" toml:"global_files_policy"`
	Concurrency       int        `json:"concurrency,omitempty" toml:"concurrency"`
	PathRules         []PathRule `json:"path_rules,omitempty" toml:"path_rules"`
	Repositories      []RepoSpec `json:"repositories" toml:"repositories"`
}

// LoadManifest parses and validates a TOML or JSON import manifest file.
// Unknown keys (such as an accidental plaintext `token` or `password` field)
// are strictly rejected so secrets cannot hide in manifest files.
func LoadManifest(filePath string) (Manifest, error) {
	body, err := os.ReadFile(filePath)
	if err != nil {
		return Manifest{}, err
	}
	ext := strings.ToLower(filepath.Ext(filePath))
	var m Manifest
	if ext == ".json" {
		dec := json.NewDecoder(strings.NewReader(string(body)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&m); err != nil {
			return Manifest{}, fmt.Errorf("gitimport: parse json manifest: %w", err)
		}
	} else {
		meta, err := toml.Decode(string(body), &m)
		if err != nil {
			return Manifest{}, fmt.Errorf("gitimport: parse toml manifest: %w", err)
		}
		if undecoded := meta.Undecoded(); len(undecoded) > 0 {
			return Manifest{}, fmt.Errorf("gitimport: unknown manifest keys: %v", undecoded)
		}
	}
	if err := NormalizeAndValidateManifest(&m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// NormalizeAndValidateManifest normalizes defaults and validates module names,
// mount paths, source_subdir paths (preventing overlapping subdirs of the same
// source monorepo), path classification rules, LFS/submodule policies, and URLs.
func NormalizeAndValidateManifest(m *Manifest) error {
	if m == nil {
		return errors.New("gitimport: manifest is nil")
	}
	m.Project = strings.TrimSpace(m.Project)
	if m.Project == "" {
		return errors.New("gitimport: project is required")
	}
	if m.ConflictPolicy == "" {
		m.ConflictPolicy = ConflictFail
	}
	if !validConflictPolicy(m.ConflictPolicy) {
		return fmt.Errorf("gitimport: invalid conflict_policy %q", m.ConflictPolicy)
	}
	m.GlobalFilesPolicy = strings.ToLower(strings.TrimSpace(m.GlobalFilesPolicy))
	if m.GlobalFilesPolicy == "" {
		m.GlobalFilesPolicy = GlobalPolicyStrict
	}
	if m.GlobalFilesPolicy != GlobalPolicyStrict && m.GlobalFilesPolicy != GlobalPolicyAllowUnmapped {
		return fmt.Errorf("gitimport: invalid global_files_policy %q", m.GlobalFilesPolicy)
	}
	if m.Concurrency <= 0 {
		m.Concurrency = 1
	} else if m.Concurrency > 4 {
		m.Concurrency = 4
	}
	if len(m.Repositories) == 0 {
		return errors.New("gitimport: at least one repository is required")
	}

	for i := range m.PathRules {
		pr := &m.PathRules[i]
		pr.Pattern = strings.Trim(strings.TrimSpace(strings.ReplaceAll(pr.Pattern, "\\", "/")), "/")
		pr.Category = strings.ToLower(strings.TrimSpace(pr.Category))
		pr.TargetModule = strings.TrimSpace(pr.TargetModule)
		pr.Reason = strings.TrimSpace(pr.Reason)
		if pr.Pattern == "" || hasControlChars(pr.Pattern) {
			return fmt.Errorf("path_rules[%d]: pattern is required", i)
		}
		if pr.Reason == "" {
			return fmt.Errorf("path_rules[%d] (%s): reason is required", i, pr.Pattern)
		}
		switch pr.Category {
		case PathCategoryExcluded:
		case PathCategorySeparateModule:
			if pr.TargetModule == "" {
				return fmt.Errorf("path_rules[%d] (%s): target_module is required for separate_module", i, pr.Pattern)
			}
		default:
			return fmt.Errorf("path_rules[%d] (%s): invalid category %q (want excluded or separate_module)", i, pr.Pattern, pr.Category)
		}
	}

	seenNames := map[string]bool{}
	var seenMounts []string
	sourceSubdirsByURL := map[string][]string{}

	for i := range m.Repositories {
		r := &m.Repositories[i]
		cleanURL, plat, err := ValidateAndDetect(r.SourceURL, r.Platform)
		if err != nil {
			return fmt.Errorf("repository[%d]: %w", i, err)
		}
		r.SourceURL = cleanURL
		r.Platform = plat

		cleanSubdir, err := NormalizeSourceSubdir(r.SourceSubdir)
		if err != nil {
			return fmt.Errorf("repository[%d] source_subdir: %w", i, err)
		}
		r.SourceSubdir = cleanSubdir

		r.ModuleName = strings.TrimSpace(r.ModuleName)
		if r.MountPath == "" {
			r.MountPath = r.ModuleName
		}
		if err := project.ValidateName(r.ModuleName); err != nil {
			return fmt.Errorf("repository[%d] module_name: %w", i, err)
		}
		normMount, err := project.NormalizeMountPath(r.MountPath)
		if err != nil {
			return fmt.Errorf("repository[%d] mount_path: %w", i, err)
		}
		r.MountPath = normMount
		if r.ConflictPolicy == "" {
			r.ConflictPolicy = m.ConflictPolicy
		}
		if !validConflictPolicy(r.ConflictPolicy) {
			return fmt.Errorf("repository[%d]: invalid conflict_policy %q", i, r.ConflictPolicy)
		}

		r.LFSMode = strings.ToLower(strings.TrimSpace(r.LFSMode))
		if r.LFSMode == "" || r.LFSMode == LFSModeAuto {
			r.LFSMode = LFSModeHydrate
		}
		if r.LFSMode != LFSModeHydrate && r.LFSMode != LFSModePointer {
			return fmt.Errorf("repository[%d]: invalid lfs_mode %q (want hydrate or pointer)", i, r.LFSMode)
		}

		r.SubmodulePolicy = strings.ToLower(strings.TrimSpace(r.SubmodulePolicy))
		if r.SubmodulePolicy == "" {
			r.SubmodulePolicy = SubmoduleRecordGitlink
		}
		if r.SubmodulePolicy != SubmoduleRecordGitlink && r.SubmodulePolicy != SubmoduleRequireRegistered {
			return fmt.Errorf("repository[%d]: invalid submodule_policy %q", i, r.SubmodulePolicy)
		}

		r.GlobalFilesPolicy = strings.ToLower(strings.TrimSpace(r.GlobalFilesPolicy))
		if r.GlobalFilesPolicy == "" {
			r.GlobalFilesPolicy = m.GlobalFilesPolicy
		}
		if r.GlobalFilesPolicy != GlobalPolicyStrict && r.GlobalFilesPolicy != GlobalPolicyAllowUnmapped {
			return fmt.Errorf("repository[%d]: invalid global_files_policy %q", i, r.GlobalFilesPolicy)
		}

		if seenNames[r.ModuleName] {
			return fmt.Errorf("repository[%d]: duplicate module_name %q in manifest", i, r.ModuleName)
		}
		seenNames[r.ModuleName] = true
		for _, prevMount := range seenMounts {
			if mountsOverlap(prevMount, r.MountPath) {
				return fmt.Errorf("repository[%d]: mount_path %q overlaps with %q in manifest", i, r.MountPath, prevMount)
			}
		}
		seenMounts = append(seenMounts, r.MountPath)

		for _, prevSub := range sourceSubdirsByURL[r.SourceURL] {
			if prevSub == "" || r.SourceSubdir == "" || mountsOverlap(prevSub, r.SourceSubdir) {
				return fmt.Errorf("repository[%d]: source_subdir %q overlaps with %q for the same source_url", i, r.SourceSubdir, prevSub)
			}
		}
		sourceSubdirsByURL[r.SourceURL] = append(sourceSubdirsByURL[r.SourceURL], r.SourceSubdir)
	}
	return nil
}

func validConflictPolicy(p string) bool {
	return p == ConflictFail || p == ConflictSkipIfImported || p == ConflictResume
}

func mountsOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// MatchPathRule matches a slash-separated repository-relative path against PathRules in order.
// Supports exact path ("README.md"), directory glob (".github/**", "ci/*"), and filename glob ("*.md").
func MatchPathRule(relPath string, rules []PathRule) (PathRule, bool) {
	relPath = strings.Trim(relPath, "/")
	for _, r := range rules {
		pat := r.Pattern
		if pat == "**" || pat == "*" || pat == relPath {
			return r, true
		}
		if strings.HasSuffix(pat, "/**") {
			prefix := strings.TrimSuffix(pat, "/**")
			if relPath == prefix || strings.HasPrefix(relPath, prefix+"/") {
				return r, true
			}
		}
		if ok, err := path.Match(pat, relPath); err == nil && ok {
			return r, true
		}
	}
	return PathRule{}, false
}

// HashManifest computes a secret-free SHA-256 digest of the normalized manifest.
func HashManifest(m Manifest) string {
	type cleanItem struct {
		SourceURL             string            `json:"source_url"`
		SourceSubdir          string            `json:"source_subdir,omitempty"`
		ModuleName            string            `json:"module_name"`
		MountPath             string            `json:"mount_path"`
		Platform              string            `json:"platform"`
		ConflictPolicy        string            `json:"conflict_policy"`
		LFSMode               string            `json:"lfs_mode"`
		SubmodulePolicy       string            `json:"submodule_policy"`
		GlobalFilesPolicy     string            `json:"global_files_policy"`
		ExpectedDefaultBranch string            `json:"expected_default_branch,omitempty"`
		ExpectedBranches      map[string]string `json:"expected_branches,omitempty"`
		ExpectedTags          map[string]string `json:"expected_tags,omitempty"`
	}
	items := make([]cleanItem, len(m.Repositories))
	for i, r := range m.Repositories {
		items[i] = cleanItem{
			SourceURL: r.SourceURL, SourceSubdir: r.SourceSubdir,
			ModuleName: r.ModuleName, MountPath: r.MountPath,
			Platform: r.Platform, ConflictPolicy: r.ConflictPolicy,
			LFSMode: r.LFSMode, SubmodulePolicy: r.SubmodulePolicy,
			GlobalFilesPolicy:     r.GlobalFilesPolicy,
			ExpectedDefaultBranch: r.ExpectedDefaultBranch,
			ExpectedBranches:      r.ExpectedBranches,
			ExpectedTags:          r.ExpectedTags,
		}
	}
	b, _ := json.Marshal(struct {
		Project   string      `json:"project"`
		DryRun    bool        `json:"dry_run"`
		PathRules []PathRule  `json:"path_rules,omitempty"`
		Items     []cleanItem `json:"items"`
	}{Project: m.Project, DryRun: m.DryRun, PathRules: m.PathRules, Items: items})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
