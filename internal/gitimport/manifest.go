package gitimport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"lore-monorepo/internal/project"
)

const (
	ConflictFail           = "fail"
	ConflictSkipIfImported = "skip_if_imported"
	ConflictResume         = "resume"

	LFSModeAuto    = "auto"
	LFSModePointer = "pointer"
)

// RepoSpec describes one external Git repository to import as a Monorepo-Lore module.
type RepoSpec struct {
	SourceURL      string     `json:"source_url" toml:"source_url"`
	ModuleName     string     `json:"module_name" toml:"module_name"`
	MountPath      string     `json:"mount_path" toml:"mount_path"`
	Platform       string     `json:"platform,omitempty" toml:"platform"`
	ConflictPolicy string     `json:"conflict_policy,omitempty" toml:"conflict_policy"`
	LFSMode        string     `json:"lfs_mode,omitempty" toml:"lfs_mode"`
	Auth           AuthConfig `json:"auth,omitempty" toml:"auth"`
}

// Manifest describes a single or batch import job.
type Manifest struct {
	JobKey         string     `json:"job_key,omitempty" toml:"job_key"`
	Project        string     `json:"project" toml:"project"`
	DryRun         bool       `json:"dry_run,omitempty" toml:"dry_run"`
	ConflictPolicy string     `json:"conflict_policy,omitempty" toml:"conflict_policy"`
	Concurrency    int        `json:"concurrency,omitempty" toml:"concurrency"`
	Repositories   []RepoSpec `json:"repositories" toml:"repositories"`
}

// LoadManifest parses and validates a TOML or JSON import manifest file.
// Unknown keys (such as an accidental plaintext `token` or `password` field)
// are strictly rejected so secrets cannot hide in manifest files.
func LoadManifest(path string) (Manifest, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	ext := strings.ToLower(filepath.Ext(path))
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
// mount paths (including intra-manifest overlap), and URLs.
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
	if m.Concurrency <= 0 {
		m.Concurrency = 1
	} else if m.Concurrency > 4 {
		m.Concurrency = 4
	}
	if len(m.Repositories) == 0 {
		return errors.New("gitimport: at least one repository is required")
	}

	seenNames := map[string]bool{}
	var seenMounts []string
	for i := range m.Repositories {
		r := &m.Repositories[i]
		cleanURL, plat, err := ValidateAndDetect(r.SourceURL, r.Platform)
		if err != nil {
			return fmt.Errorf("repository[%d]: %w", i, err)
		}
		r.SourceURL = cleanURL
		r.Platform = plat
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
		if r.LFSMode == "" {
			r.LFSMode = LFSModeAuto
		}
		if r.LFSMode != LFSModeAuto && r.LFSMode != LFSModePointer {
			return fmt.Errorf("repository[%d]: invalid lfs_mode %q", i, r.LFSMode)
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
	}
	return nil
}

func validConflictPolicy(p string) bool {
	return p == ConflictFail || p == ConflictSkipIfImported || p == ConflictResume
}

func mountsOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// HashManifest computes a secret-free SHA-256 digest of the normalized manifest.
func HashManifest(m Manifest) string {
	type cleanItem struct {
		SourceURL      string `json:"source_url"`
		ModuleName     string `json:"module_name"`
		MountPath      string `json:"mount_path"`
		Platform       string `json:"platform"`
		ConflictPolicy string `json:"conflict_policy"`
		LFSMode        string `json:"lfs_mode"`
	}
	items := make([]cleanItem, len(m.Repositories))
	for i, r := range m.Repositories {
		items[i] = cleanItem{
			SourceURL: r.SourceURL, ModuleName: r.ModuleName, MountPath: r.MountPath,
			Platform: r.Platform, ConflictPolicy: r.ConflictPolicy, LFSMode: r.LFSMode,
		}
	}
	b, _ := json.Marshal(struct {
		Project string      `json:"project"`
		DryRun  bool        `json:"dry_run"`
		Items   []cleanItem `json:"items"`
	}{Project: m.Project, DryRun: m.DryRun, Items: items})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
