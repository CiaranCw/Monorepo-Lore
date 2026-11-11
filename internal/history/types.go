// Package history indexes and queries module commit DAGs and permission-filtered
// monorepo aggregated commit timelines.
//
// Three history concepts are kept strictly separate:
//  1. Module commit history (module_commits + module_commit_parents + module_refs):
//     every real commit inside each child module repository, whether imported from
//     an external Git repository or committed natively in Lore afterwards.
//  2. Monorepo aggregated history: a live permission-filtered timeline union over
//     the caller's currently accessible modules in a project (never fabricating a
//     fake cross-repository Git DAG).
//  3. Parent snapshot history (snapshots table): published immutable module-pin
//     manifests on the parent repository.
package history

import (
	"errors"
)

var (
	ErrNotFound        = errors.New("history: not found")
	ErrInvalidCursor   = errors.New("history: invalid pagination cursor")
	ErrInvalidFilter   = errors.New("history: invalid query filter")
	ErrBranchDiscovery = errors.New("history: failed to discover repository branches")
)

const (
	OriginNativeLore = "native_lore"
	OriginGitImport  = "git_import"

	AliasDirect    = "direct"
	AliasUnchanged = "unchanged_alias"
	AliasPreModule = "pre_module_empty"

	OrderDesc = "desc"
	OrderAsc  = "asc"

	DefaultLimit = 50
	MaxLimit     = 500
)

// CommitAlias persists the per-module projection mapping for every source Git commit
// (distinguishing the raw source commit, the module's actual Lore revision, and folded aliases).
type CommitAlias struct {
	ModuleID                int64  `json:"module_id"`
	SourceCommitID          string `json:"source_commit_id"`
	AliasStatus             string `json:"alias_status"` // direct, unchanged_alias, pre_module_empty
	EffectiveSourceCommitID string `json:"effective_source_commit_id,omitempty"`
	LoreRevision            string `json:"lore_revision,omitempty"`
	SourceSubdir            string `json:"source_subdir,omitempty"`
	UpdatedAt               string `json:"updated_at,omitempty"`
}

// ParentLink represents one ordered parent edge in a module's commit DAG.
type ParentLink struct {
	Ord            int    `json:"ord"`
	LoreRevision   string `json:"lore_revision,omitempty"`
	SourceCommitID string `json:"source_commit_id,omitempty"`
}

// RefBadge is a branch or tag pointing at a commit.
type RefBadge struct {
	Type        string `json:"type"` // "branch" or "tag"
	Name        string `json:"name"`
	IsDefault   bool   `json:"is_default,omitempty"`
	IsAnnotated bool   `json:"is_annotated,omitempty"`
}

// RefDetail is full branch or tag metadata for a module.
type RefDetail struct {
	ModuleID               int64  `json:"module_id"`
	ModuleName             string `json:"module_name"`
	Type                   string `json:"type"`
	Name                   string `json:"name"`
	LoreRevision           string `json:"lore_revision"`
	SourceCommitID         string `json:"source_commit_id,omitempty"`
	OriginalSourceCommitID string `json:"original_source_commit_id,omitempty"`
	SourceTagObjectID      string `json:"source_tag_object_id,omitempty"`
	LoreBranchID           string `json:"lore_branch_id,omitempty"`
	IsDefault              bool   `json:"is_default"`
	IsAnnotated            bool   `json:"is_annotated"`
	TaggerName             string `json:"tagger_name,omitempty"`
	TaggerEmail            string `json:"tagger_email,omitempty"`
	TaggedAt               string `json:"tagged_at,omitempty"`
	TagMessage             string `json:"tag_message,omitempty"`
	UpdatedAt              string `json:"updated_at"`
}

// SpecialObject describes a Git LFS file, submodule gitlink, or symlink associated with a commit.
type SpecialObject struct {
	Kind           string `json:"kind"` // lfs_hydrated, lfs_pointer, submodule_gitlink, symlink
	Path           string `json:"path"`
	OID            string `json:"oid,omitempty"`
	SizeBytes      int64  `json:"size_bytes,omitempty"`
	DetailJSON     string `json:"detail_json,omitempty"`
	LoreRevision   string `json:"lore_revision,omitempty"`
	SourceCommitID string `json:"source_commit_id,omitempty"`
}

// Commit is one commit entry in either a single-module history or an aggregated project timeline.
type Commit struct {
	ProjectID           int64             `json:"project_id"`
	ProjectName         string            `json:"project_name"`
	ModuleID            int64             `json:"module_id"`
	ModuleName          string            `json:"module_name"`
	MountPath           string            `json:"mount_path"`
	RepositoryID        string            `json:"repository_id"`
	CanonicalID         string            `json:"canonical_id"`
	LoreRevision        string            `json:"lore_revision"`
	LoreRevisionNumber  int               `json:"lore_revision_number"`
	SourceCommitID      string            `json:"source_commit_id,omitempty"`
	QueriedSourceCommit string            `json:"queried_source_commit_id,omitempty"`
	ResolvedViaAlias    bool              `json:"resolved_via_alias,omitempty"`
	AliasStatus         string            `json:"alias_status,omitempty"`
	SourceSubdir        string            `json:"source_subdir,omitempty"`
	OriginKind          string            `json:"origin_kind"`
	IsMerge             bool              `json:"is_merge"`
	ParentCount         int               `json:"parent_count"`
	Parents             []ParentLink      `json:"parents"`
	AuthorName          string            `json:"author_name"`
	AuthorEmail         string            `json:"author_email,omitempty"`
	AuthoredAt          string            `json:"authored_at"`
	AuthoredUnixMS      int64             `json:"authored_unix_ms"`
	CommitterName       string            `json:"committer_name"`
	CommitterEmail      string            `json:"committer_email,omitempty"`
	CommittedAt         string            `json:"committed_at"`
	CommittedUnixMS     int64             `json:"committed_unix_ms"`
	LoreCommittedUnixMS int64             `json:"lore_committed_unix_ms,omitempty"`
	Subject             string            `json:"subject"`
	Message             string            `json:"message"`
	GitTreeID           string            `json:"git_tree_id,omitempty"`
	LoreBranchID        string            `json:"lore_branch_id,omitempty"`
	Refs                []RefBadge        `json:"refs,omitempty"`
	SpecialObjects      []SpecialObject   `json:"special_objects,omitempty"`
	ExtraMetadata       map[string]string `json:"extra_metadata,omitempty"`
}

// ModuleSummary identifies an authorized module included in an aggregated history response.
type ModuleSummary struct {
	ModuleID     int64  `json:"module_id"`
	Name         string `json:"name"`
	MountPath    string `json:"mount_path"`
	RepositoryID string `json:"repository_id"`
	Permission   string `json:"permission"`
}

// Filter controls history traversal, search, ordering, and cursor pagination.
type Filter struct {
	// Modules optionally restricts aggregated project history to a named subset
	// of the caller's authorized modules (matched by module Name or MountPath).
	Modules         []string
	Branch          string
	Tag             string
	FromRevision    string
	FirstParentOnly bool
	Author          string
	Search          string
	SinceUnixMS     *int64
	UntilUnixMS     *int64
	MergesOnly      bool
	NoMerges        bool
	Order           string // "desc" (default) or "asc"
	Limit           int
	Cursor          string
}

// Page is a paginated history response.
type Page struct {
	Scope             string          `json:"scope"` // "module" or "project_aggregated"
	ProjectID         int64           `json:"project_id"`
	ProjectName       string          `json:"project_name"`
	ModuleID          int64           `json:"module_id,omitempty"`
	ModuleName        string          `json:"module_name,omitempty"`
	AuthorizedModules []ModuleSummary `json:"authorized_modules,omitempty"`
	Commits           []Commit        `json:"commits"`
	TotalMatching     int             `json:"total_matching"`
	NextCursor        string          `json:"next_cursor,omitempty"`
	HasMore           bool            `json:"has_more"`
}

// SyncStats summarizes a Lore-to-SQLite DAG indexing pass.
type SyncStats struct {
	BranchSource     string `json:"branch_source"`
	BranchesIndexed  int    `json:"branches_indexed"`
	BranchesPruned   int    `json:"branches_pruned"`
	RevisionsScanned int    `json:"revisions_scanned"`
	CommitsUpserted  int    `json:"commits_upserted"`
}
