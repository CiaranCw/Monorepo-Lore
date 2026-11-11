package loreadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"lore-monorepo/internal/loreexec"
)

// HistoryBranch runs `lore history --branch <branch> <length>` to read history
// starting from a specific branch head.
func (c *Client) HistoryBranch(ctx context.Context, dir, branch string, length int) ([]HistoryEntry, error) {
	if err := requireDir(dir); err != nil {
		return nil, err
	}
	if err := validateBranchName(branch); err != nil {
		return nil, err
	}
	if length <= 0 {
		length = 200
	}
	res, err := c.run(ctx, dir, "history", "--repository", dir, "--branch", branch, fmt.Sprintf("%d", length))
	if err != nil {
		return nil, err
	}
	if !accepted(res) {
		return nil, failOutput("history branch", res)
	}
	entries, err := decodeHistory(res)
	if err != nil {
		return nil, &Error{Op: "history branch", Result: res, Err: err}
	}
	return entries, nil
}

// ListBranchesAt lists local or remote branches (`lore [--remote|--local] branch list`).
func (c *Client) ListBranchesAt(ctx context.Context, dir string, remote bool) ([]Branch, error) {
	if err := requireDir(dir); err != nil {
		return nil, err
	}
	var args []string
	if remote {
		args = []string{"--remote", "branch", "list", "--repository", dir}
	} else {
		args = []string{"--local", "branch", "list", "--repository", dir}
	}
	res, err := c.run(ctx, dir, args...)
	if err != nil {
		return nil, err
	}
	if !accepted(res) && !res.OutputSucceeded() {
		return nil, failOutput("branch list", res)
	}
	list, err := decodeBranches(res)
	if err != nil {
		return nil, &Error{Op: "branch list", Result: res, Err: err}
	}
	return list, nil
}

// RevisionDetail runs `lore revision info [--delta] [revision]` and decodes
// its revision summary, metadata map, and optional file deltas.
func (c *Client) RevisionDetail(ctx context.Context, dir, revision string, withDelta bool) (RevisionDetail, error) {
	if err := requireDir(dir); err != nil {
		return RevisionDetail{}, err
	}
	args := []string{"revision", "info", "--repository", dir}
	if withDelta {
		args = append(args, "--delta")
	}
	if revision != "" {
		if err := validateRevisionSpec(revision); err != nil {
			return RevisionDetail{}, err
		}
		args = append(args, revision)
	}
	res, err := c.run(ctx, dir, args...)
	if err != nil {
		return RevisionDetail{}, err
	}
	if !accepted(res) {
		return RevisionDetail{}, failOutput("revision info", res)
	}
	detail, err := decodeRevisionDetail(res)
	if err != nil {
		return RevisionDetail{}, &Error{Op: "revision info", Result: res, Err: err}
	}
	return detail, nil
}

// runMode invokes Lore with optional global flags such as --offline or -f.
func (c *Client) runMode(ctx context.Context, dir string, offline, force, jsonOut bool, args ...string) (loreexec.CommandResult, error) {
	if c.Exec == nil {
		return loreexec.CommandResult{}, fmt.Errorf("loreadapter: executor is nil")
	}
	argv := make([]string, 0, len(args)+4)
	argv = append(argv, "--non-interactive")
	if offline {
		argv = append(argv, "--offline")
	}
	if force {
		argv = append(argv, "-f")
	}
	if jsonOut {
		argv = append(argv, "--json")
	}
	argv = append(argv, args...)
	res, err := c.Exec.Run(ctx, loreexec.Request{Argv: argv, Dir: dir, Env: c.Env})
	if err != nil {
		return res, &Error{Op: strings.Join(args, " "), Result: res, Err: err}
	}
	return res, nil
}

// CreateOfflineRepository initializes an offline Lore repository in dir and returns its 32-hex ID.
func (c *Client) CreateOfflineRepository(ctx context.Context, dir, name string) (string, error) {
	if err := requireDir(dir); err != nil {
		return "", err
	}
	if err := validateName(name); err != nil {
		return "", err
	}
	res, err := c.runMode(ctx, dir, true, false, true, "repository", "create", "--repository", dir, name)
	if err != nil {
		return "", err
	}
	if !accepted(res) && !res.OutputSucceeded() {
		return "", failOutput("repository create", res)
	}
	raw, ok := firstData(res, "repositoryCreate")
	if !ok {
		return "", fmt.Errorf("%w: repositoryCreate missing", ErrOutput)
	}
	var wire struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil || !isHash(wire.ID, 32) {
		return "", fmt.Errorf("%w: repositoryCreate id invalid", ErrOutput)
	}
	return wire.ID, nil
}

// CreateBranchSlash creates a branch whose name may include slash hierarchies (e.g. feature/login).
func (c *Client) CreateBranchSlash(ctx context.Context, dir, name string, offline bool) error {
	if err := requireDir(dir); err != nil {
		return err
	}
	if err := validateBranchName(name); err != nil {
		return err
	}
	res, err := c.runMode(ctx, dir, offline, false, true, "branch", "create", "--repository", dir, name)
	if err != nil {
		return err
	}
	if !accepted(res) && !res.OutputSucceeded() {
		return failOutput("branch create", res)
	}
	return nil
}

// ResetBranch moves a branch's local latest pointer to a 64-hex revision.
func (c *Client) ResetBranch(ctx context.Context, dir, branch, revision string, offline bool) error {
	if err := requireDir(dir); err != nil {
		return err
	}
	if err := validateBranchName(branch); err != nil {
		return err
	}
	if err := validateHash(revision, 64); err != nil {
		return err
	}
	res, err := c.runMode(ctx, dir, offline, false, true, "branch", "reset", "--repository", dir, "--branch", branch, revision)
	if err != nil {
		return err
	}
	if !accepted(res) && !res.OutputSucceeded() {
		return failOutput("branch reset", res)
	}
	return nil
}

// SyncOffline synchronizes the local working tree to a 64-hex revision in offline mode
// (used during local DAG replay before creating a new branch at an historical branch-point).
func (c *Client) SyncOffline(ctx context.Context, dir, revision string) error {
	if err := requireDir(dir); err != nil {
		return err
	}
	if err := validateHash(revision, 64); err != nil {
		return err
	}
	res, err := c.runMode(ctx, dir, true, false, false, "sync", "--repository", dir, revision)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return failOutput("sync offline", res)
	}
	return nil
}

// SwitchBranchRevision switches to branch at an optional 64-hex revision, resetting working files when reset is true.
func (c *Client) SwitchBranchRevision(ctx context.Context, dir, branch, revision string, reset, offline bool) error {
	if err := requireDir(dir); err != nil {
		return err
	}
	if err := validateBranchName(branch); err != nil {
		return err
	}
	args := []string{"branch", "switch", "--repository", dir}
	if reset {
		args = append(args, "--reset")
	}
	if offline {
		args = append(args, "--local")
	}
	args = append(args, branch)
	if revision != "" {
		if err := validateHash(revision, 64); err != nil {
			return err
		}
		args = append(args, revision)
	}
	res, err := c.runMode(ctx, dir, offline, false, true, args...)
	if err != nil {
		return err
	}
	if !accepted(res) && !res.OutputSucceeded() {
		return failOutput("branch switch", res)
	}
	return nil
}

// StageScan runs `lore stage --scan .` inside dir so additions, modifications, and deletions are staged in one pass.
func (c *Client) StageScan(ctx context.Context, dir string, offline bool) error {
	if err := requireDir(dir); err != nil {
		return err
	}
	res, err := c.runMode(ctx, dir, offline, false, false, "stage", "--scan", ".")
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return failOutput("stage --scan", res)
	}
	return nil
}

// SetStagedMetadata sets custom and attribution metadata pairs on the staged revision.
func (c *Client) SetStagedMetadata(ctx context.Context, dir string, pairs map[string]string, offline bool) error {
	if err := requireDir(dir); err != nil {
		return err
	}
	if len(pairs) == 0 {
		return nil
	}
	keys := make([]string, 0, len(pairs))
	for k := range pairs {
		if strings.TrimSpace(k) == "" || strings.HasPrefix(k, "-") {
			return fmt.Errorf("%w: metadata key %q", ErrInvalid, k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	args := make([]string, 0, 4+2*len(keys))
	args = append(args, "revision", "metadata", "set", "--repository", dir)
	for _, k := range keys {
		args = append(args, k, pairs[k])
	}
	res, err := c.runMode(ctx, dir, offline, false, false, args...)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return failOutput("revision metadata set", res)
	}
	return nil
}

// CommitFull commits the staged state with full multiline Unicode message support.
// When force is true (-f), Lore allows empty/metadata-only commits as well.
func (c *Client) CommitFull(ctx context.Context, dir, message string, force, offline bool) (string, error) {
	if err := requireDir(dir); err != nil {
		return "", err
	}
	if strings.TrimSpace(message) == "" {
		message = "(empty commit message)"
	}
	res, err := c.runMode(ctx, dir, offline, force, true, "commit", "--repository", dir, "--", message)
	if err != nil {
		return "", err
	}
	if nothingStaged(res) {
		return "", &Error{Op: "commit", Result: res, Err: ErrNothingStaged}
	}
	if !accepted(res) {
		return "", failOutput("commit", res)
	}
	raw, ok := firstData(res, "revisionCommitRevision")
	if ok {
		var wire struct {
			Revision string `json:"revision"`
		}
		if json.Unmarshal(raw, &wire) == nil && isHash(wire.Revision, 64) {
			return wire.Revision, nil
		}
	}
	stRes, err := c.runMode(ctx, dir, offline, false, true, "status", "--revision-only", "--repository", dir)
	if err != nil {
		return "", err
	}
	st, ok := decodeStatus(stRes)
	if !ok || !isHash(st.Revision, 64) {
		return "", fmt.Errorf("%w: commit revision missing", ErrVerify)
	}
	return st.Revision, nil
}

// MergeStartNoCommit initiates a 2-parent Lore merge (`lore branch merge start --no-commit <sourceBranch>`)
// without committing yet, allowing the caller to materialize the exact target tree before committing.
func (c *Client) MergeStartNoCommit(ctx context.Context, dir, sourceBranch string, offline bool) (bool, error) {
	if err := requireDir(dir); err != nil {
		return false, err
	}
	if err := validateBranchName(sourceBranch); err != nil {
		return false, err
	}
	res, err := c.runMode(ctx, dir, offline, false, false, "branch", "merge", "start", "--no-commit", "--repository", dir, sourceBranch)
	if err != nil {
		return false, err
	}
	if res.ExitCode != 0 {
		return false, failOutput("branch merge start", res)
	}
	combined := res.Stdout + "\n" + res.Stderr
	hasConflicts := strings.Contains(combined, "Files in conflict:") || strings.Contains(combined, "conflicted") && !strings.Contains(combined, "0 conflicted")
	return hasConflicts, nil
}

// MergeResolve marks any merge conflicts resolved (`lore branch merge resolve`) after the exact target tree is written.
func (c *Client) MergeResolve(ctx context.Context, dir string, offline bool) error {
	if err := requireDir(dir); err != nil {
		return err
	}
	res, err := c.runMode(ctx, dir, offline, false, false, "branch", "merge", "resolve", "--repository", dir)
	if err != nil {
		return err
	}
	// If Lore reports "No merge is in progress" or "No conflicts resolved", exit may be non-zero only if unconflicted;
	// callers invoke MergeResolve when conflicts exist, or ignore "No conflicts" benignly.
	if res.ExitCode != 0 && !strings.Contains(res.Stdout+res.Stderr, "No conflicts") {
		return failOutput("branch merge resolve", res)
	}
	return nil
}

// ArchiveBranch archives a helper/temporary branch so it does not clutter branch listings.
func (c *Client) ArchiveBranch(ctx context.Context, dir, branch string, offline bool) error {
	if err := requireDir(dir); err != nil {
		return err
	}
	if err := validateBranchName(branch); err != nil {
		return err
	}
	res, err := c.runMode(ctx, dir, offline, false, false, "branch", "archive", "--repository", dir, branch)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return failOutput("branch archive", res)
	}
	return nil
}

// PushBranch pushes a named branch to the remote Lore server.
func (c *Client) PushBranch(ctx context.Context, dir, branch string) error {
	if err := requireDir(dir); err != nil {
		return err
	}
	if err := validateBranchName(branch); err != nil {
		return err
	}
	res, err := c.run(ctx, dir, "branch", "push", "--repository", dir, branch)
	if err != nil {
		return err
	}
	if !res.OutputSucceeded() && !accepted(res) {
		return failOutput("branch push", res)
	}
	return nil
}

// DefaultBranchName queries `lore repository metadata get` for `default-branch-name`.
func (c *Client) DefaultBranchName(ctx context.Context, dir string) (string, error) {
	if err := requireDir(dir); err != nil {
		return "", err
	}
	res, err := c.runMode(ctx, dir, true, false, true, "repository", "metadata", "get", "--repository", dir)
	if err != nil {
		return "", err
	}
	if !accepted(res) && !res.OutputSucceeded() {
		return "", failOutput("repository metadata get", res)
	}
	for _, ln := range res.StdoutParse.Lines {
		if ln.TagName != "metadata" {
			continue
		}
		k, v, _, _, ok := decodeMetadataLine(ln.Data)
		if ok && k == "default-branch-name" && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v), nil
		}
	}
	return "", nil
}
