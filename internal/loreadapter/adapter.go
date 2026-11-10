// Package loreadapter calls the Lore 0.10.1 CLI through loreexec and checks
// the repository state afterwards.
//
// Command lines come from appendix_A_cli_help.txt in the P3-A delivery
// (lore.real 0.10.1). JSON fields that are decoded into structs were captured
// in E5-manager-mechanics.json, except branchCreate and branchListEntry, which
// are taken from lore-revision/src/branch.rs serde names and are marked
// NOT_VERIFIED until a real --json capture exists.
//
// Tokens are never placed on argv. Set Client.Env (for example LORE_AUTH_STORE)
// from deployment configuration. This package does not default that variable.
package loreadapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"lore-monorepo/internal/loreexec"
	"lore-monorepo/internal/lorejson"
)

var (
	ErrInvalid       = errors.New("loreadapter: invalid argument")
	ErrOutput        = errors.New("loreadapter: lore output does not show success")
	ErrVerify        = errors.New("loreadapter: operation was not verified")
	ErrNothingStaged = errors.New("loreadapter: nothing staged")
)

// Error carries the process evidence for a failed call. Error() uses
// CommandResult.Summary so logs do not include raw stdout.
type Error struct {
	Op     string
	Result loreexec.CommandResult
	Err    error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return e.Op + ": " + e.Result.Summary()
	}
	return e.Op + ": " + e.Err.Error() + ": " + e.Result.Summary()
}

func (e *Error) Unwrap() error { return e.Err }

// Runner is the executor seam. Production passes loreexec.Executor.
// Tests pass a fake. A fake test is not a Lore integration test.
type Runner interface {
	Run(context.Context, loreexec.Request) (loreexec.CommandResult, error)
}

// Client is the repository adapter.
type Client struct {
	Exec Runner
	// Env is copied into every Lore process. It is not applied unless set.
	// LORE_AUTH_STORE is left unset unless the deployment puts it here.
	Env map[string]string
	// Delete removes a directory this call created. Tests can force a failure.
	// Nil uses os.RemoveAll. It is never used on a path that already existed.
	Delete func(path string) error
}

func (c *Client) run(ctx context.Context, dir string, args ...string) (loreexec.CommandResult, error) {
	if c.Exec == nil {
		return loreexec.CommandResult{}, errors.New("loreadapter: executor is nil")
	}
	argv := make([]string, 0, len(args)+2)
	argv = append(argv, "--non-interactive", "--json")
	argv = append(argv, args...)
	res, err := c.Exec.Run(ctx, loreexec.Request{Argv: argv, Dir: dir, Env: c.Env})
	if err != nil {
		return res, &Error{Op: strings.Join(args, " "), Result: res, Err: err}
	}
	return res, nil
}

func failOutput(op string, res loreexec.CommandResult) error {
	return &Error{Op: op, Result: res, Err: ErrOutput}
}

// Status is `lore --json status --revision-only` (CLI help and E5 step M-2).
func (c *Client) Status(ctx context.Context, dir string) (Status, error) {
	if err := requireDir(dir); err != nil {
		return Status{}, err
	}
	res, err := c.run(ctx, dir, "status", "--revision-only", "--repository", dir)
	if err != nil {
		return Status{}, err
	}
	if !res.OutputSucceeded() {
		return Status{}, failOutput("status", res)
	}
	st, ok := decodeStatus(res)
	if !ok {
		return Status{}, &Error{Op: "status", Result: res, Err: fmt.Errorf("%w: repositoryStatusRevision missing", ErrOutput)}
	}
	return st, nil
}

// History is `lore history [LENGTH] [--revision]` (CLI help and E5 step M-4).
// length <= 0 omits LENGTH. fromRevision empty starts at the branch latest.
func (c *Client) History(ctx context.Context, dir string, length int, fromRevision string) ([]HistoryEntry, error) {
	if err := requireDir(dir); err != nil {
		return nil, err
	}
	if length < 0 {
		return nil, fmt.Errorf("%w: history length", ErrInvalid)
	}
	if fromRevision != "" {
		if err := validateRevisionSpec(fromRevision); err != nil {
			return nil, err
		}
	}
	args := []string{"history", "--repository", dir}
	if fromRevision != "" {
		args = append(args, "--revision", fromRevision)
	}
	if length > 0 {
		args = append(args, fmt.Sprintf("%d", length))
	}
	res, err := c.run(ctx, dir, args...)
	if err != nil {
		return nil, err
	}
	if !accepted(res) {
		return nil, failOutput("history", res)
	}
	entries, err := decodeHistory(res)
	if err != nil {
		return nil, &Error{Op: "history", Result: res, Err: err}
	}
	return entries, nil
}

// Links is `lore link list` (CLI help and E5 step M-3).
// Non-JSON trailer lines are ignored for the returned slice and kept on the
// underlying parse by the executor.
func (c *Client) Links(ctx context.Context, dir string) ([]Link, error) {
	if err := requireDir(dir); err != nil {
		return nil, err
	}
	res, err := c.run(ctx, dir, "link", "list", "--repository", dir)
	if err != nil {
		return nil, err
	}
	if !res.OutputSucceeded() {
		return nil, failOutput("link list", res)
	}
	links, err := decodeLinks(res)
	if err != nil {
		return nil, &Error{Op: "link list", Result: res, Err: err}
	}
	return links, nil
}

// CloneOptions is `lore clone [--bare] [--revision] <url> [path]`.
type CloneOptions struct {
	URL                string
	Path               string
	Revision           string
	Bare               bool
	ExpectRepositoryID string
}

// Clone runs clone and then checks the directory and `status --revision-only`.
// A failed clone or a failed check removes Path when it did not already exist.
func (c *Client) Clone(ctx context.Context, opts CloneOptions) error {
	if err := validateRepoURL(opts.URL); err != nil {
		return err
	}
	dest, err := cleanNewPath(opts.Path)
	if err != nil {
		return err
	}
	if opts.Revision != "" {
		if err := validateHash(opts.Revision, 64); err != nil {
			return fmt.Errorf("%w: clone revision", ErrInvalid)
		}
	}
	if opts.ExpectRepositoryID != "" {
		if err := validateHash(opts.ExpectRepositoryID, 32); err != nil {
			return fmt.Errorf("%w: repository id", ErrInvalid)
		}
	}
	if statErr := destinationAbsent(dest); statErr != nil {
		return statErr
	}
	args := []string{"clone"}
	if opts.Bare {
		args = append(args, "--bare")
	}
	if opts.Revision != "" {
		args = append(args, "--revision", opts.Revision)
	}
	args = append(args, opts.URL, dest)
	res, err := c.run(ctx, filepath.Dir(dest), args...)
	if err != nil {
		return c.cleanupCreated(dest, err)
	}
	if !res.OutputSucceeded() {
		return c.cleanupCreated(dest, failOutput("clone", res))
	}
	if st, err := os.Stat(dest); err != nil || !st.IsDir() {
		return c.cleanupCreated(dest, &Error{Op: "clone", Result: res, Err: fmt.Errorf("%w: destination is not a directory", ErrVerify)})
	}
	status, err := c.Status(ctx, dest)
	if err != nil {
		return c.cleanupCreated(dest, err)
	}
	if opts.ExpectRepositoryID != "" && status.RepositoryID != opts.ExpectRepositoryID {
		return c.cleanupCreated(dest, &Error{Op: "clone", Result: res, Err: fmt.Errorf("%w: repository id %s, want %s", ErrVerify, status.RepositoryID, opts.ExpectRepositoryID)})
	}
	if opts.Revision != "" && status.Revision != opts.Revision && status.RevisionLocal != opts.Revision {
		return c.cleanupCreated(dest, &Error{Op: "clone", Result: res, Err: fmt.Errorf("%w: revision %s, want %s", ErrVerify, status.Revision, opts.Revision)})
	}
	return nil
}

// destinationAbsent rejects a clone onto anything that is already on disk.
func destinationAbsent(path string) error {
	_, err := os.Stat(path)
	if err == nil {
		return fmt.Errorf("%w: clone destination already exists", ErrInvalid)
	}
	if !os.IsNotExist(err) {
		return err
	}
	return nil
}

// cleanupCreated removes path only after this call established that it did not
// exist. A removal failure is attached to the original error and the directory
// is left in place.
func (c *Client) cleanupCreated(path string, cause error) error {
	remove := c.Delete
	if remove == nil {
		remove = os.RemoveAll
	}
	if _, statErr := os.Stat(path); statErr != nil {
		if os.IsNotExist(statErr) {
			return cause
		}
		return fmt.Errorf("%w; cleanup stat: %w", cause, statErr)
	}
	if rmErr := remove(path); rmErr != nil {
		return fmt.Errorf("%w; cleanup: %w", cause, rmErr)
	}
	return cause
}

// Push is `lore push` with no branch argument (push the current branch).
// It then reads status and requires the remote to be available, authorized,
// not behind the local revision, and to report that same revision.
func (c *Client) Push(ctx context.Context, dir string) error {
	before, err := c.Status(ctx, dir)
	if err != nil {
		return err
	}
	res, err := c.run(ctx, dir, "push", "--repository", dir)
	if err != nil {
		return err
	}
	if !res.OutputSucceeded() {
		return failOutput("push", res)
	}
	after, err := c.Status(ctx, dir)
	if err != nil {
		return err
	}
	if !after.RemoteAvailable || !after.RemoteAuthorized || after.IsLocalAhead || after.RevisionRemote != before.Revision {
		return &Error{Op: "push", Result: res, Err: fmt.Errorf("%w: remote revision %s local %s available=%t authorized=%t ahead=%t", ErrVerify, after.RevisionRemote, before.Revision, after.RemoteAvailable, after.RemoteAuthorized, after.IsLocalAhead)}
	}
	return nil
}

// Pull is `lore sync` with no revision argument, then a remote-consistency check.
// Lore has no separate pull command (CLI help: `lore sync [revision]`).
func (c *Client) Pull(ctx context.Context, dir string) error {
	return c.Sync(ctx, dir, "")
}

// ResolveRevision turns a sync revision specifier into the 64-hex hash Lore
// will land on. A hash is returned as itself. branch@number, branch@LATEST
// and branch@hash are resolved with `lore history 1 --revision <spec>`, whose
// revisionHistoryEntry shape was captured in E5 step M-4. The sync help
// (line 914) defines those specifier forms. If history does not yield a hash,
// the spec is not treated as resolved.
func (c *Client) ResolveRevision(ctx context.Context, dir, spec string) (string, error) {
	if err := requireDir(dir); err != nil {
		return "", err
	}
	if err := validateRevisionSpec(spec); err != nil {
		return "", err
	}
	if isHash(spec, 64) {
		return spec, nil
	}
	entries, err := c.History(ctx, dir, 1, spec)
	if err != nil {
		return "", err
	}
	if len(entries) == 0 || !isHash(entries[0].Revision, 64) {
		return "", fmt.Errorf("%w: %s did not resolve to a revision hash", ErrVerify, spec)
	}
	return entries[0].Revision, nil
}

// Sync is `lore sync [revision]`.
// An empty revision must leave the local revision equal to the remote revision.
// Any other specifier is resolved to a hash first; after sync the local
// revision must equal that hash. The remote must be available and authorized.
// E3 step N-9d exited 0 while unauthorized; that state fails verification.
func (c *Client) Sync(ctx context.Context, dir, revision string) error {
	if err := requireDir(dir); err != nil {
		return err
	}
	want := ""
	if revision != "" {
		var err error
		want, err = c.ResolveRevision(ctx, dir, revision)
		if err != nil {
			return err
		}
	}
	args := []string{"sync", "--repository", dir}
	if revision != "" {
		args = append(args, revision)
	}
	res, err := c.run(ctx, dir, args...)
	if err != nil {
		return err
	}
	if !res.OutputSucceeded() {
		return failOutput("sync", res)
	}
	after, err := c.Status(ctx, dir)
	if err != nil {
		return err
	}
	if !after.RemoteAvailable || !after.RemoteAuthorized {
		return &Error{Op: "sync", Result: res, Err: fmt.Errorf("%w: remote available=%t authorized=%t", ErrVerify, after.RemoteAvailable, after.RemoteAuthorized)}
	}
	if revision == "" {
		if after.IsRemoteAhead || after.Revision != after.RevisionRemote {
			return &Error{Op: "sync", Result: res, Err: fmt.Errorf("%w: local %s remote %s", ErrVerify, after.Revision, after.RevisionRemote)}
		}
		return nil
	}
	if after.Revision != want && after.RevisionLocal != want {
		return &Error{Op: "sync", Result: res, Err: fmt.Errorf("%w: revision %s, resolved target %s", ErrVerify, after.Revision, want)}
	}
	return nil
}

// AddLink is `lore link add [--pin] [--disable-branching] <path> <url> <source>`.
// sourcePath is required by the CLI. pin must be a 64-hex revision so the
// following link list can prove the pin.
func (c *Client) AddLink(ctx context.Context, dir, linkPath, repoURL, sourcePath, pin string, disableBranching bool) error {
	if err := requireDir(dir); err != nil {
		return err
	}
	if err := validateLinkPath(linkPath); err != nil {
		return err
	}
	if strings.TrimSpace(sourcePath) == "" || strings.HasPrefix(sourcePath, "-") {
		return fmt.Errorf("%w: link source path", ErrInvalid)
	}
	if err := validateRepoURL(repoURL); err != nil {
		return err
	}
	if err := validateHash(pin, 64); err != nil {
		return fmt.Errorf("%w: link pin", ErrInvalid)
	}
	args := []string{"link", "add", "--pin", pin}
	if disableBranching {
		args = append(args, "--disable-branching")
	}
	args = append(args, "--repository", dir, linkPath, repoURL, sourcePath)
	res, err := c.run(ctx, dir, args...)
	if err != nil {
		return err
	}
	if !res.OutputSucceeded() {
		return failOutput("link add", res)
	}
	return c.verifyLink(ctx, dir, linkPath, "", pin, res)
}

// UpdateLink is `lore link update --pin <path>`.
// The child repository id must stay the same and the pin must match.
func (c *Client) UpdateLink(ctx context.Context, dir, linkPath, pin string) error {
	if err := requireDir(dir); err != nil {
		return err
	}
	if err := validateLinkPath(linkPath); err != nil {
		return err
	}
	if err := validateHash(pin, 64); err != nil {
		return fmt.Errorf("%w: link pin", ErrInvalid)
	}
	before, err := c.Links(ctx, dir)
	if err != nil {
		return err
	}
	prev, ok := findLink(before, linkPath)
	if !ok {
		return fmt.Errorf("%w: link %s", ErrInvalid, linkPath)
	}
	res, err := c.run(ctx, dir, "link", "update", "--pin", pin, "--repository", dir, linkPath)
	if err != nil {
		return err
	}
	if !res.OutputSucceeded() {
		return failOutput("link update", res)
	}
	return c.verifyLink(ctx, dir, linkPath, prev.RepositoryID, pin, res)
}

// RemoveLink is `lore link remove <path>`. Lore 0.10.1 rejects `link update`
// when the checked-out link tree differs from the recorded pin, including on
// a freshly cloned parent. Replacing the link is the path that still accepts
// a new historical pin.
func (c *Client) RemoveLink(ctx context.Context, dir, linkPath string) error {
	if err := requireDir(dir); err != nil {
		return err
	}
	if err := validateLinkPath(linkPath); err != nil {
		return err
	}
	res, err := c.run(ctx, dir, "link", "remove", "--repository", dir, linkPath)
	if err != nil {
		return err
	}
	if !res.OutputSucceeded() {
		return failOutput("link remove", res)
	}
	links, err := c.Links(ctx, dir)
	if err != nil {
		return err
	}
	if _, ok := findLink(links, linkPath); ok {
		return &Error{Op: "link remove", Result: res, Err: fmt.Errorf("%w: %s still present", ErrVerify, linkPath)}
	}
	return nil
}

func (c *Client) verifyLink(ctx context.Context, dir, linkPath, repoID, pin string, op loreexec.CommandResult) error {
	links, err := c.Links(ctx, dir)
	if err != nil {
		return err
	}
	got, ok := findLink(links, linkPath)
	if !ok {
		return &Error{Op: "link verify", Result: op, Err: fmt.Errorf("%w: %s disappeared", ErrVerify, linkPath)}
	}
	if repoID != "" && got.RepositoryID != repoID {
		return &Error{Op: "link verify", Result: op, Err: fmt.Errorf("%w: repository %s, want %s", ErrVerify, got.RepositoryID, repoID)}
	}
	if got.Revision != pin {
		return &Error{Op: "link verify", Result: op, Err: fmt.Errorf("%w: pin %s, want %s", ErrVerify, got.Revision, pin)}
	}
	return nil
}

// CurrentBranch reads branchName from status (E5 M-2). There is no separate
// "current branch" command in the captured JSON.
func (c *Client) CurrentBranch(ctx context.Context, dir string) (string, error) {
	st, err := c.Status(ctx, dir)
	if err != nil {
		return "", err
	}
	if st.BranchName == "" {
		return "", fmt.Errorf("%w: branch name empty", ErrOutput)
	}
	return st.BranchName, nil
}

// ListBranches runs `lore branch list`.
//
// NOT_VERIFIED: P3-A did not capture branchListEntry JSON. Fields are the
// camelCase serde names from LoreBranchListEntryEventData. A payload that
// does not decode fails closed.
func (c *Client) ListBranches(ctx context.Context, dir string) ([]Branch, error) {
	if err := requireDir(dir); err != nil {
		return nil, err
	}
	res, err := c.run(ctx, dir, "branch", "list", "--repository", dir)
	if err != nil {
		return nil, err
	}
	if !res.OutputSucceeded() {
		return nil, failOutput("branch list", res)
	}
	list, err := decodeBranches(res)
	if err != nil {
		return nil, &Error{Op: "branch list", Result: res, Err: err}
	}
	return list, nil
}

// CreateBranch runs `lore branch create <name>` and requires ListBranches to
// show that name. A branchCreate event is checked when present; P3-A did not
// capture one, so its absence is not itself a failure.
func (c *Client) CreateBranch(ctx context.Context, dir, name string) error {
	if err := requireDir(dir); err != nil {
		return err
	}
	if err := validateName(name); err != nil {
		return err
	}
	res, err := c.run(ctx, dir, "branch", "create", "--repository", dir, name)
	if err != nil {
		return err
	}
	if !res.OutputSucceeded() {
		return failOutput("branch create", res)
	}
	if saw, ok := eventName(res, "branchCreate"); ok && saw != name {
		return &Error{Op: "branch create", Result: res, Err: fmt.Errorf("%w: branchCreate name %s, want %s", ErrVerify, saw, name)}
	}
	list, err := c.ListBranches(ctx, dir)
	if err != nil {
		return err
	}
	for _, b := range list {
		if b.Name == name {
			return nil
		}
	}
	return &Error{Op: "branch create", Result: res, Err: fmt.Errorf("%w: %s not listed", ErrVerify, name)}
}

// SwitchBranch runs `lore branch switch <branch>` and checks status.branchName.
func (c *Client) SwitchBranch(ctx context.Context, dir, name string) error {
	if err := requireDir(dir); err != nil {
		return err
	}
	if err := validateName(name); err != nil {
		return err
	}
	res, err := c.run(ctx, dir, "branch", "switch", "--repository", dir, name)
	if err != nil {
		return err
	}
	if !res.OutputSucceeded() {
		return failOutput("branch switch", res)
	}
	got, err := c.CurrentBranch(ctx, dir)
	if err != nil {
		return err
	}
	if got != name {
		return &Error{Op: "branch switch", Result: res, Err: fmt.Errorf("%w: branch %s, want %s", ErrVerify, got, name)}
	}
	return nil
}

// Commit runs `lore commit <message>`.
// "Nothing staged for commit" (E5 M-6, rc 40) returns ErrNothingStaged.
// On success the status revision must change. The commit event payload itself
// was not captured and is not decoded.
func (c *Client) Commit(ctx context.Context, dir, message string) error {
	if err := requireDir(dir); err != nil {
		return err
	}
	if strings.TrimSpace(message) == "" || strings.ContainsAny(message, "\r\n") {
		return fmt.Errorf("%w: commit message", ErrInvalid)
	}
	before, err := c.Status(ctx, dir)
	if err != nil {
		return err
	}
	res, err := c.run(ctx, dir, "commit", "--repository", dir, message)
	if err != nil {
		return err
	}
	if nothingStaged(res) {
		return &Error{Op: "commit", Result: res, Err: ErrNothingStaged}
	}
	if !accepted(res) {
		return failOutput("commit", res)
	}
	after, err := c.Status(ctx, dir)
	if err != nil {
		return err
	}
	if after.Revision == "" || after.Revision == before.Revision {
		return &Error{Op: "commit", Result: res, Err: fmt.Errorf("%w: revision did not advance", ErrVerify)}
	}
	return nil
}

// RevisionExists runs `lore revision info <revision>` and treats a successful
// complete event as existence. The info payload fields were not captured
// (NOT_VERIFIED) and are not decoded.
func (c *Client) RevisionExists(ctx context.Context, dir, revision string) (bool, error) {
	if err := requireDir(dir); err != nil {
		return false, err
	}
	if err := validateRevisionSpec(revision); err != nil {
		return false, err
	}
	res, err := c.run(ctx, dir, "revision", "info", "--repository", dir, revision)
	if err != nil {
		return false, err
	}
	if accepted(res) {
		return true, nil
	}
	for _, f := range res.Findings {
		if f.Class == lorejson.ClassRevisionNotFound || f.Class == lorejson.ClassRepositoryNotFound {
			return false, nil
		}
	}
	return false, failOutput("revision info", res)
}

// accepted is OutputSucceeded plus the trailing status Lore emits after a
// successful read when no auth endpoint is configured. E5 step M-4 and the
// B1.2.4 no-auth server both print a status-0 complete, then
// "authentication requires a configured auth endpoint" or
// "Disconnected from server" while resolving auth, and still exit 0.
// A non-zero complete that is not that trailer still fails the call.
func accepted(res loreexec.CommandResult) bool {
	if res.TimedOut || res.Cancelled || res.Truncated || !res.Started {
		return false
	}
	sawOK := false
	for _, ln := range res.StdoutParse.Lines {
		if ln.TagName != "complete" {
			continue
		}
		st, code, msg, has, ok := readComplete(ln.Data)
		if !ok || !has {
			return false
		}
		if st == 0 && code == 0 && msg == "" {
			sawOK = true
			continue
		}
		if !trailingAuthNoise(msg) {
			return false
		}
	}
	if !sawOK {
		return false
	}
	for _, f := range res.Findings {
		if trailingAuthNoise(f.Message) || strings.Contains(f.Message, "libonion.so") {
			continue
		}
		return false
	}
	return true
}

func readComplete(data json.RawMessage) (status, code int, message string, hasError, ok bool) {
	var obj map[string]json.RawMessage
	if len(data) == 0 || json.Unmarshal(data, &obj) != nil || obj == nil {
		return 0, 0, "", false, false
	}
	rawStatus, exists := obj["status"]
	if !exists || json.Unmarshal(rawStatus, &status) != nil {
		return 0, 0, "", false, false
	}
	rawErr, hasError := obj["error"]
	if hasError {
		var er struct {
			ErrorCode int    `json:"errorCode"`
			Message   string `json:"message"`
		}
		_ = json.Unmarshal(rawErr, &er)
		code, message = er.ErrorCode, er.Message
	}
	return status, code, message, hasError, true
}

func trailingAuthNoise(msg string) bool {
	return strings.Contains(msg, "authentication requires a configured auth endpoint") ||
		strings.Contains(msg, "Disconnected from server") ||
		strings.Contains(msg, "resolving auth endpoint from remote")
}

func nothingStaged(res loreexec.CommandResult) bool {
	for _, f := range res.Findings {
		if strings.Contains(f.Message, "Nothing staged for commit") || (f.HasCode && f.Code == 40) {
			return true
		}
	}
	if strings.Contains(res.Stdout, "Nothing staged for commit") || strings.Contains(res.Stderr, "Nothing staged for commit") {
		return true
	}
	return false
}

func eventName(res loreexec.CommandResult, tag string) (string, bool) {
	for _, ln := range res.StdoutParse.Lines {
		if ln.TagName != tag || len(ln.Data) == 0 {
			continue
		}
		var data struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(ln.Data, &data) == nil && data.Name != "" {
			return data.Name, true
		}
	}
	return "", false
}
