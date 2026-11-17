package gitimport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"lore-monorepo/internal/history"
)

// RemoteRefSummary classifies refs advertised by an external Git remote.
// Unadvertised internal server objects cannot be read over Git protocol; advertised
// platform-internal refs (e.g. refs/pull/*, refs/merge-requests/*) are reported
// explicitly rather than silently conflated with standard branches and tags.
type RemoteRefSummary struct {
	DefaultBranch        string            `json:"default_branch"`
	Branches             map[string]string `json:"branches"` // branch name -> sha
	Tags                 map[string]string `json:"tags"`     // tag name -> target sha
	AdvertisedHiddenRefs []string          `json:"advertised_hidden_refs,omitempty"`
}

// GitCommit holds the complete metadata and parent links of one Git commit.
type GitCommit struct {
	SHA             string
	TreeSHA         string
	Parents         []string
	AuthorName      string
	AuthorEmail     string
	AuthoredAt      string
	AuthoredUnixMS  int64
	CommitterName   string
	CommitterEmail  string
	CommittedAt     string
	CommittedUnixMS int64
	Encoding        string
	SignatureStatus string
	Message         string
}

// GitTag holds either a lightweight or annotated Git tag.
type GitTag struct {
	Name              string
	TargetSHA         string // resolved module-projected commit SHA
	OriginalTargetSHA string // original unprojected source commit SHA (when folded via alias)
	TagObjectID       string // non-empty for annotated tags
	IsAnnotated       bool
	TaggerName        string
	TaggerEmail       string
	TaggedAt          string
	Message           string
}

var ErrLFSHydrationFailed = errors.New("gitimport: git-lfs object missing or failed sha256/size verification under hydrate mode")

// MirrorGraph is the complete, topologically ordered object graph of a mirrored Git repository.
type MirrorGraph struct {
	DefaultBranch         string
	Commits               []GitCommit // strictly topological: every parent appears before its children
	CommitsBySHA          map[string]GitCommit
	Branches              map[string]string // branch name -> commit SHA
	Tags                  []GitTag
	RootCommitCount       int
	IsShallow             bool
	ShallowMissingParents []string
	LFSFetchAttempted     bool
	LFSFetchSucceeded     bool
}

var (
	safeEnvKeys = []string{
		"PATH", "PATHEXT", "SystemRoot", "SYSTEMDRIVE", "WINDIR", "COMSPEC",
		"PROGRAMFILES", "COMMONPROGRAMFILES",
		"TEMP", "TMP", "TMPDIR",
		"HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
		"USER", "LOGNAME", "LANG", "LC_ALL",
		"SSL_CERT_FILE", "SSL_CERT_DIR", "GIT_EXEC_PATH",
	}

	noHooksOnce sync.Once
	noHooksDir  string
)

func emptyHooksDir() string {
	noHooksOnce.Do(func() {
		d := filepath.Join(os.TempDir(), "lore-monorepo-git-empty-hooks")
		if err := os.MkdirAll(d, 0o755); err == nil {
			noHooksDir = d
		}
	})
	return noHooksDir
}

// minimalGitEnv builds an isolated environment for `git` child processes so
// Manager server secrets (tokens, passwords, cloud credentials) never leak to Git.
func minimalGitEnv(extraEnv []string) []string {
	env := make([]string, 0, len(safeEnvKeys)+len(extraEnv)+4)
	for _, k := range safeEnvKeys {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	env = append(env,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=",
		"SSH_ASKPASS=",
	)
	env = append(env, extraEnv...)
	return env
}

func isNetworkGitURL(sourceURL string) bool {
	s := strings.TrimSpace(sourceURL)
	if strings.Contains(s, "://") {
		return !strings.HasPrefix(strings.ToLower(s), "file://")
	}
	return scpLikeRe.MatchString(s) && !filepath.IsAbs(s)
}

func runGit(ctx context.Context, gitBin, dir string, extraEnv, secrets []string, args ...string) (string, error) {
	if gitBin == "" {
		gitBin = "git"
	}
	fullArgs := make([]string, 0, len(args)+2)
	if hd := emptyHooksDir(); hd != "" {
		fullArgs = append(fullArgs, "-c", "core.hooksPath="+hd)
	}
	fullArgs = append(fullArgs, args...)

	cmd := exec.CommandContext(ctx, gitBin, fullArgs...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = minimalGitEnv(extraEnv)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		allSecrets := append([]string{}, secrets...)
		for _, kv := range extraEnv {
			if idx := strings.IndexByte(kv, '='); idx >= 0 {
				key, val := kv[:idx], kv[idx+1:]
				if strings.HasPrefix(key, "GIT_CONFIG_VALUE_") || strings.HasPrefix(key, "LORE_GIT_SSH_") {
					allSecrets = append(allSecrets, val)
				}
			}
		}
		msg := RedactOutput(stderr.String()+"\n"+stdout.String(), allSecrets)
		return "", fmt.Errorf("git %s: %w (%s)", firstArg(args), err, msg)
	}
	return stdout.String(), nil
}

func firstArg(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	if len(args) > 0 {
		return args[0]
	}
	return ""
}

// InspectRemoteRefs runs `git ls-remote --symref` against sourceURL.
func InspectRemoteRefs(ctx context.Context, gitBin, sourceURL string, extraEnv, secrets []string) (RemoteRefSummary, error) {
	var args []string
	if isNetworkGitURL(sourceURL) {
		args = append(args, "-c", "protocol.file.allow=never")
	}
	args = append(args, "ls-remote", "--symref", "--", sourceURL)
	out, err := runGit(ctx, gitBin, "", extraEnv, secrets, args...)
	if err != nil {
		return RemoteRefSummary{}, err
	}
	res := RemoteRefSummary{
		Branches: map[string]string{},
		Tags:     map[string]string{},
	}
	peeledTags := map[string]string{}
	for _, rawLine := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "ref: ") {
			parts := strings.Split(line, "\t")
			if len(parts) == 2 && parts[1] == "HEAD" {
				target := strings.TrimPrefix(parts[0], "ref: ")
				if strings.HasPrefix(target, "refs/heads/") {
					res.DefaultBranch = strings.TrimPrefix(target, "refs/heads/")
				}
			}
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		sha, ref := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		switch {
		case ref == "HEAD":
			continue
		case strings.HasPrefix(ref, "refs/heads/"):
			res.Branches[strings.TrimPrefix(ref, "refs/heads/")] = sha
		case strings.HasPrefix(ref, "refs/tags/"):
			name := strings.TrimPrefix(ref, "refs/tags/")
			if strings.HasSuffix(name, "^{}") {
				peeledTags[strings.TrimSuffix(name, "^{}")] = sha
			} else if _, hasPeeled := peeledTags[name]; !hasPeeled {
				res.Tags[name] = sha
			}
		default:
			res.AdvertisedHiddenRefs = append(res.AdvertisedHiddenRefs, ref)
		}
	}
	for k, sha := range peeledTags {
		res.Tags[k] = sha
	}
	sort.Strings(res.AdvertisedHiddenRefs)
	if res.DefaultBranch == "" {
		if _, ok := res.Branches["main"]; ok {
			res.DefaultBranch = "main"
		} else if _, ok := res.Branches["master"]; ok {
			res.DefaultBranch = "master"
		} else {
			for b := range res.Branches {
				if res.DefaultBranch == "" || b < res.DefaultBranch {
					res.DefaultBranch = b
				}
			}
		}
	}
	return res, nil
}

// SyncBareMirror initializes or updates a bare Git mirror of sourceURL with retry/backoff.
// Credentials are supplied exclusively in extraEnv and never written to .git/config.
func SyncBareMirror(ctx context.Context, gitBin, sourceURL, mirrorDir, lfsMode string, extraEnv, secrets []string) (lfsAttempted, lfsOK bool, err error) {
	if err := os.MkdirAll(mirrorDir, 0o755); err != nil {
		return false, false, err
	}
	if _, statErr := os.Stat(filepath.Join(mirrorDir, "HEAD")); os.IsNotExist(statErr) {
		if _, err := runGit(ctx, gitBin, mirrorDir, extraEnv, secrets, "init", "--bare", "."); err != nil {
			return false, false, err
		}
	}
	if _, err := runGit(ctx, gitBin, mirrorDir, extraEnv, secrets, "config", "remote.origin.url", sourceURL); err != nil {
		return false, false, err
	}

	var fetchArgs []string
	if isNetworkGitURL(sourceURL) {
		fetchArgs = append(fetchArgs, "-c", "protocol.file.allow=never")
	}
	fetchArgs = append(fetchArgs,
		"fetch", "--prune", "--force", "--no-tags", "origin",
		"+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*")

	var fetchErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return false, false, ctx.Err()
			case <-time.After(time.Duration(attempt*300) * time.Millisecond):
			}
		}
		_, fetchErr = runGit(ctx, gitBin, mirrorDir, extraEnv, secrets, fetchArgs...)
		if fetchErr == nil {
			break
		}
	}
	if fetchErr != nil {
		return false, false, fetchErr
	}

	// If source was shallow, mirror or source may carry a shallow boundary file.
	copySourceShallowMarkerIfPresent(sourceURL, mirrorDir)

	if lfsMode == LFSModeHydrate || lfsMode == LFSModeAuto {
		lfsAttempted, lfsOK, err = FetchLFSObjects(ctx, gitBin, sourceURL, mirrorDir, extraEnv, secrets)
		if err != nil {
			return lfsAttempted, false, err
		}
	}
	return lfsAttempted, lfsOK, nil
}

// FetchLFSObjects refreshes LFS content for hydrate mode. Fetch/plugin failure
// is reported through complete=false, then every referenced object is still
// verified pointer-by-pointer by InspectExpectedSpecialObjects/materialization.
// This lets repositories without LFS work when git-lfs is absent while never
// treating the presence of one stale/partial object as complete hydration.
func FetchLFSObjects(ctx context.Context, gitBin, sourceURL, mirrorDir string, extraEnv, secrets []string) (attempted, complete bool, err error) {
	copyLocalLFSObjects(sourceURL, mirrorDir)
	if seedConfiguredLFSCache(mirrorDir) {
		return true, hasAnyLocalLFSObjects(mirrorDir), nil
	}
	if _, verErr := runGit(ctx, gitBin, "", nil, nil, "lfs", "version"); verErr != nil {
		return false, hasAnyLocalLFSObjects(mirrorDir), nil
	}

	attempted = true
	var lfsArgs []string
	if isNetworkGitURL(sourceURL) {
		lfsArgs = append(lfsArgs, "-c", "protocol.file.allow=never")
	}
	lfsArgs = append(lfsArgs, "lfs", "fetch", "--all", "origin")
	if _, lfsErr := runGit(ctx, gitBin, mirrorDir, extraEnv, secrets, lfsArgs...); lfsErr != nil {
		// Keep fetch failure non-fatal here: exhaustive pointer verification is
		// the acceptance gate, and pinned resume will retry this fetch.
		return true, false, nil
	}
	return true, true, nil
}

func copySourceShallowMarkerIfPresent(sourceURL, mirrorDir string) {
	if isNetworkGitURL(sourceURL) {
		return
	}
	src := strings.TrimPrefix(sourceURL, "file://")
	for _, cand := range []string{
		filepath.Join(src, ".git", "shallow"),
		filepath.Join(src, "shallow"),
	} {
		if data, err := os.ReadFile(cand); err == nil && len(strings.TrimSpace(string(data))) > 0 {
			_ = os.WriteFile(filepath.Join(mirrorDir, "shallow"), data, 0o644)
			return
		}
	}
}

func copyLocalLFSObjects(sourceURL, mirrorDir string) {
	if isNetworkGitURL(sourceURL) {
		return
	}
	src := strings.TrimPrefix(sourceURL, "file://")
	for _, cand := range []string{
		filepath.Join(src, ".git", "lfs", "objects"),
		filepath.Join(src, "lfs", "objects"),
	} {
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			_ = filepath.Walk(cand, func(p string, info os.FileInfo, wErr error) error {
				if wErr != nil || info == nil || info.IsDir() {
					return nil
				}
				rel, rErr := filepath.Rel(cand, p)
				if rErr != nil {
					return nil
				}
				dst := filepath.Join(mirrorDir, "lfs", "objects", rel)
				if _, dErr := os.Stat(dst); dErr == nil {
					return nil
				}
				if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
					return nil
				}
				if data, rErr := os.ReadFile(p); rErr == nil {
					_ = os.WriteFile(dst, data, 0o644)
				}
				return nil
			})
		}
	}
}

// seedConfiguredLFSCache links objects from LORE_IMPORT_LFS_CACHE into the
// mirror's lfs/objects directory. It lets hydrate verify a pre-checked cache
// without a network fetch. Existing mirror objects are left unchanged.
func seedConfiguredLFSCache(mirrorDir string) bool {
	cache := strings.TrimSpace(os.Getenv("LORE_IMPORT_LFS_CACHE"))
	if cache == "" {
		return false
	}
	src := filepath.Join(cache, "objects")
	if st, err := os.Stat(src); err != nil || !st.IsDir() {
		src = cache
	}
	_ = filepath.Walk(src, func(p string, info os.FileInfo, wErr error) error {
		if wErr != nil || info == nil || info.IsDir() || len(info.Name()) != 64 {
			return nil
		}
		name := info.Name()
		dst := filepath.Join(mirrorDir, "lfs", "objects", name[:2], name[2:4], name)
		if _, err := os.Stat(dst); err == nil {
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return nil
		}
		if err := os.Link(p, dst); err != nil {
			if data, rErr := os.ReadFile(p); rErr == nil {
				_ = os.WriteFile(dst, data, 0o644)
			}
		}
		return nil
	})
	return true
}

func hasAnyLocalLFSObjects(mirrorDir string) bool {
	found := false
	_ = filepath.Walk(filepath.Join(mirrorDir, "lfs", "objects"), func(_ string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			found = true
		}
		return nil
	})
	return found
}

// ReadMirrorGraph extracts all branches, tags, and reachable commits from mirrorDir
// and sorts commits in strict topological order (all parents before any child).
// Shallow grafts or missing parent objects are explicitly detected and recorded.
func ReadMirrorGraph(ctx context.Context, gitBin, mirrorDir, defaultBranchHint string) (MirrorGraph, error) {
	g := MirrorGraph{
		DefaultBranch: defaultBranchHint,
		CommitsBySHA:  map[string]GitCommit{},
		Branches:      map[string]string{},
	}

	if shallowData, sErr := os.ReadFile(filepath.Join(mirrorDir, "shallow")); sErr == nil && strings.TrimSpace(string(shallowData)) != "" {
		g.IsShallow = true
	} else if shOut, rErr := runGit(ctx, gitBin, mirrorDir, nil, nil, "rev-parse", "--is-shallow-repository"); rErr == nil && strings.TrimSpace(shOut) == "true" {
		g.IsShallow = true
	}

	// 1. Branches (`git for-each-ref` uses `%00` for NUL).
	bOut, err := runGit(ctx, gitBin, mirrorDir, nil, nil, "for-each-ref", "--format=%(refname:short)%00%(objectname)", "refs/heads")
	if err != nil {
		return g, err
	}
	for _, ln := range strings.Split(strings.ReplaceAll(bOut, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		parts := strings.SplitN(ln, "\x00", 2)
		if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			g.Branches[parts[0]] = strings.TrimSpace(parts[1])
		}
	}
	if g.DefaultBranch == "" || g.Branches[g.DefaultBranch] == "" {
		if g.Branches["main"] != "" {
			g.DefaultBranch = "main"
		} else if g.Branches["master"] != "" {
			g.DefaultBranch = "master"
		} else {
			for name := range g.Branches {
				if g.DefaultBranch == "" || name < g.DefaultBranch {
					g.DefaultBranch = name
				}
			}
		}
	}

	// 2. Tags (both lightweight and annotated; `%1f` unit separator, `%00` record separator).
	tOut, err := runGit(ctx, gitBin, mirrorDir, nil, nil, "for-each-ref",
		"--format=%(refname:short)%1f%(objecttype)%1f%(objectname)%1f%(*objectname)%1f%(taggername)%1f%(taggeremail)%1f%(taggerdate:iso-strict)%1f%(contents)%00",
		"refs/tags")
	if err != nil {
		return g, err
	}
	for _, rec := range strings.Split(tOut, "\x00") {
		rec = strings.TrimLeft(rec, "\r\n")
		if strings.TrimSpace(rec) == "" {
			continue
		}
		fields := strings.SplitN(rec, "\x1f", 8)
		if len(fields) < 8 {
			continue
		}
		tag := GitTag{
			Name:        fields[0],
			TaggerName:  fields[4],
			TaggerEmail: strings.Trim(fields[5], "<>"),
			TaggedAt:    fields[6],
			Message:     strings.TrimSuffix(strings.ReplaceAll(fields[7], "\r\n", "\n"), "\n"),
		}
		if fields[1] == "tag" {
			tag.IsAnnotated = true
			tag.TagObjectID = fields[2]
			tag.TargetSHA = fields[3]
			if tag.TargetSHA == "" {
				if peeled, pErr := runGit(ctx, gitBin, mirrorDir, nil, nil, "rev-parse", fields[0]+"^{commit}"); pErr == nil {
					tag.TargetSHA = strings.TrimSpace(peeled)
				}
			}
		} else if fields[1] == "commit" {
			tag.TargetSHA = fields[2]
			tag.Message = ""
		} else {
			continue
		}
		if tag.TargetSHA != "" {
			g.Tags = append(g.Tags, tag)
		}
	}
	sort.Slice(g.Tags, func(i, j int) bool { return g.Tags[i].Name < g.Tags[j].Name })

	if len(g.Branches) == 0 && len(g.Tags) == 0 {
		return g, nil
	}

	// 3. Read raw commit objects WITHOUT shallow parent grafting (`--no-grafts` / `cat-file`)!
	// Note: `git log` hides shallow-grafted parent SHAs by pretending a shallow boundary commit has 0 parents!
	// Therefore, we ALSO inspect raw commit headers for any shallow-grafted commit (or read raw `%P` with `--no-replace-objects`)
	// AND verify raw `parent <sha>` lines via `cat-file commit` on root-appearing commits when `g.IsShallow` or shallow file exists!
	cOut, err := runGit(ctx, gitBin, mirrorDir, nil, nil, "--no-replace-objects", "log", "--branches", "--tags", "--topo-order", "--reverse",
		"-z", "--format=%H%x1f%T%x1f%P%x1f%an%x1f%ae%x1f%aI%x1f%at%x1f%cn%x1f%ce%x1f%cI%x1f%ct%x1f%e%x1f%G?%x1f%B")
	if err != nil {
		return g, err
	}
	for _, rec := range strings.Split(cOut, "\x00") {
		if strings.TrimSpace(rec) == "" {
			continue
		}
		fields := strings.SplitN(rec, "\x1f", 14)
		if len(fields) < 14 {
			continue
		}
		var parents []string
		if strings.TrimSpace(fields[2]) != "" {
			parents = strings.Fields(fields[2])
		}
		aSec, _ := strconv.ParseInt(strings.TrimSpace(fields[6]), 10, 64)
		cSec, _ := strconv.ParseInt(strings.TrimSpace(fields[10]), 10, 64)
		msg := strings.ReplaceAll(fields[13], "\r\n", "\n")
		msg = strings.TrimSuffix(msg, "\n")
		c := GitCommit{
			SHA:             strings.TrimSpace(fields[0]),
			TreeSHA:         strings.TrimSpace(fields[1]),
			Parents:         parents,
			AuthorName:      fields[3],
			AuthorEmail:     fields[4],
			AuthoredAt:      fields[5],
			AuthoredUnixMS:  aSec * 1000,
			CommitterName:   fields[7],
			CommitterEmail:  fields[8],
			CommittedAt:     fields[9],
			CommittedUnixMS: cSec * 1000,
			Encoding:        fields[11],
			SignatureStatus: fields[12],
			Message:         msg,
		}
		g.CommitsBySHA[c.SHA] = c
	}

	// Inspect raw commit objects for any commit with `len(c.Parents) == 0` (or shallow boundary commits)
	// using `git cat-file commit <sha>`, because `git log %P` masks parents listed in `.git/shallow`!
	for sha, c := range g.CommitsBySHA {
		if len(c.Parents) == 0 || g.IsShallow {
			rawParents, rErr := readRawCommitParents(ctx, gitBin, mirrorDir, sha)
			if rErr == nil && len(rawParents) > len(c.Parents) {
				c.Parents = rawParents
				g.CommitsBySHA[sha] = c
			}
		}
	}

	// 4. Deterministic Kahn topological sort + missing parent detection.
	inDegree := make(map[string]int, len(g.CommitsBySHA))
	children := make(map[string][]string, len(g.CommitsBySHA))
	missingSet := map[string]bool{}
	for sha, c := range g.CommitsBySHA {
		deg := 0
		for _, p := range c.Parents {
			if _, ok := g.CommitsBySHA[p]; !ok {
				missingSet[p] = true
				continue
			}
			deg++
			children[p] = append(children[p], sha)
		}
		if len(c.Parents) == 0 {
			g.RootCommitCount++
		}
		inDegree[sha] = deg
	}
	for m := range missingSet {
		g.ShallowMissingParents = append(g.ShallowMissingParents, m)
	}
	sort.Strings(g.ShallowMissingParents)

	var ready []string
	for sha, deg := range inDegree {
		if deg == 0 {
			ready = append(ready, sha)
		}
	}
	sortCommitSHAs := func(list []string) {
		sort.Slice(list, func(i, j int) bool {
			a, b := g.CommitsBySHA[list[i]], g.CommitsBySHA[list[j]]
			if a.CommittedUnixMS != b.CommittedUnixMS {
				return a.CommittedUnixMS < b.CommittedUnixMS
			}
			if a.AuthoredUnixMS != b.AuthoredUnixMS {
				return a.AuthoredUnixMS < b.AuthoredUnixMS
			}
			return a.SHA < b.SHA
		})
	}
	sortCommitSHAs(ready)

	g.Commits = make([]GitCommit, 0, len(g.CommitsBySHA))
	for len(ready) > 0 {
		cur := ready[0]
		ready = ready[1:]
		g.Commits = append(g.Commits, g.CommitsBySHA[cur])
		var newlyReady []string
		for _, ch := range children[cur] {
			inDegree[ch]--
			if inDegree[ch] == 0 {
				newlyReady = append(newlyReady, ch)
			}
		}
		if len(newlyReady) > 0 {
			ready = append(ready, newlyReady...)
			sortCommitSHAs(ready)
		}
	}
	if len(g.Commits) != len(g.CommitsBySHA) {
		return g, fmt.Errorf("gitimport: cycle detected in commit graph (%d/%d sorted)", len(g.Commits), len(g.CommitsBySHA))
	}
	return g, nil
}

func readRawCommitParents(ctx context.Context, gitBin, mirrorDir, commitSHA string) ([]string, error) {
	raw, err := runGit(ctx, gitBin, mirrorDir, nil, nil, "cat-file", "commit", commitSHA)
	if err != nil {
		return nil, err
	}
	var parents []string
	for _, ln := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		if ln == "" {
			break // end of commit object headers
		}
		if strings.HasPrefix(ln, "parent ") {
			p := strings.TrimSpace(strings.TrimPrefix(ln, "parent "))
			if p != "" {
				parents = append(parents, p)
			}
		}
	}
	return parents, nil
}

// BatchBlobReader keeps a persistent `git cat-file --batch` subprocess open
// so reading thousands of blobs during DAG replay incurs zero process-spawn overhead.
type BatchBlobReader struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	closed bool
}

func NewBatchBlobReader(ctx context.Context, gitBin, mirrorDir string) (*BatchBlobReader, error) {
	if gitBin == "" {
		gitBin = "git"
	}
	cmd := exec.CommandContext(ctx, gitBin, "--git-dir="+mirrorDir, "cat-file", "--batch")
	cmd.Env = minimalGitEnv(nil)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &BatchBlobReader{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewReaderSize(stdout, 256*1024),
	}, nil
}

func (b *BatchBlobReader) ReadBlob(oid string) ([]byte, error) {
	if _, err := io.WriteString(b.stdin, oid+"\n"); err != nil {
		return nil, err
	}
	header, err := b.stdout.ReadString('\n')
	if err != nil {
		return nil, err
	}
	header = strings.TrimSpace(header)
	parts := strings.Fields(header)
	if len(parts) < 3 || parts[1] == "missing" {
		return nil, fmt.Errorf("gitimport: blob %s missing (%s)", oid, header)
	}
	size, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || size < 0 {
		return nil, fmt.Errorf("gitimport: invalid blob header %q", header)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(b.stdout, buf); err != nil {
		return nil, err
	}
	if _, err := b.stdout.ReadByte(); err != nil {
		return nil, err
	}
	return buf, nil
}

func (b *BatchBlobReader) Close() {
	if b == nil || b.closed {
		return
	}
	b.closed = true
	_ = b.stdin.Close()
	done := make(chan struct{})
	go func() {
		_ = b.cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		if b.cmd.Process != nil {
			_ = b.cmd.Process.Kill()
		}
		<-done
	}
}

type treeEntry struct {
	Mode string
	Type string
	OID  string
	Path string
}

func readGitTreeEntries(ctx context.Context, gitBin, mirrorDir, treeSHA string) ([]treeEntry, error) {
	out, err := runGit(ctx, gitBin, mirrorDir, nil, nil, "ls-tree", "-r", "-z", "--full-tree", treeSHA)
	if err != nil {
		return nil, err
	}
	var entries []treeEntry
	for _, rec := range strings.Split(out, "\x00") {
		if rec == "" {
			continue
		}
		tab := strings.IndexByte(rec, '\t')
		if tab < 0 {
			continue
		}
		meta := strings.Fields(rec[:tab])
		relPath := rec[tab+1:]
		if len(meta) < 3 || relPath == "" {
			continue
		}
		if relPath == ".lore" || strings.HasPrefix(relPath, ".lore/") {
			continue
		}
		entries = append(entries, treeEntry{
			Mode: meta[0], Type: meta[1], OID: meta[2], Path: relPath,
		})
	}
	return entries, nil
}

// filterEntriesForSubdir projects root Git tree entries down to a specific module subdirectory
// (or keeps the whole tree when sourceSubdir == ""), stripping `sourceSubdir + "/"` from paths
// and scoping `.gitmodules` metadata strictly to submodules inside `sourceSubdir`.
func filterEntriesForSubdir(allEntries []treeEntry, sourceSubdir string, reader *BatchBlobReader) ([]treeEntry, map[string]map[string]string) {
	rawSubmodules := map[string]map[string]string{}
	if reader != nil {
		for _, e := range allEntries {
			if sourceSubdir == "" && e.Path == ".gitmodules" && e.Type == "blob" {
				if raw, bErr := reader.ReadBlob(e.OID); bErr == nil {
					rawSubmodules = parseGitmodules(string(raw))
				}
				break
			}
			if sourceSubdir != "" && (e.Path == ".gitmodules" || e.Path == sourceSubdir+"/.gitmodules") && e.Type == "blob" {
				if raw, bErr := reader.ReadBlob(e.OID); bErr == nil {
					for k, v := range parseGitmodules(string(raw)) {
						rawSubmodules[k] = v
					}
				}
			}
		}
	}

	if sourceSubdir == "" {
		return allEntries, rawSubmodules
	}
	mapped, _, err := ApplyPathMappings(allEntries, MappingsForSubdir(sourceSubdir))
	if err != nil {
		return nil, rawSubmodules
	}
	scoped := make([]treeEntry, 0, len(mapped))
	for _, e := range mapped {
		scoped = append(scoped, e.treeEntry)
	}

	scopedSubs := map[string]map[string]string{}
	prefix := sourceSubdir + "/"
	for subPath, meta := range rawSubmodules {
		if strings.HasPrefix(subPath, prefix) {
			scopedSubs[strings.TrimPrefix(subPath, prefix)] = meta
		} else if _, direct := scopedSubs[subPath]; !direct {
			// Support a module-local .gitmodules inside sourceSubdir as well.
			scopedSubs[subPath] = meta
		}
	}
	return scoped, scopedSubs
}

// TreeMaterializeResult reports special objects and file count after materializing a Git tree.
type TreeMaterializeResult struct {
	RegularFiles int
	TreeDigest   string
	Specials     []history.SpecialObject
}

// MaterializeGitTree reconciles loreWorkDir (excluding `.lore`) so its on-disk files
// match treeSHA (or `treeSHA:sourceSubdir` when sourceSubdir != "") byte-for-byte,
// handling LFS objects/pointers, submodule gitlinks, and symlinks.
func MaterializeGitTree(
	ctx context.Context,
	gitBin, mirrorDir, loreWorkDir, treeSHA, sourceSubdir, lfsMode string,
	reader *BatchBlobReader,
	cachedBlobs map[string]string,
) (TreeMaterializeResult, error) {
	allEntries, err := readGitTreeEntries(ctx, gitBin, mirrorDir, treeSHA)
	if err != nil {
		return TreeMaterializeResult{}, err
	}
	return materializeScopedEntries(mirrorDir, loreWorkDir, sourceSubdir, MappingsForSubdir(sourceSubdir), lfsMode, allEntries, reader, cachedBlobs)
}

func materializeScopedEntries(
	mirrorDir, loreWorkDir, sourceSubdir string,
	mappings []PathMapping,
	lfsMode string,
	allEntries []treeEntry,
	reader *BatchBlobReader,
	cachedBlobs map[string]string,
) (TreeMaterializeResult, error) {
	if len(mappings) == 0 {
		mappings = MappingsForSubdir(sourceSubdir)
	}
	mapped, _, mapErr := ApplyPathMappings(allEntries, mappings)
	if mapErr != nil {
		return TreeMaterializeResult{}, mapErr
	}
	entries := make([]treeEntry, 0, len(mapped))
	for _, e := range mapped {
		entries = append(entries, e.treeEntry)
	}
	_, submodulesMeta := filterEntriesForSubdir(allEntries, sourceSubdir, reader)

	wantPaths := make(map[string]treeEntry, len(entries))
	wantDirs := map[string]bool{}
	var specials []history.SpecialObject

	for _, e := range entries {
		if e.Mode == "160000" || e.Type == "commit" {
			detail := "{}"
			if m, ok := submodulesMeta[e.Path]; ok && len(m) > 0 {
				if b, jErr := json.Marshal(m); jErr == nil {
					detail = string(b)
				}
			}
			specials = append(specials, history.SpecialObject{
				Kind:       "submodule_gitlink",
				Path:       e.Path,
				OID:        e.OID,
				DetailJSON: detail,
			})
			continue
		}
		wantPaths[e.Path] = e
		dir := filepath.ToSlash(filepath.Dir(e.Path))
		for dir != "." && dir != "/" && dir != "" {
			wantDirs[dir] = true
			dir = filepath.ToSlash(filepath.Dir(dir))
		}
	}

	if err := cleanObsoletePaths(loreWorkDir, wantPaths, wantDirs, cachedBlobs); err != nil {
		return TreeMaterializeResult{}, err
	}

	hasher := sha256.New()
	sortedPaths := make([]string, 0, len(wantPaths))
	for p := range wantPaths {
		sortedPaths = append(sortedPaths, p)
	}
	sort.Strings(sortedPaths)

	for _, relPath := range sortedPaths {
		e := wantPaths[relPath]
		fullPath := filepath.Join(loreWorkDir, filepath.FromSlash(relPath))

		raw, err := reader.ReadBlob(e.OID)
		if err != nil {
			return TreeMaterializeResult{}, err
		}

		writeBytes := raw
		cacheTag := e.Mode + ":" + e.OID

		if e.Mode == "120000" {
			detailB, _ := json.Marshal(map[string]string{"target": string(raw)})
			specials = append(specials, history.SpecialObject{
				Kind:       "symlink",
				Path:       relPath,
				OID:        e.OID,
				SizeBytes:  int64(len(raw)),
				DetailJSON: string(detailB),
			})
		} else if lfsOID, lfsSize, isLFS := parseLFSPointer(raw); isLFS {
			if lfsMode == LFSModePointer {
				detailB, _ := json.Marshal(map[string]string{"status": "pointer_preserved_unhydrated"})
				specials = append(specials, history.SpecialObject{
					Kind:       "lfs_pointer",
					Path:       relPath,
					OID:        lfsOID,
					SizeBytes:  lfsSize,
					DetailJSON: string(detailB),
				})
			} else {
				lfsData, lfsErr := readVerifiedLFSObject(mirrorDir, lfsOID, lfsSize)
				if lfsErr != nil {
					return TreeMaterializeResult{}, fmt.Errorf("%w: %s (%s): %v", ErrLFSHydrationFailed, relPath, shortOID(lfsOID), lfsErr)
				}
				writeBytes = lfsData
				cacheTag = "lfs:" + lfsOID
				specials = append(specials, history.SpecialObject{
					Kind:      "lfs_hydrated",
					Path:      relPath,
					OID:       lfsOID,
					SizeBytes: lfsSize,
				})
			}
		}

		sum := sha256.Sum256(writeBytes)
		_, _ = fmt.Fprintf(hasher, "%s\t%s\t%s\n", relPath, e.Mode, hex.EncodeToString(sum[:]))

		if cachedBlobs != nil && cachedBlobs[relPath] == cacheTag {
			if st, sErr := os.Stat(fullPath); sErr == nil && st.Mode().IsRegular() && st.Size() == int64(len(writeBytes)) {
				continue
			}
		}

		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			return TreeMaterializeResult{}, err
		}
		perm := os.FileMode(0o644)
		if e.Mode == "100755" {
			perm = 0o755
		}
		_ = os.Chmod(fullPath, 0o666)
		if err := os.WriteFile(fullPath, writeBytes, perm); err != nil {
			return TreeMaterializeResult{}, err
		}
		if cachedBlobs != nil {
			cachedBlobs[relPath] = cacheTag
		}
	}

	sort.Slice(specials, func(i, j int) bool {
		if specials[i].Path != specials[j].Path {
			return specials[i].Path < specials[j].Path
		}
		return specials[i].Kind < specials[j].Kind
	})

	return TreeMaterializeResult{
		RegularFiles: len(sortedPaths),
		TreeDigest:   hex.EncodeToString(hasher.Sum(nil)),
		Specials:     specials,
	}, nil
}

// InspectExpectedSpecialObjects returns the exact SpecialObject list expected for
// `(treeSHA, sourceSubdir, lfsMode)` directly from the bare Git mirror so verification
// can check count, kind, path, OID, size, and metadata JSON across every commit!
func InspectExpectedSpecialObjects(
	mirrorDir, sourceSubdir, lfsMode string,
	allEntries []treeEntry,
	reader *BatchBlobReader,
	mappings []PathMapping,
) ([]history.SpecialObject, error) {
	if len(mappings) == 0 {
		mappings = MappingsForSubdir(sourceSubdir)
	}
	mapped, _, mapErr := ApplyPathMappings(allEntries, mappings)
	if mapErr != nil {
		return nil, mapErr
	}
	entries := make([]treeEntry, 0, len(mapped))
	for _, e := range mapped {
		entries = append(entries, e.treeEntry)
	}
	_, submodulesMeta := filterEntriesForSubdir(allEntries, sourceSubdir, reader)
	var specials []history.SpecialObject
	for _, e := range entries {
		if e.Mode == "160000" || e.Type == "commit" {
			detail := "{}"
			if m, ok := submodulesMeta[e.Path]; ok && len(m) > 0 {
				if b, jErr := json.Marshal(m); jErr == nil {
					detail = string(b)
				}
			}
			specials = append(specials, history.SpecialObject{
				Kind:       "submodule_gitlink",
				Path:       e.Path,
				OID:        e.OID,
				DetailJSON: detail,
			})
			continue
		}
		if e.Mode == "120000" {
			raw, err := reader.ReadBlob(e.OID)
			if err != nil {
				return nil, err
			}
			detailB, _ := json.Marshal(map[string]string{"target": string(raw)})
			specials = append(specials, history.SpecialObject{
				Kind:       "symlink",
				Path:       e.Path,
				OID:        e.OID,
				SizeBytes:  int64(len(raw)),
				DetailJSON: string(detailB),
			})
			continue
		}
		raw, err := reader.ReadBlob(e.OID)
		if err != nil {
			return nil, err
		}
		if lfsOID, lfsSize, isLFS := parseLFSPointer(raw); isLFS {
			if lfsMode == LFSModePointer {
				detailB, _ := json.Marshal(map[string]string{"status": "pointer_preserved_unhydrated"})
				specials = append(specials, history.SpecialObject{
					Kind:       "lfs_pointer",
					Path:       e.Path,
					OID:        lfsOID,
					SizeBytes:  lfsSize,
					DetailJSON: string(detailB),
				})
			} else {
				if _, lfsErr := readVerifiedLFSObject(mirrorDir, lfsOID, lfsSize); lfsErr != nil {
					return nil, fmt.Errorf("%w: %s (%s): %v", ErrLFSHydrationFailed, e.Path, shortOID(lfsOID), lfsErr)
				}
				specials = append(specials, history.SpecialObject{
					Kind:       "lfs_hydrated",
					Path:       e.Path,
					OID:        lfsOID,
					SizeBytes:  lfsSize,
					DetailJSON: "{}",
				})
			}
		}
	}
	sort.Slice(specials, func(i, j int) bool {
		if specials[i].Path != specials[j].Path {
			return specials[i].Path < specials[j].Path
		}
		return specials[i].Kind < specials[j].Kind
	})
	return specials, nil
}

func cleanObsoletePaths(loreWorkDir string, wantPaths map[string]treeEntry, wantDirs map[string]bool, cachedBlobs map[string]string) error {
	var dirsToCheck []string
	err := filepath.Walk(loreWorkDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if path == loreWorkDir {
			return nil
		}
		rel, err := filepath.Rel(loreWorkDir, path)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(rel)
		if relSlash == ".lore" || strings.HasPrefix(relSlash, ".lore/") {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			if _, isNowFile := wantPaths[relSlash]; isNowFile {
				if cachedBlobs != nil {
					for k := range cachedBlobs {
						if k == relSlash || strings.HasPrefix(k, relSlash+"/") {
							delete(cachedBlobs, k)
						}
					}
				}
				if err := os.RemoveAll(path); err != nil {
					return err
				}
				return filepath.SkipDir
			}
			dirsToCheck = append(dirsToCheck, path)
			return nil
		}
		if _, wanted := wantPaths[relSlash]; !wanted || wantDirs[relSlash] {
			_ = os.Chmod(path, 0o666)
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
			if cachedBlobs != nil {
				delete(cachedBlobs, relSlash)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for i := len(dirsToCheck) - 1; i >= 0; i-- {
		d := dirsToCheck[i]
		rel, rErr := filepath.Rel(loreWorkDir, d)
		if rErr != nil {
			continue
		}
		if !wantDirs[filepath.ToSlash(rel)] {
			_ = os.RemoveAll(d)
		}
	}
	return nil
}

// ComputeWorkdirDigest computes the exact SHA-256 content manifest of regular files
// inside loreWorkDir (excluding `.lore`).
func ComputeWorkdirDigest(loreWorkDir string) (int, string, error) {
	type fileDigest struct {
		rel string
		sum string
	}
	var list []fileDigest
	err := filepath.Walk(loreWorkDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == loreWorkDir {
			return nil
		}
		rel, err := filepath.Rel(loreWorkDir, path)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(rel)
		if relSlash == ".lore" || strings.HasPrefix(relSlash, ".lore/") {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		s := sha256.Sum256(b)
		list = append(list, fileDigest{rel: relSlash, sum: hex.EncodeToString(s[:])})
		return nil
	})
	if err != nil {
		return 0, "", err
	}
	sort.Slice(list, func(i, j int) bool { return list[i].rel < list[j].rel })
	h := sha256.New()
	for _, item := range list {
		_, _ = fmt.Fprintf(h, "%s\t%s\n", item.rel, item.sum)
	}
	return len(list), hex.EncodeToString(h.Sum(nil)), nil
}

// ComputeGitTreeContentDigest computes the mode-agnostic file content digest of treeSHA
// (scoped to sourceSubdir when non-empty) matching ComputeWorkdirDigest.
func ComputeGitTreeContentDigest(ctx context.Context, gitBin, mirrorDir, treeSHA, sourceSubdir, lfsMode string, reader *BatchBlobReader) (int, string, error) {
	return ComputeMappedGitTreeContentDigest(ctx, gitBin, mirrorDir, treeSHA, MappingsForSubdir(sourceSubdir), lfsMode, reader)
}

// ComputeMappedGitTreeContentDigest applies the same current and historical
// path mappings used by materialization before hashing the expected worktree.
func ComputeMappedGitTreeContentDigest(ctx context.Context, gitBin, mirrorDir, treeSHA string, mappings []PathMapping, lfsMode string, reader *BatchBlobReader) (int, string, error) {
	allEntries, err := readGitTreeEntries(ctx, gitBin, mirrorDir, treeSHA)
	if err != nil {
		return 0, "", err
	}
	mapped, _, err := ApplyPathMappings(allEntries, mappings)
	if err != nil {
		return 0, "", err
	}
	type fileDigest struct {
		rel string
		sum string
	}
	var list []fileDigest
	for _, mappedEntry := range mapped {
		e := mappedEntry.treeEntry
		if e.Mode == "160000" || e.Type == "commit" {
			continue
		}
		raw, err := reader.ReadBlob(e.OID)
		if err != nil {
			return 0, "", err
		}
		writeBytes := raw
		if e.Mode != "120000" {
			if lfsOID, lfsSize, isLFS := parseLFSPointer(raw); isLFS && lfsMode != LFSModePointer {
				lfsData, lfsErr := readVerifiedLFSObject(mirrorDir, lfsOID, lfsSize)
				if lfsErr != nil {
					return 0, "", fmt.Errorf("%w: %s (%s): %v", ErrLFSHydrationFailed, e.Path, shortOID(lfsOID), lfsErr)
				}
				writeBytes = lfsData
			}
		}
		s := sha256.Sum256(writeBytes)
		list = append(list, fileDigest{rel: e.Path, sum: hex.EncodeToString(s[:])})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].rel < list[j].rel })
	h := sha256.New()
	for _, item := range list {
		_, _ = fmt.Fprintf(h, "%s\t%s\n", item.rel, item.sum)
	}
	return len(list), hex.EncodeToString(h.Sum(nil)), nil
}

func readVerifiedLFSObject(mirrorDir, lfsOID string, wantSize int64) ([]byte, error) {
	if len(lfsOID) != 64 {
		return nil, fmt.Errorf("invalid lfs oid %q", lfsOID)
	}
	lfsObjPath := filepath.Join(mirrorDir, "lfs", "objects", lfsOID[:2], lfsOID[2:4], lfsOID)
	st, err := os.Stat(lfsObjPath)
	if err != nil {
		return nil, fmt.Errorf("lfs binary object not present in mirror")
	}
	if st.IsDir() || st.Size() != wantSize {
		return nil, fmt.Errorf("lfs size mismatch: disk=%d want=%d", st.Size(), wantSize)
	}
	data, err := os.ReadFile(lfsObjPath)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	gotOID := hex.EncodeToString(sum[:])
	if gotOID != lfsOID {
		return nil, fmt.Errorf("lfs sha256 mismatch: got=%s want=%s", gotOID[:12], lfsOID[:12])
	}
	return data, nil
}

func shortOID(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func parseLFSPointer(raw []byte) (oid string, size int64, ok bool) {
	if len(raw) == 0 || len(raw) > 1024 {
		return "", 0, false
	}
	txt := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if !strings.HasPrefix(txt, "version https://git-lfs.github.com/spec/v1\n") {
		return "", 0, false
	}
	for _, ln := range strings.Split(txt, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "oid sha256:") {
			cand := strings.TrimPrefix(ln, "oid sha256:")
			if len(cand) == 64 {
				oid = cand
			}
		} else if strings.HasPrefix(ln, "size ") {
			if n, err := strconv.ParseInt(strings.TrimPrefix(ln, "size "), 10, 64); err == nil && n >= 0 {
				size = n
			}
		}
	}
	if oid == "" {
		return "", 0, false
	}
	return oid, size, true
}

func parseGitmodules(raw string) map[string]map[string]string {
	out := map[string]map[string]string{}
	var cur map[string]string
	var curPath string
	flush := func() {
		if cur != nil && curPath != "" {
			out[curPath] = cur
		}
	}
	for _, ln := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		s := strings.TrimSpace(ln)
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") {
			continue
		}
		if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
			flush()
			cur = map[string]string{}
			curPath = ""
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := strings.Cut(s, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(strings.ToLower(k)), strings.TrimSpace(v)
		if k == "path" {
			curPath = filepath.ToSlash(v)
		} else {
			cur[k] = v
		}
	}
	flush()
	return out
}
