// Package gitimport migrates external Git repositories (GitHub, Gitee, GitLab,
// Gongfeng, generic Git servers, and local Git repositories) into Monorepo-Lore
// modules while preserving their complete commit DAG, branches, tags, metadata,
// and special object records.
package gitimport

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

const (
	PlatformGitHub     = "github"
	PlatformGitee      = "gitee"
	PlatformGitLab     = "gitlab"
	PlatformGongfeng   = "gongfeng"
	PlatformGenericGit = "generic_git"
	PlatformLocalGit   = "local_git"

	AuthNone       = "none"
	AuthHTTPSToken = "https_token"
	AuthSSHKey     = "ssh_key"
	AuthHelper     = "git_credential_helper"
)

var (
	ErrEmbeddedCredentials   = errors.New("gitimport: credentials or query/fragment parameters must not be embedded in source_url")
	ErrInvalidSourceURL      = errors.New("gitimport: invalid source_url")
	ErrInvalidSourceSubdir   = errors.New("gitimport: invalid source_subdir")
	ErrInvalidAuth           = errors.New("gitimport: invalid authentication configuration")
	ErrInsecureHTTPAuth      = errors.New("gitimport: https_token requires https://; plaintext http:// is forbidden")
	ErrServerEnvAccessDenied = errors.New("gitimport: server is forbidden from reading client environment variable names directly")
	ErrLocalSourceNotAllowed = errors.New("gitimport: local repository path is not permitted by server policy")
	ErrSSHPathNotAllowed     = errors.New("gitimport: ssh key or known_hosts path is not permitted by server policy")

	scpLikeRe      = regexp.MustCompile(`^([A-Za-z0-9._-]+)@([A-Za-z0-9.-]+):(.+)$`)
	sshUsernameRe  = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	urlUserinfoRe  = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/@]+@`)
	urlQuerySecRe  = regexp.MustCompile(`([?&](?:token|access_token|private_token|oauth_token|password|secret|sig|signature)=)[^&\s#]+`)
	authTokenValRe = regexp.MustCompile(`(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+`)
)

// AuthConfig describes how the importer authenticates to an external Git server.
// Raw token values are supplied at runtime in memory only; they are never
// serialized to JSON/TOML, manifests, SQLite, or logs.
// Note: TokenEnv is resolved ONLY on the client CLI (`lore-mono`), NEVER by the Manager server.
type AuthConfig struct {
	Method        string `json:"auth_method" toml:"auth_method"`
	TokenUsername string `json:"token_username,omitempty" toml:"token_username"`
	TokenEnv      string `json:"token_env,omitempty" toml:"token_env"`
	Token         string `json:"-" toml:"-"` // in-memory runtime override only; never serialized
	SSHKeyPath    string `json:"ssh_key_path,omitempty" toml:"ssh_key_path"`
	SSHKeyEnv     string `json:"ssh_key_env,omitempty" toml:"ssh_key_env"`
	KnownHosts    string `json:"known_hosts,omitempty" toml:"known_hosts"`
	InsecureHost  bool   `json:"insecure_ssh_host,omitempty" toml:"insecure_ssh_host"`
}

// AuthPolicy enforces server-side security boundaries when constructing Git auth environments.
type AuthPolicy struct {
	// DisallowProcessEnv forbids reading os.Getenv(TokenEnv) or os.Getenv(SSHKeyEnv).
	// Always true in Manager / Importer.
	DisallowProcessEnv bool
	// RestrictSSHPaths requires SSHKeyPath and KnownHosts to reside inside AllowedSSHKeyDirs
	// after symlink resolution.
	RestrictSSHPaths  bool
	AllowedSSHKeyDirs []string
}

func hasControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// NormalizeSourceSubdir validates and normalizes an optional subdirectory path inside
// an external Git Monorepo (e.g. "Chess" or "games/Chess"). Empty string means whole repo.
func NormalizeSourceSubdir(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", nil
	}
	if hasControlChars(s) || strings.Contains(s, "\\") {
		return "", ErrInvalidSourceSubdir
	}
	s = strings.Trim(s, "/")
	if s == "" {
		return "", ErrInvalidSourceSubdir
	}
	parts := strings.Split(s, "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || p == ".git" || p == ".lore" || strings.HasPrefix(p, "-") {
			return "", ErrInvalidSourceSubdir
		}
	}
	return strings.Join(parts, "/"), nil
}

// ValidateAndDetect inspects sourceURL, rejects embedded credentials, query parameters,
// fragments, and unsafe UNC/remote file paths, and returns the normalized URL + platform.
// Error messages never echo raw URLs that might contain secrets.
func ValidateAndDetect(sourceURL, explicitPlatform string) (cleanURL, platform string, err error) {
	raw := strings.TrimSpace(sourceURL)
	if raw == "" || strings.HasPrefix(raw, "-") || hasControlChars(raw) {
		return "", "", ErrInvalidSourceURL
	}

	// Check SCP-style SSH URL: git@github.com:org/repo.git
	// Exclude Windows drive paths like C:\repo or C:/repo (single letter before ':').
	if !strings.Contains(raw, "://") {
		if m := scpLikeRe.FindStringSubmatch(raw); m != nil && !strings.Contains(m[1], "/") {
			userPart, hostPart, pathPart := m[1], m[2], m[3]
			if strings.Contains(userPart, ":") {
				return "", "", ErrEmbeddedCredentials
			}
			if strings.ContainsAny(pathPart, "?#") {
				return "", "", ErrEmbeddedCredentials
			}
			if strings.HasPrefix(pathPart, "-") || pathPart == "" {
				return "", "", ErrInvalidSourceURL
			}
			plat := classifyHost(strings.ToLower(hostPart))
			if explicitPlatform != "" {
				plat = strings.ToLower(strings.TrimSpace(explicitPlatform))
			}
			return raw, plat, nil
		}
	}

	// Check URL with scheme.
	if strings.Contains(raw, "://") {
		// Reject any '?' or '#' before or after parsing so query/fragment tokens never enter SQLite.
		if strings.ContainsAny(raw, "?#") {
			return "", "", ErrEmbeddedCredentials
		}
		u, parseErr := url.Parse(raw)
		if parseErr != nil || u.Scheme == "" {
			return "", "", ErrInvalidSourceURL
		}
		if u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
			return "", "", ErrEmbeddedCredentials
		}
		scheme := strings.ToLower(u.Scheme)
		switch scheme {
		case "http", "https", "git":
			if u.Host == "" {
				return "", "", ErrInvalidSourceURL
			}
			if u.User != nil {
				return "", "", ErrEmbeddedCredentials
			}
			plat := classifyHost(strings.ToLower(u.Hostname()))
			if explicitPlatform != "" {
				plat = strings.ToLower(strings.TrimSpace(explicitPlatform))
			}
			return u.String(), plat, nil

		case "ssh":
			if u.Host == "" {
				return "", "", ErrInvalidSourceURL
			}
			if u.User != nil {
				if _, hasPass := u.User.Password(); hasPass {
					return "", "", ErrEmbeddedCredentials
				}
				if u.User.Username() != "" && !sshUsernameRe.MatchString(u.User.Username()) {
					return "", "", ErrEmbeddedCredentials
				}
			}
			plat := classifyHost(strings.ToLower(u.Hostname()))
			if explicitPlatform != "" {
				plat = strings.ToLower(strings.TrimSpace(explicitPlatform))
			}
			return u.String(), plat, nil

		case "file":
			if u.User != nil {
				return "", "", ErrEmbeddedCredentials
			}
			if u.Host != "" && !strings.EqualFold(u.Host, "localhost") {
				return "", "", ErrInvalidSourceURL
			}
			localPath, fErr := fileURLToLocalPath(u)
			if fErr != nil {
				return "", "", fErr
			}
			plat := PlatformLocalGit
			if explicitPlatform != "" {
				plat = strings.ToLower(strings.TrimSpace(explicitPlatform))
			}
			return localPath, plat, nil

		default:
			return "", "", fmt.Errorf("%w: unsupported scheme %q", ErrInvalidSourceURL, scheme)
		}
	}

	// Local filesystem path: reject UNC paths (\\server\share or //server/share).
	if strings.HasPrefix(raw, `\\`) || strings.HasPrefix(raw, `//`) {
		return "", "", ErrInvalidSourceURL
	}
	if strings.ContainsAny(raw, "?#") {
		return "", "", ErrEmbeddedCredentials
	}
	abs, absErr := filepath.Abs(raw)
	if absErr != nil {
		return "", "", ErrInvalidSourceURL
	}
	if vol := filepath.VolumeName(abs); strings.HasPrefix(vol, `\\`) || strings.HasPrefix(vol, `//`) {
		return "", "", ErrInvalidSourceURL
	}
	plat := PlatformLocalGit
	if explicitPlatform != "" {
		plat = strings.ToLower(strings.TrimSpace(explicitPlatform))
	}
	return abs, plat, nil
}

func fileURLToLocalPath(u *url.URL) (string, error) {
	p := u.Path
	if p == "" {
		return "", ErrInvalidSourceURL
	}
	if runtime.GOOS == "windows" {
		// file:///C:/path/to/repo -> C:\path\to\repo
		if len(p) >= 3 && p[0] == '/' && ((p[1] >= 'A' && p[1] <= 'Z') || (p[1] >= 'a' && p[1] <= 'z')) && p[2] == ':' {
			p = p[1:]
		} else if u.Host == "" && strings.HasPrefix(p, "//") {
			return "", ErrInvalidSourceURL
		}
	}
	abs, err := filepath.Abs(filepath.FromSlash(p))
	if err != nil {
		return "", ErrInvalidSourceURL
	}
	if vol := filepath.VolumeName(abs); strings.HasPrefix(vol, `\\`) || strings.HasPrefix(vol, `//`) {
		return "", ErrInvalidSourceURL
	}
	return abs, nil
}

// ValidateLocalSourceAccess verifies that a local Git repository path is permitted
// under the server's configured allowedRoots after resolving all symlinks.
// Error responses are uniform so callers cannot probe arbitrary server paths.
func ValidateLocalSourceAccess(localPath string, restrict bool, allowedRoots []string) (string, error) {
	if strings.TrimSpace(localPath) == "" || hasControlChars(localPath) {
		return "", ErrLocalSourceNotAllowed
	}
	absTarget, err := filepath.Abs(localPath)
	if err != nil {
		return "", ErrLocalSourceNotAllowed
	}
	if vol := filepath.VolumeName(absTarget); strings.HasPrefix(vol, `\\`) || strings.HasPrefix(vol, `//`) {
		return "", ErrLocalSourceNotAllowed
	}

	if !restrict {
		if resolved, sErr := filepath.EvalSymlinks(absTarget); sErr == nil {
			return resolved, nil
		}
		return absTarget, nil
	}

	if len(allowedRoots) == 0 {
		return "", ErrLocalSourceNotAllowed
	}

	var canonicalRoots []string
	for _, root := range allowedRoots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		absRoot, rErr := filepath.Abs(root)
		if rErr != nil {
			continue
		}
		evalRoot, rErr := filepath.EvalSymlinks(absRoot)
		if rErr != nil {
			continue
		}
		if st, sErr := os.Stat(evalRoot); sErr == nil && st.IsDir() {
			canonicalRoots = append(canonicalRoots, evalRoot)
		}
	}
	if len(canonicalRoots) == 0 {
		return "", ErrLocalSourceNotAllowed
	}

	resolvedTarget, err := filepath.EvalSymlinks(absTarget)
	if err != nil {
		return "", ErrLocalSourceNotAllowed
	}
	st, err := os.Stat(resolvedTarget)
	if err != nil || !st.IsDir() {
		return "", ErrLocalSourceNotAllowed
	}

	allowed := false
	for _, root := range canonicalRoots {
		if isPathWithinRoot(root, resolvedTarget) {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", ErrLocalSourceNotAllowed
	}

	// Also verify `.git` (if present as a subdirectory or gitdir symlink) does not escape allowedRoots.
	dotGit := filepath.Join(resolvedTarget, ".git")
	if _, dgErr := os.Lstat(dotGit); dgErr == nil {
		resolvedDotGit, evalErr := filepath.EvalSymlinks(dotGit)
		if evalErr != nil {
			return "", ErrLocalSourceNotAllowed
		}
		gitAllowed := false
		for _, root := range canonicalRoots {
			if isPathWithinRoot(root, resolvedDotGit) {
				gitAllowed = true
				break
			}
		}
		if !gitAllowed {
			return "", ErrLocalSourceNotAllowed
		}
	}
	return resolvedTarget, nil
}

// ValidatePathUnderAllowedDirs resolves symlinks and ensures filePath is a regular file
// strictly inside one of allowedDirs.
func ValidatePathUnderAllowedDirs(filePath string, allowedDirs []string) (string, error) {
	if strings.TrimSpace(filePath) == "" || hasControlChars(filePath) || len(allowedDirs) == 0 {
		return "", ErrSSHPathNotAllowed
	}
	absFile, err := filepath.Abs(filePath)
	if err != nil {
		return "", ErrSSHPathNotAllowed
	}
	resolvedFile, err := filepath.EvalSymlinks(absFile)
	if err != nil {
		return "", ErrSSHPathNotAllowed
	}
	st, err := os.Stat(resolvedFile)
	if err != nil || !st.Mode().IsRegular() {
		return "", ErrSSHPathNotAllowed
	}
	for _, dir := range allowedDirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		absDir, dErr := filepath.Abs(dir)
		if dErr != nil {
			continue
		}
		resolvedDir, dErr := filepath.EvalSymlinks(absDir)
		if dErr != nil {
			continue
		}
		if isPathWithinRoot(resolvedDir, resolvedFile) && !pathsEqual(resolvedDir, resolvedFile) {
			return resolvedFile, nil
		}
	}
	return "", ErrSSHPathNotAllowed
}

func isPathWithinRoot(root, target string) bool {
	r := filepath.Clean(root)
	t := filepath.Clean(target)
	if runtime.GOOS == "windows" {
		r = strings.ToLower(r)
		t = strings.ToLower(t)
	}
	rel, err := filepath.Rel(r, t)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return false
	}
	return true
}

func pathsEqual(a, b string) bool {
	ca, cb := filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(ca, cb)
	}
	return ca == cb
}

func classifyHost(host string) string {
	switch {
	case host == "github.com" || strings.HasSuffix(host, ".github.com") || strings.Contains(host, "github"):
		return PlatformGitHub
	case host == "gitee.com" || strings.HasSuffix(host, ".gitee.com"):
		return PlatformGitee
	case host == "gitlab.com" || strings.Contains(host, "gitlab"):
		return PlatformGitLab
	case host == "git.woa.com" || strings.HasSuffix(host, ".code.tencent.com") || host == "git.tencent.com" || strings.Contains(host, "gongfeng"):
		return PlatformGongfeng
	default:
		return PlatformGenericGit
	}
}

func defaultTokenUsername(platform string) string {
	switch platform {
	case PlatformGitHub:
		return "x-access-token"
	case PlatformGitLab, PlatformGongfeng, PlatformGitee:
		return "oauth2"
	default:
		return "git"
	}
}

// BuildGitAuthEnv produces child-process-only environment variables for `git`
// without writing tokens or SSH keys to disk, .git/config, or command-line argv,
// and WITHOUT reading server-side os.Getenv(TokenEnv / SSHKeyEnv) when DisallowProcessEnv is set.
//
// SSH keys and known_hosts paths are passed in dedicated environment variables
// (`LORE_GIT_SSH_KEY` / `LORE_GIT_SSH_KH`) referenced by a 100% static `GIT_SSH_COMMAND`
// string so paths containing `$()`, backticks, quotes, semicolons, or spaces can
// never trigger shell command execution.
func BuildGitAuthEnv(sourceURL, platform string, auth AuthConfig, policy AuthPolicy) (env []string, secretsToRedact []string, method string, err error) {
	if policy.DisallowProcessEnv && strings.TrimSpace(auth.SSHKeyEnv) != "" {
		return nil, nil, AuthSSHKey, ErrServerEnvAccessDenied
	}

	method = strings.ToLower(strings.TrimSpace(auth.Method))
	if method == "" {
		switch {
		case auth.Token != "" || auth.TokenEnv != "":
			method = AuthHTTPSToken
		case auth.SSHKeyPath != "" || auth.SSHKeyEnv != "":
			method = AuthSSHKey
		default:
			method = AuthNone
		}
	}

	baseEnv := []string{"GIT_TERMINAL_PROMPT=0"}

	switch method {
	case AuthNone, AuthHelper:
		if policy.DisallowProcessEnv && strings.TrimSpace(auth.TokenEnv) != "" {
			return nil, nil, method, ErrServerEnvAccessDenied
		}
		return baseEnv, nil, method, nil

	case AuthHTTPSToken:
		tok := auth.Token
		if tok == "" && auth.TokenEnv != "" {
			if policy.DisallowProcessEnv {
				return nil, nil, method, ErrServerEnvAccessDenied
			}
			tok = os.Getenv(auth.TokenEnv)
		}
		if strings.TrimSpace(tok) == "" || hasControlChars(tok) {
			return nil, nil, method, fmt.Errorf("%w: https_token requires a non-empty runtime token", ErrInvalidAuth)
		}
		u, parseErr := url.Parse(sourceURL)
		if parseErr != nil || u.Host == "" {
			return nil, nil, method, fmt.Errorf("%w: https_token requires a valid https:// source_url", ErrInvalidAuth)
		}
		if strings.EqualFold(u.Scheme, "http") {
			return nil, nil, method, ErrInsecureHTTPAuth
		}
		if !strings.EqualFold(u.Scheme, "https") {
			return nil, nil, method, fmt.Errorf("%w: https_token requires https:// scheme", ErrInvalidAuth)
		}
		user := strings.TrimSpace(auth.TokenUsername)
		if user == "" {
			user = defaultTokenUsername(platform)
		}
		if hasControlChars(user) || strings.Contains(user, ":") {
			return nil, nil, method, fmt.Errorf("%w: invalid token_username", ErrInvalidAuth)
		}
		basic := base64.StdEncoding.EncodeToString([]byte(user + ":" + tok))
		origin := "https://" + u.Host + "/"
		env = append(baseEnv,
			"GIT_CONFIG_COUNT=1",
			"GIT_CONFIG_KEY_0=http."+origin+".extraheader",
			"GIT_CONFIG_VALUE_0=Authorization: Basic "+basic,
		)
		return env, []string{tok, basic}, method, nil

	case AuthSSHKey:
		keyPath := strings.TrimSpace(auth.SSHKeyPath)
		if keyPath == "" && auth.SSHKeyEnv != "" {
			if policy.DisallowProcessEnv {
				return nil, nil, method, ErrServerEnvAccessDenied
			}
			keyPath = strings.TrimSpace(os.Getenv(auth.SSHKeyEnv))
		}
		if keyPath == "" || hasControlChars(keyPath) {
			return nil, nil, method, fmt.Errorf("%w: ssh_key requires a valid ssh_key_path", ErrInvalidAuth)
		}
		resolvedKey := keyPath
		if policy.RestrictSSHPaths {
			var kErr error
			resolvedKey, kErr = ValidatePathUnderAllowedDirs(keyPath, policy.AllowedSSHKeyDirs)
			if kErr != nil {
				return nil, nil, method, kErr
			}
		} else {
			st, statErr := os.Stat(keyPath)
			if statErr != nil || !st.Mode().IsRegular() {
				return nil, nil, method, fmt.Errorf("%w: ssh key path is unreadable", ErrInvalidAuth)
			}
		}

		env = append(baseEnv, "LORE_GIT_SSH_KEY="+resolvedKey)
		secrets := []string{keyPath, resolvedKey}

		khRaw := strings.TrimSpace(auth.KnownHosts)
		if khRaw != "" {
			if hasControlChars(khRaw) || strings.Contains(khRaw, `"`) {
				return nil, nil, method, fmt.Errorf("%w: invalid known_hosts path", ErrInvalidAuth)
			}
			resolvedKH := khRaw
			if policy.RestrictSSHPaths {
				var khErr error
				resolvedKH, khErr = ValidatePathUnderAllowedDirs(khRaw, policy.AllowedSSHKeyDirs)
				if khErr != nil {
					return nil, nil, method, khErr
				}
			} else {
				st, statErr := os.Stat(khRaw)
				if statErr != nil || !st.Mode().IsRegular() {
					return nil, nil, method, fmt.Errorf("%w: known_hosts path is unreadable", ErrInvalidAuth)
				}
			}
			env = append(env,
				"LORE_GIT_SSH_KH="+resolvedKH,
				`GIT_SSH_COMMAND=ssh -i "$LORE_GIT_SSH_KEY" -o IdentitiesOnly=yes -o IdentityAgent=none -o BatchMode=yes -o "UserKnownHostsFile=\"$LORE_GIT_SSH_KH\"" -o StrictHostKeyChecking=yes`,
			)
			secrets = append(secrets, khRaw, resolvedKH)
		} else if auth.InsecureHost {
			env = append(env,
				`GIT_SSH_COMMAND=ssh -i "$LORE_GIT_SSH_KEY" -o IdentitiesOnly=yes -o IdentityAgent=none -o BatchMode=yes -o StrictHostKeyChecking=accept-new`,
			)
		} else {
			env = append(env,
				`GIT_SSH_COMMAND=ssh -i "$LORE_GIT_SSH_KEY" -o IdentitiesOnly=yes -o IdentityAgent=none -o BatchMode=yes -o StrictHostKeyChecking=yes`,
			)
		}
		return env, secrets, method, nil

	default:
		return nil, nil, method, fmt.Errorf("%w: unsupported auth_method %q", ErrInvalidAuth, method)
	}
}

// RedactOutput scrubs runtime secrets, Authorization headers, Bearer/Basic tokens,
// PEM blocks, and embedded URL userinfo/query secrets.
func RedactOutput(s string, secrets []string) string {
	out := s
	for _, sec := range secrets {
		if len(sec) >= 4 {
			out = strings.ReplaceAll(out, sec, "<redacted>")
		}
	}
	if start := strings.Index(out, "-----BEGIN "); start >= 0 {
		out = out[:start] + "<redacted-pem>"
	}
	out = urlUserinfoRe.ReplaceAllString(out, "${1}<redacted>@")
	out = urlQuerySecRe.ReplaceAllString(out, "${1}<redacted>")
	out = authTokenValRe.ReplaceAllString(out, "$1 <redacted>")

	lines := strings.Split(out, "\n")
	for i, ln := range lines {
		low := strings.ToLower(ln)
		if strings.Contains(low, "authorization:") || strings.Contains(low, "extraheader") {
			lines[i] = "<redacted-auth-header>"
		}
	}
	res := strings.Join(lines, "\n")
	if len(res) > 1500 {
		res = res[:1500] + "...(truncated)"
	}
	return strings.TrimSpace(res)
}
