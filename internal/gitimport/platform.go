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
	ErrEmbeddedCredentials = errors.New("gitimport: credentials must not be embedded in source_url; use token_env or ssh_key")
	ErrInvalidSourceURL    = errors.New("gitimport: invalid source_url")
	ErrInvalidAuth         = errors.New("gitimport: invalid authentication configuration")

	scpLikeRe = regexp.MustCompile(`^([A-Za-z0-9._-]+)@([A-Za-z0-9.-]+):(.+)$`)
)

// AuthConfig describes how the importer authenticates to an external Git server.
// Raw token values are supplied at runtime in memory or resolved from TokenEnv;
// they are never persisted to SQLite, manifests, or logs.
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

// ValidateAndDetect inspects sourceURL, rejects embedded secrets, and returns
// the normalized URL and auto-detected platform (unless explicitPlatform is set).
func ValidateAndDetect(sourceURL, explicitPlatform string) (cleanURL, platform string, err error) {
	raw := strings.TrimSpace(sourceURL)
	if raw == "" || strings.HasPrefix(raw, "-") {
		return "", "", ErrInvalidSourceURL
	}

	// Check SCP-style SSH URL: git@github.com:org/repo.git
	if m := scpLikeRe.FindStringSubmatch(raw); m != nil && !strings.Contains(m[1], "/") && !strings.Contains(raw, "://") {
		userPart := m[1]
		if strings.Contains(userPart, ":") {
			return "", "", ErrEmbeddedCredentials
		}
		host := strings.ToLower(m[2])
		plat := classifyHost(host)
		if explicitPlatform != "" {
			plat = strings.ToLower(strings.TrimSpace(explicitPlatform))
		}
		return raw, plat, nil
	}

	// Check URL with scheme.
	if strings.Contains(raw, "://") {
		u, parseErr := url.Parse(raw)
		if parseErr != nil || u.Scheme == "" {
			return "", "", ErrInvalidSourceURL
		}
		scheme := strings.ToLower(u.Scheme)
		switch scheme {
		case "http", "https", "ssh", "git":
			if u.Host == "" {
				return "", "", ErrInvalidSourceURL
			}
			if u.User != nil {
				if _, hasPass := u.User.Password(); hasPass {
					return "", "", ErrEmbeddedCredentials
				}
				// For HTTPS, even a single userinfo token like https://<token>@github.com/... is a secret!
				if (scheme == "http" || scheme == "https") && u.User.Username() != "" {
					return "", "", ErrEmbeddedCredentials
				}
			}
			plat := classifyHost(strings.ToLower(u.Hostname()))
			if explicitPlatform != "" {
				plat = strings.ToLower(strings.TrimSpace(explicitPlatform))
			}
			return raw, plat, nil
		case "file":
			if explicitPlatform != "" {
				return raw, strings.ToLower(strings.TrimSpace(explicitPlatform)), nil
			}
			return raw, PlatformLocalGit, nil
		default:
			return "", "", fmt.Errorf("%w: unsupported scheme %q", ErrInvalidSourceURL, u.Scheme)
		}
	}

	// Otherwise treat as local filesystem path (e.g. E:\repos\engine or /tmp/engine.git).
	abs, absErr := filepath.Abs(raw)
	if absErr != nil {
		return "", "", ErrInvalidSourceURL
	}
	plat := PlatformLocalGit
	if explicitPlatform != "" {
		plat = strings.ToLower(strings.TrimSpace(explicitPlatform))
	}
	return abs, plat, nil
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
// without writing tokens or SSH keys to disk, .git/config, or command-line argv.
func BuildGitAuthEnv(sourceURL, platform string, auth AuthConfig) (env []string, secretsToRedact []string, method string, err error) {
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
		return baseEnv, nil, method, nil

	case AuthHTTPSToken:
		tok := auth.Token
		if tok == "" && auth.TokenEnv != "" {
			tok = os.Getenv(auth.TokenEnv)
		}
		if strings.TrimSpace(tok) == "" {
			return nil, nil, method, fmt.Errorf("%w: https_token selected but token is empty (env %q)", ErrInvalidAuth, auth.TokenEnv)
		}
		u, parseErr := url.Parse(sourceURL)
		if parseErr != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return nil, nil, method, fmt.Errorf("%w: https_token requires an http(s) source_url", ErrInvalidAuth)
		}
		user := strings.TrimSpace(auth.TokenUsername)
		if user == "" {
			user = defaultTokenUsername(platform)
		}
		basic := base64.StdEncoding.EncodeToString([]byte(user + ":" + tok))
		origin := u.Scheme + "://" + u.Host + "/"
		env = append(baseEnv,
			"GIT_CONFIG_COUNT=1",
			"GIT_CONFIG_KEY_0=http."+origin+".extraheader",
			"GIT_CONFIG_VALUE_0=Authorization: Basic "+basic,
		)
		return env, []string{tok, basic}, method, nil

	case AuthSSHKey:
		keyPath := strings.TrimSpace(auth.SSHKeyPath)
		if keyPath == "" && auth.SSHKeyEnv != "" {
			keyPath = strings.TrimSpace(os.Getenv(auth.SSHKeyEnv))
		}
		if keyPath == "" {
			return nil, nil, method, fmt.Errorf("%w: ssh_key selected but key path is empty", ErrInvalidAuth)
		}
		if st, statErr := os.Stat(keyPath); statErr != nil || st.IsDir() {
			return nil, nil, method, fmt.Errorf("%w: ssh key path is unreadable", ErrInvalidAuth)
		}
		quotedKey := strings.ReplaceAll(filepath.ToSlash(keyPath), `"`, `\"`)
		sshCmd := fmt.Sprintf(`ssh -i "%s" -o IdentitiesOnly=yes -o IdentityAgent=none -o BatchMode=yes`, quotedKey)
		if auth.KnownHosts != "" {
			kh := strings.ReplaceAll(filepath.ToSlash(auth.KnownHosts), `"`, `\"`)
			sshCmd += fmt.Sprintf(` -o UserKnownHostsFile="%s" -o StrictHostKeyChecking=yes`, kh)
		} else if auth.InsecureHost {
			sshCmd += ` -o StrictHostKeyChecking=accept-new`
		}
		env = append(baseEnv, "GIT_SSH_COMMAND="+sshCmd)
		return env, []string{keyPath}, method, nil

	default:
		return nil, nil, method, fmt.Errorf("%w: unsupported auth_method %q", ErrInvalidAuth, method)
	}
}

// RedactOutput scrubs runtime secrets, Authorization headers, and embedded URL tokens.
func RedactOutput(s string, secrets []string) string {
	out := s
	for _, sec := range secrets {
		if len(sec) >= 4 {
			out = strings.ReplaceAll(out, sec, "<redacted>")
		}
	}
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
