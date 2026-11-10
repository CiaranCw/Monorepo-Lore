package loreadapter

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	hash32 = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hash64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	nameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,62}$`)
)

func validateHash(v string, n int) error {
	re := hash64
	if n == 32 {
		re = hash32
	}
	if !re.MatchString(v) {
		return fmt.Errorf("%w: %q", ErrInvalid, v)
	}
	return nil
}

func isHash(v string, n int) bool {
	return validateHash(v, n) == nil
}

// validateRevisionSpec allows a 64-hex hash or the sync help forms
// [branch]@<number>, [branch]@LATEST, and <branch>@<hash>. It rejects flags.
func validateRevisionSpec(v string) error {
	if v == "" || strings.HasPrefix(v, "-") || strings.ContainsAny(v, " \t\r\n") {
		return fmt.Errorf("%w: revision", ErrInvalid)
	}
	if hash64.MatchString(v) {
		return nil
	}
	branch, rest, ok := strings.Cut(v, "@")
	if !ok || branch == "" || rest == "" {
		return fmt.Errorf("%w: revision", ErrInvalid)
	}
	if err := validateName(strings.Trim(branch, "[]")); err != nil {
		return err
	}
	if rest == "LATEST" || hash64.MatchString(rest) {
		return nil
	}
	for _, c := range rest {
		if c < '0' || c > '9' {
			return fmt.Errorf("%w: revision", ErrInvalid)
		}
	}
	return nil
}

func validateName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("%w: name %q", ErrInvalid, name)
	}
	return nil
}

func validateLinkPath(p string) error {
	if p == "" || strings.HasPrefix(p, "-") || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\\r\n") {
		return fmt.Errorf("%w: link path", ErrInvalid)
	}
	return nil
}

func validateRepoURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: repository url", ErrInvalid)
	}
	switch u.Scheme {
	case "lore", "lores", "urc", "grpc", "grpcs":
	default:
		return fmt.Errorf("%w: repository url scheme", ErrInvalid)
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w: repository url", ErrInvalid)
	}
	p := strings.Trim(u.Path, "/")
	if p == "" || strings.Contains(p, "/") {
		return fmt.Errorf("%w: repository url path", ErrInvalid)
	}
	return nil
}

func requireDir(dir string) error {
	if strings.TrimSpace(dir) == "" || strings.HasPrefix(dir, "-") {
		return fmt.Errorf("%w: directory", ErrInvalid)
	}
	return nil
}

func cleanNewPath(p string) (string, error) {
	if strings.TrimSpace(p) == "" || strings.HasPrefix(p, "-") {
		return "", fmt.Errorf("%w: path", ErrInvalid)
	}
	clean := filepath.Clean(p)
	if clean == "." || clean == string(filepath.Separator) {
		return "", fmt.Errorf("%w: path", ErrInvalid)
	}
	return clean, nil
}
