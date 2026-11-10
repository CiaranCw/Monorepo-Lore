package loreexec

import "regexp"

// JWTs and assignment-style secrets are stripped from log text. Raw stdout and
// stderr on CommandResult are left unchanged for the caller that needs evidence.
var (
	jwtPattern    = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	secretAssign  = regexp.MustCompile(`(?i)(password|token|authorization|private[_ -]?key)\s*[:=]\s*\S+`)
	pemBlock      = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`)
	bearerPattern = regexp.MustCompile(`(?i)bearer\s+\S+`)
)
