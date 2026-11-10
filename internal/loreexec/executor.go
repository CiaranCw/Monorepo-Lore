// Package loreexec runs the Lore CLI as a process.
//
// Credentials are not accepted on the command line, except one Lore command:
// login --token-type lore --token <identity JWT>. Lore reads its own
// credential store. LORE_AUTH_STORE may be set by deployment configuration;
// this package does not default it to "fallback".
package loreexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lore-monorepo/internal/lorejson"
)

const defaultMaxOutput = 8 << 20

// Denied argument flags. Lore accepts these, but Manager must not pass
// tokens on argv (P3-A CLI help: --identity-token, --access-token, login --token).
var credentialArgs = map[string]bool{
	"--identity-token": true,
	"--access-token":   true,
	"--token":          true,
	"--password":       true,
}

// Config is process-wide executor configuration.
type Config struct {
	// Binary is the lore executable. Required.
	Binary string
	// Dir is the default working directory. Empty inherits the current directory.
	Dir string
	// Timeout is the process deadline. Zero means only the caller's context applies.
	Timeout time.Duration
	// MaxOutputBytes caps each of stdout and stderr. Zero uses 8 MiB.
	// The process is cancelled once a stream passes the cap; captured bytes are kept.
	MaxOutputBytes int
	// Env is merged over the inherited environment for every command.
	// Critical process variables and anything that looks like a secret are rejected.
	Env map[string]string
	// LeadingArgs is prepended to argv. Production leaves it nil.
	// Tests use it to re-exec the test binary as a helper process.
	LeadingArgs []string
}

// Request is one invocation. Argv is the argument vector after the binary
// and after LeadingArgs. It must not contain credential flags.
type Request struct {
	Argv []string
	Dir  string
	Env  map[string]string
}

// CommandResult keeps the raw process evidence and the lorejson view of it.
// Stdout and Stderr are not merged. Summary is safe to log; the raw fields are not.
type CommandResult struct {
	Argv         []string
	ExitCode     int
	ProcessError error
	Stdout       string
	Stderr       string
	StdoutParse  lorejson.Result
	StderrParse  lorejson.Result
	Findings     []lorejson.Finding
	Duration     time.Duration
	Started      bool
	TimedOut     bool
	Cancelled    bool
	Truncated    bool
}

// ProcessSucceeded reports whether the process was started and exited 0.
// It does not mean Lore completed the operation.
func (r CommandResult) ProcessSucceeded() bool {
	return r.Started && r.ProcessError == nil && r.ExitCode == 0 && !r.TimedOut && !r.Cancelled && !r.Truncated
}

// OutputSucceeded reports whether captured Lore output describes success.
// Exit code 0 is not enough: a complete event with a non-zero status, an
// error log, or a truncated capture all fail this check. Timeout is not
// turned into a network finding; TimedOut is separate.
func (r CommandResult) OutputSucceeded() bool {
	if r.TimedOut || r.Cancelled || r.Truncated || !r.Started {
		return false
	}
	if len(r.Findings) > 0 || hasInvalid(r.StdoutParse) || hasInvalid(r.StderrParse) {
		return false
	}
	return lorejson.Succeeded(r.StdoutParse)
}

func hasInvalid(r lorejson.Result) bool {
	for _, ln := range r.Lines {
		if ln.Kind == lorejson.KindInvalidJSON {
			return true
		}
	}
	return false
}

// Summary is a log-safe description. It redacts credential flags and JWTs.
func (r CommandResult) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "exit=%d started=%t timeout=%t cancelled=%t truncated=%t", r.ExitCode, r.Started, r.TimedOut, r.Cancelled, r.Truncated)
	if r.ProcessError != nil {
		fmt.Fprintf(&b, " process=%s", redact(r.ProcessError.Error()))
	}
	if len(r.Findings) > 0 {
		fmt.Fprintf(&b, " findings=%d first=%s", len(r.Findings), r.Findings[0].Class)
	}
	b.WriteString(" argv=")
	b.WriteString(strings.Join(r.Argv, " "))
	b.WriteString(" stdout=")
	b.WriteString(redact(clip(r.Stdout)))
	b.WriteString(" stderr=")
	b.WriteString(redact(clip(r.Stderr)))
	return b.String()
}

func clip(s string) string {
	if len(s) > 180 {
		return s[:180]
	}
	return s
}

// Executor runs Lore.
type Executor struct {
	Config Config
}

// Run starts the process. A non-nil error means the command was rejected or
// could not be started. A started process that exits non-zero, times out, or
// produces failing Lore output still returns a CommandResult and a nil error;
// callers distinguish those with ProcessSucceeded, OutputSucceeded, TimedOut,
// and Findings. The raw streams are always returned when the process started.
func (e Executor) Run(ctx context.Context, req Request) (CommandResult, error) {
	start := time.Now()
	if ctx == nil {
		ctx = context.Background()
	}
	argv := append(append([]string{}, e.Config.LeadingArgs...), req.Argv...)
	res := CommandResult{Argv: redactArgs(append([]string{e.Config.Binary}, argv...)), ExitCode: -1}
	if strings.TrimSpace(e.Config.Binary) == "" {
		err := errors.New("loreexec: binary path is empty")
		res.ProcessError = err
		res.Duration = time.Since(start)
		return res, err
	}
	if err := rejectCredentialArgs(req.Argv); err != nil {
		res.ProcessError = err
		res.Duration = time.Since(start)
		return res, err
	}
	env, err := mergeEnv(os.Environ(), e.Config.Env, req.Env)
	if err != nil {
		res.ProcessError = err
		res.Duration = time.Since(start)
		return res, err
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var timedOut atomic.Bool
	if e.Config.Timeout > 0 {
		timer := time.AfterFunc(e.Config.Timeout, func() {
			timedOut.Store(true)
			cancel()
		})
		defer timer.Stop()
	}

	cmd := exec.CommandContext(runCtx, e.Config.Binary, argv...)
	cmd.Dir = firstNonEmpty(req.Dir, e.Config.Dir)
	cmd.Env = env
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		res.ProcessError = err
		res.Duration = time.Since(start)
		return res, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		res.ProcessError = err
		res.Duration = time.Since(start)
		return res, err
	}
	if err := cmd.Start(); err != nil {
		res.ProcessError = err
		res.Duration = time.Since(start)
		return res, err
	}
	res.Started = true

	limit := e.Config.MaxOutputBytes
	if limit <= 0 {
		limit = defaultMaxOutput
	}
	var truncated atomic.Bool
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		res.Stdout = readLimit(stdout, limit, func() {
			truncated.Store(true)
			cancel()
		})
	}()
	go func() {
		defer wg.Done()
		res.Stderr = readLimit(stderr, limit, func() {
			truncated.Store(true)
			cancel()
		})
	}()
	wg.Wait()
	waitErr := cmd.Wait()
	res.Duration = time.Since(start)
	res.Truncated = truncated.Load()
	res.TimedOut = timedOut.Load()
	if ctx.Err() != nil && !res.TimedOut {
		res.Cancelled = true
	}
	if waitErr == nil {
		res.ExitCode = 0
	} else if ee := (*exec.ExitError)(nil); errors.As(waitErr, &ee) {
		res.ExitCode = ee.ExitCode()
		if !res.TimedOut && !res.Cancelled {
			res.ProcessError = waitErr
		}
	} else if !res.TimedOut && !res.Cancelled {
		res.ProcessError = waitErr
	}
	res.StdoutParse = lorejson.Parse(lorejson.Stdout, res.Stdout)
	res.StderrParse = lorejson.Parse(lorejson.Stderr, res.Stderr)
	res.Findings = append(lorejson.Classify(res.StdoutParse), lorejson.Classify(res.StderrParse)...)
	return res, nil
}

func readLimit(r io.Reader, n int, onTrunc func()) string {
	var buf bytes.Buffer
	tmp := make([]byte, 32*1024)
	hit := false
	for {
		nr, err := r.Read(tmp)
		if nr > 0 {
			if buf.Len() < n {
				keep := n - buf.Len()
				if nr < keep {
					keep = nr
				}
				buf.Write(tmp[:keep])
			}
			if buf.Len() >= n && !hit {
				hit = true
				if onTrunc != nil {
					onTrunc()
				}
			}
		}
		if err != nil {
			break
		}
	}
	return buf.String()
}

func rejectCredentialArgs(argv []string) error {
	if loreIdentityLogin(argv) {
		return nil
	}
	for _, a := range argv {
		name := a
		if i := strings.IndexByte(a, '='); i >= 0 {
			name = a[:i]
		}
		if credentialArgs[name] {
			return fmt.Errorf("loreexec: refusing credential argument %s", name)
		}
	}
	return nil
}

// loreIdentityLogin is the only argv shape allowed to carry a token.
// It is exactly: login --token-type lore --token <jwt> [--auth-url <url>] [remote].
// Flags may appear in any order. Any other command, token type, or secret flag is refused.
func loreIdentityLogin(argv []string) bool {
	if len(argv) == 0 || argv[0] != "login" {
		return false
	}
	var tokenType string
	var sawToken bool
	var sawRemote bool
	for i := 1; i < len(argv); i++ {
		name, value, hasValue := splitArg(argv[i])
		switch name {
		case "--token-type":
			if !hasValue {
				if i+1 >= len(argv) {
					return false
				}
				i++
				value = argv[i]
			}
			if tokenType != "" || value == "" {
				return false
			}
			tokenType = value
		case "--token":
			if sawToken {
				return false
			}
			sawToken = true
			if !hasValue {
				if i+1 >= len(argv) || argv[i+1] == "" || strings.HasPrefix(argv[i+1], "-") {
					return false
				}
				i++
			} else if value == "" {
				return false
			}
		case "--auth-url":
			if !hasValue {
				if i+1 >= len(argv) || argv[i+1] == "" || strings.HasPrefix(argv[i+1], "-") {
					return false
				}
				i++
			} else if value == "" {
				return false
			}
		case "--identity-token", "--access-token", "--password":
			return false
		default:
			if strings.HasPrefix(argv[i], "-") || sawRemote {
				return false
			}
			sawRemote = true
		}
	}
	return sawToken && tokenType == "lore"
}

func splitArg(arg string) (name, value string, hasValue bool) {
	if i := strings.IndexByte(arg, '='); i >= 0 {
		return arg[:i], arg[i+1:], true
	}
	return arg, "", false
}

func mergeEnv(base []string, layers ...map[string]string) ([]string, error) {
	out := append([]string{}, base...)
	index := map[string]int{}
	for i, kv := range out {
		if k, _, ok := strings.Cut(kv, "="); ok {
			index[k] = i
		}
	}
	for _, layer := range layers {
		for k, v := range layer {
			if err := checkExtraEnv(k); err != nil {
				return nil, err
			}
			kv := k + "=" + v
			if i, ok := index[k]; ok {
				out[i] = kv
			} else {
				index[k] = len(out)
				out = append(out, kv)
			}
		}
	}
	return out, nil
}

func checkExtraEnv(key string) error {
	u := strings.ToUpper(key)
	switch u {
	case "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "HOME", "USERPROFILE", "TMP", "TEMP":
		return fmt.Errorf("loreexec: refusing to override %s", key)
	}
	if strings.HasPrefix(u, "LD_") || strings.HasPrefix(u, "DYLD_") {
		return fmt.Errorf("loreexec: refusing to override %s", key)
	}
	if strings.Contains(u, "TOKEN") || strings.Contains(u, "PASSWORD") || strings.Contains(u, "SECRET") || strings.Contains(u, "PRIVATE") {
		return fmt.Errorf("loreexec: refusing secret environment variable %s", key)
	}
	return nil
}

func redactArgs(argv []string) []string {
	out := make([]string, len(argv))
	for i, a := range argv {
		name := a
		if eq := strings.IndexByte(a, '='); eq >= 0 && credentialArgs[a[:eq]] {
			out[i] = a[:eq] + "=***"
			continue
		}
		if credentialArgs[name] && i+1 < len(argv) {
			out[i] = a
			continue
		}
		if i > 0 && credentialArgs[argv[i-1]] && !strings.Contains(argv[i-1], "=") {
			out[i] = "***"
			continue
		}
		out[i] = redact(a)
	}
	return out
}

func redact(s string) string {
	s = pemBlock.ReplaceAllString(s, "<redacted-private-key>")
	s = jwtPattern.ReplaceAllString(s, "<redacted-jwt>")
	s = bearerPattern.ReplaceAllString(s, "Bearer <redacted>")
	s = secretAssign.ReplaceAllString(s, "$1=<redacted>")
	return s
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
