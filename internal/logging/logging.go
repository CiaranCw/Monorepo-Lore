// Package logging writes JSON logs with the standard library.
// Go 1.20 has no log/slog. This package does not record raw Lore output.
package logging

import (
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	Debug Level = iota
	Info
	Warn
	Error
)

func ParseLevel(s string) Level {
	switch strings.ToLower(s) {
	case "debug":
		return Debug
	case "warn":
		return Warn
	case "error":
		return Error
	default:
		return Info
	}
}

func (l Level) String() string {
	switch l {
	case Debug:
		return "debug"
	case Warn:
		return "warn"
	case Error:
		return "error"
	default:
		return "info"
	}
}

type Logger struct {
	state     *logState
	min       Level
	component string
}

type logState struct {
	mu  sync.Mutex
	out io.Writer
}

func New(out io.Writer, level Level, component string) *Logger {
	if component == "" {
		component = "manager"
	}
	return &Logger{state: &logState{out: out}, min: level, component: component}
}

func (l *Logger) WithComponent(name string) *Logger {
	return &Logger{state: l.state, min: l.min, component: name}
}

func (l *Logger) Debug(msg string, attrs map[string]any) { l.write(Debug, msg, attrs) }
func (l *Logger) Info(msg string, attrs map[string]any)  { l.write(Info, msg, attrs) }
func (l *Logger) Warn(msg string, attrs map[string]any)  { l.write(Warn, msg, attrs) }
func (l *Logger) Error(msg string, attrs map[string]any) { l.write(Error, msg, attrs) }

func (l *Logger) write(level Level, msg string, attrs map[string]any) {
	if l == nil || l.state == nil || level < l.min || l.state.out == nil {
		return
	}
	rec := map[string]any{
		"time":      time.Now().UTC().Format(time.RFC3339Nano),
		"level":     level.String(),
		"component": l.component,
		"msg":       redact(msg),
	}
	for k, v := range attrs {
		if s, ok := v.(string); ok {
			rec[k] = redact(s)
		} else {
			rec[k] = v
		}
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	l.state.mu.Lock()
	defer l.state.mu.Unlock()
	_, _ = l.state.out.Write(append(line, '\n'))
}

var (
	jwtPattern    = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	secretAssign  = regexp.MustCompile(`(?i)(password|token|authorization|private[_ -]?key)\s*[:=]\s*\S+`)
	pemBlock      = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`)
	bearerPattern = regexp.MustCompile(`(?i)bearer\s+\S+`)
)

func redact(s string) string {
	s = pemBlock.ReplaceAllString(s, "<redacted-private-key>")
	s = jwtPattern.ReplaceAllString(s, "<redacted-jwt>")
	s = bearerPattern.ReplaceAllString(s, "Bearer <redacted>")
	return secretAssign.ReplaceAllString(s, "$1=<redacted>")
}
