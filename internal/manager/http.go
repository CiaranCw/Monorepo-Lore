package manager

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"lore-monorepo/internal/loreexec"
)

type ctxKey int

const requestIDKey ctxKey = 1

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health/live", a.live)
	mux.HandleFunc("/health/ready", a.ready)
	mux.HandleFunc("/version", a.version)
	mux.HandleFunc("/api/v1/auth/login", a.login)
	mux.HandleFunc("/api/v1/auth/me", a.me)
	mux.HandleFunc("/api/v1/", a.dispatchAPI)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := requestID(r)
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		if a.Gate != nil {
			a.Gate()
		}
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, code: 200}
		mux.ServeHTTP(rec, r.WithContext(ctx))
		a.Log.WithComponent("http").Info("request", map[string]any{
			"request_id": id,
			"method":     r.Method,
			"path":       r.URL.Path,
			"status":     rec.code,
			"duration":   time.Since(start).String(),
		})
	})
}

func (a *App) live(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "live"})
}

func (a *App) ready(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{}
	ok := true
	if err := a.pingDB(r.Context()); err != nil {
		ok = false
		checks["database"] = "unavailable"
	} else {
		checks["database"] = "ok"
	}
	if err := loreBinaryReady(a.Config.LoreBinary); err != nil {
		ok = false
		checks["lore_binary"] = "missing"
	} else {
		checks["lore_binary"] = "ok"
	}
	if err := a.Config.Validate(); err != nil {
		ok = false
		checks["config"] = "invalid"
	} else {
		checks["config"] = "ok"
	}
	status := http.StatusOK
	state := "ready"
	if !ok {
		status = http.StatusServiceUnavailable
		state = "not_ready"
	}
	writeJSON(w, status, map[string]any{"status": state, "checks": checks})
}

func (a *App) version(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"manager":  Version,
		"commit":   Commit,
		"lore_cli": a.loreVersion(r.Context()),
	})
}

func (a *App) reserved(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "not implemented"})
}

func (a *App) pingDB(ctx context.Context) error {
	if a.DB == nil {
		return os.ErrClosed
	}
	var one int
	return a.DB.QueryRowContext(ctx, "SELECT 1").Scan(&one)
}

func loreBinaryReady(path string) error {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return os.ErrNotExist
	}
	if runtime.GOOS != "windows" && info.Mode()&0o111 == 0 {
		return os.ErrPermission
	}
	return nil
}

func (a *App) loreVersion(ctx context.Context) string {
	probe, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := a.Exec.Run(probe, loreexec.Request{Argv: []string{"--version"}})
	if err != nil || res.TimedOut || res.ExitCode != 0 {
		return ""
	}
	line := strings.TrimSpace(res.Stdout)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	if len(line) > 120 {
		line = line[:120]
	}
	return line
}

func requestID(r *http.Request) string {
	got := r.Header.Get("X-Request-ID")
	if got != "" && len(got) <= 64 && safeID(got) {
		return got
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}

func safeID(s string) bool {
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}
