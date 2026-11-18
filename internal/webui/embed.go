// Package webui serves the embedded zero-dependency Manager Web Console.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed static/*
var staticFS embed.FS

const cspPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"

func setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", cspPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
}

func contentTypeFor(name string) string {
	switch path.Ext(name) {
	case ".html":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "application/javascript; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".json":
		return "application/json; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

// Handler serves "/" and "/ui/*" from the embedded static assets with strict CSP
// and deterministic cross-platform MIME types.
func Handler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic("webui: missing embedded static directory: " + err.Error())
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			if r.Method != http.MethodHead {
				_, _ = w.Write([]byte(`{"error":"method not allowed"}` + "\n"))
			}
			return
		}

		p := r.URL.Path
		asset := ""
		switch {
		case p == "/" || p == "/ui" || p == "/ui/":
			asset = "index.html"
		case p == "/favicon.ico" || p == "/favicon.svg":
			asset = "favicon.svg"
		case strings.HasPrefix(p, "/ui/"):
			rel := strings.TrimPrefix(p, "/ui/")
			clean := path.Clean("/" + rel)
			clean = strings.TrimPrefix(clean, "/")
			if clean != "" && !strings.Contains(clean, "..") {
				asset = clean
			}
		}
		if asset == "" {
			http.NotFound(w, r)
			return
		}

		data, readErr := fs.ReadFile(sub, asset)
		if readErr != nil {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", contentTypeFor(asset))
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(data)
		}
	})
}
