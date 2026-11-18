package webui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebUIHandlerHeadersMIMEsAndBounds(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	cases := []struct {
		path       string
		wantStatus int
		wantCT     string
		wantSubstr string
	}{
		{"/", http.StatusOK, "text/html; charset=utf-8", `<script type="module" src="/ui/app.js"></script>`},
		{"/ui/", http.StatusOK, "text/html; charset=utf-8", `Monorepo-Lore`},
		{"/ui/styles.css", http.StatusOK, "text/css; charset=utf-8", `data-theme="dark"`},
		{"/ui/app.js", http.StatusOK, "application/javascript; charset=utf-8", `data-theme-toggle`},
		{"/ui/api.js", http.StatusOK, "application/javascript; charset=utf-8", `/api/v1/projects/`},
		{"/ui/presets.js", http.StatusOK, "application/javascript; charset=utf-8", `cloudpunk-web-study`},
		{"/favicon.svg", http.StatusOK, "image/svg+xml", `<svg`},
		{"/ui/does-not-exist.js", http.StatusNotFound, "", ""},
		{"/unknown-route", http.StatusNotFound, "", ""},
	}

	for _, tc := range cases {
		res, err := http.Get(srv.URL + tc.path)
		if err != nil {
			t.Fatalf("GET %s: %v", tc.path, err)
		}
		raw, _ := io.ReadAll(res.Body)
		res.Body.Close()

		if res.StatusCode != tc.wantStatus {
			t.Fatalf("GET %s status=%d, want %d", tc.path, res.StatusCode, tc.wantStatus)
		}
		if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || strings.Contains(csp, "unsafe-inline") {
			t.Fatalf("GET %s unexpected CSP: %q", tc.path, csp)
		}
		if res.Header.Get("X-Content-Type-Options") != "nosniff" || res.Header.Get("X-Frame-Options") != "DENY" {
			t.Fatalf("GET %s missing security headers: %v", tc.path, res.Header)
		}
		if tc.wantCT != "" && res.Header.Get("Content-Type") != tc.wantCT {
			t.Fatalf("GET %s Content-Type=%q, want %q", tc.path, res.Header.Get("Content-Type"), tc.wantCT)
		}
		if tc.wantSubstr != "" && !strings.Contains(string(raw), tc.wantSubstr) {
			t.Fatalf("GET %s body missing %q", tc.path, tc.wantSubstr)
		}
	}

	// Non-GET/HEAD methods are rejected with 405.
	res, err := http.Post(srv.URL+"/", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST / status=%d, want 405", res.StatusCode)
	}
}
