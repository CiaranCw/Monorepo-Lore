package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestLevelAndRedaction(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, Info, "manager")
	log.Debug("hidden", nil)
	log.Info("login", map[string]any{
		"authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.signature",
		"note":          "password=hunter2",
	})
	log.Error("key", map[string]any{"pem": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"})
	if strings.Contains(buf.String(), "hidden") {
		t.Fatal("debug passed the info threshold")
	}
	if strings.Contains(buf.String(), "eyJhbGci") || strings.Contains(buf.String(), "hunter2") || strings.Contains(buf.String(), "BEGIN PRIVATE KEY") {
		t.Fatalf("secret leaked: %s", buf.String())
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.Split(buf.String(), "\n")[0]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["level"] != "info" || rec["component"] != "manager" || rec["time"] == "" {
		t.Fatalf("%v", rec)
	}
}

func TestWarnComponent(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, Warn, "manager").WithComponent("http")
	log.Info("skip", nil)
	log.Warn("slow", map[string]any{"request_id": "abc"})
	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["component"] != "http" || rec["level"] != "warn" || rec["request_id"] != "abc" {
		t.Fatalf("%v", rec)
	}
}
