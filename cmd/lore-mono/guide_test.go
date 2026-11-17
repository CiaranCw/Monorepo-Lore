package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestHelpOutputCategorizedAndPointsToGuide(t *testing.T) {
	for _, args := range [][]string{nil, {"-h"}, {"--help"}, {"help"}} {
		var out, errBuf bytes.Buffer
		prevOut, prevErr := stdout, stderr
		stdout, stderr = &out, &errBuf
		code := run(args)
		stdout, stderr = prevOut, prevErr
		if code != 0 {
			t.Fatalf("args=%v exit=%d stderr=%s", args, code, errBuf.String())
		}
		text := out.String()
		if !strings.Contains(text, "lore-mono guide") || !strings.Contains(text, "lore-mono guide --json") {
			t.Fatalf("help missing guide entrypoint for args=%v:\n%s", args, text)
		}
		for _, section := range []string{
			"Discovery & Authentication:",
			"Workspace & Sync:",
			"Stage, Commit & Push",
			"History & Inspection:",
			"Admin / Migration",
			"Typical Workflows:",
		} {
			if !strings.Contains(text, section) {
				t.Fatalf("help missing section %q for args=%v", section, args)
			}
		}
		if lines := strings.Count(text, "\n"); lines > 60 {
			t.Fatalf("help output too long (%d lines)", lines)
		}
	}
}

func TestGuideTextOfflineAndComplete(t *testing.T) {
	var out, errBuf bytes.Buffer
	prevOut, prevErr := stdout, stderr
	stdout, stderr = &out, &errBuf
	code := run([]string{"guide"})
	stdout, stderr = prevOut, prevErr
	if code != 0 || errBuf.Len() != 0 {
		t.Fatalf("guide failed code=%d stderr=%s", code, errBuf.String())
	}
	text := out.String()
	required := []string{
		"A. Architecture",
		"B. Authentication & Session",
		"C. Repository Discovery Flow",
		"D. Command Reference",
		"E. Common Workflows",
		"F. Operational Constraints",
		"Connect/Login -> Project List -> Select Project -> Module List -> Select Module -> Clone",
		"lore-mono connect --manager",
		"lore-mono-session.tok",
		"lore-mono stage --all",
		"lore-mono commit --all --message",
		"lore-mono push --all",
		"lore-mono history",
		"lore-mono refs",
		"lore-mono show",
		"lore-mono import",
		"lore-mono publish",
		"Never guess Repository IDs",
		"Cross-module parent pointers",
	}
	for _, needle := range required {
		if !strings.Contains(text, needle) {
			t.Fatalf("guide text missing %q", needle)
		}
	}
}

func TestGuideJSONValidAndMatchesCLI(t *testing.T) {
	var out, errBuf bytes.Buffer
	prevOut, prevErr := stdout, stderr
	stdout, stderr = &out, &errBuf
	code := run([]string{"guide", "--json"})
	stdout, stderr = prevOut, prevErr
	if code != 0 || errBuf.Len() != 0 {
		t.Fatalf("guide --json failed code=%d stderr=%s", code, errBuf.String())
	}
	var payload guidePayload
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, out.String())
	}
	if payload.Name != "lore-mono" || strings.TrimSpace(payload.Version) == "" {
		t.Fatalf("unexpected header: %+v", payload)
	}
	if len(payload.DiscoveryFlow.Steps) < 6 || len(payload.Workflows) < 4 || len(payload.Constraints) < 5 {
		t.Fatalf("incomplete guide sections: steps=%d workflows=%d constraints=%d",
			len(payload.DiscoveryFlow.Steps), len(payload.Workflows), len(payload.Constraints))
	}
	if err := validateGuideReferences(); err != nil {
		t.Fatal(err)
	}

	validOps := map[string]bool{
		"read_only":    true,
		"local_write":  true,
		"remote_write": true,
		"admin":        true,
	}
	seen := map[string]bool{}
	for _, cmd := range payload.Commands {
		if !validOps[cmd.OperationType] {
			t.Fatalf("command %q has invalid operation_type %q", cmd.Name, cmd.OperationType)
		}
		if strings.TrimSpace(cmd.Purpose) == "" || strings.TrimSpace(cmd.Example) == "" {
			t.Fatalf("command %q missing purpose/example", cmd.Name)
		}
		seen[cmd.Name] = true
		if !strings.Contains(guideText, cmd.Name) {
			t.Fatalf("command %q in JSON guide is missing from text guide", cmd.Name)
		}
	}

	expectedCommands := []string{
		"guide", "help", "connect", "login", "password", "logout",
		"project list", "project use", "module list",
		"clone", "status", "sync", "stage", "commit", "push",
		"history", "refs", "show", "import", "publish",
	}
	for _, name := range expectedCommands {
		if !seen[name] {
			t.Fatalf("expected CLI command %q missing from guide --json", name)
		}
	}
}

func TestGuideUnknownFlagRejected(t *testing.T) {
	var out, errBuf bytes.Buffer
	prevOut, prevErr := stdout, stderr
	stdout, stderr = &out, &errBuf
	code := run([]string{"guide", "--unknown"})
	stdout, stderr = prevOut, prevErr
	if code == 0 {
		t.Fatalf("expected non-zero exit for unknown guide flag")
	}
	if !strings.Contains(errBuf.String(), "unknown argument") {
		t.Fatalf("unexpected stderr: %s", errBuf.String())
	}
}
