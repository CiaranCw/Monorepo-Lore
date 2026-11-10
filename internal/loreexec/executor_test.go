package loreexec

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("LORE_EXEC_HELPER") != "1" {
		return
	}
	args := helperArgs(os.Args)
	if len(args) == 0 {
		os.Exit(2)
	}
	switch args[0] {
	case "args":
		enc := json.NewEncoder(os.Stdout)
		_ = enc.Encode(args[1:])
	case "ok":
		os.Stdout.WriteString("{\"tagName\":\"complete\",\"data\":{\"status\":0,\"error\":{\"errorCode\":0,\"message\":\"\",\"traceLocations\":[]}}}\n")
	case "both":
		os.Stdout.WriteString("{\"tagName\":\"complete\",\"data\":{\"status\":0,\"error\":{\"errorCode\":0,\"message\":\"\",\"traceLocations\":[]}}}\n")
		os.Stderr.WriteString("[Error] Not authenticated\n")
	case "badjson":
		os.Stdout.WriteString("{\n{\"tagName\":\"complete\",\"data\":{\"status\":0,\"error\":{\"errorCode\":0,\"message\":\"\",\"traceLocations\":[]}}}\n")
	case "exit":
		os.Exit(17)
	case "sleep":
		time.Sleep(5 * time.Second)
	case "big":
		os.Stdout.Write(bytesRepeat(200000))
	case "env":
		os.Stdout.WriteString(os.Getenv("LORE_AUTH_STORE"))
	default:
		os.Exit(2)
	}
	os.Exit(0)
}

func helperArgs(argv []string) []string {
	for i, a := range argv {
		if a == "--" && i+1 < len(argv) {
			return argv[i+1:]
		}
	}
	return nil
}

func bytesRepeat(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'A'
	}
	return b
}

func testExec(t *testing.T) Executor {
	t.Helper()
	return Executor{Config: Config{
		Binary:      os.Args[0],
		LeadingArgs: []string{"-test.run=^TestHelperProcess$", "--"},
		Env:         map[string]string{"LORE_EXEC_HELPER": "1"},
		Timeout:     3 * time.Second,
	}}
}

func TestArgsWithSpacesAndSpecialCharacters(t *testing.T) {
	ex := testExec(t)
	want := []string{"args", "alpha beta", "c&d|e", "quote\"here", "semi;colon"}
	res, err := ex.Run(context.Background(), Request{Argv: want})
	if err != nil {
		t.Fatal(err)
	}
	if !res.ProcessSucceeded() {
		t.Fatalf("%s", res.Summary())
	}
	var got []string
	if err := json.Unmarshal([]byte(res.Stdout), &got); err != nil {
		t.Fatalf("stdout %q: %v", res.Stdout, err)
	}
	if strings.Join(got, "\x00") != strings.Join(want[1:], "\x00") {
		t.Fatalf("args %#v", got)
	}
}

func TestCommandMissing(t *testing.T) {
	ex := Executor{Config: Config{Binary: filepath.Join(t.TempDir(), "missing-lore")}}
	res, err := ex.Run(context.Background(), Request{Argv: []string{"status"}})
	if err == nil || res.Started {
		t.Fatalf("err=%v started=%t", err, res.Started)
	}
	if res.ExitCode != -1 {
		t.Fatalf("exit %d", res.ExitCode)
	}
}

func TestNonZeroExit(t *testing.T) {
	ex := testExec(t)
	res, err := ex.Run(context.Background(), Request{Argv: []string{"exit"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.ProcessSucceeded() || res.ExitCode != 17 {
		t.Fatalf("exit=%d summary=%s", res.ExitCode, res.Summary())
	}
	var ee *exec.ExitError
	if !errors.As(res.ProcessError, &ee) {
		t.Fatalf("process error %v", res.ProcessError)
	}
}

func TestStdoutJSONAndStderrText(t *testing.T) {
	ex := testExec(t)
	res, err := ex.Run(context.Background(), Request{Argv: []string{"both"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.ProcessSucceeded() != true {
		t.Fatal(res.Summary())
	}
	if !strings.Contains(res.Stdout, `"tagName":"complete"`) {
		t.Fatalf("stdout %s", res.Stdout)
	}
	if !strings.Contains(res.Stderr, "Not authenticated") {
		t.Fatalf("stderr %s", res.Stderr)
	}
	if res.OutputSucceeded() {
		t.Fatal("stderr authentication error must fail output success")
	}
	if len(res.Findings) != 1 || res.Findings[0].Class != "authentication" || res.Findings[0].Stream != "stderr" {
		t.Fatalf("%+v", res.Findings)
	}
}

func TestInvalidJSONKept(t *testing.T) {
	ex := testExec(t)
	res, err := ex.Run(context.Background(), Request{Argv: []string{"badjson"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Stdout, "{") || !strings.Contains(res.Stdout, "complete") {
		t.Fatalf("raw stdout lost: %s", res.Stdout)
	}
	if res.StdoutParse.Lines[0].Kind != "invalidJSON" {
		t.Fatalf("first line %+v", res.StdoutParse.Lines[0])
	}
	if res.OutputSucceeded() {
		t.Fatal("invalid JSON must not count as output success")
	}
}

func TestTimeout(t *testing.T) {
	ex := testExec(t)
	ex.Config.Timeout = 200 * time.Millisecond
	res, err := ex.Run(context.Background(), Request{Argv: []string{"sleep"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || res.Cancelled || res.OutputSucceeded() || res.ProcessSucceeded() {
		t.Fatalf("%s", res.Summary())
	}
	for _, f := range res.Findings {
		if f.Class == "network" || f.Class == "timeout" {
			t.Fatalf("timeout was classified as %s", f.Class)
		}
	}
}

func TestCancel(t *testing.T) {
	ex := testExec(t)
	ex.Config.Timeout = 0
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	res, err := ex.Run(ctx, Request{Argv: []string{"sleep"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cancelled || res.TimedOut {
		t.Fatalf("%s", res.Summary())
	}
}

func TestOutputLimit(t *testing.T) {
	ex := testExec(t)
	ex.Config.MaxOutputBytes = 1024
	res, err := ex.Run(context.Background(), Request{Argv: []string{"big"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || len(res.Stdout) > 1024 {
		t.Fatalf("truncated=%t len=%d", res.Truncated, len(res.Stdout))
	}
	if res.OutputSucceeded() {
		t.Fatal("truncated output is not success")
	}
}

func TestRejectsCredentialArgsAndRedactsSummary(t *testing.T) {
	ex := testExec(t)
	secret := "secret-token-value"
	res, err := ex.Run(context.Background(), Request{Argv: []string{"--access-token", secret}})
	if err == nil || res.Started {
		t.Fatalf("err=%v started=%t", err, res.Started)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(res.Summary(), secret) {
		t.Fatalf("secret leaked: %v %s", err, res.Summary())
	}
	leaky := CommandResult{Stdout: "header eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.signature"}
	if strings.Contains(leaky.Summary(), "eyJhbGci") {
		t.Fatal("jwt leaked into summary")
	}
	leaky.Stderr = "Authorization: Bearer secret-value\npassword=hunter2\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"
	sum := leaky.Summary()
	for _, secret := range []string{"secret-value", "hunter2", "BEGIN PRIVATE KEY"} {
		if strings.Contains(sum, secret) {
			t.Fatalf("secret %q leaked into summary: %s", secret, sum)
		}
	}
	if !strings.Contains(leaky.Stdout, "eyJhbGci") {
		t.Fatal("raw stdout must still keep the evidence")
	}
}

func TestLoreIdentityLoginIsTheOnlyTokenException(t *testing.T) {
	ex := testExec(t)
	token := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.signature"
	res, err := ex.Run(context.Background(), Request{Argv: []string{"login", "--token-type", "lore", "--token", token, "--auth-url", "http://127.0.0.1:52010"}})
	if err != nil || !res.Started {
		t.Fatalf("identity login was refused: %v", err)
	}
	if strings.Contains(res.Summary(), token) || strings.Contains(errString(err), token) {
		t.Fatalf("token leaked: %s", res.Summary())
	}
	for _, argv := range [][]string{
		{"status", "--token", token},
		{"login", "--token-type", "api-key", "--token", token},
		{"login", "--identity-token", token},
		{"login", "--token-type", "lore", "--token", token, "--password", "secret"},
	} {
		res, err := ex.Run(context.Background(), Request{Argv: argv})
		if err == nil || res.Started || strings.Contains(err.Error(), token) {
			t.Fatalf("argv %v err=%v started=%t", argv[:2], err, res.Started)
		}
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestEnvGuard(t *testing.T) {
	ex := testExec(t)
	_, err := ex.Run(context.Background(), Request{Argv: []string{"ok"}, Env: map[string]string{"PATH": "hijack"}})
	if err == nil || !strings.Contains(err.Error(), "PATH") {
		t.Fatalf("%v", err)
	}
	_, err = ex.Run(context.Background(), Request{Argv: []string{"ok"}, Env: map[string]string{"SECRET_FILE": "x"}})
	if err == nil {
		t.Fatal("secret env was accepted")
	}
	res, err := ex.Run(context.Background(), Request{Argv: []string{"env"}, Env: map[string]string{"LORE_AUTH_STORE": "fallback"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(res.Stdout) != "fallback" {
		t.Fatalf("stdout %q", res.Stdout)
	}
}
