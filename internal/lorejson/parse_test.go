package lorejson

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func classes(fs []Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Class
	}
	return out
}

func TestSingleStatusLine(t *testing.T) {
	text := strings.Split(readFixture(t, "e5_m2_status.jsonl"), "\n")[0]
	got := Parse(Stdout, text)
	if len(got.Lines) != 1 || got.BlankLines != 0 {
		t.Fatalf("lines=%d blanks=%d", len(got.Lines), got.BlankLines)
	}
	ln := got.Lines[0]
	if ln.Kind != KindEvent || ln.TagName != "repositoryStatusRevision" || !ln.KnownTag || len(ln.Missing) != 0 {
		t.Fatalf("line %+v", ln)
	}
	if !strings.Contains(string(ln.Data), `"remoteAuthorized":1`) {
		t.Fatalf("status data was not preserved: %s", ln.Data)
	}
	if Succeeded(got) || len(Classify(got)) != 0 {
		t.Fatal("a lone status event has no complete event, so it is not success")
	}
}

func TestMultilineStatusAndBlanks(t *testing.T) {
	raw := readFixture(t, "e5_m2_status.jsonl")
	withBlank := strings.Replace(raw, "\n", "\n\n", 1)
	got := Parse(Stdout, withBlank)
	if got.BlankLines != 1 || len(got.Lines) != 2 {
		t.Fatalf("blanks=%d lines=%d", got.BlankLines, len(got.Lines))
	}
	if got.Lines[0].Number != 1 || got.Lines[1].Number != 3 {
		t.Fatalf("numbers %d %d", got.Lines[0].Number, got.Lines[1].Number)
	}
	if got.Lines[1].TagName != "complete" || len(got.Lines[1].Missing) != 0 {
		t.Fatalf("complete %+v", got.Lines[1])
	}
	if !Succeeded(got) {
		t.Fatal("M-2 status plus complete status 0 should succeed")
	}
}

func TestLinkListKeepsNonJSONTrailer(t *testing.T) {
	got := Parse(Stdout, readFixture(t, "e5_m3_links.jsonl"))
	if len(got.Lines) != 5 {
		t.Fatalf("lines=%d", len(got.Lines))
	}
	last := got.Lines[4]
	if last.Kind != KindText || last.Raw != "No links found in this repository" {
		t.Fatalf("trailer %+v", last)
	}
	for _, ln := range got.Lines[:4] {
		if len(ln.Missing) != 0 {
			t.Fatalf("missing %v on %s", ln.Missing, ln.TagName)
		}
	}
	if !Succeeded(got) || len(Classify(got)) != 0 {
		t.Fatalf("trailer was classified: %+v", Classify(got))
	}
}

func TestInvalidAndTruncatedJSONDoesNotStopTheStream(t *testing.T) {
	got := Parse(Stdout, "{\n\n"+readFixture(t, "e5_m4_history.jsonl"))
	if got.Lines[0].Kind != KindInvalidJSON || got.Lines[0].ParseError == "" {
		t.Fatalf("synthetic incomplete object: %+v", got.Lines[0])
	}
	if got.BlankLines != 1 {
		t.Fatalf("blanks=%d", got.BlankLines)
	}
	// The saved M-4 blob itself starts with a truncated fragment.
	var invalid, events int
	for _, ln := range got.Lines[1:] {
		switch ln.Kind {
		case KindInvalidJSON:
			invalid++
			if ln.Raw != "17815026}}}" {
				t.Fatalf("truncated fragment raw %q", ln.Raw)
			}
		case KindEvent:
			events++
		default:
			t.Fatalf("unexpected %+v", ln)
		}
	}
	if invalid != 1 || events != 18 {
		t.Fatalf("invalid=%d events=%d", invalid, events)
	}
}

func TestUnknownEventIsPreserved(t *testing.T) {
	// Synthetic tag. P3-A did not capture this name; the parser must not drop it.
	raw := `{"tagName":"notCaptured","data":{"keep":true},"extra":1}`
	got := Parse(Stdout, raw)
	ln := got.Lines[0]
	if ln.Kind != KindEvent || ln.KnownTag || ln.TagName != "notCaptured" {
		t.Fatalf("%+v", ln)
	}
	if !strings.Contains(ln.ParseError, "unknown event") {
		t.Fatalf("parse error %q", ln.ParseError)
	}
	if string(ln.Data) != `{"keep":true}` || string(ln.Fields["extra"]) != "1" {
		t.Fatalf("data lost: data=%s fields=%v", ln.Data, ln.Fields)
	}
	if len(Classify(got)) != 0 {
		t.Fatal("an unknown non-error tag is not a failure by itself")
	}
}

func TestMissingFields(t *testing.T) {
	raw := "{\"tagName\":\"complete\"}\n{\"tagName\":\"complete\",\"data\":{}}"
	got := Parse(Stdout, raw)
	if len(got.Lines) != 2 {
		t.Fatal(len(got.Lines))
	}
	if strings.Join(got.Lines[0].Missing, ",") != "data" {
		t.Fatalf("missing data: %v", got.Lines[0].Missing)
	}
	if !strings.Contains(strings.Join(got.Lines[1].Missing, ","), "data.status") ||
		!strings.Contains(strings.Join(got.Lines[1].Missing, ","), "data.error") {
		t.Fatalf("missing keys: %v", got.Lines[1].Missing)
	}
	if got.Lines[1].Data == nil || got.Lines[0].Raw == "" {
		t.Fatal("incomplete events must still keep the original line")
	}
	fs := Classify(got)
	if len(fs) != 2 || fs[0].Class != ClassUnknown || fs[1].Class != ClassUnknown {
		t.Fatalf("%+v", fs)
	}
}

func TestCapturedErrors(t *testing.T) {
	cases := []struct {
		file  string
		class string
	}{
		{"e5_m13_not_found.jsonl", ClassRepositoryNotFound},
		{"human_not_found.txt", ClassRepositoryNotFound},
		{"human_not_authorized.txt", ClassAuthorization},
		{"human_not_authenticated.txt", ClassAuthentication},
		{"human_auth_header.txt", ClassAuthentication},
		{"human_diverged.txt", ClassConflict},
		{"human_address_not_found.txt", ClassRevisionNotFound},
		{"human_state_address.txt", ClassRevisionNotFound},
		{"human_nothing_staged.txt", ClassUnknown},
	}
	for _, tc := range cases {
		got := Parse(Stdout, readFixture(t, tc.file))
		fs := Classify(got)
		if len(fs) == 0 || fs[0].Class != tc.class {
			t.Errorf("%s: %+v", tc.file, classes(fs))
		}
		if Succeeded(got) {
			t.Errorf("%s was treated as success", tc.file)
		}
	}
	// Authorization must win over the "Repository not found" trace in the same block.
	authz := Classify(Parse(Stdout, readFixture(t, "human_not_authorized.txt")))
	if len(authz) != 1 || authz[0].Class != ClassAuthorization {
		t.Fatalf("authz block %+v", authz)
	}
	// rc 0 in E3 N-9d still carries a connection warning and an authorization sentence.
	conn := Classify(Parse(Stdout, readFixture(t, "human_connection_unauthorized.txt")))
	if len(conn) != 2 || conn[0].Class != ClassNetwork || conn[1].Class != ClassAuthorization {
		t.Fatalf("N-9d %+v", conn)
	}
}

func TestHistoryCaptureExitZeroIsNotSuccess(t *testing.T) {
	got := Parse(Stdout, readFixture(t, "e5_m4_history.jsonl"))
	fs := Classify(got)
	var auth int
	var sawZero bool
	for _, ln := range got.Lines {
		if ln.TagName != "complete" {
			continue
		}
		st, _, _, _, ok := completeParts(ln)
		if ok && st == 0 {
			sawZero = true
		}
	}
	for _, f := range fs {
		if f.Class == ClassAuthentication {
			auth++
		}
		if f.Class == ClassTimeout || f.Class == ClassInvalidArgument {
			t.Fatalf("unsupported class returned: %+v", f)
		}
	}
	if !sawZero || auth != 2 || Succeeded(got) {
		t.Fatalf("sawZero=%v auth=%d findings=%v succeeded=%v", sawZero, auth, classes(fs), Succeeded(got))
	}
}

func TestPartialStream(t *testing.T) {
	mixed := readFixture(t, "e5_m2_status.jsonl") + "\n" + readFixture(t, "e5_m13_not_found.jsonl")
	got := Parse(Stdout, mixed)
	if Succeeded(got) {
		t.Fatal("a later not-found event must fail the stream")
	}
	fs := Classify(got)
	if len(fs) != 2 || fs[0].Class != ClassRepositoryNotFound || fs[1].Class != ClassRepositoryNotFound {
		t.Fatalf("%+v", fs)
	}
	if fs[1].HasCode && fs[1].Code != 79 {
		t.Fatalf("code %+v", fs[1])
	}
}

func TestStdoutAndStderr(t *testing.T) {
	// Serializer-error shape is from lore-client/src/cli/cli.rs. The text is synthetic;
	// P3-A did not capture a serde failure.
	got := ParseOutputs(readFixture(t, "e5_m13_not_found.jsonl"), `{"error":"synthetic serializer failure"}`)
	if len(got.Lines) != 3 {
		t.Fatalf("lines=%d", len(got.Lines))
	}
	if got.Lines[0].Stream != Stdout || got.Lines[2].Stream != Stderr {
		t.Fatalf("streams %s %s", got.Lines[0].Stream, got.Lines[2].Stream)
	}
	if got.Lines[2].Kind != KindSerializerError || got.Lines[2].Number != 1 {
		t.Fatalf("stderr line %+v", got.Lines[2])
	}
	fs := Classify(got)
	if len(fs) != 3 || fs[2].Class != ClassUnknown || fs[2].Stream != Stderr {
		t.Fatalf("%+v", fs)
	}
}

func TestMergeProgressIsNotConflict(t *testing.T) {
	// E1-tier2-steps.json D-3e, rc 0. This is a merge in progress, not the rc 255 error.
	text := "Remote and local branch have diverged, performing merge\n"
	got := Parse(Stdout, text)
	if len(got.Lines) != 1 || got.Lines[0].Kind != KindText {
		t.Fatalf("%+v", got.Lines)
	}
	if len(Classify(got)) != 0 {
		t.Fatalf("progress classified: %+v", Classify(got))
	}
}

func TestSourceShapedErrorEvent(t *testing.T) {
	// Not a P3-A capture. tagName "error" is LoreEvent::Error; the message text is from rc 17.
	raw := `{"tagName":"error","data":{"errorType":17,"errorInner":"Not authorized to access repository"}}`
	got := Parse(Stderr, raw)
	ln := got.Lines[0]
	if ln.KnownTag || ln.TagName != "error" || !strings.Contains(ln.ParseError, "unknown event") {
		t.Fatalf("%+v", ln)
	}
	fs := Classify(got)
	if len(fs) != 1 || fs[0].Class != ClassAuthorization || fs[0].Code != 17 || fs[0].Stream != Stderr {
		t.Fatalf("%+v", fs)
	}
}
