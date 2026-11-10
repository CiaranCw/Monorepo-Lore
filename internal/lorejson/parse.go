// Package lorejson parses Lore 0.10.1 --json stdout/stderr.
//
// The captured shape is one JSON object per line:
//
//	{"tagName":"<camelCase variant>","data":{...}}
//
// That tagging comes from LoreEvent in lore-revision/src/event.rs
// (serde tag "tagName", content "data", rename_all camelCase) and from
// output_formatter in lore-client/src/cli/cli.rs, which prints one event
// per line and skips LoreEvent::End. P3-A only captured six tag names.
// Every other tag is kept and reported as unknown; its data is not dropped.
package lorejson

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Stream identifies which process pipe a line was read from.
// P3-A stored command output in one blob, so the caller supplies the label.
type Stream string

const (
	Stdout Stream = "stdout"
	Stderr Stream = "stderr"
)

// Kind is how a physical line was interpreted.
type Kind string

const (
	// KindEvent is a JSON object with a string tagName. KnownTag says whether
	// that name appeared in the P3-A --json captures.
	KindEvent Kind = "event"
	// KindText is a non-JSON line. link list captured one of these after complete
	// ("No links found in this repository").
	KindText Kind = "text"
	// KindInvalidJSON is a line that contains a brace but is not valid JSON.
	// The saved E5 history blob starts with such a truncated fragment.
	KindInvalidJSON Kind = "invalidJSON"
	// KindSerializerError is the stderr object cli.rs writes when serde fails:
	// {"error":"<text>"} with no tagName. No P3-A capture of this line exists.
	KindSerializerError Kind = "serializerError"
	// KindUnstructuredJSON is valid JSON that is not a tagName event and not
	// the serializer-error object. No P3-A capture of this shape exists.
	KindUnstructuredJSON Kind = "unstructuredJSON"
)

// capturedTags lists tagName values present in P3-A E5-manager-mechanics.json
// and the data keys those lines actually contained. A key missing from a later
// line is reported; it is not a reason to discard the line.
var capturedTags = map[string][]string{
	"repositoryStatusRevision": {
		"repository", "branch", "branchName", "revision", "revisionNumber",
		"revisionStaged", "revisionMerged", "revisionMergedParentBranch",
		"revisionLocal", "revisionLocalNumber", "revisionRemote", "revisionRemoteNumber",
		"isLocalAhead", "isRemoteAhead", "remoteAvailable", "remoteAuthorized", "remoteBranchExist",
	},
	"complete": {"status", "error"},
	"linkEntry": {
		"link", "linkNode", "linkPath", "sourceNode", "sourcePath",
		"branch", "tracking", "revision", "flags",
	},
	"metadata":             {"key", "value"},
	"revisionHistoryEntry": {"revision", "revisionNumber", "parent"},
	"log":                  {"level", "category", "timestamp", "location", "message"},
}

// Line is one physical line. Raw is the original text without the newline.
// Data and Fields hold the original JSON values; nothing is re-encoded.
type Line struct {
	Stream     Stream
	Number     int
	Raw        string
	Kind       Kind
	TagName    string
	KnownTag   bool
	Data       json.RawMessage
	Fields     map[string]json.RawMessage
	Missing    []string
	ParseError string
}

// Result is a parse of one or two pipes.
type Result struct {
	Lines      []Line
	BlankLines int
}

// Parse reads one pipe. Blank lines are counted and not returned as lines.
// A JSON error on one line does not stop the rest of the pipe.
func Parse(stream Stream, text string) Result {
	var out Result
	for i, raw := range physicalLines(text) {
		if strings.TrimSpace(raw) == "" {
			out.BlankLines++
			continue
		}
		out.Lines = append(out.Lines, classifyLine(stream, i+1, raw))
	}
	return out
}

// ParseOutputs parses stdout and stderr separately, then returns stdout lines
// followed by stderr lines. Line numbers restart at 1 for each pipe.
func ParseOutputs(stdout, stderr string) Result {
	a := Parse(Stdout, stdout)
	b := Parse(Stderr, stderr)
	return Result{Lines: append(a.Lines, b.Lines...), BlankLines: a.BlankLines + b.BlankLines}
}

func physicalLines(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	if text == "" {
		return nil
	}
	parts := strings.Split(text, "\n")
	if parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	for i, p := range parts {
		parts[i] = strings.TrimRight(p, "\r")
	}
	return parts
}

func classifyLine(stream Stream, number int, raw string) Line {
	ln := Line{Stream: stream, Number: number, Raw: raw}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		if strings.ContainsAny(raw, "{}") {
			ln.Kind = KindInvalidJSON
			ln.ParseError = err.Error()
			return ln
		}
		ln.Kind = KindText
		return ln
	}
	if fields == nil {
		// JSON null, array, string, or number. None of these were captured.
		ln.Kind = KindUnstructuredJSON
		ln.ParseError = "json value is not an object"
		return ln
	}
	ln.Fields = fields
	tagRaw, hasTag := fields["tagName"]
	if !hasTag {
		if msg, ok := jsonString(fields["error"]); ok && len(fields) == 1 {
			ln.Kind = KindSerializerError
			ln.ParseError = msg
			return ln
		}
		ln.Kind = KindUnstructuredJSON
		ln.Missing = append(ln.Missing, "tagName")
		return ln
	}
	tag, ok := jsonString(tagRaw)
	if !ok {
		ln.Kind = KindUnstructuredJSON
		ln.ParseError = "tagName is not a string"
		return ln
	}
	ln.Kind = KindEvent
	ln.TagName = tag
	_, ln.KnownTag = capturedTags[tag]
	if !ln.KnownTag {
		ln.ParseError = fmt.Sprintf("unknown event %q", tag)
	}
	data, hasData := fields["data"]
	if !hasData || string(bytes.TrimSpace(data)) == "null" {
		ln.Missing = append(ln.Missing, "data")
		return ln
	}
	ln.Data = append(json.RawMessage(nil), data...)
	if keys, known := capturedTags[tag]; known {
		ln.Missing = append(ln.Missing, missingDataKeys(data, keys)...)
	}
	return ln
}

func missingDataKeys(data json.RawMessage, keys []string) []string {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil || obj == nil {
		return []string{"data object"}
	}
	var missing []string
	for _, k := range keys {
		if _, ok := obj[k]; !ok {
			missing = append(missing, "data."+k)
		}
	}
	return missing
}

func jsonString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// ReadLines is the same as Parse, reading until EOF.
func ReadLines(stream Stream, r io.Reader) (Result, error) {
	var b strings.Builder
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	first := true
	for sc.Scan() {
		if !first {
			b.WriteByte('\n')
		}
		first = false
		b.WriteString(sc.Text())
	}
	if err := sc.Err(); err != nil {
		return Result{}, err
	}
	return Parse(stream, b.String()), nil
}
