package lorejson

import (
	"encoding/json"
	"strings"
)

// Class is a failure category grounded in P3-A command output.
//
// ClassTimeout and ClassInvalidArgument are named because the task asks for
// them, but no P3-A log or --json capture contains a timeout or an invalid
// argument. Classify never returns those two values.
const (
	ClassAuthentication     = "authentication"
	ClassAuthorization      = "authorization"
	ClassRepositoryNotFound = "repositoryNotFound"
	ClassRevisionNotFound   = "revisionNotFound"
	ClassNetwork            = "network"
	ClassConflict           = "conflict"
	ClassUnknown            = "unknown"
	ClassTimeout            = "timeout"
	ClassInvalidArgument    = "invalidArgument"
)

// Finding is one classified problem. Raw is the line or the event that carried it.
// Exit codes are not an input: E5 step M-4 was recorded as rc 0 while its JSON
// contains complete.status 9, and E3 step N-9d was rc 0 with a connection warning.
type Finding struct {
	Class   string
	Stream  Stream
	Line    int
	TagName string
	Code    int
	HasCode bool
	Message string
	Raw     string
}

// Classify reports problems in parsed output.
// A stream with no error line is not treated as success; use Succeeded.
func Classify(r Result) []Finding {
	var out []Finding
	var block []Line
	flush := func() {
		if len(block) == 0 {
			return
		}
		if f, ok := classifyTextBlock(block); ok {
			out = append(out, f)
		}
		block = nil
	}
	for _, ln := range r.Lines {
		if ln.Kind == KindText {
			if len(block) > 0 && isTraceLine(ln.Raw) {
				block = append(block, ln)
				continue
			}
			flush()
			block = []Line{ln}
			continue
		}
		flush()
		if f, ok := classifyStructured(ln); ok {
			out = append(out, f)
		}
	}
	flush()
	return out
}

// Succeeded is true only when the output contains at least one complete event,
// every complete event is status 0 with an empty error, and Classify found nothing.
// Missing a complete event is not success: sync can finish without a usable result.
func Succeeded(r Result) bool {
	if len(Classify(r)) > 0 {
		return false
	}
	n := 0
	for _, ln := range r.Lines {
		if ln.TagName != "complete" {
			continue
		}
		n++
		st, code, msg, hasError, ok := completeParts(ln)
		if !ok || !hasError || st != 0 || code != 0 || msg != "" {
			return false
		}
	}
	return n > 0
}

func classifyStructured(ln Line) (Finding, bool) {
	switch ln.TagName {
	case "log":
		level, msg := logParts(ln)
		class, specific := classOf(msg)
		if level == "error" || specific {
			if !specific {
				class = ClassUnknown
			}
			return finding(ln, class, msg, 0, false), true
		}
		return Finding{}, false
	case "complete":
		st, code, msg, hasError, ok := completeParts(ln)
		if !ok {
			return finding(ln, ClassUnknown, "", 0, false), true
		}
		text := msg
		if ctx := traceContext(ln); ctx != "" {
			text = strings.TrimSpace(msg + "\n" + ctx)
		}
		if st == 0 && hasError && code == 0 && msg == "" {
			return Finding{}, false
		}
		class, specific := classOf(text)
		if !specific {
			class = classOfCode(code)
			if class == "" {
				class = classOfCode(st)
			}
		}
		if class == "" {
			class = ClassUnknown
		}
		use := code
		if use == 0 {
			use = st
		}
		return finding(ln, class, msg, use, true), true
	case "error":
		// LoreEvent::Error was not present in the P3-A --json captures.
		// output_formatter still serializes it, so the fields from
		// LoreErrorEventData are read when a line has this tag.
		msg, code, has := errorEventParts(ln)
		class, specific := classOf(msg)
		if !specific {
			class = classOfCode(code)
		}
		if class == "" {
			class = ClassUnknown
		}
		return finding(ln, class, msg, code, has), true
	default:
		if ln.Kind == KindSerializerError {
			return finding(ln, ClassUnknown, ln.ParseError, 0, false), true
		}
		return Finding{}, false
	}
}

func classifyTextBlock(block []Line) (Finding, bool) {
	var b strings.Builder
	for i, ln := range block {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(ln.Raw)
	}
	text := b.String()
	first := strings.TrimSpace(block[0].Raw)
	class, specific := classOf(text)
	switch {
	case specific:
		return finding(block[0], class, text, 0, false), true
	case strings.HasPrefix(first, "[Error]"):
		return finding(block[0], ClassUnknown, text, 0, false), true
	default:
		return Finding{}, false
	}
}

func finding(ln Line, class, msg string, code int, has bool) Finding {
	return Finding{
		Class: class, Stream: ln.Stream, Line: ln.Number, TagName: ln.TagName,
		Code: code, HasCode: has, Message: msg, Raw: ln.Raw,
	}
}

func classOf(text string) (string, bool) {
	switch {
	case hasAny(text,
		"Not authenticated",
		"valid authentication credentials",
		"authorization header required",
		"Failed to decrypt user token",
		"authentication requires a configured auth endpoint"):
		return ClassAuthentication, true
	case hasAny(text,
		"Not authorized",
		"authorization failure",
		"not authorized or unavailable"):
		return ClassAuthorization, true
	case strings.Contains(text, "Branch has diverged, sync to merge remote changes"):
		return ClassConflict, true
	case text == "Not found" || strings.HasPrefix(text, "Not found\n") || strings.HasPrefix(text, "[Error] Not found") ||
		hasAny(text, "Failed to resolve repository", "Failed to list repositories", "Repository not found"):
		return ClassRepositoryNotFound, true
	case hasAny(text, "state data address not found", "Address not found"):
		return ClassRevisionNotFound, true
	case (strings.Contains(text, "Connection to ") && strings.Contains(text, " failed")) ||
		hasAny(text, "Not connected to remote", "Failed to connect to remote repository"):
		return ClassNetwork, true
	default:
		return "", false
	}
}

// classOfCode maps a status seen together with a P3-A message when the message
// itself is empty. Code 9 is not mapped: the only captured status 9 is
// distinguished by its authentication message. Codes 3 (invalid argument) and
// any timeout code were not captured.
func classOfCode(code int) string {
	switch code {
	case 16:
		return ClassAuthentication
	case 17:
		return ClassAuthorization
	case 80:
		return ClassRevisionNotFound
	default:
		return ""
	}
}

func hasAny(text string, parts ...string) bool {
	for _, p := range parts {
		if strings.Contains(text, p) {
			return true
		}
	}
	return false
}

func isTraceLine(raw string) bool {
	s := strings.TrimSpace(raw)
	return strings.HasPrefix(s, "at ") || strings.HasPrefix(s, "at\t")
}

func logParts(ln Line) (level, message string) {
	var data struct {
		Level   string `json:"level"`
		Message string `json:"message"`
	}
	if len(ln.Data) > 0 {
		_ = json.Unmarshal(ln.Data, &data)
	}
	return data.Level, data.Message
}

func completeParts(ln Line) (status, code int, message string, hasError, ok bool) {
	var obj map[string]json.RawMessage
	if len(ln.Data) == 0 || json.Unmarshal(ln.Data, &obj) != nil || obj == nil {
		return 0, 0, "", false, false
	}
	rawStatus, exists := obj["status"]
	if !exists || json.Unmarshal(rawStatus, &status) != nil {
		return 0, 0, "", false, false
	}
	rawErr, hasError := obj["error"]
	if hasError {
		var er struct {
			ErrorCode int    `json:"errorCode"`
			Message   string `json:"message"`
		}
		_ = json.Unmarshal(rawErr, &er)
		code, message = er.ErrorCode, er.Message
	}
	return status, code, message, hasError, true
}

func traceContext(ln Line) string {
	var data struct {
		Error struct {
			Trace []struct {
				Context string `json:"context"`
			} `json:"traceLocations"`
		} `json:"error"`
	}
	if len(ln.Data) == 0 || json.Unmarshal(ln.Data, &data) != nil {
		return ""
	}
	var b strings.Builder
	for _, t := range data.Error.Trace {
		if t.Context == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(t.Context)
	}
	return b.String()
}

func errorEventParts(ln Line) (message string, code int, has bool) {
	var data struct {
		ErrorType  int    `json:"errorType"`
		ErrorInner string `json:"errorInner"`
	}
	if len(ln.Data) == 0 || json.Unmarshal(ln.Data, &data) != nil {
		return "", 0, false
	}
	// errorType is a u32 in LoreErrorEventData. Zero is a real code (none),
	// so HasCode is true whenever the object decoded.
	return data.ErrorInner, data.ErrorType, true
}
