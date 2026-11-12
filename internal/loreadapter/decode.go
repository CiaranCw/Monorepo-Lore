package loreadapter

import (
	"bytes"
	"encoding/json"
	"fmt"

	"lore-monorepo/internal/loreexec"
)

// Status is the repositoryStatusRevision object captured in E5 step M-2.
// Ahead and availability flags were JSON numbers 0 and 1 in that capture.
type Status struct {
	RepositoryID       string
	BranchID           string
	BranchName         string
	Revision           string
	RevisionNumber     int
	RevisionStaged     string
	RevisionMerged     string
	MergedParentBranch string
	RevisionLocal      string
	RevisionRemote     string
	RemoteAvailable    bool
	RemoteAuthorized   bool
	RemoteBranchExist  bool
	IsLocalAhead       bool
	IsRemoteAhead      bool
	Raw                json.RawMessage
}

// Link is one linkEntry object captured in E5 step M-3.
type Link struct {
	RepositoryID string
	LinkPath     string
	Revision     string
	Tracking     bool
	Raw          json.RawMessage
}

// HistoryEntry is one revisionHistoryEntry captured in E5 step M-4,
// together with the metadata events Lore emits immediately after it.
type HistoryEntry struct {
	Revision        string
	RevisionNumber  int
	Parent          []string
	TimestampUnixMS int64
	Metadata        map[string]string
	Raw             json.RawMessage
}

// Branch is a branchListEntry.
// NOT_VERIFIED against a P3-A capture; see ListBranches.
type Branch struct {
	ID            string
	Name          string
	Latest        string
	Location      string
	Creator       string
	CreatedUnixMS int64
	IsCurrent     bool
	Archived      bool
	Raw           json.RawMessage
}

// FileDelta is one revisionInfoDelta event emitted by `lore revision info --delta`.
type FileDelta struct {
	Path       string `json:"path"`
	FromPath   string `json:"from_path,omitempty"`
	Size       uint64 `json:"size"`
	Action     string `json:"action"`
	FlagModify bool   `json:"flag_modify"`
	FlagMerged bool   `json:"flag_merged"`
	FlagFile   bool   `json:"flag_file"`
}

// RevisionDetail is the full result of `lore revision info [--delta]`.
type RevisionDetail struct {
	RepositoryID    string
	Revision        string
	RevisionNumber  int
	Parent          []string
	TimestampUnixMS int64
	Metadata        map[string]string
	Deltas          []FileDelta
}

func decodeStatus(res loreexec.CommandResult) (Status, bool) {
	raw, ok := firstData(res, "repositoryStatusRevision")
	if !ok {
		return Status{}, false
	}
	var wire struct {
		Repository         string `json:"repository"`
		Branch             string `json:"branch"`
		BranchName         string `json:"branchName"`
		Revision           string `json:"revision"`
		RevisionNumber     int    `json:"revisionNumber"`
		RevisionStaged     string `json:"revisionStaged"`
		RevisionMerged     string `json:"revisionMerged"`
		MergedParentBranch string `json:"revisionMergedParentBranch"`
		RevisionLocal      string `json:"revisionLocal"`
		RevisionRemote     string `json:"revisionRemote"`
		RemoteAvailable    bit    `json:"remoteAvailable"`
		RemoteAuthorized   bit    `json:"remoteAuthorized"`
		RemoteBranchExist  bit    `json:"remoteBranchExist"`
		IsLocalAhead       bit    `json:"isLocalAhead"`
		IsRemoteAhead      bit    `json:"isRemoteAhead"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil || wire.Repository == "" || wire.Revision == "" {
		return Status{}, false
	}
	return Status{
		RepositoryID: wire.Repository, BranchID: wire.Branch, BranchName: wire.BranchName,
		Revision: wire.Revision, RevisionNumber: wire.RevisionNumber,
		RevisionStaged: wire.RevisionStaged, RevisionMerged: wire.RevisionMerged,
		MergedParentBranch: wire.MergedParentBranch,
		RevisionLocal:      wire.RevisionLocal, RevisionRemote: wire.RevisionRemote,
		RemoteAvailable: bool(wire.RemoteAvailable), RemoteAuthorized: bool(wire.RemoteAuthorized),
		RemoteBranchExist: bool(wire.RemoteBranchExist),
		IsLocalAhead:      bool(wire.IsLocalAhead), IsRemoteAhead: bool(wire.IsRemoteAhead),
		Raw: append(json.RawMessage(nil), raw...),
	}, true
}

func decodeLinks(res loreexec.CommandResult) ([]Link, error) {
	raws := allData(res, "linkEntry")
	out := make([]Link, 0, len(raws))
	for _, raw := range raws {
		var wire struct {
			Link     string `json:"link"`
			LinkPath string `json:"linkPath"`
			Revision string `json:"revision"`
			Tracking bit    `json:"tracking"`
		}
		if err := json.Unmarshal(raw, &wire); err != nil || wire.LinkPath == "" {
			return nil, fmt.Errorf("%w: linkEntry did not match the captured fields", ErrOutput)
		}
		out = append(out, Link{
			RepositoryID: wire.Link, LinkPath: wire.LinkPath, Revision: wire.Revision,
			Tracking: bool(wire.Tracking), Raw: append(json.RawMessage(nil), raw...),
		})
	}
	return out, nil
}

func decodeHistory(res loreexec.CommandResult) ([]HistoryEntry, error) {
	var out []HistoryEntry
	for _, ln := range res.StdoutParse.Lines {
		switch ln.TagName {
		case "revisionHistoryEntry":
			var wire struct {
				Revision       string   `json:"revision"`
				RevisionNumber int      `json:"revisionNumber"`
				Parent         []string `json:"parent"`
			}
			if err := json.Unmarshal(ln.Data, &wire); err != nil || wire.Revision == "" {
				return nil, fmt.Errorf("%w: revisionHistoryEntry did not match the captured fields", ErrOutput)
			}
			out = append(out, HistoryEntry{
				Revision:       wire.Revision,
				RevisionNumber: wire.RevisionNumber,
				Parent:         wire.Parent,
				Metadata:       map[string]string{},
				Raw:            append(json.RawMessage(nil), ln.Data...),
			})
		case "metadata":
			if len(out) == 0 {
				continue
			}
			k, v, num, hasNum, ok := decodeMetadataLine(ln.Data)
			if !ok {
				continue
			}
			cur := &out[len(out)-1]
			cur.Metadata[k] = v
			if k == "timestamp" && hasNum {
				cur.TimestampUnixMS = num
			}
		}
	}
	return out, nil
}

func decodeMetadataLine(raw json.RawMessage) (key, val string, num int64, hasNum, ok bool) {
	var wire struct {
		Key   string `json:"key"`
		Value struct {
			TagName string          `json:"tagName"`
			Data    json.RawMessage `json:"data"`
		} `json:"value"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &wire) != nil || wire.Key == "" {
		return "", "", 0, false, false
	}
	switch wire.Value.TagName {
	case "numeric":
		var n int64
		if json.Unmarshal(wire.Value.Data, &n) == nil {
			return wire.Key, fmt.Sprintf("%d", n), n, true, true
		}
		var u uint64
		if json.Unmarshal(wire.Value.Data, &u) == nil {
			return wire.Key, fmt.Sprintf("%d", u), int64(u), true, true
		}
	default:
		var s string
		if json.Unmarshal(wire.Value.Data, &s) == nil {
			return wire.Key, s, 0, false, true
		}
	}
	return wire.Key, string(bytes.TrimSpace(wire.Value.Data)), 0, false, true
}

func decodeBranches(res loreexec.CommandResult) ([]Branch, error) {
	raws := allData(res, "branchListEntry")
	out := make([]Branch, 0, len(raws))
	for _, raw := range raws {
		var wire struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Latest    string `json:"latest"`
			Location  string `json:"location"`
			Creator   string `json:"creator"`
			Created   int64  `json:"created"`
			IsCurrent bit    `json:"isCurrent"`
			Archived  bit    `json:"archived"`
		}
		if err := json.Unmarshal(raw, &wire); err != nil || wire.Name == "" {
			return nil, fmt.Errorf("%w: branchListEntry did not match the source struct", ErrVerify)
		}
		out = append(out, Branch{
			ID: wire.ID, Name: wire.Name, Latest: wire.Latest,
			Location: wire.Location, Creator: wire.Creator, CreatedUnixMS: wire.Created,
			IsCurrent: bool(wire.IsCurrent), Archived: bool(wire.Archived),
			Raw: append(json.RawMessage(nil), raw...),
		})
	}
	return out, nil
}

func decodeRevisionDetail(res loreexec.CommandResult) (RevisionDetail, error) {
	var out RevisionDetail
	out.Metadata = map[string]string{}
	sawInfo := false
	for _, ln := range res.StdoutParse.Lines {
		switch ln.TagName {
		case "revisionInfo":
			var wire struct {
				Repository     string   `json:"repository"`
				Revision       string   `json:"revision"`
				RevisionNumber int      `json:"revisionNumber"`
				Parent         []string `json:"parent"`
			}
			if err := json.Unmarshal(ln.Data, &wire); err != nil || wire.Revision == "" {
				return RevisionDetail{}, fmt.Errorf("%w: revisionInfo decode failed", ErrOutput)
			}
			out.RepositoryID = wire.Repository
			out.Revision = wire.Revision
			out.RevisionNumber = wire.RevisionNumber
			out.Parent = wire.Parent
			sawInfo = true
		case "metadata":
			k, v, num, hasNum, ok := decodeMetadataLine(ln.Data)
			if !ok {
				continue
			}
			out.Metadata[k] = v
			if k == "timestamp" && hasNum {
				out.TimestampUnixMS = num
			}
		case "revisionInfoDelta":
			var wire struct {
				Path       string `json:"path"`
				FromPath   string `json:"fromPath"`
				Size       uint64 `json:"size"`
				Action     string `json:"action"`
				FlagModify bit    `json:"flagModify"`
				FlagMerged bit    `json:"flagMerged"`
				FlagFile   bit    `json:"flagFile"`
			}
			if err := json.Unmarshal(ln.Data, &wire); err != nil {
				return RevisionDetail{}, fmt.Errorf("%w: revisionInfoDelta decode failed", ErrOutput)
			}
			out.Deltas = append(out.Deltas, FileDelta{
				Path: wire.Path, FromPath: wire.FromPath, Size: wire.Size, Action: wire.Action,
				FlagModify: bool(wire.FlagModify), FlagMerged: bool(wire.FlagMerged), FlagFile: bool(wire.FlagFile),
			})
		}
	}
	if !sawInfo {
		return RevisionDetail{}, fmt.Errorf("%w: revisionInfo missing", ErrOutput)
	}
	return out, nil
}

func firstData(res loreexec.CommandResult, tag string) (json.RawMessage, bool) {
	all := allData(res, tag)
	if len(all) == 0 {
		return nil, false
	}
	return all[0], true
}

func allData(res loreexec.CommandResult, tag string) []json.RawMessage {
	var out []json.RawMessage
	for _, ln := range res.StdoutParse.Lines {
		if ln.TagName == tag && len(ln.Data) > 0 {
			out = append(out, ln.Data)
		}
	}
	return out
}

func findLink(links []Link, path string) (Link, bool) {
	for _, l := range links {
		if l.LinkPath == path {
			return l, true
		}
	}
	return Link{}, false
}

// bit accepts the 0/1 numbers from E5 and a JSON bool (link tracking was false).
type bit bool

func (b *bit) UnmarshalJSON(p []byte) error {
	p = bytes.TrimSpace(p)
	switch string(p) {
	case "1", "true":
		*b = true
	case "0", "false":
		*b = false
	default:
		return fmt.Errorf("bit %s", p)
	}
	return nil
}
