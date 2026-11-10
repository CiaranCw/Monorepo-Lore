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
	RepositoryID      string
	BranchID          string
	BranchName        string
	Revision          string
	RevisionNumber    int
	RevisionLocal     string
	RevisionRemote    string
	RemoteAvailable   bool
	RemoteAuthorized  bool
	RemoteBranchExist bool
	IsLocalAhead      bool
	IsRemoteAhead     bool
	Raw               json.RawMessage
}

// Link is one linkEntry object captured in E5 step M-3.
type Link struct {
	RepositoryID string
	LinkPath     string
	Revision     string
	Tracking     bool
	Raw          json.RawMessage
}

// HistoryEntry is one revisionHistoryEntry captured in E5 step M-4.
type HistoryEntry struct {
	Revision       string
	RevisionNumber int
	Parent         []string
	Raw            json.RawMessage
}

// Branch is a branchListEntry.
// NOT_VERIFIED against a P3-A capture; see ListBranches.
type Branch struct {
	ID        string
	Name      string
	Latest    string
	IsCurrent bool
	Raw       json.RawMessage
}

func decodeStatus(res loreexec.CommandResult) (Status, bool) {
	raw, ok := firstData(res, "repositoryStatusRevision")
	if !ok {
		return Status{}, false
	}
	var wire struct {
		Repository        string `json:"repository"`
		Branch            string `json:"branch"`
		BranchName        string `json:"branchName"`
		Revision          string `json:"revision"`
		RevisionNumber    int    `json:"revisionNumber"`
		RevisionLocal     string `json:"revisionLocal"`
		RevisionRemote    string `json:"revisionRemote"`
		RemoteAvailable   bit    `json:"remoteAvailable"`
		RemoteAuthorized  bit    `json:"remoteAuthorized"`
		RemoteBranchExist bit    `json:"remoteBranchExist"`
		IsLocalAhead      bit    `json:"isLocalAhead"`
		IsRemoteAhead     bit    `json:"isRemoteAhead"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil || wire.Repository == "" || wire.Revision == "" {
		return Status{}, false
	}
	return Status{
		RepositoryID: wire.Repository, BranchID: wire.Branch, BranchName: wire.BranchName,
		Revision: wire.Revision, RevisionNumber: wire.RevisionNumber,
		RevisionLocal: wire.RevisionLocal, RevisionRemote: wire.RevisionRemote,
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
	raws := allData(res, "revisionHistoryEntry")
	out := make([]HistoryEntry, 0, len(raws))
	for _, raw := range raws {
		var wire struct {
			Revision       string   `json:"revision"`
			RevisionNumber int      `json:"revisionNumber"`
			Parent         []string `json:"parent"`
		}
		if err := json.Unmarshal(raw, &wire); err != nil || wire.Revision == "" {
			return nil, fmt.Errorf("%w: revisionHistoryEntry did not match the captured fields", ErrOutput)
		}
		out = append(out, HistoryEntry{
			Revision: wire.Revision, RevisionNumber: wire.RevisionNumber, Parent: wire.Parent,
			Raw: append(json.RawMessage(nil), raw...),
		})
	}
	return out, nil
}

func decodeBranches(res loreexec.CommandResult) ([]Branch, error) {
	raws := allData(res, "branchListEntry")
	out := make([]Branch, 0, len(raws))
	for _, raw := range raws {
		var wire struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Latest    string `json:"latest"`
			IsCurrent bit    `json:"isCurrent"`
		}
		if err := json.Unmarshal(raw, &wire); err != nil || wire.Name == "" {
			return nil, fmt.Errorf("%w: branchListEntry did not match the source struct", ErrVerify)
		}
		out = append(out, Branch{
			ID: wire.ID, Name: wire.Name, Latest: wire.Latest, IsCurrent: bool(wire.IsCurrent),
			Raw: append(json.RawMessage(nil), raw...),
		})
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
