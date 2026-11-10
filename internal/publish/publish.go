// Package publish updates a project's parent repository pins.
//
// A snapshot is the module revisions captured at one moment. Later module
// HEAD moves do not change that set. SQLite records the attempt. It does not
// make the Lore push atomic. The publisher never syncs the parent between
// writing pins and committing, because a Lore sync can replace those pins.
// Two publishes of one project cannot run together: the operations table
// allows one running snapshot_publish.
package publish

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"lore-monorepo/internal/database"
)

var (
	ErrBusy        = errors.New("publish already running")
	ErrRemoteMoved = errors.New("parent remote revision changed")
	ErrChanged     = errors.New("module set changed during publish")
	ErrPush        = errors.New("push failed")
	ErrVerify      = errors.New("published pins do not match")
	ErrNeedsHuman  = errors.New("publish needs human review")
	ErrNoChange    = errors.New("publish: nothing to commit")
)

// Pin is one module link the parent must record.
type Pin struct {
	Name          string `json:"name"`
	MountPath     string `json:"mount_path"`
	RepositoryID  string `json:"repository_id"`
	RepositoryURL string `json:"repository_url"`
	Revision      string `json:"revision"`
}

// Request is one publish attempt.
type Request struct {
	ProjectID  int64
	ParentDir  string
	ModuleDirs map[string]string // module name -> working copy
	Actor      string
	Message    string
}

// Result is the verified parent revision and pins.
type Result struct {
	OperationID    int64
	ParentRevision string
	Pins           []Pin
}

// Driver talks to Lore working copies. Tests supply a fake.
type Driver interface {
	Revisions(ctx context.Context, dir string) (local, remote string, err error)
	Links(ctx context.Context, dir string) (map[string]string, error)
	EnsureLink(ctx context.Context, dir, mount, repoURL, revision string) error
	RemoveLink(ctx context.Context, dir, mount string) error
	Commit(ctx context.Context, dir, message string) error
	Push(ctx context.Context, dir string) error
	// FindOperation reports a parent revision whose commit message carries op=<id>
	// and the link pins at that revision. found is false when that commit is absent.
	FindOperation(ctx context.Context, dir string, operationID int64) (found bool, revision string, pins map[string]string, err error)
}

// Publisher serializes snapshot publication for one project.
type Publisher struct {
	DB     *sql.DB
	Driver Driver
	// AfterCapture runs after the pin set is stored. It must not change that set.
	// Tests use it to move module HEAD or archive a module before publish continues.
	AfterCapture func(context.Context) error
	// Halt is a crash-injection point. A non-nil hook may exit the process.
	// Steps: created, captured, links, committed, pushed, verified.
	Halt func(step string)
}

type manifest struct {
	ParentBaseRevision   string `json:"parent_base_revision"`
	ParentResultRevision string `json:"parent_result_revision,omitempty"`
	ManifestHash         string `json:"manifest_hash"`
	Pins                 []Pin  `json:"pins"`
}

type moduleRow struct {
	Name          string
	Mount         string
	RepositoryID  string
	RepositoryURL string
}

// Publish builds pins from active modules and pushes the parent.
func (p Publisher) Publish(ctx context.Context, req Request) (Result, error) {
	if req.Actor == "" || req.ParentDir == "" || req.ProjectID == 0 {
		return Result{}, errors.New("publish: incomplete request")
	}
	if req.Message == "" {
		req.Message = "publish module pins"
	}
	opID, err := p.begin(ctx, req)
	if err != nil {
		return Result{}, err
	}
	result, err := p.run(ctx, opID, req)
	if err != nil {
		_ = p.finish(ctx, opID, "failed", err.Error())
		return Result{}, err
	}
	if err := p.finish(ctx, opID, "succeeded", ""); err != nil {
		return Result{}, err
	}
	result.OperationID = opID
	return result, nil
}

// Recover inspects every running publish. A remote commit whose message carries
// the operation id and whose pins match the captured manifest is recorded as
// success. A publish that never left the capture step is marked interrupted.
// Anything already written locally but not found remotely is needs_human and
// is not pushed again.
func (p Publisher) Recover(ctx context.Context, parentDir func(projectID int64) (string, error)) error {
	rows, err := p.DB.QueryContext(ctx, `SELECT operation_id, project_id, request_json, progress
		FROM operations WHERE operation_type='snapshot_publish' AND status='running' ORDER BY operation_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type row struct {
		id      int64
		project int64
		raw     string
		step    string
	}
	var pending []row
	for rows.Next() {
		var item row
		var step sql.NullString
		if err := rows.Scan(&item.id, &item.project, &item.raw, &step); err != nil {
			return err
		}
		item.step = step.String
		pending = append(pending, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, item := range pending {
		if err := p.recoverOne(ctx, item.id, item.project, item.raw, item.step, parentDir); err != nil {
			return err
		}
	}
	return nil
}

func (p Publisher) recoverOne(ctx context.Context, id, projectID int64, raw, step string, parentDir func(int64) (string, error)) error {
	man, ok := decodeManifest(raw)
	if !ok || len(man.Pins) == 0 {
		return p.finish(ctx, id, "failed", "interrupted before capture")
	}
	dir, err := parentDir(projectID)
	if err != nil {
		return err
	}
	found, rev, pins, err := p.Driver.FindOperation(ctx, dir, id)
	if err != nil {
		if !found {
			return err
		}
		return p.finish(ctx, id, "failed", ErrNeedsHuman.Error()+": "+err.Error())
	}
	if found && pinsMatch(man.Pins, pins) {
		man.ParentResultRevision = rev
		body, _ := json.Marshal(man)
		if _, err := p.DB.ExecContext(ctx, `UPDATE operations SET request_json=? WHERE operation_id=?`, string(body), id); err != nil {
			return err
		}
		if err := p.insertSnapshot(ctx, projectID, id, rev, man.Pins); err != nil {
			return err
		}
		return p.finish(ctx, id, "succeeded", "")
	}
	switch step {
	case "", "created", "captured":
		return p.finish(ctx, id, "failed", "interrupted before push")
	default:
		return p.finish(ctx, id, "failed", ErrNeedsHuman.Error()+": remote publish for operation was not found")
	}
}

func (p Publisher) begin(ctx context.Context, req Request) (int64, error) {
	var id int64
	err := database.Tx(ctx, p.DB, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO operations(project_id, operation_type, status, request_json, requested_by)
			VALUES (?, 'snapshot_publish', 'running', '{}', ?)`, req.ProjectID, req.Actor)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return ErrBusy
			}
			return err
		}
		id, _ = res.LastInsertId()
		return database.Audit(ctx, tx, req.Actor, "snapshot_publish_start", fmt.Sprint(req.ProjectID), fmt.Sprint(id))
	})
	return id, err
}

func (p Publisher) run(ctx context.Context, opID int64, req Request) (Result, error) {
	p.halt("created")
	baseLocal, baseRemote, err := p.Driver.Revisions(ctx, req.ParentDir)
	if err != nil {
		return Result{}, err
	}
	if baseRemote != "" && baseRemote != baseLocal {
		return Result{}, ErrRemoteMoved
	}
	mods, err := p.active(ctx, req.ProjectID)
	if err != nil {
		return Result{}, err
	}
	captured, err := p.pins(ctx, req, mods)
	if err != nil {
		return Result{}, err
	}
	man := manifest{ParentBaseRevision: baseLocal, Pins: captured, ManifestHash: hashPins(captured)}
	if err := p.store(ctx, opID, "captured", man); err != nil {
		return Result{}, err
	}
	p.halt("captured")
	if p.AfterCapture != nil {
		if err := p.AfterCapture(ctx); err != nil {
			return Result{}, err
		}
	}
	existing, err := p.Driver.Links(ctx, req.ParentDir)
	if err != nil {
		return Result{}, err
	}
	keep := map[string]bool{}
	for _, pin := range captured {
		keep[pin.MountPath] = true
	}
	for mount := range existing {
		if keep[mount] {
			continue
		}
		if err := p.Driver.RemoveLink(ctx, req.ParentDir, mount); err != nil {
			return Result{}, err
		}
	}
	for _, pin := range captured {
		if err := p.Driver.EnsureLink(ctx, req.ParentDir, pin.MountPath, pin.RepositoryURL, pin.Revision); err != nil {
			return Result{}, err
		}
	}
	if err := p.touch(ctx, opID, "links"); err != nil {
		return Result{}, err
	}
	p.halt("links")
	message := fmt.Sprintf("%s op=%d manifest=%s", req.Message, opID, man.ManifestHash)
	unchanged := false
	if err := p.Driver.Commit(ctx, req.ParentDir, message); err != nil {
		if !errors.Is(err, ErrNoChange) {
			return Result{}, err
		}
		got, err := p.Driver.Links(ctx, req.ParentDir)
		if err != nil {
			return Result{}, err
		}
		if !pinsExact(captured, got) {
			return Result{}, ErrVerify
		}
		unchanged = true
	}
	if !unchanged {
		if err := p.touch(ctx, opID, "committed"); err != nil {
			return Result{}, err
		}
		p.halt("committed")
		if err := p.Driver.Push(ctx, req.ParentDir); err != nil {
			return Result{}, fmt.Errorf("%w: %v", ErrPush, err)
		}
		if err := p.touch(ctx, opID, "pushed"); err != nil {
			return Result{}, err
		}
		p.halt("pushed")
	}
	got, err := p.Driver.Links(ctx, req.ParentDir)
	if err != nil {
		return Result{}, err
	}
	if !pinsExact(captured, got) {
		return Result{}, ErrVerify
	}
	parentRev, _, err := p.Driver.Revisions(ctx, req.ParentDir)
	if err != nil {
		return Result{}, err
	}
	man.ParentResultRevision = parentRev
	if err := p.store(ctx, opID, "verified", man); err != nil {
		return Result{}, err
	}
	p.halt("verified")
	if err := p.insertSnapshot(ctx, req.ProjectID, opID, parentRev, captured); err != nil {
		return Result{}, err
	}
	return Result{ParentRevision: parentRev, Pins: captured}, nil
}

func (p Publisher) halt(step string) {
	if p.Halt != nil {
		p.Halt(step)
	}
}

func (p Publisher) store(ctx context.Context, id int64, step string, man manifest) error {
	raw, err := json.Marshal(man)
	if err != nil {
		return err
	}
	_, err = p.DB.ExecContext(ctx, `UPDATE operations SET request_json=?, progress=? WHERE operation_id=?`, string(raw), step, id)
	return err
}

func (p Publisher) touch(ctx context.Context, id int64, step string) error {
	_, err := p.DB.ExecContext(ctx, `UPDATE operations SET progress=? WHERE operation_id=?`, step, id)
	return err
}

func (p Publisher) insertSnapshot(ctx context.Context, projectID, opID int64, parentRev string, pins []Pin) error {
	raw, err := json.Marshal(pins)
	if err != nil {
		return err
	}
	var n int
	if err := p.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM snapshots WHERE operation_id=?`, opID).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	_, err = p.DB.ExecContext(ctx, `INSERT INTO snapshots(project_id, parent_revision, pins_json, description, operation_id, created_by)
		SELECT ?, ?, ?, ?, ?, user_id FROM users WHERE username=(SELECT requested_by FROM operations WHERE operation_id=?)`,
		projectID, parentRev, string(raw), "op="+fmt.Sprint(opID), opID, opID)
	if err == nil || !strings.Contains(err.Error(), "UNIQUE") {
		return err
	}
	var existing string
	qerr := p.DB.QueryRowContext(ctx, `SELECT pins_json FROM snapshots WHERE project_id=? AND parent_revision=?`, projectID, parentRev).Scan(&existing)
	if qerr != nil {
		return err
	}
	if !samePins(existing, raw) {
		return err
	}
	return nil
}

func (p Publisher) active(ctx context.Context, projectID int64) ([]moduleRow, error) {
	rows, err := p.DB.QueryContext(ctx, `SELECT name, mount_path, repository_id, repository_url
		FROM modules WHERE project_id=? AND archived_at IS NULL ORDER BY mount_path`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []moduleRow
	for rows.Next() {
		var m moduleRow
		if err := rows.Scan(&m.Name, &m.Mount, &m.RepositoryID, &m.RepositoryURL); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (p Publisher) pins(ctx context.Context, req Request, mods []moduleRow) ([]Pin, error) {
	out := make([]Pin, 0, len(mods))
	for _, m := range mods {
		dir := req.ModuleDirs[m.Name]
		if dir == "" {
			return nil, fmt.Errorf("publish: missing working copy for %s", m.Name)
		}
		rev, _, err := p.Driver.Revisions(ctx, dir)
		if err != nil {
			return nil, err
		}
		if rev == "" || strings.Trim(rev, "0") == "" {
			continue
		}
		out = append(out, Pin{Name: m.Name, MountPath: m.Mount, RepositoryID: m.RepositoryID, RepositoryURL: m.RepositoryURL, Revision: rev})
	}
	return out, nil
}

func (p Publisher) finish(ctx context.Context, id int64, status, reason string) error {
	_, err := p.DB.ExecContext(ctx, `UPDATE operations SET status=?, error=?, finished_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE operation_id=?`,
		status, reason, id)
	return err
}

func hashPins(pins []Pin) string {
	raw, _ := json.Marshal(pins)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func decodeManifest(raw string) (manifest, bool) {
	var man manifest
	if err := json.Unmarshal([]byte(raw), &man); err != nil || man.ManifestHash == "" {
		return manifest{}, false
	}
	return man, true
}

func samePins(existing string, raw []byte) bool {
	var a, b []Pin
	if json.Unmarshal([]byte(existing), &a) != nil || json.Unmarshal(raw, &b) != nil || len(a) != len(b) {
		return false
	}
	got := map[string]string{}
	for _, pin := range a {
		got[pin.MountPath] = pin.Revision
	}
	return pinsExact(b, got)
}

func pinsExact(want []Pin, got map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	return pinsMatch(want, got)
}

func pinsMatch(want []Pin, got map[string]string) bool {
	if len(got) < len(want) {
		return false
	}
	for _, pin := range want {
		if got[pin.MountPath] != pin.Revision {
			return false
		}
	}
	return true
}
