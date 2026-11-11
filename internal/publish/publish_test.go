package publish

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"lore-monorepo/internal/database"
	"lore-monorepo/internal/project"
	"lore-monorepo/internal/user"
)

func TestPublishSerialAndRecovery(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	uid, err := user.Create(ctx, db, "test", "carol", "correct-horse", "user")
	if err != nil {
		t.Fatal(err)
	}
	pr, err := project.CreateProject(ctx, db, "carol", project.Project{
		Name: "Alpha", ParentRepositoryID: "00112233445566778899aabbccddeeff",
		ParentRepositoryURL: "grpc://127.0.0.1:53547/alpha", CreatedBy: uid,
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := project.CreateModule(ctx, db, "carol", project.Module{
		ProjectID: pr.ID, Name: "Engine", RepositoryID: "0123456789abcdef0123456789abcdef",
		RepositoryURL: "grpc://127.0.0.1:53547/engine", MountPath: "Engine",
	})
	if err != nil {
		t.Fatal(err)
	}
	drv := newMem()
	pub := Publisher{DB: db, Driver: drv}
	req := Request{ProjectID: pr.ID, ParentDir: "parent", ModuleDirs: map[string]string{"Engine": "engine"}, Actor: "carol"}
	got, err := pub.Publish(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if got.ParentRevision != "rev-parent-2" || len(got.Pins) != 1 || got.Pins[0].Revision != "rev-engine-1" {
		t.Fatalf("%+v", got)
	}
	if drv.link("Engine") != "rev-engine-1" || drv.pushCount() != 1 {
		t.Fatalf("link=%s pushes=%d", drv.link("Engine"), drv.pushCount())
	}
	drv.setLocal("engine", "")
	if _, err := pub.Publish(ctx, req); err == nil || !strings.Contains(err.Error(), "has no capturable revision") {
		t.Fatalf("active module with empty revision produced incomplete snapshot: %v", err)
	}
	drv.setLocal("engine", "rev-engine-1")

	hold := make(chan struct{})
	drv.setBlock(hold)
	errCh := make(chan error, 1)
	go func() {
		_, err := pub.Publish(ctx, req)
		errCh <- err
	}()
	<-drv.entered
	if _, err := pub.Publish(ctx, req); !errors.Is(err, ErrBusy) {
		t.Fatalf("concurrent %v", err)
	}
	close(hold)
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	drv.setBlock(nil)

	drv.failPush = true
	if _, err := pub.Publish(ctx, req); !errors.Is(err, ErrPush) {
		t.Fatalf("push %v", err)
	}
	drv.failPush = false
	drv.setRemote("parent", "rev-other")
	if _, err := pub.Publish(ctx, req); !errors.Is(err, ErrRemoteMoved) {
		t.Fatalf("remote %v", err)
	}
	drv.setRemote("parent", drv.localOf("parent"))

	pub.AfterCapture = func(context.Context) error {
		drv.setLocal("engine", "rev-engine-2")
		return nil
	}
	frozen, err := pub.Publish(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if frozen.Pins[0].Revision != "rev-engine-1" {
		t.Fatalf("capture changed to %s", frozen.Pins[0].Revision)
	}
	pub.AfterCapture = func(ctx context.Context) error {
		return project.ArchiveModule(ctx, db, "carol", engine.ID)
	}
	archived, err := pub.Publish(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(archived.Pins) != 1 || archived.Pins[0].Name != "Engine" {
		t.Fatalf("captured pin lost on archive %+v", archived.Pins)
	}
	pub.AfterCapture = nil
	if _, err := pub.Publish(ctx, req); err != nil {
		t.Fatal(err)
	}

	opID, err := pub.begin(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Recover(ctx, func(int64) (string, error) { return "parent", nil }); err != nil {
		t.Fatal(err)
	}
	var status, reason string
	if err := db.QueryRow(`SELECT status, error FROM operations WHERE operation_id=?`, opID).Scan(&status, &reason); err != nil || status != "failed" || reason != "interrupted before capture" {
		t.Fatalf("recover %s %s %v", status, reason, err)
	}
	if _, err := pub.Publish(ctx, req); err != nil {
		t.Fatalf("after recover %v", err)
	}
}

func TestRecoverAfterPushKeepsSuccess(t *testing.T) {
	ctx := context.Background()
	db, drv, pub, req := newPublishTest(t)
	pub.Halt = func(step string) {
		if step == "pushed" {
			panic("injected crash after push")
		}
	}
	func() {
		defer func() { _ = recover() }()
		_, _ = pub.Publish(ctx, req)
	}()
	pushes := drv.pushCount()
	pub.Halt = nil
	if err := pub.Recover(ctx, func(int64) (string, error) { return req.ParentDir, nil }); err != nil {
		t.Fatal(err)
	}
	if drv.pushCount() != pushes {
		t.Fatal("recovery pushed again")
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM operations ORDER BY operation_id DESC LIMIT 1`).Scan(&status); err != nil || status != "succeeded" {
		t.Fatalf("status %s %v", status, err)
	}
	var snapshots int
	if err := db.QueryRow(`SELECT COUNT(*) FROM snapshots`).Scan(&snapshots); err != nil || snapshots != 1 {
		t.Fatalf("snapshots %d %v", snapshots, err)
	}
	if err := pub.Recover(ctx, func(int64) (string, error) { return req.ParentDir, nil }); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverRejectsPublishedRevisionWithExtraLinks(t *testing.T) {
	ctx := context.Background()
	db, drv, pub, req := newPublishTest(t)
	pub.Halt = func(step string) {
		if step == "pushed" {
			panic("injected crash after push")
		}
	}
	func() {
		defer func() { _ = recover() }()
		_, _ = pub.Publish(ctx, req)
	}()
	drv.mu.Lock()
	drv.published[len(drv.published)-1].links["Unexpected"] = "rev-other-project"
	drv.mu.Unlock()
	pub.Halt = nil
	if err := pub.Recover(ctx, func(int64) (string, error) { return req.ParentDir, nil }); err != nil {
		t.Fatal(err)
	}
	var status, reason string
	if err := db.QueryRow(`SELECT status, error FROM operations ORDER BY operation_id DESC LIMIT 1`).Scan(&status, &reason); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || !strings.Contains(reason, ErrNeedsHuman.Error()) {
		t.Fatalf("recovery accepted extra parent links: status=%s reason=%s", status, reason)
	}
}

func newPublishTest(t *testing.T) (*sql.DB, *memDriver, Publisher, Request) {
	t.Helper()
	ctx := context.Background()
	db, err := database.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	uid, err := user.Create(ctx, db, "test", "carol", "correct-horse", "user")
	if err != nil {
		t.Fatal(err)
	}
	pr, err := project.CreateProject(ctx, db, "carol", project.Project{
		Name: "Alpha", ParentRepositoryID: "00112233445566778899aabbccddeeff",
		ParentRepositoryURL: "grpc://127.0.0.1:53547/alpha", CreatedBy: uid,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := project.CreateModule(ctx, db, "carol", project.Module{
		ProjectID: pr.ID, Name: "Engine", RepositoryID: "0123456789abcdef0123456789abcdef",
		RepositoryURL: "grpc://127.0.0.1:53547/engine", MountPath: "Engine",
	}); err != nil {
		t.Fatal(err)
	}
	drv := newMem()
	return db, drv, Publisher{DB: db, Driver: drv}, Request{ProjectID: pr.ID, ParentDir: "parent", ModuleDirs: map[string]string{"Engine": "engine"}, Actor: "carol"}
}

type memDriver struct {
	mu        sync.Mutex
	local     map[string]string
	remote    map[string]string
	links     map[string]string
	pushes    int
	message   string
	published []memPublish
	failPush  bool
	blockPush chan struct{}
	entered   chan struct{}
	next      int
}

func newMem() *memDriver {
	return &memDriver{
		local:   map[string]string{"parent": "rev-parent-1", "engine": "rev-engine-1"},
		remote:  map[string]string{"parent": "rev-parent-1"},
		links:   map[string]string{},
		entered: make(chan struct{}, 1),
		next:    1,
	}
}

func (m *memDriver) Revisions(_ context.Context, dir string) (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.local[dir], m.remote[dir], nil
}

func (m *memDriver) Links(context.Context, string) (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]string{}
	for k, v := range m.links {
		out[k] = v
	}
	return out, nil
}

func (m *memDriver) EnsureLink(_ context.Context, _, mount, _, revision string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.links[mount] = revision
	return nil
}

func (m *memDriver) RemoveLink(_ context.Context, _, mount string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.links, mount)
	return nil
}

func (m *memDriver) Commit(_ context.Context, _, message string) error {
	m.mu.Lock()
	m.message = message
	m.mu.Unlock()
	return nil
}

func (m *memDriver) Push(context.Context, string) error {
	m.mu.Lock()
	block := m.blockPush
	m.mu.Unlock()
	if block != nil {
		select {
		case m.entered <- struct{}{}:
		default:
		}
		<-m.blockPush
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failPush {
		return errors.New("network")
	}
	m.next++
	rev := "rev-parent-" + itoa(m.next)
	m.local["parent"] = rev
	m.remote["parent"] = rev
	m.pushes++
	copied := map[string]string{}
	for k, v := range m.links {
		copied[k] = v
	}
	m.published = append(m.published, memPublish{message: m.message, revision: rev, links: copied})
	return nil
}

func (m *memDriver) FindOperation(_ context.Context, _ string, operationID int64) (bool, string, map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	needle := fmt.Sprintf("op=%d ", operationID)
	for _, item := range m.published {
		if strings.Contains(item.message, needle) || strings.HasSuffix(item.message, fmt.Sprintf("op=%d", operationID)) {
			return true, item.revision, item.links, nil
		}
	}
	return false, "", nil, nil
}

func (m *memDriver) setBlock(ch chan struct{}) {
	m.mu.Lock()
	m.blockPush = ch
	m.mu.Unlock()
}

func (m *memDriver) setLocal(dir, rev string) {
	m.mu.Lock()
	m.local[dir] = rev
	m.mu.Unlock()
}

func (m *memDriver) setRemote(dir, rev string) {
	m.mu.Lock()
	m.remote[dir] = rev
	m.mu.Unlock()
}

func (m *memDriver) localOf(dir string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.local[dir]
}

func (m *memDriver) link(path string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.links[path]
}

func (m *memDriver) pushCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pushes
}

type memPublish struct {
	message  string
	revision string
	links    map[string]string
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
