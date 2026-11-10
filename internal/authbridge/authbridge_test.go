package authbridge

import (
	"context"
	"database/sql"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"lore-monorepo/gen/epic_urc"
	"lore-monorepo/gen/ucs_auth"
	"lore-monorepo/internal/database"
	"lore-monorepo/internal/project"
	"lore-monorepo/internal/token"
	"lore-monorepo/internal/user"
)

const (
	repoA = "0123456789abcdef0123456789abcdef"
	repoB = "fedcba9876543210fedcba9876543210"
)

func TestAuthBridgeRPCsUseDatabaseGrants(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	tokens := openTokens(t)
	uid := makeUser(t, db, "alice", "correct-horse")
	moduleA := makeModule(t, db, uid, "alpha", "Engine", repoA, "Engine")
	_ = makeModule(t, db, uid, "alpha", "Client", repoB, "Client")
	if err := project.GrantModule(ctx, db, "test", uid, moduleA); err != nil {
		t.Fatal(err)
	}
	svc := New(UserDirectory{Get: func(ctx context.Context, id int64) (*user.User, error) {
		return user.GetByID(ctx, db, id)
	}}, tokens, tokens, NewStoreResolver(db))
	identity := mustIdentity(t, tokens, uid, "alice", 1)
	conn := grpcClient(t, svc)
	api := epic_urc.NewUrcAuthApiClient(conn)
	authCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+identity))

	health, err := api.HealthCheck(ctx, &epic_urc.HealthCheckRequest{})
	if err != nil || health.GetStatus() != "ok" {
		t.Fatalf("health %v %v", err, health)
	}
	checked, err := api.CheckUserPermission(authCtx, &epic_urc.CheckUserPermissionRequest{ResourceId: []string{"urc-" + repoA, "urc-" + repoB, "nope"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(checked.AllowedResourcePermission) != 1 || checked.AllowedResourcePermission[0].GetResourceId() != "urc-"+repoA {
		t.Fatalf("allowed %#v", checked.AllowedResourcePermission)
	}
	if len(checked.DeniedResourcePermission) != 2 {
		t.Fatalf("denied %#v", checked.DeniedResourcePermission)
	}
	listed, err := api.LookupUserPermissions(authCtx, &epic_urc.LookupUserPermissionsRequest{ResourceFilter: "urc"})
	if err != nil || len(listed.ResourcePermission) != 1 || listed.ResourcePermission[0].GetResourceId() != "urc-"+repoA {
		t.Fatalf("lookup %v %#v", err, listed.GetResourcePermission())
	}
	exchanged, err := api.ExchangeUserTokenForMultiresourceToken(authCtx, &epic_urc.ExchangeUserTokenForMultiresourceTokenRequest{ResourceId: []string{"urc-" + repoA, "urc-" + repoB}})
	if err != nil {
		t.Fatal(err)
	}
	access, err := tokens.VerifyAccess(exchanged.Token.GetUserToken())
	if err != nil || len(access.Resources) != 1 || access.Resources[0].ResourceID != "urc-"+repoA || access.AuthVersion != 1 {
		t.Fatalf("access %v %+v", err, access)
	}
	if access.Expires.After(time.Now().Add(6*time.Minute)) || access.Expires.Before(time.Now().Add(4*time.Minute)) {
		t.Fatalf("ttl %s", access.Expires)
	}
	infoCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+exchanged.Token.GetUserToken()))
	info, err := api.GetUserInfo(infoCtx, &epic_urc.GetUserInfoRequest{UserId: []string{"1", "99"}})
	if err != nil || len(info.UserInfo) != 1 || info.UserInfo[0].GetDisplayName() != "alice" {
		t.Fatalf("info %v %#v", err, info.GetUserInfo())
	}
	if _, err := api.ExchangeUserTokenForMultiresourceToken(authCtx, &epic_urc.ExchangeUserTokenForMultiresourceTokenRequest{ResourceId: []string{"urc-" + repoB}}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unauthorized exchange %v", err)
	}

	if err := user.SetStatus(ctx, db, "test", "alice", "disabled"); err != nil {
		t.Fatal(err)
	}
	if _, err := api.CheckUserPermission(authCtx, &epic_urc.CheckUserPermissionRequest{ResourceId: []string{"urc-" + repoA}}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("disabled %v", err)
	}
	if err := user.SetStatus(ctx, db, "test", "alice", "active"); err != nil {
		t.Fatal(err)
	}
	if _, err := api.CheckUserPermission(authCtx, &epic_urc.CheckUserPermissionRequest{ResourceId: []string{"urc-" + repoA}}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("re-enabled old token %v", err)
	}
	fresh := mustIdentity(t, tokens, uid, "alice", 2)
	freshCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+fresh))
	if _, err := api.CheckUserPermission(freshCtx, &epic_urc.CheckUserPermissionRequest{ResourceId: []string{"urc-" + repoA}}); err != nil {
		t.Fatal(err)
	}
	tokens.SetClock(func() time.Time { return time.Now().Add(13 * time.Hour) })
	if _, err := api.CheckUserPermission(freshCtx, &epic_urc.CheckUserPermissionRequest{ResourceId: []string{"urc-" + repoA}}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expired %v", err)
	}
	tokens.SetClock(time.Now)
	if _, err := api.CheckUserPermission(ctx, &epic_urc.CheckUserPermissionRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing token %v", err)
	}
	if _, err := api.CheckUserPermission(metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+exchanged.Token.GetUserToken())), &epic_urc.CheckUserPermissionRequest{ResourceId: []string{"urc-" + repoA}}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("access token used as identity %v", err)
	}
}

func TestCreateResourceDoesNotGrant(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	tokens := openTokens(t)
	uid := makeUser(t, db, "alice", "correct-horse")
	svc := New(UserDirectory{Get: func(ctx context.Context, id int64) (*user.User, error) {
		return user.GetByID(ctx, db, id)
	}}, tokens, tokens, NewStoreResolver(db))
	identity := mustIdentity(t, tokens, uid, "alice", 1)
	api := ucs_auth.NewRebacApiClient(grpcClient(t, svc))
	authCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+identity))
	if _, err := api.CreateResource(authCtx, &ucs_auth.CreateResourceRequest{
		ResourceId: "urc-" + repoA, ResourceName: "engine",
	}); err != nil {
		t.Fatal(err)
	}
	allowed, err := NewStoreResolver(db).Allows(ctx, uid, repoA)
	if err != nil || allowed {
		t.Fatalf("create resource granted access err=%v allowed=%v", err, allowed)
	}
	if _, err := api.CreateResource(ctx, &ucs_auth.CreateResourceRequest{ResourceId: "urc-" + repoA, ResourceName: "engine"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("anonymous create %v", err)
	}
	if _, err := api.CreateResource(authCtx, &ucs_auth.CreateResourceRequest{ResourceId: "not-a-repo", ResourceName: "engine"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad id %v", err)
	}
}

func TestConcurrentExchangeAndRotation(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	tokens := openTokens(t)
	uid := makeUser(t, db, "alice", "correct-horse")
	moduleA := makeModule(t, db, uid, "alpha", "Engine", repoA, "Engine")
	if err := project.GrantModule(ctx, db, "test", uid, moduleA); err != nil {
		t.Fatal(err)
	}
	svc := New(UserDirectory{Get: func(ctx context.Context, id int64) (*user.User, error) {
		return user.GetByID(ctx, db, id)
	}}, tokens, tokens, NewStoreResolver(db))
	identity := mustIdentity(t, tokens, uid, "alice", 1)
	var wg sync.WaitGroup
	errCh := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+identity))
			_, err := svc.ExchangeUserTokenForMultiresourceToken(ctx, &epic_urc.ExchangeUserTokenForMultiresourceTokenRequest{ResourceId: []string{"urc-" + repoA}})
			errCh <- err
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tokens.Rotate(); err != nil {
		t.Fatal(err)
	}
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+identity))
	if _, err := svc.CheckUserPermission(ctx, &epic_urc.CheckUserPermissionRequest{ResourceId: []string{"urc-" + repoA}}); err != nil {
		t.Fatalf("draining key rejected: %v", err)
	}
}

func TestResolverErrorDoesNotLeak(t *testing.T) {
	tokens := openTokens(t)
	db := openDB(t)
	uid := makeUser(t, db, "alice", "correct-horse")
	identity := mustIdentity(t, tokens, uid, "alice", 1)
	svc := New(UserDirectory{Get: func(ctx context.Context, id int64) (*user.User, error) {
		return user.GetByID(ctx, db, id)
	}}, tokens, tokens, StoreResolver{List: func(context.Context, int64) ([]string, error) {
		return nil, context.DeadlineExceeded
	}})
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+identity))
	_, err := svc.CheckUserPermission(ctx, &epic_urc.CheckUserPermissionRequest{ResourceId: []string{"urc-" + repoA}})
	if status.Code(err) != codes.Internal || (err != nil && len(err.Error()) > 80) {
		t.Fatalf("internal error leaked: %v", err)
	}
}

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "manager.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func openTokens(t *testing.T) *token.Service {
	t.Helper()
	dir := t.TempDir()
	svc, err := token.Open(token.Options{
		Issuer: "http://127.0.0.1:52010", Audience: []string{"127.0.0.1"},
		IdentityTTL: 12 * time.Hour, AccessTTL: 5 * time.Minute,
		PrivateKey: filepath.Join(dir, "k.pem"), PublicKey: filepath.Join(dir, "k.pub"), JWKS: filepath.Join(dir, "jwks.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func makeUser(t *testing.T, db *sql.DB, name, password string) int64 {
	t.Helper()
	id, err := user.Create(context.Background(), db, "test", name, password, "user")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func makeModule(t *testing.T, db *sql.DB, owner int64, projectName, module, repo, mount string) int64 {
	t.Helper()
	p, err := project.CreateProject(context.Background(), db, "test", project.Project{
		Name: projectName, ParentRepositoryID: repo[:30] + "aa", ParentRepositoryURL: "grpc://127.0.0.1:1/" + repo[:30] + "aa", CreatedBy: owner,
	})
	if err != nil && projectName != "alpha" {
		t.Fatal(err)
	}
	if p == nil {
		p, err = project.GetProject(context.Background(), db, "alpha")
		if err != nil {
			t.Fatal(err)
		}
	}
	m, err := project.CreateModule(context.Background(), db, "test", project.Module{
		ProjectID: p.ID, Name: module, RepositoryID: repo, RepositoryURL: "grpc://127.0.0.1:1/" + repo, MountPath: mount,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m.ID
}

func mustIdentity(t *testing.T, tokens *token.Service, id int64, name string, version int64) string {
	t.Helper()
	raw, err := tokens.IssueIdentity(itoa(id), name, version)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}

func grpcClient(t *testing.T, svc *Service) *grpc.ClientConn {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	epic_urc.RegisterUrcAuthApiServer(server, svc)
	ucs_auth.RegisterRebacApiServer(server, svc)
	go server.Serve(lis)
	t.Cleanup(server.Stop)
	conn, err := grpc.Dial(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}
