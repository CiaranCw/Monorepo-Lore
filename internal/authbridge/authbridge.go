// Package authbridge is the Lore 0.10.1 UrcAuthApi implementation.
//
// Identity checks match GET /api/v1/auth/me: signature, expiry, active user,
// auth_version, and preferred_username. Repository grants come from the
// PermissionResolver, not from claims inside the identity token.
package authbridge

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"lore-monorepo/gen/epic_urc"
	"lore-monorepo/gen/ucs_auth"
	"lore-monorepo/internal/token"
	"lore-monorepo/internal/user"
)

// ErrUnauthenticated means the bearer token or the account is not usable.
var ErrUnauthenticated = errors.New("unauthenticated")

// ErrDenied means the caller is authenticated but may not exchange the request.
var ErrDenied = errors.New("not permitted")

// Directory loads accounts. *sql.DB is not used directly.
type Directory interface {
	GetByID(ctx context.Context, id int64) (*user.User, error)
}

// IdentityChecker verifies identity tokens. *token.Service satisfies it.
type IdentityChecker interface {
	VerifyIdentity(raw string) (token.IdentityClaims, error)
}

// AccessChecker verifies access tokens.
type AccessChecker interface {
	VerifyAccess(raw string) (token.AccessClaims, error)
	IssueAccess(subject string, authVersion int64, resources []token.Resource) (string, error)
}

// Resolver answers which repositories a user may reach right now.
type Resolver interface {
	Repositories(ctx context.Context, userID int64) ([]string, error)
	Allows(ctx context.Context, userID int64, repositoryID string) (bool, error)
}

// Service implements the RPCs Lore Server and the Lore client actually call.
type Service struct {
	epic_urc.UnimplementedUrcAuthApiServer
	ucs_auth.UnimplementedRebacApiServer
	users     Directory
	identity  IdentityChecker
	access    AccessChecker
	permits   Resolver
	exchanges atomic.Int64
	mu        sync.Mutex
	calls     []CallRecord
}

// CallRecord is a redacted RPC trace. It never contains a token or a password.
type CallRecord struct {
	At        string `json:"at"`
	RPC       string `json:"rpc"`
	OK        bool   `json:"ok"`
	RequestN  int    `json:"request_resources"`
	ResponseN int    `json:"response_resources"`
	Code      string `json:"code"`
}

// New builds an AuthBridge. All dependencies are explicit.
func New(users Directory, identity IdentityChecker, access AccessChecker, permits Resolver) *Service {
	return &Service{users: users, identity: identity, access: access, permits: permits}
}

// Session is an identity token that matches the current user row.
type Session struct {
	User   *user.User
	Claims token.IdentityClaims
}

// AuthenticateIdentity is the shared check used by HTTP /auth/me and gRPC.
func AuthenticateIdentity(ctx context.Context, checker IdentityChecker, users Directory, raw string) (Session, error) {
	claims, err := checker.VerifyIdentity(raw)
	if err != nil {
		return Session{}, ErrUnauthenticated
	}
	account, err := loadMatchingUser(ctx, users, claims.Subject, claims.AuthVersion, claims.PreferredUsername)
	if err != nil {
		return Session{}, err
	}
	return Session{User: account, Claims: claims}, nil
}

func loadMatchingUser(ctx context.Context, users Directory, subject string, version int64, username string) (*user.User, error) {
	id, err := strconv.ParseInt(subject, 10, 64)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	account, err := users.GetByID(ctx, id)
	if err != nil || account == nil || account.Status != "active" || account.AuthVersion != version {
		return nil, ErrUnauthenticated
	}
	if username != "" && account.Username != username {
		return nil, ErrUnauthenticated
	}
	return account, nil
}

func (s *Service) HealthCheck(context.Context, *epic_urc.HealthCheckRequest) (*epic_urc.HealthCheckResponse, error) {
	return &epic_urc.HealthCheckResponse{Status: "ok"}, nil
}

// CreateResource acknowledges the repository Lore just created.
// Lore Server calls this before RepositoryCreate can succeed. It checks the
// caller is a live identity and does not write a module grant.
func (s *Service) CreateResource(ctx context.Context, req *ucs_auth.CreateResourceRequest) (*ucs_auth.CreateResourceResponse, error) {
	if _, err := s.identitySession(ctx); err != nil {
		err = grpcAuth(err)
		s.record("CreateResource", 1, 0, err)
		return nil, err
	}
	if _, ok := repositoryID(req.GetResourceId()); !ok || strings.TrimSpace(req.GetResourceName()) == "" {
		err := status.Error(codes.InvalidArgument, "invalid resource")
		s.record("CreateResource", 1, 0, err)
		return nil, err
	}
	s.record("CreateResource", 1, 0, nil)
	return &ucs_auth.CreateResourceResponse{}, nil
}

func (s *Service) CheckUserPermission(ctx context.Context, req *epic_urc.CheckUserPermissionRequest) (*epic_urc.CheckUserPermissionResponse, error) {
	session, err := s.identitySession(ctx)
	if err != nil {
		err = grpcAuth(err)
		s.record("CheckUserPermission", len(req.GetResourceId()), 0, err)
		return nil, err
	}
	out := &epic_urc.CheckUserPermissionResponse{}
	var callErr error
	defer func() {
		s.record("CheckUserPermission", len(req.GetResourceId()), len(out.GetAllowedResourcePermission()), callErr)
	}()
	for _, resourceID := range req.GetResourceId() {
		entry := &epic_urc.ResourcePermission{ResourceId: resourceID, Permission: []string{"access"}}
		repo, ok := repositoryID(resourceID)
		if !ok {
			out.DeniedResourcePermission = append(out.DeniedResourcePermission, entry)
			continue
		}
		allowed, err := s.permits.Allows(ctx, session.User.ID, repo)
		if err != nil {
			callErr = status.Error(codes.Internal, "authbridge unavailable")
			return nil, callErr
		}
		if allowed {
			out.AllowedResourcePermission = append(out.AllowedResourcePermission, entry)
		} else {
			out.DeniedResourcePermission = append(out.DeniedResourcePermission, entry)
		}
	}
	return out, nil
}

func (s *Service) LookupUserPermissions(ctx context.Context, req *epic_urc.LookupUserPermissionsRequest) (*epic_urc.LookupUserPermissionsResponse, error) {
	session, err := s.identitySession(ctx)
	var callErr error
	var responseN int
	defer func() { s.record("LookupUserPermissions", 0, responseN, callErr) }()
	if err != nil {
		callErr = grpcAuth(err)
		return nil, callErr
	}
	if req.GetResourceFilter() != "" && req.GetResourceFilter() != "urc" {
		return &epic_urc.LookupUserPermissionsResponse{}, nil
	}
	repos, err := s.permits.Repositories(ctx, session.User.ID)
	if err != nil {
		callErr = status.Error(codes.Internal, "authbridge unavailable")
		return nil, callErr
	}
	page, next := pageResources(repos, int(req.GetPageSize()), req.GetPageToken())
	responseN = len(page)
	out := &epic_urc.LookupUserPermissionsResponse{}
	for _, id := range page {
		out.ResourcePermission = append(out.ResourcePermission, &epic_urc.ResourcePermission{
			ResourceId: "urc-" + id,
			Permission: []string{"access"},
		})
	}
	if next != "" {
		out.NextPageToken = &next
	}
	return out, nil
}

func (s *Service) GetUserInfo(ctx context.Context, req *epic_urc.GetUserInfoRequest) (*epic_urc.GetUserInfoResponse, error) {
	var callErr error
	out := &epic_urc.GetUserInfoResponse{}
	defer func() { s.record("GetUserInfo", len(req.GetUserId()), len(out.GetUserInfo()), callErr) }()
	if _, err := s.caller(ctx); err != nil {
		callErr = grpcAuth(err)
		return nil, callErr
	}
	for _, rawID := range req.GetUserId() {
		id, err := strconv.ParseInt(rawID, 10, 64)
		if err != nil {
			continue
		}
		account, err := s.users.GetByID(ctx, id)
		if err != nil || account == nil || account.Status != "active" {
			continue
		}
		out.UserInfo = append(out.UserInfo, &epic_urc.UserInfo{
			UserId:      strconv.FormatInt(account.ID, 10),
			DisplayName: account.Username,
		})
	}
	return out, nil
}

// Exchanges counts ExchangeUserTokenForMultiresourceToken calls that passed identity checks.
func (s *Service) Exchanges() int64 {
	return s.exchanges.Load()
}

// Calls returns the redacted RPC trace.
func (s *Service) Calls() []CallRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]CallRecord, len(s.calls))
	copy(out, s.calls)
	return out
}

func (s *Service) record(rpc string, requestN, responseN int, err error) {
	code := "ok"
	if err != nil {
		code = status.Code(err).String()
		if code == "OK" {
			code = "error"
		}
	}
	s.mu.Lock()
	s.calls = append(s.calls, CallRecord{
		At: time.Now().UTC().Format(time.RFC3339Nano), RPC: rpc, OK: err == nil,
		RequestN: requestN, ResponseN: responseN, Code: code,
	})
	s.mu.Unlock()
}

func (s *Service) ExchangeUserTokenForMultiresourceToken(ctx context.Context, req *epic_urc.ExchangeUserTokenForMultiresourceTokenRequest) (*epic_urc.ExchangeUserTokenForMultiresourceTokenResponse, error) {
	session, err := s.identitySession(ctx)
	if err == nil {
		s.exchanges.Add(1)
	}
	if err != nil {
		err = grpcAuth(err)
		s.record("ExchangeUserTokenForMultiresourceToken", len(req.GetResourceId()), 0, err)
		return nil, err
	}
	var resources []token.Resource
	for _, resourceID := range req.GetResourceId() {
		repo, ok := repositoryID(resourceID)
		if !ok {
			continue
		}
		allowed, err := s.permits.Allows(ctx, session.User.ID, repo)
		if err != nil {
			err = status.Error(codes.Internal, "authbridge unavailable")
			s.record("ExchangeUserTokenForMultiresourceToken", len(req.GetResourceId()), 0, err)
			return nil, err
		}
		if !allowed {
			continue
		}
		resources = append(resources, token.Resource{ResourceID: "urc-" + repo, Permission: []string{"access"}})
	}
	if len(resources) == 0 {
		err := status.Error(codes.PermissionDenied, "not permitted")
		s.record("ExchangeUserTokenForMultiresourceToken", len(req.GetResourceId()), 0, err)
		return nil, err
	}
	signed, err := s.access.IssueAccess(strconv.FormatInt(session.User.ID, 10), session.User.AuthVersion, resources)
	if err != nil {
		err = status.Error(codes.Internal, "authbridge unavailable")
		s.record("ExchangeUserTokenForMultiresourceToken", len(req.GetResourceId()), 0, err)
		return nil, err
	}
	s.record("ExchangeUserTokenForMultiresourceToken", len(req.GetResourceId()), len(resources), nil)
	claims, err := s.access.VerifyAccess(signed)
	if err != nil {
		return nil, status.Error(codes.Internal, "authbridge unavailable")
	}
	return &epic_urc.ExchangeUserTokenForMultiresourceTokenResponse{
		Token: &epic_urc.UserToken{
			UserToken: signed,
			ExpiresAt: claims.Expires.Unix(),
			UserId:    strconv.FormatInt(session.User.ID, 10),
			UserName:  session.User.Username,
		},
	}, nil
}

func (s *Service) identitySession(ctx context.Context) (Session, error) {
	raw := bearer(ctx)
	if raw == "" {
		return Session{}, ErrUnauthenticated
	}
	return AuthenticateIdentity(ctx, s.identity, s.users, raw)
}

// caller accepts the identity token Lore sends to repository calls, or the
// access token the Lore client sends to GetUserInfo.
func (s *Service) caller(ctx context.Context) (*user.User, error) {
	raw := bearer(ctx)
	if raw == "" {
		return nil, ErrUnauthenticated
	}
	if session, err := AuthenticateIdentity(ctx, s.identity, s.users, raw); err == nil {
		return session.User, nil
	}
	claims, err := s.access.VerifyAccess(raw)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	return loadMatchingUser(ctx, s.users, claims.Subject, claims.AuthVersion, "")
}

func bearer(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	values := md.Get("authorization")
	if len(values) == 0 {
		return ""
	}
	header := values[0]
	const prefix = "Bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

func repositoryID(resource string) (string, bool) {
	id := strings.TrimPrefix(resource, "urc-")
	if len(id) != 32 || id == resource {
		return "", false
	}
	for _, c := range id {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return "", false
		}
	}
	return id, true
}

func pageResources(repos []string, pageSize int, pageToken string) ([]string, string) {
	start := 0
	if pageToken != "" {
		found := false
		for i, id := range repos {
			if id == pageToken {
				start = i + 1
				found = true
			}
		}
		if !found {
			return nil, ""
		}
	}
	rest := repos[start:]
	if pageSize <= 0 || pageSize >= len(rest) {
		return rest, ""
	}
	page := rest[:pageSize]
	return page, page[len(page)-1]
}

func grpcAuth(err error) error {
	if errors.Is(err, ErrDenied) {
		return status.Error(codes.PermissionDenied, "not permitted")
	}
	if errors.Is(err, ErrUnauthenticated) {
		return status.Error(codes.Unauthenticated, "unauthenticated")
	}
	return status.Error(codes.Internal, "authbridge unavailable")
}
