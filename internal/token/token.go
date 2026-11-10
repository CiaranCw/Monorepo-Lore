// Package token signs and verifies Manager JWTs.
//
// Lore Server verifies iss, aud, exp, and resources. It does not understand
// auth_version or token_use. Those claims are enforced here, when Manager
// code calls Verify. This package does not listen on a port and does not
// decide whether a user is still allowed to receive a new token.
package token

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	useIdentity = "identity"
	useAccess   = "access"
	permAccess  = "access"
)

// ErrRejected means a token must not be accepted. The text names a category
// and never includes the token, the signature, or a key.
var ErrRejected = errors.New("token rejected")

// ErrKeys means the signing files cannot be used. The text never includes
// key bytes.
var ErrKeys = errors.New("signing keys")

// Options selects the issuer, audience, lifetimes, and key files.
type Options struct {
	Issuer      string
	Audience    []string
	IdentityTTL time.Duration
	AccessTTL   time.Duration
	PrivateKey  string
	PublicKey   string
	JWKS        string
}

func (o Options) validate() error {
	if o.Issuer == "" || len(o.Audience) == 0 || o.IdentityTTL <= 0 || o.AccessTTL <= 0 {
		return keyErr("token options are incomplete")
	}
	if o.PrivateKey == "" || o.PublicKey == "" || o.JWKS == "" {
		return keyErr("token key paths are incomplete")
	}
	return nil
}

// Resource is one Lore 0.10.1 grant entry.
type Resource struct {
	ResourceID string   `json:"resource_id"`
	Permission []string `json:"permission"`
}

// IdentityClaims is a verified identity token.
type IdentityClaims struct {
	Subject           string
	PreferredUsername string
	AuthVersion       int64
	Expires           time.Time
	KID               string
}

// AccessClaims is a verified access token.
type AccessClaims struct {
	Subject     string
	AuthVersion int64
	Resources   []Resource
	Expires     time.Time
	KID         string
}

// Issuer is the surface a future AuthBridge can call. B2.1 does not start
// that server.
type Issuer interface {
	IssueIdentity(subject, username string, authVersion int64) (string, error)
	IssueAccess(subject string, authVersion int64, resources []Resource) (string, error)
	VerifyIdentity(raw string) (IdentityClaims, error)
	VerifyAccess(raw string) (AccessClaims, error)
}

// Service holds the active signer and the public keys still accepted.
type Service struct {
	mu        sync.Mutex
	opt       Options
	statePath string
	now       func() time.Time
	active    *rsa.PrivateKey
	activeKID string
	verify    map[string]*rsa.PublicKey
	state     keyFile
}

var _ Issuer = (*Service)(nil)

var (
	subjectPattern  = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
	namePattern     = regexp.MustCompile(`^[a-z][a-z0-9._-]{1,62}$`)
	resourcePattern = regexp.MustCompile(`^urc-[0-9a-f]{32}$`)
)

// Open loads the key files, or creates them when none of the key files exist.
// A partial or damaged set is returned as an error and is never replaced.
func Open(opt Options) (*Service, error) {
	return openOrCreate(opt)
}

func newService(opt Options, statePath string, active *rsa.PrivateKey, kid string, pubs map[string]*rsa.PublicKey, state keyFile) *Service {
	return &Service{
		opt:       opt,
		statePath: statePath,
		now:       time.Now,
		active:    active,
		activeKID: kid,
		verify:    pubs,
		state:     state,
	}
}

// SetClock replaces the clock used for expiry. Tests use it. Production does not.
func (s *Service) SetClock(now func() time.Time) {
	if now == nil {
		now = time.Now
	}
	s.mu.Lock()
	s.now = now
	s.mu.Unlock()
}

// ActiveKID is the key used to sign new tokens.
func (s *Service) ActiveKID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeKID
}

// Keys returns the recorded key states. Retired keys remain listed so a
// restart can keep refusing them.
func (s *Service) Keys() []KeyInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]KeyInfo, len(s.state.Keys))
	for i, rec := range s.state.Keys {
		out[i] = KeyInfo{KID: rec.KID, State: rec.State}
	}
	return out
}

// Rotate creates a new active key and moves the previous active key to draining.
func (s *Service) Rotate() (KeyInfo, error) {
	return s.rotate()
}

// Retire stops accepting a draining key. The active key cannot be retired.
func (s *Service) Retire(kid string) error {
	return s.retire(kid)
}

// IssueIdentity signs an identity token. It has no resources claim.
func (s *Service) IssueIdentity(subject, username string, authVersion int64) (string, error) {
	if !subjectPattern.MatchString(subject) || !namePattern.MatchString(username) || authVersion < 1 {
		return "", claimErr("claims")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	claims := jwt.MapClaims{
		"iss":                s.opt.Issuer,
		"sub":                subject,
		"aud":                append([]string(nil), s.opt.Audience...),
		"iat":                now.Unix(),
		"exp":                now.Add(s.opt.IdentityTTL).Unix(),
		"preferred_username": username,
		"auth_version":       authVersion,
		"token_use":          useIdentity,
	}
	return s.signLocked(claims)
}

// IssueAccess signs an access token. permission is only the Lore reachability
// marker "access". It is not a read or write distinction.
func (s *Service) IssueAccess(subject string, authVersion int64, resources []Resource) (string, error) {
	if !subjectPattern.MatchString(subject) || authVersion < 1 {
		return "", claimErr("claims")
	}
	if err := validateResources(resources); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	copied := append([]Resource(nil), resources...)
	claims := jwt.MapClaims{
		"iss":          s.opt.Issuer,
		"sub":          subject,
		"aud":          append([]string(nil), s.opt.Audience...),
		"iat":          now.Unix(),
		"exp":          now.Add(s.opt.AccessTTL).Unix(),
		"auth_version": authVersion,
		"token_use":    useAccess,
		"resources":    copied,
	}
	return s.signLocked(claims)
}

func (s *Service) signRaw(method jwt.SigningMethod, kid string, claims jwt.MapClaims) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if method == nil {
		method = jwt.SigningMethodRS256
	}
	tok := jwt.NewWithClaims(method, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	var key any = s.active
	if method.Alg() == jwt.SigningMethodHS256.Alg() {
		key = []byte("test-secret")
	}
	signed, err := tok.SignedString(key)
	if err != nil {
		return "", claimErr("signature")
	}
	return signed, nil
}

func (s *Service) signLocked(claims jwt.MapClaims) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = s.activeKID
	signed, err := tok.SignedString(s.active)
	if err != nil {
		return "", claimErr("signature")
	}
	return signed, nil
}

// VerifyIdentity accepts only an identity token.
func (s *Service) VerifyIdentity(raw string) (IdentityClaims, error) {
	payload, kid, err := s.verifyCommon(raw, useIdentity)
	if err != nil {
		return IdentityClaims{}, err
	}
	if _, ok := payload["resources"]; ok {
		return IdentityClaims{}, claimErr("type")
	}
	name, _ := payload["preferred_username"].(string)
	if !namePattern.MatchString(name) {
		return IdentityClaims{}, claimErr("claims")
	}
	version, err := integerClaim(payload["auth_version"])
	if err != nil {
		return IdentityClaims{}, err
	}
	return IdentityClaims{
		Subject:           payload["sub"].(string),
		PreferredUsername: name,
		AuthVersion:       version,
		Expires:           expTime(payload["exp"]),
		KID:               kid,
	}, nil
}

// VerifyAccess accepts only an access token.
func (s *Service) VerifyAccess(raw string) (AccessClaims, error) {
	payload, kid, err := s.verifyCommon(raw, useAccess)
	if err != nil {
		return AccessClaims{}, err
	}
	rawResources, ok := payload["resources"]
	if !ok {
		return AccessClaims{}, claimErr("type")
	}
	resources, err := decodeResources(rawResources)
	if err != nil {
		return AccessClaims{}, err
	}
	version, err := integerClaim(payload["auth_version"])
	if err != nil {
		return AccessClaims{}, err
	}
	return AccessClaims{
		Subject:     payload["sub"].(string),
		AuthVersion: version,
		Resources:   resources,
		Expires:     expTime(payload["exp"]),
		KID:         kid,
	}, nil
}

func (s *Service) verifyCommon(raw string, wantUse string) (map[string]any, string, error) {
	header, payloadBytes, err := splitToken(raw)
	if err != nil {
		return nil, "", err
	}
	alg, _ := header["alg"].(string)
	if alg != jwt.SigningMethodRS256.Alg() {
		return nil, "", claimErr("alg")
	}
	kid, _ := header["kid"].(string)
	if kid == "" {
		return nil, "", claimErr("kid")
	}
	s.mu.Lock()
	pub := s.verify[kid]
	issuer := s.opt.Issuer
	audience := append([]string(nil), s.opt.Audience...)
	now := s.now
	s.mu.Unlock()
	if pub == nil {
		return nil, "", claimErr("kid")
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithoutClaimsValidation(),
	)
	parsed, err := parser.Parse(raw, func(t *jwt.Token) (any, error) {
		if t.Method == nil || t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, claimErr("alg")
		}
		got, _ := t.Header["kid"].(string)
		if got != kid {
			return nil, claimErr("kid")
		}
		return pub, nil
	})
	if err != nil || parsed == nil || !parsed.Valid {
		return nil, "", claimErr("signature")
	}
	payload, err := decodePayload(payloadBytes)
	if err != nil {
		return nil, "", err
	}
	if payload["iss"] != issuer || !sameAudience(payload["aud"], audience) {
		return nil, "", claimErr("claims")
	}
	sub, _ := payload["sub"].(string)
	if !subjectPattern.MatchString(sub) {
		return nil, "", claimErr("claims")
	}
	issued, err := integerClaim(payload["iat"])
	if err != nil {
		return nil, "", claimErr("claims")
	}
	expires, err := integerClaim(payload["exp"])
	if err != nil {
		return nil, "", claimErr("claims")
	}
	current := now().UTC()
	if issued > expires || issued > current.Add(time.Minute).Unix() {
		return nil, "", claimErr("claims")
	}
	if !current.Before(time.Unix(expires, 0)) {
		return nil, "", claimErr("expired")
	}
	use, _ := payload["token_use"].(string)
	if use != wantUse {
		return nil, "", claimErr("type")
	}
	if err := allowedFields(payload, wantUse); err != nil {
		return nil, "", err
	}
	return payload, kid, nil
}

func splitToken(raw string) (map[string]any, []byte, error) {
	parts := bytes.Split([]byte(raw), []byte{'.'})
	if len(parts) != 3 || len(parts[0]) == 0 || len(parts[1]) == 0 || len(parts[2]) == 0 {
		return nil, nil, claimErr("signature")
	}
	head, err := base64.RawURLEncoding.DecodeString(string(parts[0]))
	if err != nil {
		return nil, nil, claimErr("signature")
	}
	var header map[string]any
	if err := json.Unmarshal(head, &header); err != nil {
		return nil, nil, claimErr("signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(string(parts[1]))
	if err != nil {
		return nil, nil, claimErr("signature")
	}
	return header, payload, nil
}

func decodePayload(payload []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return nil, claimErr("claims")
	}
	return raw, nil
}

func allowedFields(payload map[string]any, use string) error {
	allow := map[string]bool{
		"iss": true, "sub": true, "aud": true, "iat": true, "exp": true,
		"auth_version": true, "token_use": true,
	}
	if use == useIdentity {
		allow["preferred_username"] = true
	}
	if use == useAccess {
		allow["resources"] = true
	}
	for key := range payload {
		if !allow[key] {
			return claimErr("claims")
		}
	}
	return nil
}

func integerClaim(v any) (int64, error) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		if err != nil || i < 1 {
			return 0, claimErr("claims")
		}
		return i, nil
	default:
		return 0, claimErr("claims")
	}
}

func expTime(v any) time.Time {
	n, err := integerClaim(v)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(n, 0).UTC()
}

func sameAudience(v any, want []string) bool {
	var got []string
	switch aud := v.(type) {
	case string:
		got = []string{aud}
	case []any:
		for _, item := range aud {
			s, ok := item.(string)
			if !ok {
				return false
			}
			got = append(got, s)
		}
	default:
		return false
	}
	if len(got) != len(want) {
		return false
	}
	count := map[string]int{}
	for _, item := range got {
		count[item]++
	}
	for _, item := range want {
		if count[item] == 0 {
			return false
		}
		count[item]--
	}
	return true
}

func validateResources(resources []Resource) error {
	if len(resources) == 0 {
		return claimErr("claims")
	}
	seen := map[string]bool{}
	for _, resource := range resources {
		if !resourcePattern.MatchString(resource.ResourceID) || seen[resource.ResourceID] {
			return claimErr("claims")
		}
		seen[resource.ResourceID] = true
		if len(resource.Permission) != 1 || resource.Permission[0] != permAccess {
			return claimErr("claims")
		}
	}
	return nil
}

func decodeResources(v any) ([]Resource, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, claimErr("claims")
	}
	var resources []Resource
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&resources); err != nil {
		return nil, claimErr("claims")
	}
	if err := validateResources(resources); err != nil {
		return nil, err
	}
	return resources, nil
}

func claimErr(code string) error {
	return fmt.Errorf("%w: %s", ErrRejected, code)
}
