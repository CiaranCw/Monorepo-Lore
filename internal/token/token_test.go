package token

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const repo = "urc-0123456789abcdef0123456789abcdef"

func testOpt(t *testing.T) Options {
	t.Helper()
	dir := t.TempDir()
	return Options{
		Issuer:      "http://127.0.0.1:52010",
		Audience:    []string{"lore-host.internal"},
		IdentityTTL: 12 * time.Hour,
		AccessTTL:   5 * time.Minute,
		PrivateKey:  filepath.Join(dir, "identity-active.pem"),
		PublicKey:   filepath.Join(dir, "identity-active.pub.pem"),
		JWKS:        filepath.Join(dir, "jwks.json"),
	}
}

func openTest(t *testing.T) *Service {
	t.Helper()
	svc, err := Open(testOpt(t))
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func category(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()[strings.LastIndex(err.Error(), ": ")+2:]
}

func mustIdentity(t *testing.T, svc *Service) string {
	t.Helper()
	raw, err := svc.IssueIdentity("42", "alice", 3)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustAccess(t *testing.T, svc *Service) string {
	t.Helper()
	raw, err := svc.IssueAccess("42", 3, []Resource{{ResourceID: repo, Permission: []string{"access"}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestIdentityAndAccessClaims(t *testing.T) {
	svc := openTest(t)
	identity := mustIdentity(t, svc)
	access := mustAccess(t, svc)
	id, err := svc.VerifyIdentity(identity)
	if err != nil || id.Subject != "42" || id.PreferredUsername != "alice" || id.AuthVersion != 3 || id.KID != svc.ActiveKID() {
		t.Fatalf("identity %v %+v", err, id)
	}
	if !id.Expires.After(time.Now().Add(11 * time.Hour)) {
		t.Fatalf("identity exp %s", id.Expires)
	}
	ac, err := svc.VerifyAccess(access)
	if err != nil || ac.AuthVersion != 3 || len(ac.Resources) != 1 || ac.Resources[0].ResourceID != repo {
		t.Fatalf("access %v %+v", err, ac)
	}
	if !ac.Expires.Before(time.Now().Add(6*time.Minute)) || !ac.Expires.After(time.Now().Add(4*time.Minute)) {
		t.Fatalf("access exp %s", ac.Expires)
	}
	accessPayload := decodedPayload(t, access)
	resources, ok := accessPayload["resources"].([]any)
	if !ok || len(resources) != 1 {
		t.Fatalf("access resources %#v", accessPayload["resources"])
	}
	payload := decodedPayload(t, identity)
	for _, forbidden := range []string{"resources", "password", "password_hash"} {
		if _, ok := payload[forbidden]; ok {
			t.Fatalf("identity contains %s", forbidden)
		}
	}
	for _, required := range []string{"iss", "sub", "aud", "iat", "exp", "preferred_username", "auth_version", "token_use"} {
		if _, ok := payload[required]; !ok {
			t.Fatalf("identity missing %s", required)
		}
	}
	if payload["iss"] != "http://127.0.0.1:52010" {
		t.Fatalf("iss %v", payload["iss"])
	}
	if payload["token_use"] != "identity" {
		t.Fatalf("use %v", payload["token_use"])
	}
}

func TestRejectsBadTokens(t *testing.T) {
	svc := openTest(t)
	identity := mustIdentity(t, svc)
	access := mustAccess(t, svc)
	if _, err := svc.VerifyAccess(identity); category(err) != "type" {
		t.Fatalf("identity as access: %v", err)
	}
	if _, err := svc.VerifyIdentity(access); category(err) != "type" {
		t.Fatalf("access as identity: %v", err)
	}
	parts := strings.Split(identity, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) == 0 {
		t.Fatal(err)
	}
	sig[0] ^= 0xff
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	flipped := strings.Join(parts, ".")
	if _, err := svc.VerifyIdentity(flipped); category(err) != "signature" {
		t.Fatalf("bad signature: %v", err)
	}
	hs, err := svc.signRaw(jwt.SigningMethodHS256, svc.ActiveKID(), jwt.MapClaims{"sub": "1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyIdentity(hs); category(err) != "alg" {
		t.Fatalf("alg: %v", err)
	}
	noKid, err := svc.signRaw(jwt.SigningMethodRS256, "", baseClaims("identity"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyIdentity(noKid); category(err) != "kid" {
		t.Fatalf("missing kid: %v", err)
	}
	unknown, err := svc.signRaw(jwt.SigningMethodRS256, "unknown-kid", baseClaims("identity"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyIdentity(unknown); category(err) != "kid" {
		t.Fatalf("unknown kid: %v", err)
	}
	other := baseClaims("refresh")
	other["preferred_username"] = "alice"
	raw, err := svc.signRaw(jwt.SigningMethodRS256, svc.ActiveKID(), other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyIdentity(raw); category(err) != "type" {
		t.Fatalf("type: %v", err)
	}
	withResources := baseClaims("identity")
	withResources["preferred_username"] = "alice"
	withResources["resources"] = []Resource{{ResourceID: repo, Permission: []string{"access"}}}
	raw, err = svc.signRaw(jwt.SigningMethodRS256, svc.ActiveKID(), withResources)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyIdentity(raw); category(err) != "type" && category(err) != "claims" {
		t.Fatalf("identity with resources: %v", err)
	}
	empty := baseClaims("access")
	empty["resources"] = []Resource{}
	raw, err = svc.signRaw(jwt.SigningMethodRS256, svc.ActiveKID(), empty)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyAccess(raw); category(err) != "claims" {
		t.Fatalf("empty resources: %v", err)
	}
	badID := baseClaims("access")
	badID["resources"] = []Resource{{ResourceID: "urc-ZZ", Permission: []string{"access"}}}
	raw, err = svc.signRaw(jwt.SigningMethodRS256, svc.ActiveKID(), badID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyAccess(raw); category(err) != "claims" {
		t.Fatalf("bad repository: %v", err)
	}
	readOnly := baseClaims("access")
	readOnly["resources"] = []Resource{{ResourceID: repo, Permission: []string{"read"}}}
	raw, err = svc.signRaw(jwt.SigningMethodRS256, svc.ActiveKID(), readOnly)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyAccess(raw); category(err) != "claims" {
		t.Fatalf("read permission: %v", err)
	}
	version := baseClaims("identity")
	version["preferred_username"] = "alice"
	version["auth_version"] = "3"
	raw, err = svc.signRaw(jwt.SigningMethodRS256, svc.ActiveKID(), version)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyIdentity(raw); category(err) != "claims" {
		t.Fatalf("string auth_version: %v", err)
	}
	if _, err := svc.IssueAccess("42", 1, nil); category(err) != "claims" {
		t.Fatalf("issue empty: %v", err)
	}
	if _, err := svc.IssueAccess("42", 1, []Resource{{ResourceID: "not-a-repo", Permission: []string{"access"}}}); err == nil {
		t.Fatal("issued an illegal repository id")
	}
	svc.setClock(func() time.Time { return time.Now().Add(-13 * time.Hour) })
	expired := mustIdentity(t, svc)
	svc.setClock(time.Now)
	if _, err := svc.VerifyIdentity(expired); category(err) != "expired" {
		t.Fatalf("expired: %v", err)
	}
}

func TestErrorsDoNotLeakMaterial(t *testing.T) {
	svc := openTest(t)
	raw := mustIdentity(t, svc)
	_, err := svc.VerifyIdentity(raw + "tamper")
	if err == nil || strings.Contains(err.Error(), raw) || strings.Contains(err.Error(), "BEGIN") {
		t.Fatalf("error leaked material: %v", err)
	}
	if !errors.Is(err, ErrRejected) {
		t.Fatal(err)
	}
}

func TestKeyLifecycle(t *testing.T) {
	opt := testOpt(t)
	svc, err := Open(opt)
	if err != nil {
		t.Fatal(err)
	}
	first := mustIdentity(t, svc)
	kid := svc.ActiveKID()
	privBefore, err := os.ReadFile(opt.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(opt.PrivateKey)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("private key mode %v %v", info, err)
		}
	}
	jwks, err := os.ReadFile(opt.JWKS)
	if err != nil || bytesContainsPrivate(jwks) {
		t.Fatal("jwks contains private material or is missing")
	}
	again, err := Open(opt)
	if err != nil || again.ActiveKID() != kid {
		t.Fatalf("reload %v %s", err, again.ActiveKID())
	}
	privAfter, _ := os.ReadFile(opt.PrivateKey)
	if string(privBefore) != string(privAfter) {
		t.Fatal("reload rewrote the private key")
	}
	if _, err := again.VerifyIdentity(first); err != nil {
		t.Fatal(err)
	}

	rotated, err := again.Rotate()
	if err != nil || rotated.KID == kid || rotated.State != "active" {
		t.Fatalf("rotate %+v %v", rotated, err)
	}
	if _, err := again.VerifyIdentity(first); err != nil {
		t.Fatalf("draining key rejected: %v", err)
	}
	fresh := mustIdentity(t, again)
	if _, err := again.VerifyIdentity(fresh); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Open(opt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reloaded.VerifyIdentity(first); err != nil {
		t.Fatalf("restart dropped draining key: %v", err)
	}
	if err := reloaded.Retire(kid); err != nil {
		t.Fatal(err)
	}
	if _, err := reloaded.VerifyIdentity(first); category(err) != "kid" {
		t.Fatalf("retired key still accepted: %v", err)
	}
	if _, err := reloaded.VerifyIdentity(fresh); err != nil {
		t.Fatalf("active token after retire: %v", err)
	}
	if err := reloaded.Retire(reloaded.ActiveKID()); err == nil {
		t.Fatal("active key was retired")
	}
	persisted, err := Open(opt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persisted.VerifyIdentity(first); err == nil {
		t.Fatal("retired key accepted after restart")
	}
}

func TestKeyFailuresDoNotRegenerate(t *testing.T) {
	opt := testOpt(t)
	svc, err := Open(opt)
	if err != nil {
		t.Fatal(err)
	}
	kid := svc.ActiveKID()
	original, err := os.ReadFile(opt.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(opt.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := os.ReadFile(opt.JWKS)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(opt.PrivateKey, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(opt); err == nil || strings.Contains(err.Error(), "not a key") || !errors.Is(err, ErrKeys) {
		t.Fatalf("corrupt private: %v", err)
	}
	body, _ := os.ReadFile(opt.PrivateKey)
	if string(body) != "not a key" {
		t.Fatal("corrupt private key was replaced")
	}

	if err := os.WriteFile(opt.PrivateKey, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opt.PublicKey, []byte("bad public"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(opt); err == nil {
		t.Fatal("corrupt public key was accepted")
	}
	if err := os.WriteFile(opt.PublicKey, pub, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(opt.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(opt); err == nil {
		t.Fatal("missing private key generated a replacement")
	}
	if got, _ := os.ReadFile(opt.PublicKey); string(got) != string(pub) {
		t.Fatal("public key changed while the private key was missing")
	}

	if err := os.WriteFile(opt.PrivateKey, original, 0o600); err != nil {
		t.Fatal(err)
	}
	replacement := openTest(t)
	foreign, err := os.ReadFile(replacement.opt.JWKS)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opt.JWKS, foreign, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(opt); err == nil {
		t.Fatal("mismatched jwks was accepted")
	}
	if err := os.WriteFile(opt.JWKS, jwks, 0o644); err != nil {
		t.Fatal(err)
	}
	restored, err := Open(opt)
	if err != nil || restored.ActiveKID() != kid {
		t.Fatalf("restore %v", err)
	}

	statePath := filepath.Join(filepath.Dir(opt.PrivateKey), stateName)
	stateBody, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var state keyFile
	if err := json.Unmarshal(stateBody, &state); err != nil {
		t.Fatal(err)
	}
	state.Keys = append(state.Keys, keyRecord{KID: "second", State: stateActive, SPKI: "nope"})
	raw, _ := json.MarshalIndent(state, "", "  ")
	if err := os.WriteFile(statePath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(opt); err == nil || !strings.Contains(err.Error(), "multiple active") {
		t.Fatalf("multiple active: %v", err)
	}
}

func baseClaims(use string) jwt.MapClaims {
	now := time.Now().UTC()
	return jwt.MapClaims{
		"iss":          "http://127.0.0.1:52010",
		"sub":          "42",
		"aud":          []string{"lore-host.internal"},
		"iat":          now.Unix(),
		"exp":          now.Add(time.Hour).Unix(),
		"auth_version": int64(3),
		"token_use":    use,
	}
}

func (s *Service) setClock(now func() time.Time) {
	s.mu.Lock()
	s.now = now
	s.mu.Unlock()
}

func decodedPayload(t *testing.T, raw string) map[string]any {
	t.Helper()
	part := strings.Split(raw, ".")[1]
	body, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func bytesContainsPrivate(body []byte) bool {
	if strings.Contains(string(body), "PRIVATE") {
		return true
	}
	var raw struct {
		Keys []map[string]any `json:"keys"`
	}
	if json.Unmarshal(body, &raw) != nil {
		return true
	}
	for _, key := range raw.Keys {
		for _, name := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			if _, ok := key[name]; ok {
				return true
			}
		}
	}
	block, _ := pem.Decode(body)
	if block != nil {
		if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return true
		}
	}
	return false
}
