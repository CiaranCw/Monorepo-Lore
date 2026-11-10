package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
)

const (
	rsaBits       = 2048
	stateName     = "keys-state.json"
	stateActive   = "active"
	stateDraining = "draining"
	stateRetired  = "retired"
)

// KeyInfo describes one signing key without its material.
type KeyInfo struct {
	KID   string
	State string
}

type keyRecord struct {
	KID   string `json:"kid"`
	State string `json:"state"`
	SPKI  string `json:"spki_sha256"`
}

type keyFile struct {
	Keys []keyRecord `json:"keys"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func openOrCreate(opt Options) (*Service, error) {
	if err := opt.validate(); err != nil {
		return nil, err
	}
	dir := filepath.Dir(opt.PrivateKey)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, keyErr("cannot create key directory")
	}
	statePath := filepath.Join(dir, stateName)
	if !anyKeyFile(opt, statePath) {
		return createInitial(opt, statePath)
	}
	return loadExisting(opt, statePath)
}

func anyKeyFile(opt Options, statePath string) bool {
	return fileExists(opt.PrivateKey) || fileExists(opt.PublicKey) || fileExists(opt.JWKS) || fileExists(statePath)
}

func createInitial(opt Options, statePath string) (*Service, error) {
	key, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, keyErr("cannot generate signing key")
	}
	kid := kidOf(&key.PublicKey)
	state := keyFile{Keys: []keyRecord{{
		KID: kid, State: stateActive, SPKI: spkiHash(&key.PublicKey),
	}}}
	pubs := map[string]*rsa.PublicKey{kid: &key.PublicKey}
	if err := persist(opt, statePath, key, state, pubs); err != nil {
		return nil, err
	}
	return newService(opt, statePath, key, kid, pubs, state), nil
}

func loadExisting(opt Options, statePath string) (*Service, error) {
	if !fileExists(opt.PrivateKey) {
		return nil, keyErr("private key is missing")
	}
	if !fileExists(opt.PublicKey) || !fileExists(opt.JWKS) || !fileExists(statePath) {
		return nil, keyErr("signing key set is incomplete")
	}
	priv, err := readPrivate(opt.PrivateKey)
	if err != nil {
		return nil, err
	}
	if priv.N.BitLen() < rsaBits {
		return nil, keyErr("private key is shorter than RSA 2048")
	}
	pub, err := readPublic(opt.PublicKey)
	if err != nil {
		return nil, err
	}
	if !pub.Equal(&priv.PublicKey) {
		return nil, keyErr("public key does not match private key")
	}
	set, err := readJWKS(opt.JWKS)
	if err != nil {
		return nil, err
	}
	state, err := readState(statePath)
	if err != nil {
		return nil, err
	}
	active, pubs, err := reconcile(priv, set, state)
	if err != nil {
		return nil, err
	}
	return newService(opt, statePath, priv, active, pubs, state), nil
}

func reconcile(priv *rsa.PrivateKey, set jwkSet, state keyFile) (string, map[string]*rsa.PublicKey, error) {
	var active string
	pubs := map[string]*rsa.PublicKey{}
	seen := map[string]bool{}
	for _, rec := range state.Keys {
		if rec.KID == "" || seen[rec.KID] {
			return "", nil, keyErr("key state has a duplicate or empty kid")
		}
		seen[rec.KID] = true
		switch rec.State {
		case stateActive:
			if active != "" {
				return "", nil, keyErr("multiple active signing keys")
			}
			if kidOf(&priv.PublicKey) != rec.KID || spkiHash(&priv.PublicKey) != rec.SPKI {
				return "", nil, keyErr("private key does not match the active key record")
			}
			fromJWKS, err := publicFromSet(set, rec.KID)
			if err != nil || !fromJWKS.Equal(&priv.PublicKey) {
				return "", nil, keyErr("jwks does not match the active private key")
			}
			active = rec.KID
			pubs[rec.KID] = &priv.PublicKey
		case stateDraining:
			fromJWKS, err := publicFromSet(set, rec.KID)
			if err != nil || kidOf(fromJWKS) != rec.KID || spkiHash(fromJWKS) != rec.SPKI {
				return "", nil, keyErr("jwks does not match a draining key")
			}
			pubs[rec.KID] = fromJWKS
		case stateRetired:
			if _, ok := findJWK(set, rec.KID); ok {
				return "", nil, keyErr("jwks still contains a retired key")
			}
		default:
			return "", nil, keyErr("key state has an unknown status")
		}
	}
	if active == "" {
		return "", nil, keyErr("no active signing key")
	}
	for _, key := range set.Keys {
		rec := findRecord(state, key.Kid)
		if rec == nil || (rec.State != stateActive && rec.State != stateDraining) {
			return "", nil, keyErr("jwks contains a key that is not active or draining")
		}
	}
	return active, pubs, nil
}

func (s *Service) rotate() (KeyInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return KeyInfo{}, keyErr("cannot generate signing key")
	}
	kid := kidOf(&key.PublicKey)
	next := keyFile{}
	for _, rec := range s.state.Keys {
		if rec.State == stateActive {
			rec.State = stateDraining
		}
		next.Keys = append(next.Keys, rec)
	}
	next.Keys = append(next.Keys, keyRecord{KID: kid, State: stateActive, SPKI: spkiHash(&key.PublicKey)})
	pubs := map[string]*rsa.PublicKey{kid: &key.PublicKey}
	for id, pub := range s.verify {
		pubs[id] = pub
	}
	if err := persist(s.opt, s.statePath, key, next, pubs); err != nil {
		return KeyInfo{}, err
	}
	s.active = key
	s.activeKID = kid
	s.verify = pubs
	s.state = next
	return KeyInfo{KID: kid, State: stateActive}, nil
}

func (s *Service) retire(kid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var found bool
	var status string
	for _, rec := range s.state.Keys {
		if rec.KID == kid {
			found = true
			status = rec.State
		}
	}
	if !found {
		return keyErr("unknown signing key")
	}
	if status != stateDraining {
		return keyErr("only a draining key can be retired")
	}
	next := keyFile{Keys: append([]keyRecord(nil), s.state.Keys...)}
	for i := range next.Keys {
		if next.Keys[i].KID == kid {
			next.Keys[i].State = stateRetired
		}
	}
	pubs := map[string]*rsa.PublicKey{}
	for id, pub := range s.verify {
		if id != kid {
			pubs[id] = pub
		}
	}
	if err := persist(s.opt, s.statePath, s.active, next, pubs); err != nil {
		return err
	}
	s.verify = pubs
	s.state = next
	return nil
}

func persist(opt Options, statePath string, active *rsa.PrivateKey, state keyFile, pubs map[string]*rsa.PublicKey) error {
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(active)})
	pubDER, err := x509.MarshalPKIXPublicKey(&active.PublicKey)
	if err != nil {
		return keyErr("cannot encode public key")
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	set, err := jwksFor(state, pubs)
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return keyErr("cannot encode jwks")
	}
	body = append(body, '\n')
	rawState, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return keyErr("cannot encode key state")
	}
	rawState = append(rawState, '\n')
	if err := atomicWrite(opt.PrivateKey, privPEM, 0o600); err != nil {
		return keyErr("cannot write private key")
	}
	if err := atomicWrite(opt.PublicKey, pubPEM, 0o644); err != nil {
		return keyErr("cannot write public key")
	}
	if err := atomicWrite(opt.JWKS, body, 0o644); err != nil {
		return keyErr("cannot write jwks")
	}
	if err := atomicWrite(statePath, rawState, 0o644); err != nil {
		return keyErr("cannot write key state")
	}
	return nil
}

func jwksFor(state keyFile, pubs map[string]*rsa.PublicKey) (jwkSet, error) {
	var set jwkSet
	for _, rec := range state.Keys {
		if rec.State != stateActive && rec.State != stateDraining {
			continue
		}
		pub := pubs[rec.KID]
		if pub == nil {
			return jwkSet{}, keyErr("jwks is missing a public key")
		}
		set.Keys = append(set.Keys, jwk{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: rec.KID,
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		})
	}
	if len(set.Keys) == 0 {
		return jwkSet{}, keyErr("jwks would contain no keys")
	}
	return set, nil
}

func kidOf(pub *rsa.PublicKey) string {
	sum := sha256.Sum256(mustSPKI(pub))
	return hex.EncodeToString(sum[:16])
}

func spkiHash(pub *rsa.PublicKey) string {
	sum := sha256.Sum256(mustSPKI(pub))
	return hex.EncodeToString(sum[:])
}

func mustSPKI(pub *rsa.PublicKey) []byte {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	return b
}

func readPrivate(path string) (*rsa.PrivateKey, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, keyErr("cannot read private key")
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, keyErr("private key is not a PEM file")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		if parsed, err2 := x509.ParsePKCS8PrivateKey(block.Bytes); err2 == nil {
			rsaKey, ok := parsed.(*rsa.PrivateKey)
			if ok {
				return rsaKey, nil
			}
		}
		return nil, keyErr("private key is unreadable")
	}
	return key, nil
}

func readPublic(path string) (*rsa.PublicKey, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, keyErr("cannot read public key")
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, keyErr("public key is not a PEM file")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, keyErr("public key is unreadable")
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, keyErr("public key is not RSA")
	}
	return key, nil
}

func readJWKS(path string) (jwkSet, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return jwkSet{}, keyErr("cannot read jwks")
	}
	if err := rejectPrivateJWKFields(body); err != nil {
		return jwkSet{}, err
	}
	var set jwkSet
	if err := json.Unmarshal(body, &set); err != nil || len(set.Keys) == 0 {
		return jwkSet{}, keyErr("jwks is unreadable")
	}
	return set, nil
}

func rejectPrivateJWKFields(body []byte) error {
	var raw struct {
		Keys []map[string]json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return keyErr("jwks is unreadable")
	}
	for _, key := range raw.Keys {
		for _, name := range []string{"d", "p", "q", "dp", "dq", "qi", "oth"} {
			if _, ok := key[name]; ok {
				return keyErr("jwks contains private key material")
			}
		}
	}
	return nil
}

func readState(path string) (keyFile, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return keyFile{}, keyErr("cannot read key state")
	}
	var state keyFile
	if err := json.Unmarshal(body, &state); err != nil || len(state.Keys) == 0 {
		return keyFile{}, keyErr("key state is unreadable")
	}
	return state, nil
}

func publicFromSet(set jwkSet, kid string) (*rsa.PublicKey, error) {
	key, ok := findJWK(set, kid)
	if !ok || key.Kty != "RSA" || key.Alg != "RS256" || key.N == "" || key.E == "" {
		return nil, keyErr("jwks entry is unusable")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, keyErr("jwks modulus is unreadable")
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil || len(eBytes) == 0 {
		return nil, keyErr("jwks exponent is unreadable")
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

func findJWK(set jwkSet, kid string) (jwk, bool) {
	for _, key := range set.Keys {
		if key.Kid == kid {
			return key, true
		}
	}
	return jwk{}, false
}

func findRecord(state keyFile, kid string) *keyRecord {
	for i := range state.Keys {
		if state.Keys[i].KID == kid {
			return &state.Keys[i]
		}
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	keep := false
	defer func() {
		if !keep {
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
			return err
		}
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
	}
	keep = true
	return nil
}

func keyErr(msg string) error {
	return fmt.Errorf("%w: %s", ErrKeys, msg)
}
