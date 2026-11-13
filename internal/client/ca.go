package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type trustError struct {
	msg string
}

func (e trustError) Error() string { return e.msg }

func newTrustError(format string, args ...any) error {
	return trustError{msg: fmt.Sprintf(format, args...)}
}

// IsTrustError reports whether err is a client TLS/CA/pin validation failure.
func IsTrustError(err error) bool {
	var te trustError
	return errors.As(err, &te)
}

// CAPin represents a parsed versioned CA/certificate pin.
// Version 1 (legacy B2.13): bare 64-hex or "sha256:<64-hex>" covering a single certificate only.
// Version 2 (B2.13.1+): "v2:<64-hex>" covering the canonicalized certificate set digest.
type CAPin struct {
	Version int
	Digest  string
}

func (p CAPin) String() string {
	if p.Version == 1 {
		return p.Digest
	}
	return fmt.Sprintf("v2:%s", p.Digest)
}

func makeSetPin(certs []*x509.Certificate) CAPin {
	return CAPin{
		Version: 2,
		Digest:  CertSetSHA256Hex(certs),
	}
}

// CheckCA reads a PEM certificate bundle and rejects unreadable, invalid, expired,
// or not-yet-valid certificates. An empty path means the caller is not pinning a CA.
func CheckCA(path string, now time.Time) error {
	if path == "" {
		return nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return newTrustError("ca file is unreadable")
	}
	_, _, err = parsePEMCerts(body, now)
	return err
}

// ParseCAPEMBundle parses PEM certificates without checking wall-clock validity
// and returns the deduplicated canonical PEM plus canonical set SHA-256 digest.
func ParseCAPEMBundle(body []byte) (string, string, error) {
	certs, clean, err := parsePEMCertsNoTime(body)
	if err != nil {
		return "", "", err
	}
	return string(clean), CertSetSHA256Hex(certs), nil
}

func parsePEMCerts(body []byte, now time.Time) ([]*x509.Certificate, []byte, error) {
	certs, _, err := parsePEMCertsRaw(body, true, now)
	if err != nil {
		return nil, nil, err
	}
	var clean bytes.Buffer
	for _, cert := range certs {
		_ = pem.Encode(&clean, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	return certs, clean.Bytes(), nil
}

func parsePEMCertsNoTime(body []byte) ([]*x509.Certificate, []byte, error) {
	certs, _, err := parsePEMCertsRaw(body, false, time.Time{})
	if err != nil {
		return nil, nil, err
	}
	var clean bytes.Buffer
	for _, cert := range certs {
		_ = pem.Encode(&clean, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	return certs, clean.Bytes(), nil
}

func parsePEMCertsRaw(body []byte, checkTime bool, now time.Time) ([]*x509.Certificate, []byte, error) {
	var certs []*x509.Certificate
	var clean bytes.Buffer
	seen := map[string]bool{}
	rest := body
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, newTrustError("ca file is not a certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, newTrustError("ca file is not a certificate")
		}
		if checkTime && (now.Before(cert.NotBefore) || !now.Before(cert.NotAfter)) {
			return nil, nil, newTrustError("ca certificate is not currently valid")
		}
		fp := CertSHA256Hex(cert)
		if seen[fp] {
			continue
		}
		seen[fp] = true
		certs = append(certs, cert)
		_ = pem.Encode(&clean, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	if len(certs) == 0 {
		return nil, nil, newTrustError("ca file is not a certificate")
	}
	return certs, clean.Bytes(), nil
}

// CertSHA256Hex returns the lowercase hex SHA-256 fingerprint of a certificate's DER bytes.
func CertSHA256Hex(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// CertSetSHA256Hex returns a deterministic, order-independent SHA-256 digest over
// the full set of certificates. For a single unique certificate, it returns that
// certificate's SHA-256 digest; for multiple unique certificates, it hashes the
// sorted unique per-certificate hex digests separated by newlines.
func CertSetSHA256Hex(certs []*x509.Certificate) string {
	if len(certs) == 0 {
		return ""
	}
	seen := make(map[string]struct{}, len(certs))
	hashes := make([]string, 0, len(certs))
	for _, c := range certs {
		if c == nil {
			continue
		}
		h := CertSHA256Hex(c)
		if _, ok := seen[h]; !ok {
			seen[h] = struct{}{}
			hashes = append(hashes, h)
		}
	}
	if len(hashes) == 0 {
		return ""
	}
	sort.Strings(hashes)
	if len(hashes) == 1 {
		return hashes[0]
	}
	sum := sha256.Sum256([]byte(strings.Join(hashes, "\n")))
	return hex.EncodeToString(sum[:])
}

// PinPathForCA returns the companion fingerprint pin file path for a CA file.
func PinPathForCA(caPath string) string {
	if strings.TrimSpace(caPath) == "" {
		return ""
	}
	if filepath.Base(caPath) == "ca.pem" {
		return filepath.Join(filepath.Dir(caPath), "ca.pin")
	}
	return caPath + ".pin"
}

func resolveConfigPinPath(cfg Config) string {
	if strings.TrimSpace(cfg.CAFile) != "" {
		return PinPathForCA(cfg.CAFile)
	}
	if strings.TrimSpace(cfg.Path) != "" {
		return filepath.Join(filepath.Dir(cfg.Path), "ca.pin")
	}
	return ""
}

func isAutoProfileConfig(cfg Config) bool {
	if strings.EqualFold(strings.TrimSpace(cfg.TrustMode), "pinned") {
		return true
	}
	if strings.TrimSpace(cfg.Path) == "" {
		return false
	}
	baseDir, err := UserConfigBaseDir()
	if err != nil {
		return false
	}
	profilesDir := filepath.Clean(filepath.Join(baseDir, "profiles"))
	cfgAbs, err := filepath.Abs(cfg.Path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(profilesDir, cfgAbs)
	if err != nil {
		return false
	}
	return rel != "." && !strings.HasPrefix(rel, "..")
}

func isHTTPSURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && strings.EqualFold(u.Scheme, "https")
}

func parsePinString(raw string) (CAPin, error) {
	s := strings.TrimSpace(strings.ToLower(raw))
	if strings.HasPrefix(s, "v2:") {
		hexPart := strings.TrimPrefix(s, "v2:")
		if !isHex64(hexPart) {
			return CAPin{}, newTrustError("invalid ca pin")
		}
		return CAPin{Version: 2, Digest: hexPart}, nil
	}
	s = strings.TrimPrefix(s, "sha256:")
	if !isHex64(s) {
		return CAPin{}, newTrustError("invalid ca pin")
	}
	return CAPin{Version: 1, Digest: s}, nil
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func readPinFile(path string) (CAPin, error) {
	if strings.TrimSpace(path) == "" {
		return CAPin{}, os.ErrNotExist
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return CAPin{}, err
	}
	return parsePinString(string(body))
}

func writePinFile(path string, pin CAPin) error {
	if strings.TrimSpace(path) == "" || strings.TrimSpace(pin.Digest) == "" {
		return nil
	}
	return writeFile(path, []byte(pin.String()+"\n"))
}

// verifyCertsMatchPin ensures that ALL certificates participating in trust
// verification match the stored pin. Legacy v1 pins strictly allow only 1 cert.
func verifyCertsMatchPin(certs []*x509.Certificate, pin CAPin) error {
	if len(certs) == 0 {
		return newTrustError("ca file contains no certificates")
	}
	if pin.Version == 1 {
		if len(certs) != 1 {
			return newTrustError("legacy ca pin covers only a single certificate; refusing multi-certificate bundle without explicit --retrust-ca")
		}
		actual := CertSHA256Hex(certs[0])
		if actual != pin.Digest {
			return newTrustError("tls ca fingerprint mismatch: expected %s, got %s", pin.Digest, actual)
		}
		return nil
	}
	actual := CertSetSHA256Hex(certs)
	if actual != pin.Digest {
		return newTrustError("tls ca fingerprint mismatch: expected %s, got %s", pin.Digest, actual)
	}
	return nil
}

func pinsEquivalentForCerts(a, b CAPin, certs []*x509.Certificate) bool {
	if a.Version == b.Version && a.Digest == b.Digest {
		return true
	}
	if len(certs) == 1 {
		return verifyCertsMatchPin(certs, a) == nil && verifyCertsMatchPin(certs, b) == nil
	}
	return false
}

// ValidateHTTPTrust checks cfg's TLS CA and pin configuration without performing network I/O.
func ValidateHTTPTrust(cfg Config) error {
	_, err := NewHTTPClient(cfg)
	return err
}

// NewHTTPClient builds an HTTP client enforcing cfg.CAFile and CA pins fail-closed.
// Auto profiles always require a valid CA pin on HTTPS; manual configs without a pin
// require cfg.CAFile (if set) to be readable and valid without falling back to system roots.
func NewHTTPClient(cfg Config) (*http.Client, error) {
	baseClient := func(tr http.RoundTripper) *http.Client {
		return &http.Client{
			Timeout:   20 * time.Second,
			Transport: tr,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("redirect refused")
			},
		}
	}

	auto := isAutoProfileConfig(cfg)
	pinPath := resolveConfigPinPath(cfg)
	hostName := ""
	if u, err := url.Parse(strings.TrimSpace(cfg.ManagerURL)); err == nil {
		hostName = u.Hostname()
	}

	if strings.TrimSpace(cfg.CAFile) != "" {
		body, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, newTrustError("ca file is unreadable")
		}
		certs, cleanPEM, parseErr := parsePEMCerts(body, time.Now())
		if parseErr != nil {
			return nil, parseErr
		}

		pin, pinErr := readPinFile(pinPath)
		hasPin := pinErr == nil
		if pinErr != nil {
			if errors.Is(pinErr, os.ErrNotExist) {
				if auto {
					return nil, newTrustError("auto profile missing ca pin")
				}
			} else {
				return nil, newTrustError("invalid ca pin")
			}
		}
		if hasPin {
			if err := verifyCertsMatchPin(certs, pin); err != nil {
				return nil, err
			}
			hc, err := pinnedHTTPClient(certs, cleanPEM, hostName)
			if err != nil {
				return nil, err
			}
			return hc, nil
		}

		// Manual config without companion .pin: fail-closed if pool fails, never fall back to system roots.
		hc, err := pinnedHTTPClient(certs, cleanPEM, hostName)
		if err != nil {
			return nil, err
		}
		return hc, nil
	}

	// No CAFile configured.
	if auto && isHTTPSURL(cfg.ManagerURL) {
		pin, pinErr := readPinFile(pinPath)
		if pinErr != nil {
			return nil, newTrustError("auto profile missing or invalid ca pin")
		}
		return systemPinnedHTTPClient(pin, hostName), nil
	}
	if pinPath != "" {
		pin, pinErr := readPinFile(pinPath)
		if pinErr == nil && isHTTPSURL(cfg.ManagerURL) {
			return systemPinnedHTTPClient(pin, hostName), nil
		}
		if pinErr != nil && !errors.Is(pinErr, os.ErrNotExist) {
			return nil, newTrustError("invalid ca pin")
		}
	}

	return baseClient(&http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}), nil
}

// HTTPClient returns an HTTP client enforcing cfg's TLS trust policy.
// Any configuration, CA, or pin error produces a fail-closed client whose
// requests always fail with that error (never falling back to system roots).
func HTTPClient(cfg Config) *http.Client {
	hc, err := NewHTTPClient(cfg)
	if err != nil {
		return &http.Client{
			Timeout:   20 * time.Second,
			Transport: failingTransport{err: err},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("redirect refused")
			},
		}
	}
	return hc
}

type failingTransport struct{ err error }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, f.err
}

// ClientInfo is the public bootstrap metadata exposed by Manager's
// unauthenticated /api/v1/client/info endpoint.
type ClientInfo struct {
	ManagerVersion string `json:"manager_version"`
	AuthURL        string `json:"auth_url"`
	RemoteBaseURL  string `json:"remote_base_url"`
	CAPEM          string `json:"ca_pem"`
	CASHA256       string `json:"ca_sha256"`
}

type tlsBootstrapResult struct {
	Info         ClientInfo
	CAFile       string
	CASHA256     string
	TrustMode    string
	TOFUTrusted  bool
	TOFULeafOnly bool
}

func hostPortForURL(u *url.URL) string {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(host, port)
}

func bootstrapTLSAndInfo(ctx context.Context, managerURL, explicitCAFile string, retrustCA bool, caSavePath, profilePinPath, hostPinPath, hostCAPath string) (tlsBootstrapResult, error) {
	u, err := url.Parse(managerURL)
	if err != nil {
		return tlsBootstrapResult{}, errors.New("invalid manager url")
	}
	if u.Scheme == "http" {
		info, _ := fetchClientInfo(ctx, &http.Client{Timeout: 10 * time.Second}, managerURL)
		return tlsBootstrapResult{Info: info}, nil
	}

	now := time.Now()
	existingPin, hasExistingPin, err := loadExistingPin(profilePinPath, hostPinPath, caSavePath, hostCAPath, now)
	if err != nil && !retrustCA {
		return tlsBootstrapResult{}, err
	}
	if retrustCA {
		hasExistingPin = false
	}

	// Case 1: Caller explicitly passed --ca-file.
	if strings.TrimSpace(explicitCAFile) != "" {
		raw, err := os.ReadFile(explicitCAFile)
		if err != nil {
			return tlsBootstrapResult{}, newTrustError("ca file is unreadable")
		}
		certs, cleanPEM, err := parsePEMCerts(raw, now)
		if err != nil {
			return tlsBootstrapResult{}, err
		}
		newPin := makeSetPin(certs)
		if hasExistingPin {
			if err := verifyCertsMatchPin(certs, existingPin); err != nil {
				return tlsBootstrapResult{}, err
			}
		}
		hc, err := pinnedHTTPClient(certs, cleanPEM, u.Hostname())
		if err != nil {
			return tlsBootstrapResult{}, err
		}
		if err := verifyHTTPSReachable(ctx, hc, managerURL); err != nil {
			return tlsBootstrapResult{}, err
		}
		if caSavePath != "" && caSavePath != explicitCAFile {
			if err := writeFile(caSavePath, cleanPEM); err != nil {
				return tlsBootstrapResult{}, err
			}
		}
		targetCA := explicitCAFile
		if caSavePath != "" {
			targetCA = caSavePath
		}
		if err := writePinFile(profilePinPath, newPin); err != nil {
			return tlsBootstrapResult{}, err
		}
		if err := writePinFile(hostPinPath, newPin); err != nil {
			return tlsBootstrapResult{}, err
		}
		if hostCAPath != "" {
			_ = writeFile(hostCAPath, cleanPEM)
		}
		info, _ := fetchClientInfo(ctx, hc, managerURL)
		return tlsBootstrapResult{
			Info:      info,
			CAFile:    targetCA,
			CASHA256:  newPin.Digest,
			TrustMode: "pinned",
		}, nil
	}

	// Case 2: Pin already exists for this profile or Manager URL -> strictly enforce it, never re-TOFU.
	if hasExistingPin {
		var certPath string
		for _, candidate := range []string{caSavePath, hostCAPath} {
			if candidate != "" {
				if _, statErr := os.Stat(candidate); statErr == nil {
					certPath = candidate
					break
				}
			}
		}
		if certPath != "" {
			raw, err := os.ReadFile(certPath)
			if err != nil {
				return tlsBootstrapResult{}, newTrustError("pinned ca file is unreadable")
			}
			certs, cleanPEM, err := parsePEMCerts(raw, now)
			if err != nil {
				return tlsBootstrapResult{}, err
			}
			if err := verifyCertsMatchPin(certs, existingPin); err != nil {
				return tlsBootstrapResult{}, err
			}
			hc, err := pinnedHTTPClient(certs, cleanPEM, u.Hostname())
			if err != nil {
				return tlsBootstrapResult{}, err
			}
			if err := verifyHTTPSReachable(ctx, hc, managerURL); err != nil {
				return tlsBootstrapResult{}, newTrustError("tls verification against pinned certificate failed: %v", err)
			}
			if caSavePath != "" && certPath != caSavePath {
				if err := writeFile(caSavePath, cleanPEM); err != nil {
					return tlsBootstrapResult{}, err
				}
			}
			upgradedPin := makeSetPin(certs)
			_ = writePinFile(profilePinPath, upgradedPin)
			_ = writePinFile(hostPinPath, upgradedPin)
			info, _ := fetchClientInfo(ctx, hc, managerURL)
			return tlsBootstrapResult{
				Info:      info,
				CAFile:    caSavePath,
				CASHA256:  upgradedPin.Digest,
				TrustMode: "pinned",
			}, nil
		}

		// Publicly trusted host previously pinned without a local CA file: verify system TLS + VerifiedChains root pin.
		sysHC, _, verifiedChains, err := probeSystemTLS(ctx, u, managerURL)
		if err != nil {
			return tlsBootstrapResult{}, err
		}
		if !pinMatchesVerifiedChains(existingPin, verifiedChains) {
			got := ""
			if len(verifiedChains) > 0 && len(verifiedChains[0]) > 0 {
				chain := verifiedChains[0]
				got = CertSHA256Hex(chain[len(chain)-1])
			}
			return tlsBootstrapResult{}, newTrustError("tls certificate fingerprint changed (expected %s, got %s); refusing connection", existingPin.Digest, got)
		}
		info, _ := fetchClientInfo(ctx, sysHC, managerURL)
		return tlsBootstrapResult{
			Info:      info,
			CASHA256:  existingPin.Digest,
			TrustMode: "pinned",
		}, nil
	}

	// Case 3: First connection (or explicit --retrust-ca). First try standard system roots.
	sysHC, peerCerts, verifiedChains, sysErr := probeSystemTLS(ctx, u, managerURL)
	if sysErr == nil {
		info, _ := fetchClientInfo(ctx, sysHC, managerURL)
		var finalPin CAPin
		if len(verifiedChains) > 0 && len(verifiedChains[0]) > 0 {
			chain := verifiedChains[0]
			finalPin = makeSetPin([]*x509.Certificate{chain[len(chain)-1]})
		} else if len(peerCerts) > 0 {
			finalPin = makeSetPin([]*x509.Certificate{peerCerts[len(peerCerts)-1]})
		}
		savedCA := ""
		if strings.TrimSpace(info.CAPEM) != "" && len(peerCerts) > 0 {
			if caCerts, cleanCA, err := parsePEMCerts([]byte(info.CAPEM), now); err == nil {
				if info.CASHA256 == "" || strings.EqualFold(info.CASHA256, CertSetSHA256Hex(caCerts)) {
					if _, err := verifyLeafAgainstCA(peerCerts, caCerts, u.Hostname(), now); err == nil {
						finalPin = makeSetPin(caCerts)
						if caSavePath != "" {
							if err := writeFile(caSavePath, cleanCA); err != nil {
								return tlsBootstrapResult{}, err
							}
							savedCA = caSavePath
						}
						if hostCAPath != "" {
							_ = writeFile(hostCAPath, cleanCA)
						}
					}
				}
			}
		}
		if err := writePinFile(profilePinPath, finalPin); err != nil {
			return tlsBootstrapResult{}, err
		}
		if err := writePinFile(hostPinPath, finalPin); err != nil {
			return tlsBootstrapResult{}, err
		}
		return tlsBootstrapResult{
			Info:      info,
			CAFile:    savedCA,
			CASHA256:  finalPin.Digest,
			TrustMode: "pinned",
		}, nil
	}

	// Reject hostname/expiry/certificate validity/network errors immediately;
	// only true x509.UnknownAuthorityError may enter constrained TOFU.
	if !isUnknownAuthorityError(sysErr) {
		return tlsBootstrapResult{}, newTrustError("tls verification failed: %v", sysErr)
	}

	// Explicit TOFU probe: connect only to inspect certificates, immediately validate SAN/hostname, EKU & time bounds.
	certs, err := dialPeerCertificates(ctx, u)
	if err != nil {
		return tlsBootstrapResult{}, err
	}
	leaf := certs[0]
	for _, c := range certs {
		if now.Before(c.NotBefore) || !now.Before(c.NotAfter) {
			return tlsBootstrapResult{}, newTrustError("server tls certificate is expired or not yet valid")
		}
	}
	if err := leaf.VerifyHostname(u.Hostname()); err != nil {
		return tlsBootstrapResult{}, newTrustError("server tls certificate hostname mismatch: %v", err)
	}
	if !leafAllowsServerAuth(leaf) {
		return tlsBootstrapResult{}, newTrustError("server tls certificate is not valid for server authentication")
	}

	candidateCerts, candidatePEM := selectTrustCandidate(certs, u.Hostname(), now)
	bootstrapHC, err := pinnedHTTPClient(candidateCerts, candidatePEM, u.Hostname())
	if err != nil {
		return tlsBootstrapResult{}, err
	}
	info, _ := fetchClientInfo(ctx, bootstrapHC, managerURL)

	finalCerts := candidateCerts
	finalPEM := candidatePEM
	if strings.TrimSpace(info.CAPEM) != "" {
		caCerts, cleanCA, err := parsePEMCerts([]byte(info.CAPEM), now)
		if err != nil {
			return tlsBootstrapResult{}, newTrustError("manager returned invalid ca_pem: %v", err)
		}
		if info.CASHA256 != "" && !strings.EqualFold(info.CASHA256, CertSetSHA256Hex(caCerts)) {
			return tlsBootstrapResult{}, newTrustError("manager ca_sha256 does not match ca_pem")
		}
		if _, err := verifyLeafAgainstCA(certs, caCerts, u.Hostname(), now); err != nil {
			return tlsBootstrapResult{}, newTrustError("manager ca_pem does not verify server certificate: %v", err)
		}
		finalCerts = caCerts
		finalPEM = cleanCA
	}

	finalPin := makeSetPin(finalCerts)
	if caSavePath != "" {
		if err := writeFile(caSavePath, finalPEM); err != nil {
			return tlsBootstrapResult{}, err
		}
	}
	if hostCAPath != "" {
		if err := writeFile(hostCAPath, finalPEM); err != nil {
			return tlsBootstrapResult{}, err
		}
	}
	if err := writePinFile(profilePinPath, finalPin); err != nil {
		return tlsBootstrapResult{}, err
	}
	if err := writePinFile(hostPinPath, finalPin); err != nil {
		return tlsBootstrapResult{}, err
	}
	return tlsBootstrapResult{
		Info:         info,
		CAFile:       caSavePath,
		CASHA256:     finalPin.Digest,
		TrustMode:    "pinned",
		TOFUTrusted:  true,
		TOFULeafOnly: len(finalCerts) == 1 && !finalCerts[0].IsCA,
	}, nil
}

func loadExistingPin(profilePinPath, hostPinPath, caSavePath, hostCAPath string, now time.Time) (CAPin, bool, error) {
	pPin, pErr := readPinFile(profilePinPath)
	pExists := pErr == nil
	if pErr != nil && !errors.Is(pErr, os.ErrNotExist) {
		return CAPin{}, false, pErr
	}
	hPin, hErr := readPinFile(hostPinPath)
	hExists := hErr == nil
	if hErr != nil && !errors.Is(hErr, os.ErrNotExist) {
		return CAPin{}, false, hErr
	}
	if !pExists && !hExists {
		return CAPin{}, false, nil
	}
	if pExists && hExists {
		var certs []*x509.Certificate
		for _, candidate := range []string{caSavePath, hostCAPath} {
			if candidate != "" {
				if raw, err := os.ReadFile(candidate); err == nil {
					if parsed, _, perr := parsePEMCerts(raw, now); perr == nil {
						certs = parsed
						break
					}
				}
			}
		}
		if !pinsEquivalentForCerts(pPin, hPin, certs) {
			return CAPin{}, false, newTrustError("pinned ca fingerprint conflict (%s != %s); refusing connection", pPin.String(), hPin.String())
		}
		if pPin.Version >= hPin.Version {
			return pPin, true, nil
		}
		return hPin, true, nil
	}
	if pExists {
		return pPin, true, nil
	}
	return hPin, true, nil
}

func pinnedHTTPClient(certs []*x509.Certificate, pemBytes []byte, host string) (*http.Client, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, newTrustError("ca file is not a certificate")
	}
	allowedRoots := make(map[string]struct{}, len(certs))
	for _, c := range certs {
		allowedRoots[CertSHA256Hex(c)] = struct{}{}
	}

	tlsCfg := &tls.Config{
		RootCAs:    pool,
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}
	if len(certs) == 1 && !certs[0].IsCA {
		pinnedLeaf := CertSHA256Hex(certs[0])
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return newTrustError("missing peer certificate")
			}
			if CertSHA256Hex(cs.PeerCertificates[0]) != pinnedLeaf {
				return newTrustError("tls certificate fingerprint mismatch")
			}
			if len(cs.VerifiedChains) == 0 {
				return newTrustError("tls certificate chain was not verified")
			}
			return nil
		}
	} else {
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return newTrustError("missing peer certificate")
			}
			if len(cs.VerifiedChains) == 0 {
				return newTrustError("tls certificate chain was not verified")
			}
			for _, chain := range cs.VerifiedChains {
				if len(chain) == 0 {
					continue
				}
				root := chain[len(chain)-1]
				if _, ok := allowedRoots[CertSHA256Hex(root)]; ok {
					return nil
				}
			}
			return newTrustError("tls verified chain did not terminate at a pinned ca")
		}
	}
	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirect refused")
		},
	}, nil
}

func systemPinnedHTTPClient(pin CAPin, host string) *http.Client {
	tlsCfg := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.VerifiedChains) == 0 {
				return newTrustError("tls certificate chain was not verified")
			}
			if !pinMatchesVerifiedChains(pin, cs.VerifiedChains) {
				return newTrustError("tls certificate fingerprint mismatch")
			}
			return nil
		},
	}
	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirect refused")
		},
	}
}

func pinMatchesVerifiedChains(pin CAPin, chains [][]*x509.Certificate) bool {
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		if verifyCertsMatchPin([]*x509.Certificate{chain[len(chain)-1]}, pin) == nil {
			return true
		}
	}
	return false
}

// verifyLeafAgainstCA verifies peerCerts[0] using peerCerts[1:] as intermediates
// against the provided trust roots, enforcing hostname, validity window, and ServerAuth.
func verifyLeafAgainstCA(peerCerts []*x509.Certificate, roots []*x509.Certificate, host string, now time.Time) ([][]*x509.Certificate, error) {
	if len(peerCerts) == 0 || len(roots) == 0 {
		return nil, newTrustError("missing certificate")
	}
	rootPool := x509.NewCertPool()
	for _, c := range roots {
		rootPool.AddCert(c)
	}
	var interPool *x509.CertPool
	if len(peerCerts) > 1 {
		interPool = x509.NewCertPool()
		for _, c := range peerCerts[1:] {
			interPool.AddCert(c)
		}
	}
	chains, err := peerCerts[0].Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: interPool,
		DNSName:       host,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return nil, err
	}
	if len(chains) == 0 {
		return nil, newTrustError("no verified certificate chain")
	}
	return chains, nil
}

func leafAllowsServerAuth(leaf *x509.Certificate) bool {
	if len(leaf.ExtKeyUsage) == 0 {
		return true
	}
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth || eku == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func selectTrustCandidate(certs []*x509.Certificate, host string, now time.Time) ([]*x509.Certificate, []byte) {
	interPool := x509.NewCertPool()
	for _, c := range certs[1:] {
		interPool.AddCert(c)
	}
	for i := len(certs) - 1; i >= 1; i-- {
		c := certs[i]
		if !c.IsCA {
			continue
		}
		rootPool := x509.NewCertPool()
		rootPool.AddCert(c)
		if chains, err := certs[0].Verify(x509.VerifyOptions{
			Roots:         rootPool,
			Intermediates: interPool,
			DNSName:       host,
			CurrentTime:   now,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err == nil && len(chains) > 0 {
			return []*x509.Certificate{c}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
		}
	}
	return []*x509.Certificate{certs[0]}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certs[0].Raw})
}

func dialPeerCertificates(ctx context.Context, u *url.URL) ([]*x509.Certificate, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config: &tls.Config{
			ServerName:         u.Hostname(),
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // Used strictly to read peer certs during TOFU; leaf hostname, EKU, and time bounds are verified immediately after dial.
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", hostPortForURL(u))
	if err != nil {
		return nil, fmt.Errorf("tls connect failed: %w", err)
	}
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, errors.New("unexpected non-tls connection")
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("server presented no tls certificates")
	}
	return certs, nil
}

func probeSystemTLS(ctx context.Context, u *url.URL, managerURL string) (*http.Client, []*x509.Certificate, [][]*x509.Certificate, error) {
	hc := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: u.Hostname(),
				MinVersion: tls.VersionTLS12,
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirect refused")
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(managerURL, "/")+"/health/live", nil)
	if err != nil {
		return nil, nil, nil, err
	}
	res, err := hc.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	var certs []*x509.Certificate
	var chains [][]*x509.Certificate
	if res.TLS != nil {
		certs = res.TLS.PeerCertificates
		chains = res.TLS.VerifiedChains
	}
	return hc, certs, chains, nil
}

func verifyHTTPSReachable(ctx context.Context, hc *http.Client, managerURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(managerURL, "/")+"/health/live", nil)
	if err != nil {
		return err
	}
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	return nil
}

func fetchClientInfo(ctx context.Context, hc *http.Client, managerURL string) (ClientInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(managerURL, "/")+"/api/v1/client/info", nil)
	if err != nil {
		return ClientInfo{}, err
	}
	res, err := hc.Do(req)
	if err != nil {
		return ClientInfo{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return ClientInfo{}, fmt.Errorf("client info status %d", res.StatusCode)
	}
	var info ClientInfo
	if err := json.NewDecoder(io.LimitReader(res.Body, 256*1024)).Decode(&info); err != nil {
		return ClientInfo{}, err
	}
	return info, nil
}

func isUnknownAuthorityError(err error) bool {
	var unknown x509.UnknownAuthorityError
	return errors.As(err, &unknown)
}
