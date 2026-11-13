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
	"strings"
	"time"
)

// CheckCA reads a PEM certificate and rejects one that is expired or not yet valid.
// An empty path means the caller is not pinning a CA.
func CheckCA(path string, now time.Time) error {
	if path == "" {
		return nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return errors.New("ca file is unreadable")
	}
	_, _, err = parsePEMCerts(body, now)
	return err
}

func parsePEMCerts(body []byte, now time.Time) ([]*x509.Certificate, []byte, error) {
	var certs []*x509.Certificate
	var clean bytes.Buffer
	rest := body
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, errors.New("ca file is not a certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, errors.New("ca file is not a certificate")
		}
		if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return nil, nil, errors.New("ca certificate is not currently valid")
		}
		certs = append(certs, cert)
		_ = pem.Encode(&clean, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	if len(certs) == 0 {
		return nil, nil, errors.New("ca file is not a certificate")
	}
	return certs, clean.Bytes(), nil
}

// CertSHA256Hex returns the lowercase hex SHA-256 fingerprint of a certificate's DER bytes.
func CertSHA256Hex(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
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

func readPinFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", os.ErrNotExist
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	pin := strings.TrimSpace(string(body))
	pin = strings.TrimPrefix(strings.ToLower(pin), "sha256:")
	if len(pin) != 64 {
		return "", errors.New("invalid ca pin")
	}
	return pin, nil
}

func writePinFile(path, sha string) error {
	if strings.TrimSpace(path) == "" || strings.TrimSpace(sha) == "" {
		return nil
	}
	return writeFile(path, []byte(strings.ToLower(strings.TrimSpace(sha))+"\n"))
}

// HTTPClient trusts cfg.CAFile when it is set. If a companion .pin file exists,
// it refuses to trust a modified CA or mismatched leaf certificate.
// It does not change the process environment.
func HTTPClient(cfg Config) *http.Client {
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("redirect refused")
	}}
	if cfg.CAFile == "" {
		return client
	}
	body, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return client
	}
	certs, _, parseErr := parsePEMCerts(body, time.Now())
	if parseErr != nil {
		client.Transport = failingTransport{err: parseErr}
		return client
	}
	if pin, pinErr := readPinFile(PinPathForCA(cfg.CAFile)); pinErr == nil {
		actual := CertSHA256Hex(certs[0])
		if actual != pin {
			client.Transport = failingTransport{err: fmt.Errorf("tls ca fingerprint mismatch: expected %s, got %s", pin, actual)}
			return client
		}
	} else if !errors.Is(pinErr, os.ErrNotExist) {
		client.Transport = failingTransport{err: pinErr}
		return client
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(body) {
		return client
	}
	tlsCfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if len(certs) == 1 && !certs[0].IsCA {
		pinnedLeaf := CertSHA256Hex(certs[0])
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("missing peer certificate")
			}
			if CertSHA256Hex(cs.PeerCertificates[0]) != pinnedLeaf {
				return errors.New("tls certificate fingerprint mismatch")
			}
			return nil
		}
	}
	client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	return client
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

func bootstrapTLSAndInfo(ctx context.Context, managerURL, explicitCAFile, caSavePath, profilePinPath, hostPinPath, hostCAPath string) (tlsBootstrapResult, error) {
	u, err := url.Parse(managerURL)
	if err != nil {
		return tlsBootstrapResult{}, errors.New("invalid manager url")
	}
	if u.Scheme == "http" {
		info, _ := fetchClientInfo(ctx, &http.Client{Timeout: 10 * time.Second}, managerURL)
		return tlsBootstrapResult{Info: info}, nil
	}

	now := time.Now()
	existingPin, err := loadExistingPin(profilePinPath, hostPinPath)
	if err != nil {
		return tlsBootstrapResult{}, err
	}

	// Case 1: Caller explicitly passed --ca-file.
	if strings.TrimSpace(explicitCAFile) != "" {
		raw, err := os.ReadFile(explicitCAFile)
		if err != nil {
			return tlsBootstrapResult{}, errors.New("ca file is unreadable")
		}
		certs, cleanPEM, err := parsePEMCerts(raw, now)
		if err != nil {
			return tlsBootstrapResult{}, err
		}
		sha := CertSHA256Hex(certs[0])
		if existingPin != "" && existingPin != sha {
			return tlsBootstrapResult{}, fmt.Errorf("ca certificate fingerprint mismatch (expected %s, got %s); refusing connection", existingPin, sha)
		}
		hc, err := pinnedHTTPClient(certs, cleanPEM, sha, u.Hostname())
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
		if err := writePinFile(profilePinPath, sha); err != nil {
			return tlsBootstrapResult{}, err
		}
		if err := writePinFile(hostPinPath, sha); err != nil {
			return tlsBootstrapResult{}, err
		}
		if hostCAPath != "" {
			_ = writeFile(hostCAPath, cleanPEM)
		}
		info, _ := fetchClientInfo(ctx, hc, managerURL)
		return tlsBootstrapResult{Info: info, CAFile: targetCA, CASHA256: sha}, nil
	}

	// Case 2: Pin already exists for this profile or Manager URL -> strictly enforce it, never re-TOFU.
	if existingPin != "" {
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
				return tlsBootstrapResult{}, errors.New("pinned ca file is unreadable")
			}
			certs, cleanPEM, err := parsePEMCerts(raw, now)
			if err != nil {
				return tlsBootstrapResult{}, err
			}
			actual := CertSHA256Hex(certs[0])
			if actual != existingPin {
				return tlsBootstrapResult{}, fmt.Errorf("tls certificate fingerprint changed (expected %s, got %s); refusing connection", existingPin, actual)
			}
			hc, err := pinnedHTTPClient(certs, cleanPEM, existingPin, u.Hostname())
			if err != nil {
				return tlsBootstrapResult{}, err
			}
			if err := verifyHTTPSReachable(ctx, hc, managerURL); err != nil {
				return tlsBootstrapResult{}, fmt.Errorf("tls verification against pinned certificate failed: %w", err)
			}
			if caSavePath != "" && certPath != caSavePath {
				if err := writeFile(caSavePath, cleanPEM); err != nil {
					return tlsBootstrapResult{}, err
				}
			}
			_ = writePinFile(profilePinPath, existingPin)
			_ = writePinFile(hostPinPath, existingPin)
			info, _ := fetchClientInfo(ctx, hc, managerURL)
			return tlsBootstrapResult{Info: info, CAFile: caSavePath, CASHA256: existingPin}, nil
		}

		// Publicly trusted host previously pinned without a local CA file: verify system TLS + matching root/leaf pin.
		sysHC, peerCerts, err := probeSystemTLS(ctx, u, managerURL)
		if err != nil {
			return tlsBootstrapResult{}, err
		}
		if !pinMatchesPeerChain(existingPin, peerCerts) {
			got := ""
			if len(peerCerts) > 0 {
				got = CertSHA256Hex(peerCerts[len(peerCerts)-1])
			}
			return tlsBootstrapResult{}, fmt.Errorf("tls certificate fingerprint changed (expected %s, got %s); refusing connection", existingPin, got)
		}
		info, _ := fetchClientInfo(ctx, sysHC, managerURL)
		return tlsBootstrapResult{Info: info, CASHA256: existingPin}, nil
	}

	// Case 3: First connection (no pin yet). First try standard system roots.
	sysHC, peerCerts, sysErr := probeSystemTLS(ctx, u, managerURL)
	if sysErr == nil {
		info, _ := fetchClientInfo(ctx, sysHC, managerURL)
		var sha string
		if len(peerCerts) > 0 {
			sha = CertSHA256Hex(peerCerts[len(peerCerts)-1])
		}
		savedCA := ""
		if strings.TrimSpace(info.CAPEM) != "" && len(peerCerts) > 0 {
			if caCerts, cleanCA, err := parsePEMCerts([]byte(info.CAPEM), now); err == nil {
				if verifyLeafAgainstCA(peerCerts[0], caCerts, u.Hostname(), now) == nil {
					sha = CertSHA256Hex(caCerts[0])
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
		_ = writePinFile(profilePinPath, sha)
		_ = writePinFile(hostPinPath, sha)
		return tlsBootstrapResult{Info: info, CAFile: savedCA, CASHA256: sha}, nil
	}

	// Reject hostname/expiry/certificate validity errors immediately; only allow TOFU on unknown authority.
	if !isUnknownAuthorityError(sysErr) {
		return tlsBootstrapResult{}, fmt.Errorf("tls verification failed: %w", sysErr)
	}

	// Explicit TOFU probe: connect only to inspect certificates, immediately validate SAN/hostname & time bounds.
	certs, err := dialPeerCertificates(ctx, u)
	if err != nil {
		return tlsBootstrapResult{}, err
	}
	leaf := certs[0]
	for _, c := range certs {
		if now.Before(c.NotBefore) || !now.Before(c.NotAfter) {
			return tlsBootstrapResult{}, errors.New("server tls certificate is expired or not yet valid")
		}
	}
	if err := leaf.VerifyHostname(u.Hostname()); err != nil {
		return tlsBootstrapResult{}, fmt.Errorf("server tls certificate hostname mismatch: %w", err)
	}

	candidateCerts, candidatePEM := selectTrustCandidate(certs, u.Hostname(), now)
	candidateSHA := CertSHA256Hex(candidateCerts[0])
	bootstrapHC, err := pinnedHTTPClient(candidateCerts, candidatePEM, candidateSHA, u.Hostname())
	if err != nil {
		return tlsBootstrapResult{}, err
	}
	info, _ := fetchClientInfo(ctx, bootstrapHC, managerURL)

	finalCerts := candidateCerts
	finalPEM := candidatePEM
	finalSHA := candidateSHA
	if strings.TrimSpace(info.CAPEM) != "" {
		caCerts, cleanCA, err := parsePEMCerts([]byte(info.CAPEM), now)
		if err != nil {
			return tlsBootstrapResult{}, fmt.Errorf("manager returned invalid ca_pem: %w", err)
		}
		if err := verifyLeafAgainstCA(leaf, caCerts, u.Hostname(), now); err != nil {
			return tlsBootstrapResult{}, fmt.Errorf("manager ca_pem does not verify server certificate: %w", err)
		}
		finalCerts = caCerts
		finalPEM = cleanCA
		finalSHA = CertSHA256Hex(finalCerts[0])
	}

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
	if err := writePinFile(profilePinPath, finalSHA); err != nil {
		return tlsBootstrapResult{}, err
	}
	if err := writePinFile(hostPinPath, finalSHA); err != nil {
		return tlsBootstrapResult{}, err
	}
	return tlsBootstrapResult{
		Info:         info,
		CAFile:       caSavePath,
		CASHA256:     finalSHA,
		TOFUTrusted:  true,
		TOFULeafOnly: len(finalCerts) > 0 && !finalCerts[0].IsCA,
	}, nil
}

func loadExistingPin(profilePinPath, hostPinPath string) (string, error) {
	pPin, pErr := readPinFile(profilePinPath)
	if pErr != nil && !errors.Is(pErr, os.ErrNotExist) {
		return "", pErr
	}
	hPin, hErr := readPinFile(hostPinPath)
	if hErr != nil && !errors.Is(hErr, os.ErrNotExist) {
		return "", hErr
	}
	if pPin != "" && hPin != "" && pPin != hPin {
		return "", fmt.Errorf("pinned ca fingerprint conflict (%s != %s); refusing connection", pPin, hPin)
	}
	if pPin != "" {
		return pPin, nil
	}
	return hPin, nil
}

func pinnedHTTPClient(certs []*x509.Certificate, pemBytes []byte, pinnedSHA, host string) (*http.Client, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("ca file is not a certificate")
	}
	tlsCfg := &tls.Config{
		RootCAs:    pool,
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}
	if len(certs) == 1 && !certs[0].IsCA {
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("missing peer certificate")
			}
			if CertSHA256Hex(cs.PeerCertificates[0]) != pinnedSHA {
				return errors.New("tls certificate fingerprint mismatch")
			}
			return nil
		}
	} else {
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("missing peer certificate")
			}
			if !pinMatchesPeerChain(pinnedSHA, cs.PeerCertificates) && verifyLeafAgainstCA(cs.PeerCertificates[0], certs, host, time.Now()) != nil {
				return errors.New("tls certificate does not chain to pinned ca")
			}
			return nil
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

func pinMatchesPeerChain(pin string, certs []*x509.Certificate) bool {
	for _, c := range certs {
		if CertSHA256Hex(c) == pin {
			return true
		}
	}
	return false
}

func verifyLeafAgainstCA(leaf *x509.Certificate, caCerts []*x509.Certificate, host string, now time.Time) error {
	pool := x509.NewCertPool()
	for _, c := range caCerts {
		pool.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:       pool,
		DNSName:     host,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
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
		if _, err := certs[0].Verify(x509.VerifyOptions{
			Roots:         rootPool,
			Intermediates: interPool,
			DNSName:       host,
			CurrentTime:   now,
		}); err == nil {
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
			InsecureSkipVerify: true, // Used strictly for TOFU cert inspection; validated with VerifyHostname & validity window before use.
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

func probeSystemTLS(ctx context.Context, u *url.URL, managerURL string) (*http.Client, []*x509.Certificate, error) {
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
		return nil, nil, err
	}
	res, err := hc.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	var certs []*x509.Certificate
	if res.TLS != nil {
		certs = res.TLS.PeerCertificates
	}
	return hc, certs, nil
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
	if errors.As(err, &unknown) {
		return true
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "unknown authority") ||
		strings.Contains(msg, "certificate signed by unknown authority") ||
		strings.Contains(msg, "self-signed") ||
		strings.Contains(msg, "certificate is not trusted") {
		return true
	}
	return false
}
