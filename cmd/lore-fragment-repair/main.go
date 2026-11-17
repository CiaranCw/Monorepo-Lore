// Command lore-fragment-repair is a migration-only immutable fragment copier.
// It inventories addresses through the Lore CLI, reads exact wire fragments
// from an isolated source Lore server, and writes only absent addresses through
// Lore's official StorageService API.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protowire"

	"lore-monorepo/gen/epic_urc"
)

const (
	storageGet   = "/lore.storage.v1.StorageService/Get"
	storagePut   = "/lore.storage.v1.StorageService/Put"
	storageQuery = "/lore.storage.v1.StorageService/Query"
	// PayloadStoredDurable / reserved / PayloadStoredLocal are store-local
	// observations, not content encoding. Sending them back in PutRequest makes
	// Lore reject an otherwise valid payload.
	payloadStoredMask = uint32(0b111000000000000000000)
)

type options struct {
	Workdir, LoreBin, Source, Destination string
	CAFile, ServerName                    string
	ManagerURL, AuthAddress               string
	Username, PasswordFile                string
	Report, Progress                      string
	Inventory                             string
	AddressFile                           string
	Apply                                 bool
	Workers                               int
}

type address struct {
	Hash    []byte
	Context []byte
}

func (a address) String() string {
	return hex.EncodeToString(a.Hash) + "-" + hex.EncodeToString(a.Context)
}

type fragment struct {
	Address     address
	Flags       uint32
	PayloadSize uint32
	ContentSize uint64
	Payload     []byte
}

type report struct {
	StartedAt          string   `json:"started_at"`
	FinishedAt         string   `json:"finished_at"`
	Workdir            string   `json:"workdir"`
	RepositoryID       string   `json:"repository_id"`
	Branches           int      `json:"branches"`
	Revisions          int      `json:"revisions"`
	RootAddresses      int      `json:"root_addresses"`
	Addresses          int      `json:"addresses"`
	MissingBefore      int      `json:"missing_before"`
	Transferred        int      `json:"transferred"`
	AlreadyPresent     int      `json:"already_present"`
	VerifiedAfter      int      `json:"verified_after"`
	MissingAfter       int      `json:"missing_after"`
	Apply              bool     `json:"apply"`
	MissingAddresses   []string `json:"missing_addresses,omitempty"`
	TransferredAddress []string `json:"transferred_addresses,omitempty"`
}

type rawMessage struct{ data []byte }
type rawCodec struct{}

func (rawCodec) Name() string { return "proto" }
func (rawCodec) Marshal(v any) ([]byte, error) {
	m, ok := v.(*rawMessage)
	if !ok {
		return nil, fmt.Errorf("raw codec: %T", v)
	}
	return m.data, nil
}
func (rawCodec) Unmarshal(data []byte, v any) error {
	m, ok := v.(*rawMessage)
	if !ok {
		return fmt.Errorf("raw codec: %T", v)
	}
	m.data = append(m.data[:0], data...)
	return nil
}

type storageClient struct {
	conn         *grpc.ClientConn
	tokenMu      sync.RWMutex
	token        string
	repositoryID []byte
}

func main() {
	var o options
	flag.StringVar(&o.Workdir, "workdir", "", "existing Lore worktree")
	flag.StringVar(&o.LoreBin, "lore", "lore", "Lore 0.10.1 CLI")
	flag.StringVar(&o.Source, "source", "127.0.0.1:53937", "plaintext source StorageService")
	flag.StringVar(&o.Destination, "destination", "", "destination StorageService")
	flag.StringVar(&o.CAFile, "ca-file", "", "destination CA PEM")
	flag.StringVar(&o.ServerName, "server-name", "localhost", "destination TLS server name")
	flag.StringVar(&o.ManagerURL, "manager", "", "Manager login URL")
	flag.StringVar(&o.AuthAddress, "auth", "", "AuthBridge gRPC address")
	flag.StringVar(&o.Username, "username", "", "service username")
	flag.StringVar(&o.PasswordFile, "password-file", "", "protected username/password file")
	flag.StringVar(&o.Report, "report", "", "protected JSON report")
	flag.StringVar(&o.Progress, "progress", "", "protected progress file")
	flag.StringVar(&o.Inventory, "inventory", "", "protected reusable inventory file")
	flag.StringVar(&o.AddressFile, "address-file", "", "additional fragment addresses, one per line")
	flag.BoolVar(&o.Apply, "apply", false, "transfer missing fragments")
	flag.IntVar(&o.Workers, "workers", 8, "inventory workers")
	flag.Parse()
	if err := run(context.Background(), o); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, o options) error {
	if o.Workdir == "" || o.Destination == "" || o.Report == "" {
		return errors.New("--workdir, --destination and --report are required")
	}
	if o.Workers < 1 || o.Workers > 32 {
		return errors.New("--workers must be between 1 and 32")
	}
	st, err := os.Stat(filepath.Join(o.Workdir, ".lore"))
	if err != nil || !st.IsDir() {
		return errors.New("workdir is not a Lore repository")
	}
	if err := os.MkdirAll(filepath.Dir(o.Report), 0o700); err != nil {
		return err
	}
	started := time.Now().UTC()
	snapshot, err := loadOrCreateInventory(ctx, o)
	if err != nil {
		return err
	}
	repoID, branches, revisions, roots, addresses := snapshot.RepositoryID, snapshot.Branches, snapshot.Revisions, snapshot.Roots, snapshot.Addresses
	repositoryBytes, err := hex.DecodeString(repoID)
	if err != nil || len(repositoryBytes) != 16 {
		return errors.New("invalid repository id from inventory")
	}
	token, err := accessToken(ctx, o, repoID)
	if err != nil {
		return err
	}
	defer wipe([]byte(token))
	dest, err := dialStorage(ctx, o.Destination, o.CAFile, o.ServerName, token, repositoryBytes, false)
	if err != nil {
		return fmt.Errorf("destination: %w", err)
	}
	defer dest.close()
	refreshCtx, stopRefresh := context.WithCancel(ctx)
	defer stopRefresh()
	if o.Username != "" {
		go func() {
			ticker := time.NewTicker(3 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-refreshCtx.Done():
					return
				case <-ticker.C:
					if refreshed, err := accessToken(refreshCtx, o, repoID); err == nil {
						dest.setToken(refreshed)
					}
				}
			}
		}()
	}

	states, err := dest.query(ctx, addresses)
	if err != nil {
		return err
	}
	var missing []address
	already := 0
	for i, state := range states {
		if state == 0 {
			already++
		} else {
			missing = append(missing, addresses[i])
		}
	}
	rep := report{
		StartedAt: started.Format(time.RFC3339Nano), Workdir: o.Workdir,
		RepositoryID: repoID, Branches: len(branches), Revisions: len(revisions),
		RootAddresses: len(roots), Addresses: len(addresses),
		MissingBefore: len(missing), AlreadyPresent: already, Apply: o.Apply,
	}
	for _, a := range missing {
		rep.MissingAddresses = append(rep.MissingAddresses, a.String())
	}
	if err := writeReport(o.Report, rep); err != nil {
		return err
	}
	fmt.Printf("repository=%s branches=%d revisions=%d roots=%d addresses=%d missing=%d apply=%t\n",
		repoID, len(branches), len(revisions), len(roots), len(addresses), len(missing), o.Apply)
	if !o.Apply {
		rep.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return writeReport(o.Report, rep)
	}
	if len(missing) == 0 {
		rep.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return writeReport(o.Report, rep)
	}
	source, err := dialStorage(ctx, o.Source, "", "", "", repositoryBytes, true)
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}
	defer source.close()
	done := loadProgress(o.Progress)
	transferCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan address)
	errs := make(chan error, 1)
	var transferWG sync.WaitGroup
	var progressMu sync.Mutex
	for worker := 0; worker < o.Workers; worker++ {
		transferWG.Add(1)
		go func() {
			defer transferWG.Done()
			for a := range jobs {
				if transferCtx.Err() != nil {
					return
				}
				src, err := source.get(transferCtx, a)
				if err == nil && (src.Address.String() != a.String() || uint32(len(src.Payload)) != src.PayloadSize) {
					err = fmt.Errorf("source identity mismatch")
				}
				if err == nil {
					err = dest.put(transferCtx, src)
				}
				var got fragment
				if err == nil {
					got, err = dest.get(transferCtx, a)
				}
				if err == nil {
					err = sameFragment(src, got)
				}
				if err != nil {
					select {
					case errs <- fmt.Errorf("transfer %s flags=%d wire_flags=%d payload=%d declared=%d content=%d sha256=%x: %w",
						a.String(), src.Flags, src.Flags&^payloadStoredMask, len(src.Payload),
						src.PayloadSize, src.ContentSize, sha256.Sum256(src.Payload), err):
					default:
					}
					cancel()
					return
				}
				progressMu.Lock()
				done[a.String()] = true
				rep.Transferred++
				rep.VerifiedAfter++
				rep.TransferredAddress = append(rep.TransferredAddress, a.String())
				count := rep.Transferred
				saveErr := saveProgress(o.Progress, done)
				if saveErr == nil && (count%100 == 0 || count == len(missing)) {
					fmt.Printf("transferred=%d/%d\n", count, len(missing))
					saveErr = writeReport(o.Report, rep)
				}
				progressMu.Unlock()
				if saveErr != nil {
					select {
					case errs <- saveErr:
					default:
					}
					cancel()
					return
				}
			}
		}()
	}
sendLoop:
	for _, a := range missing {
		select {
		case jobs <- a:
		case <-transferCtx.Done():
			break sendLoop
		}
	}
	close(jobs)
	transferWG.Wait()
	select {
	case err := <-errs:
		return err
	default:
	}
	after, err := dest.query(ctx, addresses)
	if err != nil {
		return err
	}
	for _, state := range after {
		if state != 0 {
			rep.MissingAfter++
		}
	}
	rep.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := writeReport(o.Report, rep); err != nil {
		return err
	}
	if rep.MissingAfter != 0 {
		return fmt.Errorf("%d fragments remain missing", rep.MissingAfter)
	}
	fmt.Printf("complete transferred=%d verified=%d missing_after=0\n", rep.Transferred, rep.VerifiedAfter)
	return nil
}

type inventorySnapshot struct {
	RepositoryID string            `json:"repository_id"`
	Branches     map[string]string `json:"branches"`
	Revisions    []string          `json:"revisions"`
	Roots        []address         `json:"roots"`
	Addresses    []address         `json:"addresses"`
}

func loadOrCreateInventory(ctx context.Context, o options) (inventorySnapshot, error) {
	if o.Inventory != "" {
		if body, err := os.ReadFile(o.Inventory); err == nil {
			var snapshot inventorySnapshot
			if json.Unmarshal(body, &snapshot) == nil && snapshot.RepositoryID != "" && len(snapshot.Addresses) > 0 {
				return addExplicitAddresses(snapshot, o.AddressFile)
			}
		}
	}
	repoID, branches, revisions, roots, addresses, err := inventory(ctx, o)
	if err != nil {
		return inventorySnapshot{}, err
	}
	snapshot := inventorySnapshot{
		RepositoryID: repoID, Branches: branches, Revisions: revisions,
		Roots: roots, Addresses: addresses,
	}
	if o.Inventory != "" {
		body, err := json.Marshal(snapshot)
		if err != nil {
			return inventorySnapshot{}, err
		}
		if err := os.WriteFile(o.Inventory, append(body, '\n'), 0o600); err != nil {
			return inventorySnapshot{}, err
		}
	}
	return addExplicitAddresses(snapshot, o.AddressFile)
}

func addExplicitAddresses(snapshot inventorySnapshot, path string) (inventorySnapshot, error) {
	if path == "" {
		return snapshot, nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return snapshot, err
	}
	seen := map[string]bool{}
	for _, value := range snapshot.Addresses {
		seen[value.String()] = true
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || seen[line] {
			continue
		}
		value, err := parseAddress(line)
		if err != nil {
			return snapshot, err
		}
		snapshot.Addresses = append(snapshot.Addresses, value)
		seen[line] = true
	}
	sort.Slice(snapshot.Addresses, func(i, j int) bool {
		return snapshot.Addresses[i].String() < snapshot.Addresses[j].String()
	})
	return snapshot, nil
}

func inventory(ctx context.Context, o options) (string, map[string]string, []string, []address, []address, error) {
	branchOut, err := loreJSON(ctx, o, "branch", "list", "--repository", o.Workdir)
	if err != nil {
		return "", nil, nil, nil, nil, err
	}
	branches := map[string]string{}
	for _, event := range branchOut {
		if event.TagName != "branchListEntry" {
			continue
		}
		var data struct {
			Name, Latest, Location string
			Archived               bool
		}
		if json.Unmarshal(event.Data, &data) == nil && data.Location == "local" && !data.Archived {
			branches[data.Name] = data.Latest
		}
	}
	if len(branches) == 0 {
		return "", nil, nil, nil, nil, errors.New("no local branches")
	}
	revisionSet := map[string]bool{}
	for branch := range branches {
		events, err := loreJSON(ctx, o, "revision", "history", "--repository", o.Workdir, "--branch", branch, "1000000")
		if err != nil {
			return "", nil, nil, nil, nil, err
		}
		for _, event := range events {
			if event.TagName != "revisionHistoryEntry" {
				continue
			}
			var data struct{ Revision string }
			if json.Unmarshal(event.Data, &data) == nil && len(data.Revision) == 64 {
				revisionSet[data.Revision] = true
			}
		}
	}
	revisions := sortedKeys(revisionSet)
	rootSet := map[string]bool{}
	repoID := ""
	for _, revision := range revisions {
		events, err := loreJSON(ctx, o, "repository", "dump", "--repository", o.Workdir, "--revision", revision)
		if err != nil {
			return "", nil, nil, nil, nil, err
		}
		for _, event := range events {
			switch event.TagName {
			case "repositoryDumpBegin":
				var data struct{ Repository string }
				if json.Unmarshal(event.Data, &data) == nil {
					if repoID == "" {
						repoID = data.Repository
					} else if repoID != data.Repository {
						return "", nil, nil, nil, nil, errors.New("repository id changed during inventory")
					}
				}
			case "repositoryStateDumpNode":
				var data struct{ TypeData string }
				if json.Unmarshal(event.Data, &data) == nil && strings.HasPrefix(data.TypeData, "addr ") {
					rootSet[strings.TrimPrefix(data.TypeData, "addr ")] = true
				}
			}
		}
	}
	roots, err := parseAddresses(sortedKeys(rootSet))
	if err != nil {
		return "", nil, nil, nil, nil, err
	}
	all := map[string]address{}
	jobs := make(chan address)
	errs := make(chan error, o.Workers)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < o.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for root := range jobs {
				events, err := loreJSON(ctx, o, "repository", "store", "immutable", "query", "--recurse", "--repository", o.Workdir, root.String())
				if err != nil {
					errs <- err
					return
				}
				for _, event := range events {
					if event.TagName != "repositoryStoreImmutableQuery" {
						continue
					}
					var data struct {
						Address string
						Status  int
						Payload bool
					}
					if json.Unmarshal(event.Data, &data) != nil || data.Status != 0 || !data.Payload {
						continue
					}
					a, err := parseAddress(data.Address)
					if err != nil {
						errs <- err
						return
					}
					mu.Lock()
					all[a.String()] = a
					mu.Unlock()
				}
			}
		}()
	}
	for _, root := range roots {
		jobs <- root
	}
	close(jobs)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return "", nil, nil, nil, nil, err
		}
	}
	addresses := make([]address, 0, len(all))
	for _, a := range all {
		addresses = append(addresses, a)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].String() < addresses[j].String() })
	return repoID, branches, revisions, roots, addresses, nil
}

type loreEvent struct {
	TagName string          `json:"tagName"`
	Data    json.RawMessage `json:"data"`
}

func loreJSON(ctx context.Context, o options, args ...string) ([]loreEvent, error) {
	argv := append([]string{"--non-interactive", "--offline", "--json"}, args...)
	cmd := exec.CommandContext(ctx, o.LoreBin, argv...)
	cmd.Dir = o.Workdir
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return nil, fmt.Errorf("lore %s: %s", strings.Join(args, " "), string(exit.Stderr))
		}
		return nil, err
	}
	var events []loreEvent
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 64<<10), 16<<20)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var event loreEvent
		if json.Unmarshal(line, &event) == nil {
			events = append(events, event)
		}
	}
	return events, scanner.Err()
}

func dialStorage(ctx context.Context, target, caFile, serverName, token string, repositoryID []byte, plaintext bool) (*storageClient, error) {
	var creds credentials.TransportCredentials
	if plaintext {
		creds = insecure.NewCredentials()
	} else {
		body, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(body) {
			return nil, errors.New("invalid CA PEM")
		}
		creds = credentials.NewTLS(&tls.Config{RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS12})
	}
	conn, err := grpc.DialContext(ctx, target,
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})),
	)
	if err != nil {
		return nil, err
	}
	return &storageClient{conn: conn, token: token, repositoryID: append([]byte(nil), repositoryID...)}, nil
}

func (c *storageClient) close() { _ = c.conn.Close() }

func (c *storageClient) authContext(ctx context.Context) context.Context {
	c.tokenMu.RLock()
	token := c.token
	c.tokenMu.RUnlock()
	pairs := []string{
		"lore-partition-bin", string(c.repositoryID),
		"urc-repository-id-bin", string(c.repositoryID),
	}
	if token != "" {
		pairs = append(pairs, "authorization", "Bearer "+token)
	}
	return metadata.NewOutgoingContext(ctx, metadata.Pairs(pairs...))
}

func (c *storageClient) setToken(token string) {
	c.tokenMu.Lock()
	old := c.token
	c.token = token
	c.tokenMu.Unlock()
	wipe([]byte(old))
}

func (c *storageClient) query(ctx context.Context, addresses []address) ([]int32, error) {
	const batch = 256
	var all []int32
	for start := 0; start < len(addresses); start += batch {
		end := start + batch
		if end > len(addresses) {
			end = len(addresses)
		}
		req := rawMessage{data: encodeQueryRequest(addresses[start:end])}
		var res rawMessage
		if err := c.conn.Invoke(c.authContext(ctx), storageQuery, &req, &res); err != nil {
			return nil, err
		}
		states, err := decodeQueryResponse(res.data)
		if err != nil {
			return nil, err
		}
		if len(states) != end-start {
			return nil, fmt.Errorf("query returned %d states for %d addresses", len(states), end-start)
		}
		all = append(all, states...)
	}
	return all, nil
}

func (c *storageClient) get(ctx context.Context, want address) (fragment, error) {
	desc := &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}
	stream, err := c.conn.NewStream(c.authContext(ctx), desc, storageGet)
	if err != nil {
		return fragment{}, err
	}
	if err := stream.SendMsg(&rawMessage{data: encodeAddress(want)}); err != nil {
		return fragment{}, err
	}
	if err := stream.CloseSend(); err != nil {
		return fragment{}, err
	}
	for {
		var msg rawMessage
		err := stream.RecvMsg(&msg)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fragment{}, err
		}
		got, err := decodeGetResponse(msg.data)
		if err != nil {
			return fragment{}, err
		}
		if got.Address.String() == want.String() {
			return got, nil
		}
	}
	return fragment{}, errors.New("source did not return requested fragment")
}

func (c *storageClient) put(ctx context.Context, value fragment) error {
	desc := &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}
	stream, err := c.conn.NewStream(c.authContext(ctx), desc, storagePut)
	if err != nil {
		return err
	}
	if err := stream.SendMsg(&rawMessage{data: encodePutRequest(value)}); err != nil {
		return err
	}
	if err := stream.CloseSend(); err != nil {
		return err
	}
	found := false
	for {
		var msg rawMessage
		err := stream.RecvMsg(&msg)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		got, code, message, err := decodePutResponse(msg.data)
		if err != nil {
			return err
		}
		if code != 0 {
			return fmt.Errorf("server rejected %s: code=%d message=%s", got.String(), code, message)
		}
		if got.String() == value.Address.String() {
			found = true
		}
	}
	if !found {
		return errors.New("destination did not acknowledge address")
	}
	return nil
}

func accessToken(ctx context.Context, o options, repoID string) (string, error) {
	if o.Username == "" {
		return "", nil
	}
	password, err := passwordFor(o.PasswordFile, o.Username)
	if err != nil {
		return "", err
	}
	defer wipe(password)
	body, _ := json.Marshal(map[string]string{"username": o.Username, "password": string(password)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(o.ManagerURL, "/")+"/api/v1/auth/login", bytes.NewReader(body))
	if err != nil {
		wipe(body)
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	wipe(body)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var login struct {
		IdentityToken string `json:"identity_token"`
	}
	if res.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&login) != nil || login.IdentityToken == "" {
		return "", errors.New("manager login failed")
	}
	conn, err := grpc.DialContext(ctx, o.AuthAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	auth := epic_urc.NewUrcAuthApiClient(conn)
	authCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+login.IdentityToken))
	exchanged, err := auth.ExchangeUserTokenForMultiresourceToken(authCtx,
		&epic_urc.ExchangeUserTokenForMultiresourceTokenRequest{ResourceId: []string{"urc-" + repoID}})
	login.IdentityToken = ""
	if err != nil || exchanged.GetToken().GetUserToken() == "" {
		return "", fmt.Errorf("access token exchange failed: %w", err)
	}
	return exchanged.GetToken().GetUserToken(), nil
}

func passwordFor(path, username string) ([]byte, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer wipe(body)
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == username {
			return []byte(fields[1]), nil
		}
	}
	return nil, errors.New("username not found in password file")
}

func parseAddress(text string) (address, error) {
	parts := strings.Split(text, "-")
	if len(parts) != 2 {
		return address{}, fmt.Errorf("invalid address %q", text)
	}
	hash, err := hex.DecodeString(parts[0])
	if err != nil || len(hash) != 32 {
		return address{}, fmt.Errorf("invalid address hash %q", parts[0])
	}
	context, err := hex.DecodeString(parts[1])
	if err != nil || len(context) == 0 {
		return address{}, fmt.Errorf("invalid address context %q", parts[1])
	}
	return address{Hash: hash, Context: context}, nil
}

func parseAddresses(texts []string) ([]address, error) {
	out := make([]address, 0, len(texts))
	for _, text := range texts {
		a, err := parseAddress(text)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func encodeAddress(a address) []byte {
	var out []byte
	out = appendBytes(out, 1, a.Hash)
	out = appendBytes(out, 2, a.Context)
	return out
}

func decodeAddress(data []byte) (address, error) {
	var out address
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return out, protowire.ParseError(n)
		}
		data = data[n:]
		switch num {
		case 1, 2:
			value, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return out, protowire.ParseError(n)
			}
			if num == 1 {
				out.Hash = append([]byte(nil), value...)
			} else {
				out.Context = append([]byte(nil), value...)
			}
			data = data[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return out, protowire.ParseError(n)
			}
			data = data[n:]
		}
	}
	if len(out.Hash) != 32 || len(out.Context) == 0 {
		return out, errors.New("incomplete address")
	}
	return out, nil
}

func encodeFragment(f fragment) []byte {
	var out []byte
	out = appendVarint(out, 1, uint64(f.Flags))
	out = appendVarint(out, 2, uint64(f.PayloadSize))
	out = appendVarint(out, 3, f.ContentSize)
	return out
}

func decodeFragment(data []byte) (fragment, error) {
	var out fragment
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return out, protowire.ParseError(n)
		}
		data = data[n:]
		if typ == protowire.VarintType && (num == 1 || num == 2 || num == 3) {
			value, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return out, protowire.ParseError(n)
			}
			switch num {
			case 1:
				out.Flags = uint32(value)
			case 2:
				out.PayloadSize = uint32(value)
			case 3:
				out.ContentSize = value
			}
			data = data[n:]
			continue
		}
		n = protowire.ConsumeFieldValue(num, typ, data)
		if n < 0 {
			return out, protowire.ParseError(n)
		}
		data = data[n:]
	}
	return out, nil
}

func encodeQueryRequest(addresses []address) []byte {
	var out []byte
	for _, a := range addresses {
		out = appendMessage(out, 1, encodeAddress(a))
	}
	return out
}

func decodeQueryResponse(data []byte) ([]int32, error) {
	var out []int32
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		data = data[n:]
		if num == 1 && typ == protowire.BytesType {
			packed, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			for len(packed) > 0 {
				value, m := protowire.ConsumeVarint(packed)
				if m < 0 {
					return nil, protowire.ParseError(m)
				}
				out = append(out, int32(value))
				packed = packed[m:]
			}
			data = data[n:]
			continue
		}
		if num == 1 && typ == protowire.VarintType {
			value, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			out = append(out, int32(value))
			data = data[n:]
			continue
		}
		n = protowire.ConsumeFieldValue(num, typ, data)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		data = data[n:]
	}
	return out, nil
}

func decodeGetResponse(data []byte) (fragment, error) {
	var out fragment
	var statusCode uint32
	var statusMessage string
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return out, protowire.ParseError(n)
		}
		data = data[n:]
		if typ == protowire.BytesType && (num == 1 || num == 2 || num == 3 || num == 4) {
			value, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return out, protowire.ParseError(n)
			}
			switch num {
			case 1:
				a, err := decodeAddress(value)
				if err != nil {
					return out, err
				}
				out.Address = a
			case 2:
				f, err := decodeFragment(value)
				if err != nil {
					return out, err
				}
				out.Flags, out.PayloadSize, out.ContentSize = f.Flags, f.PayloadSize, f.ContentSize
			case 3:
				out.Payload = append([]byte(nil), value...)
			case 4:
				statusCode, statusMessage, _ = decodeItemStatus(value)
			}
			data = data[n:]
			continue
		}
		n = protowire.ConsumeFieldValue(num, typ, data)
		if n < 0 {
			return out, protowire.ParseError(n)
		}
		data = data[n:]
	}
	if statusCode != 0 {
		return out, fmt.Errorf("get rejected: code=%d message=%s", statusCode, statusMessage)
	}
	return out, nil
}

func encodePutRequest(f fragment) []byte {
	f.Flags &^= payloadStoredMask
	var out []byte
	out = appendMessage(out, 1, encodeAddress(f.Address))
	out = appendMessage(out, 2, encodeFragment(f))
	out = appendBytes(out, 3, f.Payload)
	return out
}

func decodePutResponse(data []byte) (address, uint32, string, error) {
	var out address
	var code uint32
	var message string
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return out, code, message, protowire.ParseError(n)
		}
		data = data[n:]
		if num == 1 && typ == protowire.BytesType {
			value, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return out, code, message, protowire.ParseError(n)
			}
			var err error
			out, err = decodeAddress(value)
			if err != nil {
				return out, code, message, err
			}
			data = data[n:]
			continue
		}
		if num == 2 && typ == protowire.BytesType {
			value, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return out, code, message, protowire.ParseError(n)
			}
			code, message, _ = decodeItemStatus(value)
			data = data[n:]
			continue
		}
		n = protowire.ConsumeFieldValue(num, typ, data)
		if n < 0 {
			return out, code, message, protowire.ParseError(n)
		}
		data = data[n:]
	}
	if len(out.Hash) == 0 {
		return out, code, message, errors.New("put response has no address")
	}
	return out, code, message, nil
}

func decodeItemStatus(data []byte) (uint32, string, error) {
	var code uint32
	var message string
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return code, message, protowire.ParseError(n)
		}
		data = data[n:]
		switch {
		case num == 1 && typ == protowire.VarintType:
			value, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return code, message, protowire.ParseError(n)
			}
			code = uint32(value)
			data = data[n:]
		case num == 2 && typ == protowire.BytesType:
			value, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return code, message, protowire.ParseError(n)
			}
			message = string(value)
			data = data[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return code, message, protowire.ParseError(n)
			}
			data = data[n:]
		}
	}
	return code, message, nil
}

func appendBytes(dst []byte, field protowire.Number, value []byte) []byte {
	dst = protowire.AppendTag(dst, field, protowire.BytesType)
	return protowire.AppendBytes(dst, value)
}
func appendMessage(dst []byte, field protowire.Number, value []byte) []byte {
	return appendBytes(dst, field, value)
}
func appendVarint(dst []byte, field protowire.Number, value uint64) []byte {
	dst = protowire.AppendTag(dst, field, protowire.VarintType)
	return protowire.AppendVarint(dst, value)
}

func sameFragment(a, b fragment) error {
	if a.Address.String() != b.Address.String() ||
		(a.Flags&^payloadStoredMask) != (b.Flags&^payloadStoredMask) || a.PayloadSize != b.PayloadSize ||
		a.ContentSize != b.ContentSize ||
		sha256.Sum256(a.Payload) != sha256.Sum256(b.Payload) {
		return errors.New("fragment metadata or payload differs")
	}
	return nil
}

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func writeReport(path string, value report) error {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(body, '\n'), 0o600)
}

func loadProgress(path string) map[string]bool {
	out := map[string]bool{}
	if path == "" {
		return out
	}
	body, err := os.ReadFile(path)
	if err == nil {
		_ = json.Unmarshal(body, &out)
	}
	return out
}

func saveProgress(path string, value map[string]bool) error {
	if path == "" {
		return nil
	}
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(body, '\n'), 0o600)
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
