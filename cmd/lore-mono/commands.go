package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"lore-monorepo/internal/client"
	"lore-monorepo/internal/loreexec"
)

func dispatch(args []string) error {
	switch args[0] {
	case "logout":
		return logout(args[1:])
	case "project":
		return projectCmd(args[1:])
	case "module":
		return moduleCmd(args[1:])
	case "clone":
		return cloneCmd(args[1:])
	case "status":
		return statusCmd(args[1:])
	case "sync":
		return batchAction("sync", args[1:])
	case "stage":
		return batchAction("stage", args[1:])
	case "commit":
		return batchAction("commit", args[1:])
	case "push":
		return batchAction("push", args[1:])
	case "publish":
		return publishCmd(args[1:])
	case "history":
		return historyCmd(args[1:])
	case "refs":
		return refsCmd(args[1:])
	case "show":
		return showCmd(args[1:])
	case "import":
		return importCmd(args[1:])
	default:
		return fmt.Errorf("unknown command")
	}
}

func logout(args []string) error {
	cfg, err := loadCmd(args)
	if err != nil {
		return err
	}
	_ = client.DeleteSession(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := execRun(ctx, cfg.LoreBinary, loreexec.Request{Argv: []string{"auth", "logout"}, Env: loreEnv(cfg)})
	if err != nil || res.ExitCode != 0 {
		return fmt.Errorf("logout failed")
	}
	fmt.Fprintln(stdout, "logged out")
	return nil
}

func projectCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("project needs list or use")
	}
	switch args[0] {
	case "list":
		body, err := managerGET(args[1:], "/api/v1/projects")
		if err != nil {
			return err
		}
		var parsed struct {
			Projects []struct {
				Name string
			}
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return fmt.Errorf("project list failed")
		}
		for _, p := range parsed.Projects {
			fmt.Fprintln(stdout, p.Name)
		}
		return nil
	case "use":
		if len(args) < 2 {
			return fmt.Errorf("project use needs a name")
		}
		cfg, err := loadCmd(args[2:])
		if err != nil {
			return err
		}
		cfg.Project = args[1]
		if err := client.Save(cfg); err != nil {
			return err
		}
		fmt.Fprintln(stdout, cfg.Project)
		return nil
	default:
		return fmt.Errorf("unknown project command")
	}
}

func moduleCmd(args []string) error {
	if len(args) == 0 || args[0] != "list" {
		return fmt.Errorf("module needs list")
	}
	body, err := managerGET(args[1:], "/api/v1/me/modules")
	if err != nil {
		return err
	}
	var parsed struct {
		Modules []struct {
			ProjectName   string
			Name          string
			MountPath     string
			RepositoryURL string
			Permission    string
		}
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("module list failed")
	}
	cfg, _ := loadCmd(args[1:])
	for _, m := range parsed.Modules {
		if cfg.Project != "" && m.ProjectName != cfg.Project {
			continue
		}
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n", m.Name, m.MountPath, m.Permission, m.RepositoryURL)
	}
	return nil
}

func cloneCmd(args []string) error {
	if hasAny(args, "--all-authorized", "--all") {
		return batchAction("clone", args)
	}
	if len(args) == 0 {
		return fmt.Errorf("clone needs a module")
	}
	name := args[0]
	dest, cfg, rest, err := parseDest(args[1:])
	if err != nil {
		return err
	}
	body, err := managerGET(rest, "/api/v1/me/modules")
	if err != nil {
		return err
	}
	var parsed struct {
		Modules []struct {
			ProjectName   string
			Name          string
			MountPath     string
			RepositoryURL string
			DefaultBranch string
		}
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("clone failed")
	}
	var chosen *struct {
		ProjectName, Name, MountPath, RepositoryURL, DefaultBranch string
	}
	for _, m := range parsed.Modules {
		if cfg.Project != "" && m.ProjectName != cfg.Project {
			continue
		}
		if m.Name == name {
			item := m
			chosen = &struct {
				ProjectName, Name, MountPath, RepositoryURL, DefaultBranch string
			}{item.ProjectName, item.Name, item.MountPath, item.RepositoryURL, item.DefaultBranch}
			break
		}
	}
	if chosen == nil {
		return fmt.Errorf("module is not accessible")
	}
	if dest == "" {
		dest = chosen.MountPath
	}
	if err := ensureLoreCredential(cfg); err != nil {
		return err
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return fmt.Errorf("clone failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	res, err := execRun(ctx, cfg.LoreBinary, loreexec.Request{Argv: []string{"clone", chosen.RepositoryURL, dest}, Env: loreEnv(cfg)})
	if err != nil || res.ExitCode != 0 {
		_ = os.RemoveAll(dest)
		return fmt.Errorf("clone failed")
	}
	if err := switchDefaultBranch(ctx, cfg, dest, chosen.DefaultBranch); err != nil {
		_ = os.RemoveAll(dest)
		return err
	}
	fmt.Fprintln(stdout, dest)
	return nil
}

func statusCmd(args []string) error {
	if hasAny(args, "--all") || (len(args) > 0 && !strings.HasPrefix(args[0], "--")) {
		return batchAction("status", args)
	}
	cfg, err := loadCmd(args)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := execRun(ctx, cfg.LoreBinary, loreexec.Request{Argv: []string{"status"}, Env: loreEnv(cfg)})
	if err != nil || res.ExitCode != 0 {
		return fmt.Errorf("status failed")
	}
	fmt.Fprint(stdout, res.Stdout)
	return nil
}

func publishCmd(args []string) error {
	cfg, err := loadCmd(args)
	if err != nil {
		return err
	}
	if cfg.Project == "" {
		return fmt.Errorf("publish needs a selected project")
	}
	token, err := identityToken(cfg)
	if err != nil {
		return err
	}
	defer wipe([]byte(token))
	payload, _ := json.Marshal(map[string]string{"message": "publish module pins"})
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(cfg.ManagerURL, "/")+"/api/v1/projects/"+cfg.Project+"/publish", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("publish failed")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.HTTPClient(cfg).Do(req)
	if err != nil {
		if client.IsTrustError(err) {
			return err
		}
		return fmt.Errorf("publish failed")
	}
	defer res.Body.Close()
	resp, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("publish failed")
	}
	fmt.Fprintln(stdout, strings.TrimSpace(string(resp)))
	return nil
}

func batchAction(action string, args []string) error {
	all := hasAny(args, "--all", "--all-authorized")
	root := "."
	message := "update"
	var names []string
	var rest []string
	for i := 0; i < len(args); i++ {
		name, val, ok := splitFlag(args[i])
		switch name {
		case "--all", "--all-authorized":
			all = true
		case "--root", "--message", "--config", "--manager", "--lore-binary", "--auth-url", "--auth-path", "--auth-store":
			if !ok {
				if i+1 >= len(args) {
					return fmt.Errorf("missing value")
				}
				i++
				val = args[i]
			}
			switch name {
			case "--root":
				root = val
			case "--message":
				message = val
			default:
				rest = append(rest, name, val)
			}
		default:
			if strings.HasPrefix(args[i], "--") {
				rest = append(rest, args[i])
				continue
			}
			names = append(names, args[i])
		}
	}
	if !all && len(names) == 0 {
		return fmt.Errorf("%s needs a module", action)
	}
	if action == "commit" && strings.TrimSpace(message) == "" {
		return fmt.Errorf("commit needs a message")
	}
	cfg, err := loadCmd(rest)
	if err != nil {
		return err
	}
	payload := map[string]any{"action": action}
	if cfg.Project != "" {
		payload["project"] = cfg.Project
	}
	if !all {
		payload["modules"] = names
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("%s failed", action)
	}
	raw, err := managerPOST(cfg, "/api/v1/me/batch", body)
	if err != nil {
		return err
	}
	var parsed struct {
		Results []struct {
			ProjectName   string
			Name          string
			MountPath     string
			RepositoryURL string
			DefaultBranch string
		}
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return fmt.Errorf("%s failed", action)
	}
	if !all && len(parsed.Results) == 0 {
		return fmt.Errorf("module is not accessible")
	}
	if err := ensureLoreCredential(cfg); err != nil {
		return err
	}
	okN, skipN, failN := 0, 0, 0
	for _, item := range parsed.Results {
		limit := 2 * time.Minute
		if action == "clone" {
			limit = 45 * time.Minute
		}
		ctx, cancel := context.WithTimeout(context.Background(), limit)
		dir := filepath.Join(root, item.MountPath)
		var argv []string
		runDir := ""
		switch action {
		case "clone":
			argv = []string{"clone", item.RepositoryURL, dir}
		case "status":
			argv = []string{"status", "--revision-only", "--repository", dir}
		case "sync":
			argv = []string{"sync", "--repository", dir}
		case "stage":
			if !isClonedLoreDir(dir) {
				cancel()
				skipN++
				fmt.Fprintf(stdout, "[SKIP] %s (not cloned)\n", item.Name)
				continue
			}
			runDir = dir
			argv = []string{"stage", "--scan", "--repository", dir, "."}
		case "commit":
			argv = []string{"commit", "--repository", dir, message}
		case "push":
			argv = []string{"push", "--repository", dir}
		}
		res, err := execRun(ctx, cfg.LoreBinary, loreexec.Request{Argv: argv, Dir: runDir, Env: loreEnv(cfg)})
		if err != nil || res.ExitCode != 0 {
			cancel()
			failN++
			if action == "stage" {
				fmt.Fprintf(stdout, "[FAIL] %s\n", item.Name)
			} else {
				fmt.Fprintf(stdout, "%s\t%s\tfailed\n", item.ProjectName, item.Name)
			}
			continue
		}
		if action == "clone" {
			if err := switchDefaultBranch(ctx, cfg, dir, item.DefaultBranch); err != nil {
				cancel()
				_ = os.RemoveAll(dir)
				failN++
				fmt.Fprintf(stdout, "%s\t%s\tfailed\n", item.ProjectName, item.Name)
				continue
			}
		}
		cancel()
		okN++
		if action == "stage" {
			fmt.Fprintf(stdout, "[OK] %s\n", item.Name)
		} else {
			fmt.Fprintf(stdout, "%s\t%s\tok\n", item.ProjectName, item.Name)
		}
	}
	if action == "stage" {
		fmt.Fprintf(stdout, "summary ok=%d skipped=%d failed=%d\n", okN, skipN, failN)
	} else {
		fmt.Fprintf(stdout, "summary ok=%d failed=%d\n", okN, failN)
	}
	if failN > 0 {
		return fmt.Errorf("%s failed", action)
	}
	return nil
}

func isClonedLoreDir(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, ".lore"))
	return err == nil && info.IsDir()
}

func hasAny(args []string, flags ...string) bool {
	for _, arg := range args {
		name, _, _ := splitFlag(arg)
		for _, flag := range flags {
			if name == flag {
				return true
			}
		}
	}
	return false
}

func changePasswordCmd(args []string) error {
	for _, arg := range args {
		if strings.HasPrefix(arg, "--password=") || arg == "--password" {
			return fmt.Errorf("password must not be passed as an argument")
		}
	}
	cfg, err := loadCmd(args)
	if err != nil {
		return err
	}
	stdinPassword := false
	for _, arg := range args {
		if arg == "--password-stdin" {
			stdinPassword = true
		}
	}
	var password []byte
	if stdinPassword {
		line, err := readLine()
		if err != nil {
			return fmt.Errorf("password failed")
		}
		password = []byte(strings.TrimRight(line, "\r\n"))
	} else {
		fmt.Fprint(stderr, "New password: ")
		password, err = readPassword()
		fmt.Fprintln(stderr)
		if err != nil {
			return fmt.Errorf("password failed")
		}
		fmt.Fprint(stderr, "Confirm password: ")
		again, againErr := readPassword()
		fmt.Fprintln(stderr)
		if againErr != nil {
			wipe(password)
			return fmt.Errorf("password failed")
		}
		if string(password) != string(again) {
			wipe(password)
			wipe(again)
			return fmt.Errorf("password failed")
		}
		wipe(again)
	}
	defer wipe(password)
	if len(password) == 0 {
		return fmt.Errorf("password failed")
	}
	payload, err := json.Marshal(map[string]string{"password": string(password)})
	if err != nil {
		return fmt.Errorf("password failed")
	}
	defer wipe(payload)
	token, err := identityToken(cfg)
	if err != nil {
		return err
	}
	defer wipe([]byte(token))
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(cfg.ManagerURL, "/")+"/api/v1/auth/password", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("password failed")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.HTTPClient(cfg).Do(req)
	if err != nil {
		if client.IsTrustError(err) {
			return err
		}
		return fmt.Errorf("password failed")
	}
	defer res.Body.Close()
	resp, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("password failed")
	}
	if bytes.Contains(resp, password) {
		return fmt.Errorf("password failed")
	}
	fmt.Fprintln(stdout, "password updated")
	return nil
}

func switchDefaultBranch(ctx context.Context, cfg client.Config, dir, branch string) error {
	branch = strings.TrimSpace(branch)
	if branch == "" {
		return nil
	}
	res, err := execRun(ctx, cfg.LoreBinary, loreexec.Request{
		Argv: []string{"branch", "switch", "--reset", "--repository", dir, branch},
		Env:  loreEnv(cfg),
	})
	if err != nil || res.ExitCode != 0 {
		return fmt.Errorf("clone failed")
	}
	return nil
}

func managerPOST(cfg client.Config, path string, payload []byte) ([]byte, error) {
	token, err := identityToken(cfg)
	if err != nil {
		return nil, err
	}
	defer wipe([]byte(token))
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(cfg.ManagerURL, "/")+path, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("request failed")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.HTTPClient(cfg).Do(req)
	if err != nil {
		if client.IsTrustError(err) {
			return nil, err
		}
		return nil, fmt.Errorf("request failed")
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed")
	}
	return body, nil
}

func managerGET(args []string, path string) ([]byte, error) {
	cfg, err := loadCmd(args)
	if err != nil {
		return nil, err
	}
	token, err := identityToken(cfg)
	if err != nil {
		return nil, err
	}
	defer wipe([]byte(token))
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(cfg.ManagerURL, "/")+path, nil)
	if err != nil {
		return nil, fmt.Errorf("request failed")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.HTTPClient(cfg).Do(req)
	if err != nil {
		if client.IsTrustError(err) {
			return nil, err
		}
		return nil, fmt.Errorf("request failed")
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed")
	}
	return body, nil
}

func identityToken(cfg client.Config) (string, error) {
	if tok, err := client.LoadSession(cfg); err == nil && len(tok) > 0 {
		s := string(tok)
		wipe(tok)
		return s, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := execRun(ctx, cfg.LoreBinary, loreexec.Request{Argv: []string{"auth", "list", "--with-token"}, Env: loreEnv(cfg)})
	if err != nil || res.ExitCode != 0 {
		return "", fmt.Errorf("not logged in")
	}
	for _, line := range strings.Split(res.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Token:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Token:")), nil
		}
	}
	return "", fmt.Errorf("not logged in")
}

func ensureLoreCredential(cfg client.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if execRun == nil {
		return client.EnsureLoreCredential(ctx, cfg, newExecutor(cfg.LoreBinary))
	}
	return client.EnsureLoreCredentialWith(ctx, cfg, func(c context.Context, req loreexec.Request) (loreexec.CommandResult, error) {
		return execRun(c, cfg.LoreBinary, req)
	})
}

func loadCmd(args []string) (client.Config, error) {
	flags, err := parseLogin(args)
	if err != nil {
		return client.Config{}, err
	}
	cfg := client.Config{LoreBinary: "lore"}
	if flags.configPath != "" {
		loaded, err := client.Load(flags.configPath)
		if err != nil {
			return client.Config{}, fmt.Errorf("client config")
		}
		cfg = loaded
	} else if flags.managerURL == "" {
		if activePath, activeErr := client.ActiveConfigPath(); activeErr == nil && activePath != "" {
			loaded, err := client.Load(activePath)
			if err != nil {
				return client.Config{}, fmt.Errorf("client config")
			}
			cfg = loaded
		}
	}
	if flags.managerURL != "" {
		cfg.ManagerURL = flags.managerURL
	}
	if flags.loreBinary != "" {
		cfg.LoreBinary = flags.loreBinary
	}
	if flags.authPath != "" {
		cfg.AuthPath = flags.authPath
	}
	if flags.authStore != "" {
		cfg.AuthStore = flags.authStore
	}
	if cfg.ManagerURL == "" {
		return client.Config{}, fmt.Errorf("manager url is required")
	}
	if err := client.CheckCA(cfg.CAFile, time.Now()); err != nil {
		return client.Config{}, err
	}
	if err := client.ValidateHTTPTrust(cfg); err != nil {
		return client.Config{}, err
	}
	return cfg, nil
}

func parseDest(args []string) (string, client.Config, []string, error) {
	dest := ""
	var rest []string
	for i := 0; i < len(args); i++ {
		name, val, ok := splitFlag(args[i])
		if name == "--dest" {
			if !ok {
				if i+1 >= len(args) {
					return "", client.Config{}, nil, fmt.Errorf("missing dest")
				}
				i++
				val = args[i]
			}
			dest = val
			continue
		}
		rest = append(rest, args[i])
	}
	cfg, err := loadCmd(rest)
	return dest, cfg, rest, err
}

var execRun = func(ctx context.Context, binary string, req loreexec.Request) (loreexec.CommandResult, error) {
	return newExecutor(binary).Run(ctx, req)
}

func loreEnv(cfg client.Config) map[string]string {
	env := map[string]string{}
	if cfg.AuthStore != "" {
		env["LORE_AUTH_STORE"] = cfg.AuthStore
	}
	if cfg.AuthPath != "" {
		env["LORE_AUTH_PATH"] = cfg.AuthPath
	}
	if cfg.CAFile != "" {
		env["SSL_CERT_FILE"] = cfg.CAFile
	}
	if len(env) == 0 {
		return nil
	}
	return env
}
