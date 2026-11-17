package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"lore-monorepo/internal/client"
)

type connectFlags struct {
	managerURL    string
	username      string
	passwordStdin bool
	project       string
	caFile        string
	retrustCA     bool
	authURL       string
	loreBinary    string
	configPath    string
	authPath      string
	authStore     string
	asJSON        bool
}

func parseConnectFlags(args []string) (connectFlags, error) {
	var f connectFlags
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--password=") || arg == "--password" {
			return f, fmt.Errorf("password must not be passed as an argument")
		}
		name, val, hasEq := splitFlag(arg)
		switch name {
		case "--manager", "--username", "--project", "--ca-file", "--auth-url", "--lore-binary", "--config", "--auth-path", "--auth-store":
			if !hasEq {
				if i+1 >= len(args) {
					return f, fmt.Errorf("missing value for %s", name)
				}
				i++
				val = args[i]
			}
			switch name {
			case "--manager":
				f.managerURL = val
			case "--username":
				f.username = val
			case "--project":
				f.project = val
			case "--ca-file":
				f.caFile = val
			case "--auth-url":
				f.authURL = val
			case "--lore-binary":
				f.loreBinary = val
			case "--config":
				f.configPath = val
			case "--auth-path":
				f.authPath = val
			case "--auth-store":
				f.authStore = val
			}
		case "--password-stdin":
			f.passwordStdin = true
		case "--retrust-ca":
			f.retrustCA = true
		case "--json":
			f.asJSON = true
		default:
			return f, fmt.Errorf("unknown argument %s", arg)
		}
	}
	return f, nil
}

func connectCmd(args []string) error {
	flags, err := parseConnectFlags(args)
	if err != nil {
		return err
	}
	managerURL := strings.TrimSpace(flags.managerURL)
	if managerURL == "" && flags.configPath != "" {
		if loaded, loadErr := client.Load(flags.configPath); loadErr == nil {
			managerURL = loaded.ManagerURL
		}
	}
	if managerURL == "" {
		fmt.Fprint(stderr, "Manager URL: ")
		line, readErr := readLine()
		if readErr != nil {
			return fmt.Errorf("connect failed")
		}
		managerURL = strings.TrimSpace(line)
	}
	if err := client.CheckManagerURL(managerURL); err != nil {
		return err
	}
	username := strings.TrimSpace(flags.username)
	if username == "" {
		fmt.Fprint(stderr, "Username: ")
		line, readErr := readLine()
		if readErr != nil {
			return fmt.Errorf("connect failed")
		}
		username = strings.TrimSpace(line)
	}
	var password []byte
	if flags.passwordStdin {
		line, readErr := readLine()
		if readErr != nil {
			return fmt.Errorf("connect failed")
		}
		password = []byte(strings.TrimRight(line, "\r\n"))
	} else {
		fmt.Fprint(stderr, "Password: ")
		password, err = readPassword()
		fmt.Fprintln(stderr)
		if err != nil {
			return fmt.Errorf("connect failed")
		}
	}
	defer wipe(password)

	if flags.caFile != "" {
		if err := client.CheckCA(flags.caFile, time.Now()); err != nil {
			return err
		}
	}
	loreBinary := client.ResolveLoreBinary(flags.loreBinary)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	res, err := client.Connect(ctx, client.ConnectOptions{
		ManagerURL:         managerURL,
		Username:           username,
		Password:           password,
		Project:            flags.project,
		ExplicitCAFile:     flags.caFile,
		RetrustCA:          flags.retrustCA,
		ExplicitAuthURL:    flags.authURL,
		LoreBinary:         loreBinary,
		ExplicitConfigPath: flags.configPath,
		ExplicitAuthPath:   flags.authPath,
		AuthStore:          flags.authStore,
	}, newExecutor(loreBinary))
	if err != nil {
		return err
	}
	if res.TOFUTrusted {
		fmt.Fprintf(stderr, "trusted internal CA via TOFU (sha256=%s)\n", res.CASHA256)
	}
	if flags.asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	fmt.Fprintf(stdout, "connected user=%s manager=%s\n", res.Username, res.ManagerURL)
	fmt.Fprintf(stdout, "config=%s\n", res.ConfigPath)
	if res.CASHA256 != "" {
		fmt.Fprintf(stdout, "ca_sha256=%s\n", res.CASHA256)
	}
	if res.AuthURL != "" {
		fmt.Fprintf(stdout, "auth_url=%s\n", res.AuthURL)
	}
	if res.Project != "" {
		fmt.Fprintf(stdout, "project=%s\n", res.Project)
	}
	if len(res.Projects) > 0 {
		fmt.Fprintf(stdout, "projects=%s\n", strings.Join(res.Projects, ","))
	}
	fmt.Fprintf(stdout, "authorized_modules=%d\n", res.ModulesCount)
	_ = os.Stderr
	return nil
}
