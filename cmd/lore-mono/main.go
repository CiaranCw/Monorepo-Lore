package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"lore-monorepo/internal/client"
	"lore-monorepo/internal/loreexec"
)

var (
	stdin        io.Reader = os.Stdin
	stdout       io.Writer = os.Stdout
	stderr       io.Writer = os.Stderr
	readPassword           = func() ([]byte, error) {
		return term.ReadPassword(int(os.Stdin.Fd()))
	}
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	switch args[0] {
	case "guide":
		if err := guideCmd(args[1:]); err != nil {
			fmt.Fprintln(stderr, err.Error())
			return 1
		}
		return 0
	case "connect":
		if err := connectCmd(args[1:]); err != nil {
			fmt.Fprintln(stderr, err.Error())
			return 1
		}
		return 0
	case "login":
		if err := login(args[1:]); err != nil {
			fmt.Fprintln(stderr, err.Error())
			return 1
		}
		fmt.Fprintln(stdout, "logged in")
		return 0
	case "password":
		if err := changePasswordCmd(args[1:]); err != nil {
			fmt.Fprintln(stderr, err.Error())
			return 1
		}
		return 0
	case "logout", "project", "module", "clone", "status", "sync", "stage", "commit", "push", "publish", "history", "refs", "show", "import":
		if err := dispatch(args); err != nil {
			fmt.Fprintln(stderr, err.Error())
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "lore-mono: %s is not implemented yet\n", args[0])
		fmt.Fprint(stderr, usage)
		return 2
	}
}

func login(args []string) error {
	flags, err := parseLogin(args)
	if err != nil {
		return err
	}
	cfg := client.Config{LoreBinary: "lore"}
	if flags.configPath != "" {
		loaded, err := client.Load(flags.configPath)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("client config")
		}
		if err == nil {
			cfg = loaded
		}
	} else if flags.managerURL == "" {
		if activePath, err := client.ActiveConfigPath(); err == nil && activePath != "" {
			if loaded, loadErr := client.Load(activePath); loadErr == nil {
				cfg = loaded
			}
		}
	}
	if flags.managerURL != "" {
		cfg.ManagerURL = flags.managerURL
	}
	if flags.loreBinary != "" {
		cfg.LoreBinary = flags.loreBinary
	}
	if flags.authURL != "" {
		cfg.AuthURL = flags.authURL
	}
	if flags.authPath != "" {
		cfg.AuthPath = flags.authPath
	}
	if flags.authStore != "" {
		cfg.AuthStore = flags.authStore
	}
	if cfg.ManagerURL == "" {
		fmt.Fprint(stderr, "Manager URL: ")
		line, err := readLine()
		if err != nil {
			return fmt.Errorf("login failed")
		}
		cfg.ManagerURL = strings.TrimSpace(line)
	}
	if err := client.CheckManagerURL(cfg.ManagerURL); err != nil {
		return err
	}
	username := flags.username
	if username == "" {
		fmt.Fprint(stderr, "Username: ")
		line, err := readLine()
		if err != nil {
			return fmt.Errorf("login failed")
		}
		username = strings.TrimSpace(line)
	}
	var password []byte
	if flags.passwordStdin {
		line, err := readLine()
		if err != nil {
			return fmt.Errorf("login failed")
		}
		password = []byte(strings.TrimRight(line, "\r\n"))
	} else {
		fmt.Fprint(stderr, "Password: ")
		password, err = readPassword()
		fmt.Fprintln(stderr)
		if err != nil {
			return fmt.Errorf("login failed")
		}
	}
	defer wipe(password)
	if flags.configPath != "" {
		cfg.Path = flags.configPath
		if err := client.Save(cfg); err != nil {
			return fmt.Errorf("client config")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return client.Login(ctx, cfg, username, password, newExecutor(cfg.LoreBinary))
}

var newExecutor = func(binary string) loreexec.Executor {
	return loreexec.Executor{Config: loreexec.Config{Binary: binary, Timeout: time.Minute}}
}

type loginFlags struct {
	configPath    string
	managerURL    string
	username      string
	loreBinary    string
	authURL       string
	authPath      string
	authStore     string
	passwordStdin bool
}

func parseLogin(args []string) (loginFlags, error) {
	var f loginFlags
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--password=") || arg == "--password" {
			return f, fmt.Errorf("password must not be passed as an argument")
		}
		name, val, ok := splitFlag(arg)
		switch name {
		case "--config", "--manager", "--username", "--lore-binary", "--auth-url", "--auth-path", "--auth-store":
			if !ok {
				if i+1 >= len(args) {
					return f, fmt.Errorf("missing value for %s", name)
				}
				i++
				val = args[i]
			}
			switch name {
			case "--config":
				f.configPath = val
			case "--manager":
				f.managerURL = val
			case "--username":
				f.username = val
			case "--lore-binary":
				f.loreBinary = val
			case "--auth-url":
				f.authURL = val
			case "--auth-path":
				f.authPath = val
			case "--auth-store":
				f.authStore = val
			}
		case "--password-stdin":
			f.passwordStdin = true
		default:
			return f, fmt.Errorf("unknown argument")
		}
	}
	return f, nil
}

func splitFlag(arg string) (string, string, bool) {
	if i := strings.IndexByte(arg, '='); i >= 0 {
		return arg[:i], arg[i+1:], true
	}
	return arg, "", false
}

func readLine() (string, error) {
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && len(line) == 0 {
		return "", err
	}
	return line, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

const usage = `lore-mono is the CLI for Monorepo-Lore (multi-module Lore repositories via Manager).

First time or AI Agent? Run:
  lore-mono guide           Full onboarding guide (architecture, rules, workflows)
  lore-mono guide --json    Machine-readable capability & command inventory

Discovery & Authentication:
  lore-mono connect --manager <url> [--username name] [--password-stdin] [--project P] [--ca-file pem] [--json]
  lore-mono login [--config file] [--manager url] [--username name] [--password-stdin]
  lore-mono password [--config file] [--password-stdin]
  lore-mono logout [--config file]
  lore-mono project list [--config file]
  lore-mono project use <project> [--config file]
  lore-mono module list [--config file]

Workspace & Sync:
  lore-mono clone <module> [--config file] [--dest dir]
  lore-mono clone --all-authorized [--config file] [--root dir]
  lore-mono status [--all|<module>] [--config file] [--root dir]
  lore-mono sync [--all|<module>] [--config file] [--root dir]

Stage, Commit & Push (each module keeps independent revisions):
  lore-mono stage [--all|<module>] [--config file] [--root dir]
  lore-mono commit [--all|<module>] --message text [--config file] [--root dir]
  lore-mono push [--all|<module>] [--config file] [--root dir]

History & Inspection:
  lore-mono history [module|--all] [--project name] [--branch b] [--tag t] [--limit n] [--all-pages] [--sync] [--json]
  lore-mono refs <module> [--type branch|tag] [--json] [--config file]
  lore-mono show <module> <commit-or-revision> [--json] [--config file]

Admin / Migration (requires project_admin):
  lore-mono import --manifest file [--dry-run] [--on-conflict policy] [--config file]
  lore-mono import jobs [--project name] [--job id] [--json] [--config file]
  lore-mono publish [--config file]

Typical Workflows:
  1. Zero-config connect: connect --manager <url> --username <U> --password-stdin -> project list -> module list -> clone <M>
  2. Multi-repo batch edit: stage --all -> commit --all --message "..." -> push --all

Notes: client.toml never stores passwords or tokens; batch commands run once per authorized module.
`
